import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from network_scanner import settings
from network_scanner.modules import (
    external_tools,
    os_detection,
    ping_sweep,
    port_scanner,
    risk,
    service_scan,
    vulnerability,
)
from network_scanner.scanner.parser import validate_target
from network_scanner.scanner.report import Colors, ReportMixin


class NetworkScanner(ReportMixin):
    def __init__(
        self,
        target,
        threads=100,
        timeout=2,
        aggressive=False,
        ports=None,
        output_dir='reports',
        profile='quick',
        max_hosts=4096,
        compare_report=None,
        intrusive_checks=False,
        host_workers=10,
        service_workers=32,
        proxy_url=None,
        external_enrichment=False,
        progress_callback=None,
        log_callback=None,
        skip_discovery=False,
        no_external_enrichment=False,
        external_timeout=120,
    ):
        self.target = validate_target(target)
        for label, value, limit in (
            ('threads', threads, 512), ('host_workers', host_workers, 64),
            ('service_workers', service_workers, 128), ('timeout', timeout, 3600),
            ('max_hosts', max_hosts, 65536), ('external_timeout', external_timeout, 3600),
        ):
            if not 1 <= value <= limit:
                raise ValueError(f'{label} must be between 1 and {limit}')
        self.threads = threads
        self.timeout = timeout
        self.profile = 'full' if aggressive else profile
        self.aggressive = aggressive or self.profile in {'full', 'internal', 'web'}
        if self.profile not in settings.SCAN_PROFILES:
            raise ValueError(f'unknown profile: {self.profile}')
        self.ports = list(settings.SCAN_PROFILES[self.profile] if ports is None else ports)
        if not self.ports or any(not isinstance(port, int) or not 1 <= port <= 65535 for port in self.ports):
            raise ValueError('ports must contain valid TCP port numbers')
        self.output_dir = output_dir
        self.max_hosts = max(1, max_hosts)
        self.compare_report = compare_report
        self.intrusive_checks = intrusive_checks
        self.host_workers = max(1, host_workers)
        self.service_workers = max(1, service_workers)
        self.proxy_url = proxy_url
        self.external_enrichment = not no_external_enrichment and bool(external_enrichment or aggressive or self.profile == 'full')
        self.skip_discovery = skip_discovery
        self.external_timeout = external_timeout
        self._error_lock = threading.Lock()
        self.progress_callback = progress_callback
        self.log_callback = log_callback
        self.results = {
            'hosts': [],
            'open_ports': {},
            'services': {},
            'os': {},
            'vulnerabilities': {},
            'risks': {},
            'external_enrichment': {},
            'errors': [],
            'host_status': {},
            'scan_status': 'running',
        }
        self.start_time = datetime.now(timezone.utc)

    def emit_progress(self, percent, message=''):
        if self.progress_callback:
            self.progress_callback(max(0, min(100, int(percent))), message)

    def emit_log(self, message):
        if self.log_callback:
            self.log_callback(message)
        else:
            print(message)

    def scan_network(self):
        try:
            return self._scan_network()
        except KeyboardInterrupt:
            self.results['scan_status'] = 'interrupted'
            self.generate_report()
            raise

    def _scan_network(self):
        self.emit_log(f"{Colors.BOLD}{Colors.CYAN}BlackScan - Network Vulnerability Scanner{Colors.RESET}")
        self.emit_log(f"{Colors.YELLOW}Use this tool only on systems you are authorized to assess.{Colors.RESET}\n")

        self.emit_progress(1, 'Host discovery')
        self.emit_log(f"{Colors.BLUE}[*] Step 1: host discovery...{Colors.RESET}")
        discovery_ports = tuple(dict.fromkeys((*ping_sweep.TCP_DISCOVERY_PORTS, *self.ports)))
        # Large ranges use a small representative probe set; --skip-discovery
        # explicitly scans every address without relying on discovery.
        discovery_ports = discovery_ports[:32]
        hosts = ping_sweep.sweep(
            self.target, self.threads, self.timeout, self.max_hosts, discovery_ports,
            skip_discovery=self.skip_discovery, log_callback=self.emit_log,
        )

        if not hosts:
            self.emit_progress(100, 'No hosts found')
            self.emit_log(f"{Colors.RED}[!] No hosts found on {self.target}{Colors.RESET}")
            self.results['scan_status'] = 'no_hosts'
            return self.generate_report()

        self.results['hosts'] = sorted(hosts)
        self.emit_progress(10, f'{len(hosts)} host(s) found')
        self.emit_log(f"{Colors.GREEN}[+] {len(hosts)} host(s) found{Colors.RESET}")
        self.emit_log(f"\n{Colors.BLUE}[*] Step 2: scanning {len(self.ports)} port(s)...{Colors.RESET}")

        scan_results = {}
        workers = min(self.host_workers, len(self.results['hosts']))
        completed_hosts = 0
        total_hosts = len(self.results['hosts'])
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self.scan_host, host): host for host in self.results['hosts']}
            for future in as_completed(futures):
                host = futures[future]
                try:
                    host_result = future.result()
                except Exception as exc:  # noqa: BLE001 -- one host must not discard the rest of a scan
                    self.emit_log(f"{Colors.RED}[!] Failed to scan {host}: {exc}{Colors.RESET}")
                    self.record_error('host', host, exc)
                    self.results['host_status'][host] = 'error'
                    continue
                self.results['host_status'][host] = 'complete'
                if host_result:
                    scan_results[host] = host_result
                    # Checkpoint each completed host before the next future can fail.
                    self.results['open_ports'][host] = host_result['open_ports']
                    self.results['services'][host] = host_result['services']
                    self.results['vulnerabilities'].update(host_result['vulnerabilities'])
                    self.results['risks'].update(host_result['risks'])
                completed_hosts += 1
                self.emit_progress(10 + (completed_hosts * 70 / total_hosts), f'Scanned {completed_hosts}/{total_hosts} host(s)')

        for host in self.results['hosts']:
            host_result = scan_results.get(host)
            if not host_result:
                continue
            self.results['open_ports'][host] = host_result['open_ports']
            self.results['services'][host] = host_result['services']
            if host_result.get('os'):
                self.results['os'][host] = host_result['os']
            self.results['vulnerabilities'].update(host_result['vulnerabilities'])
            self.results['risks'].update(host_result['risks'])

        if self.external_enrichment:
            self.emit_progress(84, 'External enrichment')
            self.emit_log(f"\n{Colors.BLUE}[*] Step 3: external enrichment...{Colors.RESET}")
            try:
                self.results['external_enrichment'] = external_tools.run_external_enrichment(
                    self.target, self.results['hosts'], self.results['services'],
                    self.timeout, self.proxy_url, self.emit_log,
                    command_timeout=self.external_timeout,
                )
                self.merge_external_findings()
                for step in self.results['external_enrichment'].get('pipeline', []):
                    if step.get('status') in {'error', 'timeout'}:
                        self.record_error('external', step['tool'], step.get('reason') or step['status'])
            except Exception as exc:  # noqa: BLE001 -- preserve internal findings if an optional tool fails
                self.record_error('external', self.target, exc)
            self.emit_log(f"{Colors.GREEN}[+] External enrichment finished; consult individual step statuses{Colors.RESET}")

        self.emit_progress(94, 'Generating reports')
        self.results['scan_status'] = 'partial' if self.results['errors'] else 'complete'
        reports = self.generate_report()
        self.emit_progress(100, 'Scan complete')
        return reports

    def scan_host(self, host):
        self.emit_log(f"\n{Colors.CYAN}[*] Scanning {host}{Colors.RESET}")
        open_ports = port_scanner.scan_ports(host, self.ports, self.threads, self.timeout)

        host_result = {
            'open_ports': open_ports,
            'services': {},
            'os': {},
            'vulnerabilities': {},
            'risks': {},
        }

        os_info = None
        if self.aggressive and settings.WEB_PORTS.union({22}).intersection(open_ports):
            os_info = os_detection.detect_os(host, self.timeout)
            if os_info:
                host_result['os'] = os_info
                label = os_info.get('family', 'Unknown') if isinstance(os_info, dict) else os_info
                self.emit_log(f"    {Colors.PURPLE}[+] Probable OS: {label}{Colors.RESET}")

        workers = min(self.service_workers, len(open_ports))
        if not workers:
            return host_result
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self.scan_service, host, port): port for port in open_ports}
            for future in as_completed(futures):
                port = futures[future]
                try:
                    service, vulns, risk_info = future.result()
                except Exception as exc:  # noqa: BLE001 -- retain the open port and record fingerprint failure
                    self.emit_log(f"    {Colors.RED}[!] Failed to fingerprint {host}:{port}: {exc}{Colors.RESET}")
                    service = {'name': 'unknown', 'banner': '', 'http': {}, 'tls': {}}
                    vulns = []
                    risk_info = risk.score_service(host, port, service, vulns)
                    self.record_error('service', f'{host}:{port}', exc)
                host_result['services'][str(port)] = service
                if vulns:
                    host_result['vulnerabilities'][f"{host}:{port}"] = vulns
                host_result['risks'][f"{host}:{port}"] = risk_info

        return host_result

    def scan_service(self, host, port):
        service = service_scan.detect_service(host, port, self.timeout, self.proxy_url)
        service['check_timeout'] = self.timeout

        service_name = service.get('name', 'unknown')
        banner = service.get('banner', '').replace('\n', ' ')[:80]
        banner_display = f" ({banner})" if banner else ""
        self.emit_log(f"    {Colors.GREEN}[+] Port {port}/tcp: {service_name}{banner_display}{Colors.RESET}")

        vulns = vulnerability.check_vulnerabilities(host, port, service, self.intrusive_checks) if self.aggressive or self.intrusive_checks else []
        for error in service.get('errors', []):
            self.record_error('fingerprint', f'{host}:{port}', error)
        if vulns:
            for vuln in vulns:
                self.emit_log(f"    {Colors.RED}[!] {vuln['severity'].upper()}: {vuln['name']}{Colors.RESET}")

        risk_info = risk.score_service(host, port, service, vulns)
        if risk_info['score'] in {'medium', 'high'}:
            self.emit_log(f"    {Colors.YELLOW}[!] {risk_info['score']} risk: {host}:{port}{Colors.RESET}")

        return service, vulns, risk_info

    def record_error(self, stage, target, error):
        with self._error_lock:
            self.results['errors'].append({'stage': stage, 'target': target, 'message': str(error)[:500]})

    def merge_external_findings(self):
        for finding in self.results['external_enrichment'].get('normalized_findings', []):
            target = finding['target']
            findings = self.results['vulnerabilities'].setdefault(target, [])
            if finding not in findings:
                findings.append(finding)
            current = self.results['risks'].setdefault(target, {'score': 'info', 'factors': []})
            current['score'] = risk.max_severity([current['score'], finding['severity']])
