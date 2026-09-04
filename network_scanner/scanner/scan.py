from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from network_scanner import settings
from network_scanner.modules import external_tools, os_detection, ping_sweep, port_scanner, risk, service_scan, vulnerability
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
    ):
        self.target = target
        self.threads = max(1, threads)
        self.timeout = max(1, timeout)
        self.profile = 'full' if aggressive else profile
        self.aggressive = aggressive or self.profile in {'full', 'internal', 'web'}
        self.ports = ports or settings.SCAN_PROFILES[self.profile]
        self.output_dir = output_dir
        self.max_hosts = max(1, max_hosts)
        self.compare_report = compare_report
        self.intrusive_checks = intrusive_checks
        self.host_workers = max(1, host_workers)
        self.service_workers = max(1, service_workers)
        self.proxy_url = proxy_url
        self.external_enrichment = bool(external_enrichment or aggressive or self.profile == 'full')
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
        self.emit_log(f"{Colors.BOLD}{Colors.CYAN}BlackScan - Network Vulnerability Scanner{Colors.RESET}")
        self.emit_log(f"{Colors.YELLOW}Use this tool only on systems you are authorized to assess.{Colors.RESET}\n")

        self.emit_progress(1, 'Host discovery')
        self.emit_log(f"{Colors.BLUE}[*] Step 1: host discovery...{Colors.RESET}")
        hosts = ping_sweep.sweep(self.target, self.threads, self.timeout, self.max_hosts)

        if not hosts:
            self.emit_progress(100, 'No hosts found')
            self.emit_log(f"{Colors.RED}[!] No hosts found on {self.target}{Colors.RESET}")
            return None

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
                except (OSError, RuntimeError, ValueError) as exc:
                    self.emit_log(f"{Colors.RED}[!] Failed to scan {host}: {exc}{Colors.RESET}")
                    continue
                if host_result:
                    scan_results[host] = host_result
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
            self.results['external_enrichment'] = external_tools.run_external_enrichment(
                self.target,
                self.results['hosts'],
                self.results['services'],
                self.timeout,
                self.proxy_url,
                self.emit_log,
            )
            self.emit_log(f"{Colors.GREEN}[+] External enrichment complete{Colors.RESET}")

        self.emit_progress(94, 'Generating reports')
        reports = self.generate_report()
        self.emit_progress(100, 'Scan complete')
        return reports

    def scan_host(self, host):
        self.emit_log(f"\n{Colors.CYAN}[*] Scanning {host}{Colors.RESET}")
        open_ports = port_scanner.scan_ports(host, self.ports, self.threads, self.timeout)

        if not open_ports:
            return None

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
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self.scan_service, host, port): port for port in open_ports}
            for future in as_completed(futures):
                port = futures[future]
                try:
                    service, vulns, risk_info = future.result()
                except (OSError, RuntimeError, ValueError) as exc:
                    self.emit_log(f"    {Colors.RED}[!] Failed to fingerprint {host}:{port}: {exc}{Colors.RESET}")
                    service = {'name': 'unknown', 'banner': '', 'http': {}, 'tls': {}}
                    vulns = []
                    risk_info = risk.score_service(host, port, service, vulns)
                host_result['services'][str(port)] = service
                if vulns:
                    host_result['vulnerabilities'][f"{host}:{port}"] = vulns
                host_result['risks'][f"{host}:{port}"] = risk_info

        return host_result

    def scan_service(self, host, port):
        service = service_scan.detect_service(host, port, self.timeout, self.proxy_url)

        service_name = service.get('name', 'unknown')
        banner = service.get('banner', '').replace('\n', ' ')[:80]
        banner_display = f" ({banner})" if banner else ""
        self.emit_log(f"    {Colors.GREEN}[+] Port {port}/tcp: {service_name}{banner_display}{Colors.RESET}")

        vulns = vulnerability.check_vulnerabilities(host, port, service, self.intrusive_checks) if self.aggressive else []
        if vulns:
            for vuln in vulns:
                self.emit_log(f"    {Colors.RED}[!] {vuln['severity'].upper()}: {vuln['name']}{Colors.RESET}")

        risk_info = risk.score_service(host, port, service, vulns)
        if risk_info['score'] in {'medium', 'high'}:
            self.emit_log(f"    {Colors.YELLOW}[!] {risk_info['score']} risk: {host}:{port}{Colors.RESET}")

        return service, vulns, risk_info
