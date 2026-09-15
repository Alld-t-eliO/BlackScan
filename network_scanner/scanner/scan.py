import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from network_scanner.payloads.exploits import (list_exploits, Exploit,)
from network_scanner.payloads.exploits.ssh.auth_bypass import (SSHAuthBypass, SSHEmptyPasswordExploit, SSHUsernameEnumerator,)
from network_scanner.payloads.exploits.ssh.privilege_escalation import (SSHPrivilegeEscalation,)
from network_scanner.payloads.exploits.ssh.persistence import (SSHPersistence,)
from network_scanner.payloads.exploits.web.web_exploits import (TomcatManagerExploit, DirectoryTraversalExploit, WordPressExploit, JenkinsExploit,)
from network_scanner.payloads.exploits.databases.database_exploits import (MySQLExploit, RedisExploit, MongoDBExploit, PostgreSQLExploit,)
from network_scanner.payloads.exploits.web.rce import (CommandInjectionExploit, SSTIExploit, FileUploadRCE, LFIExploit, XXEExploit, SSRFExploit, DeserializationExploit, JWTExploit,)
from network_scanner.payloads.exploits.xss import (SliderRevolutionExploit,)
from network_scanner import settings
from network_scanner.modules import (external_tools, os_detection, ping_sweep, port_scanner, risk, service_scan, vulnerability,)
from network_scanner.scanner.parser import validate_target
from network_scanner.scanner.report import Colors, ReportMixin


EXPLOIT_REGISTRY: dict[str, list[type]] = {
    'ssh': [
        SSHAuthBypass,
        SSHEmptyPasswordExploit,
        SSHUsernameEnumerator,
        SSHPrivilegeEscalation,
        SSHPersistence,
    ],
    'http': [
        TomcatManagerExploit,
        JenkinsExploit,
        WordPressExploit,
        DirectoryTraversalExploit,
        CommandInjectionExploit,
        SSTIExploit,
        FileUploadRCE,
        LFIExploit,
        XXEExploit,
        SSRFExploit,
        DeserializationExploit,
        JWTExploit,
        SliderRevolutionExploit,
    ],
    'https': [
        TomcatManagerExploit,
        JenkinsExploit,
        WordPressExploit,
        DirectoryTraversalExploit,
        CommandInjectionExploit,
        SSTIExploit,
        FileUploadRCE,
        LFIExploit,
        XXEExploit,
        SSRFExploit,
        DeserializationExploit,
        JWTExploit,
        SliderRevolutionExploit,
    ],
    'mysql': [
        MySQLExploit,
    ],
    'redis': [
        RedisExploit,
    ],
    'mongodb': [
        MongoDBExploit,
    ],
    'postgresql': [
        PostgreSQLExploit,
    ],
}

PORT_TO_SERVICE: dict[int, str] = {
    22: 'ssh',
    80: 'http',
    443: 'https',
    8000: 'http',
    8080: 'http',
    8443: 'https',
    8888: 'http',
    3306: 'mysql',
    5432: 'postgresql',
    6379: 'redis',
    27017: 'mongodb',
}

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
        exploit_mode=False,
        exploit_timeout=60,
        exploit_targets=None,
        exploit_auto_confirm=False,
        exploit_module='all',
    ):
        self.target = validate_target(target)
        for label, value, limit in (
            ('threads', threads, 512), ('host_workers', host_workers, 64),
            ('service_workers', service_workers, 128), ('timeout', timeout, 3600),
            ('max_hosts', max_hosts, 65536), ('external_timeout', external_timeout, 3600),
            ('exploit_timeout', exploit_timeout, 3600),
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
        self.exploit_mode = exploit_mode
        self.exploit_timeout = exploit_timeout
        self.exploit_targets = exploit_targets
        self.exploit_auto_confirm = exploit_auto_confirm
        self.exploit_module = exploit_module
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

    def emit_log(self, message, end='\n'):
        if self.log_callback:
            self.log_callback(message)
        else:
            print(message, end=end)

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
                except Exception as exc:
                    self.emit_log(f"{Colors.RED}[!] Failed to scan {host}: {exc}{Colors.RESET}")
                    self.record_error('host', host, exc)
                    self.results['host_status'][host] = 'error'
                    continue
                self.results['host_status'][host] = 'complete'
                if host_result:
                    scan_results[host] = host_result
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
            except Exception as exc:
                self.record_error('external', self.target, exc)
            self.emit_log(f"{Colors.GREEN}[+] External enrichment finished; consult individual step statuses{Colors.RESET}")

        self.emit_progress(94, 'Generating reports')
        self.results['scan_status'] = 'partial' if self.results['errors'] else 'complete'

        if self.exploit_mode:
            self.emit_log(f"\n{Colors.BLUE}[*] Step 4: Exploitation phase...{Colors.RESET}")
            
            if not self.intrusive_checks:
                self.emit_log(f"{Colors.RED}[!] Exploitation requires --intrusive-checks{Colors.RESET}")
                self.emit_log(f"{Colors.YELLOW}[!] Run with --intrusive-checks to enable exploitation{Colors.RESET}")
            else:
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    exploit_results = loop.run_until_complete(self.run_exploit_phase())
                else:
                    exploit_results = loop.run_until_complete(self.run_exploit_phase())
                
                if exploit_results:
                    self.results['exploit_results'] = []
                    for r in exploit_results:
                        if hasattr(r, 'as_dict'):
                            self.results['exploit_results'].append(r.as_dict())
                        elif isinstance(r, dict):
                            self.results['exploit_results'].append(r)

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
                except Exception as exc:
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

     async def run_exploit_phase(self) -> List[ExploitResult]:
        from datetime import datetime

        start_time = datetime.now()

        self.emit_log(f"\n{Colors.BOLD}{Colors.RED}{'='*70}{Colors.RESET}")
        self.emit_log(f"{Colors.BOLD}{Colors.RED}    AUTOMATIC EXPLOITATION PHASE{Colors.RESET}")
        self.emit_log(f"{Colors.BOLD}{Colors.RED}{'='*70}{Colors.RESET}")
        self.emit_log(f"{Colors.YELLOW}  [WARNING] Only run on authorized targets{Colors.RESET}")

        missing = []
        for dep in ('paramiko', 'aiohttp'):
            try:
                __import__(dep)
            except ImportError:
                missing.append(dep)

        if missing:
            self.emit_log(
                f"{Colors.YELLOW}[!] Optional dependencies missing: "
                f"{', '.join(missing)}. "
                f"Some exploits will be skipped.{Colors.RESET}"
            )

        self.emit_log(f"\n{Colors.BLUE}[*] Analyzing exploitable targets...{Colors.RESET}")
        targets = self._analyze_targets()

        if not targets:
            self.emit_log(
                f"{Colors.YELLOW}[!] No exploitable targets detected{Colors.RESET}"
            )
            return []

        self._display_targets_summary(targets)

        if not getattr(self, 'exploit_auto_confirm', False):
            self.emit_log(
                f"\n{Colors.BOLD}{Colors.CYAN}"
                f"  Start the exploitation phase? (y/N): "
                f"{Colors.RESET}",
                end='',
            )
            try:
                response = input().strip().lower()
            except EOFError:
                response = 'n'

            if response not in ('y', 'yes', 'o', 'oui'):
                self.emit_log(f"{Colors.YELLOW}[!] Cancelled by user{Colors.RESET}")
                return []

        results = await self._execute_exploits(targets)
        self._display_exploitation_summary(results, start_time)
        self._save_exploit_results(results)

        return results

    async def _execute_exploits(self, targets: List[Dict[str, Any]]) -> List[ExploitResult]:
        results: List[ExploitResult] = []
        total = sum(len(t['exploits']) for t in targets)
        completed = 0

        self.emit_log(
            f"{Colors.BLUE}[*] Starting {total} exploitation attempt(s)..."
            f"{Colors.RESET}\n"
        )

        for target_idx, target in enumerate(targets, 1):
            self.emit_log(
                f"\n{Colors.BOLD}{Colors.CYAN}"
                f"TARGET {target_idx}/{len(targets)}: "
                f"{target['host']}:{target['port']}{Colors.RESET}"
            )
            self.emit_log(
                f"{Colors.WHITE}   Service: {target['service_display']} | "
                f"Risk: {target['risk'].upper()}{Colors.RESET}"
            )
            self.emit_log(f"{Colors.BOLD}{'-'*70}{Colors.RESET}")

            for exploit_info in target['exploits']:
                exploit_class = exploit_info['class']
                exploit_name = exploit_info['name']

                completed += 1
                pct = int((completed / total) * 100) if total else 0
                self.emit_progress(pct, f"Exploitation: {exploit_name}")

                self.emit_log(
                    f"\n  {Colors.BOLD}[{completed}/{total}] {exploit_name}"
                    f"{Colors.RESET}"
                )

                try:
                    exploit = self._instantiate_exploit(
                        exploit_class, target['host'], target['port'], target
                    )
                    if exploit is None:
                        self.emit_log(
                            f"  {Colors.YELLOW}[-] Cannot instantiate (missing deps)"
                            f"{Colors.RESET}"
                        )
                        continue

                    self.emit_log(
                        f"  {Colors.BLUE}[*] Checking vulnerability..."
                        f"{Colors.RESET}"
                    )
                    try:
                        is_vuln, reason = await asyncio.wait_for(
                            exploit.check(), timeout=30
                        )
                    except asyncio.TimeoutError:
                        self.emit_log(
                            f"  {Colors.YELLOW}[-] Check timeout{Colors.RESET}"
                        )
                        continue

                    if not is_vuln:
                        self.emit_log(
                            f"  {Colors.YELLOW}[-] {reason}{Colors.RESET}"
                        )
                        continue

                    self.emit_log(
                        f"  {Colors.GREEN}[+] Vulnerable: {reason}{Colors.RESET}"
                    )

                    self.emit_log(
                        f"  {Colors.BLUE}[*] Running exploit...{Colors.RESET}"
                    )
                    try:
                        result = await asyncio.wait_for(
                            exploit.exploit(),
                            timeout=getattr(self, 'exploit_timeout', 60),
                        )
                    except asyncio.TimeoutError:
                        self.emit_log(
                            f"  {Colors.YELLOW}[-] Exploit timeout{Colors.RESET}"
                        )
                        continue

                    results.append(result)

                    if result.success:
                        self.emit_log(
                            f"\n  {Colors.RED}{'='*50}{Colors.RESET}"
                        )
                        self.emit_log(
                            f"  {Colors.BOLD}{Colors.RED}[+] EXPLOIT SUCCEEDED"
                            f"{Colors.RESET}"
                        )
                        self.emit_log(
                            f"  {Colors.RED}{'='*50}{Colors.RESET}"
                        )
                        self.emit_log(
                            f"  {Colors.GREEN}{result.description}{Colors.RESET}"
                        )

                        if result.credentials:
                            self.emit_log(
                                f"  {Colors.RED}- Credentials: "
                                f"{result.credentials[0]}:{result.credentials[1]}"
                                f"{Colors.RESET}"
                            )
                        if result.shell_url:
                            self.emit_log(
                                f"  {Colors.CYAN}- Shell URL: {result.shell_url}"
                                f"{Colors.RESET}"
                            )

                        self._record_exploit_success(target, exploit_name, result)
                    else:
                        self.emit_log(
                            f"  {Colors.YELLOW}[-] Failed: "
                            f"{result.error or result.description}{Colors.RESET}"
                        )

                except Exception as exc:
                    self.emit_log(
                        f"  {Colors.RED}[!] ERROR: {type(exc).__name__}: {exc}"
                        f"{Colors.RESET}"
                    )
                    self.record_error(
                        'exploit',
                        f"{target['host']}:{target['port']}",
                        exc,
                    )

        return results

    def _instantiate_exploit(
        self,
        exploit_class: type,
        host: str,
        port: int,
        target: Dict[str, Any],
    ) -> Optional[Exploit]:
        class_name = exploit_class.__name__

        if class_name in ('SSHPrivilegeEscalation', 'SSHPersistence'):
            creds = self._find_ssh_credentials(host, port)
            if not creds:
                self.emit_log(
                    f"  {Colors.YELLOW}[-] No SSH credentials found for "
                    f"{host}:{port}{Colors.RESET}"
                )
                return None
            return exploit_class(host, port, credentials=creds)

        if class_name in ('CommandInjectionExploit', 'SSTIExploit',
                          'LFIExploit', 'SSRFExploit', 'JWTExploit'):
            return exploit_class(host, port, path='/')

        if class_name == 'FileUploadRCE':
            return exploit_class(host, port, upload_path='/upload')

        if class_name == 'XXEExploit':
            return exploit_class(host, port, path='/')

        if class_name == 'DeserializationExploit':
            return exploit_class(host, port, path='/')

        return exploit_class(host, port)

    def _find_ssh_credentials(self, host: str, port: int) -> Optional[Tuple[str, str]]:
        if hasattr(self, '_exploit_results_cache'):
            key = f"{host}:{port}"
            cached = self._exploit_results_cache.get(key)
            if cached and cached.get('credentials'):
                return tuple(cached['credentials'])

        target_key = f"{host}:{port}"
        vulns = self.results.get('vulnerabilities', {}).get(target_key, [])
        for v in vulns:
            if v.get('credentials'):
                try:
                    user, pwd = v['credentials']
                    return (user, pwd)
                except (TypeError, ValueError):
                    continue

        return None

    def _record_exploit_success(
        self,
        target: Dict[str, Any],
        exploit_name: str,
        result: ExploitResult,
    ):
        """Enregistre un exploit réussi dans les vulnérabilités"""
        target_key = f"{target['host']}:{target['port']}"

        finding = {
            'name': f"EXPLOIT SUCCEEDED: {exploit_name}",
            'severity': 'critical',
            'target': target_key,
            'evidence': result.proof or result.description,
            'recommendation': 'SYSTEM COMPROMISED - Immediate action required',
            'exploit_details': result.as_dict() if hasattr(result, 'as_dict') else str(result),
        }

        existing = self.results.setdefault('vulnerabilities', {}).setdefault(target_key, [])
        existing.append(finding)

        current = self.results.setdefault('risks', {}).setdefault(
            target_key, {'score': 'info', 'factors': []}
        )
        current['score'] = 'critical'

        if result.credentials:
            if not hasattr(self, '_exploit_results_cache'):
                self._exploit_results_cache = {}
            self._exploit_results_cache[target_key] = {
                'credentials': result.credentials,
            }

    def _analyze_targets(self) -> List[Dict[str, Any]]:
        targets: List[Dict[str, Any]] = []
        seen: set[Tuple[str, int]] = set()

        for host, services in self.results.get('services', {}).items():
            for port_str, service in services.items():
                try:
                    port = int(port_str)
                except (TypeError, ValueError):
                    continue

                raw_name = (service.get('name') or '').lower()

                service_name = self._normalize_service_name(raw_name, port)

                if not service_name:
                    continue

                key = (host, port)
                if key in seen:
                    continue
                seen.add(key)

                exploit_classes = EXPLOIT_REGISTRY.get(service_name, [])
                if not exploit_classes:
                    continue

                exploits = []
                for cls in exploit_classes:
                    if not self._exploit_dependencies_ok(cls):
                        continue
                    exploits.append({
                        'class': cls,
                        'name': getattr(cls, 'name', cls.__name__),
                        'severity': getattr(cls, 'severity', 'info'),
                    })

                if not exploits:
                    continue

                target_key = f"{host}:{port}"
                existing_vulns = self.results.get('vulnerabilities', {}).get(target_key, [])
                risk_info = self.results.get('risks', {}).get(target_key, {})

                targets.append({
                    'host': host,
                    'port': port,
                    'service': service_name,
                    'service_display': service.get('name', 'unknown'),
                    'exploits': exploits,
                    'vulns_count': len(existing_vulns),
                    'risk': risk_info.get('score', 'info'),
                    'banner': (service.get('banner') or '')[:60],
                })

        module_filter = getattr(self, 'exploit_module', 'all')
        if module_filter and module_filter != 'all':
            targets = [
                t for t in targets
                if self._service_in_module(t['service'], module_filter)
            ]

        if getattr(self, 'exploit_targets', None):
            target_list = [
                x.strip() for x in self.exploit_targets.split(',')
                if x.strip()
            ]
            targets = [
                t for t in targets
                if f"{t['host']}:{t['port']}" in target_list
            ]

        risk_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        targets.sort(key=lambda t: (risk_order.get(t['risk'], 5), t['host'], t['port']))

        return targets

    @staticmethod
    def _normalize_service_name(raw_name: str, port: int) -> Optional[str]:
        if raw_name in EXPLOIT_REGISTRY:
            return raw_name

        for svc in EXPLOIT_REGISTRY:
            if svc in raw_name:
                return svc

        return PORT_TO_SERVICE.get(port)

    @staticmethod
    def _service_in_module(service: str, module: str) -> bool:
        mapping = {
            'ssh': ['ssh'],
            'web': ['http', 'https'],
            'database': ['mysql', 'postgresql', 'redis', 'mongodb'],
        }
        allowed = mapping.get(module, [])
        return service in allowed

    @staticmethod
    def _exploit_dependencies_ok(cls: type) -> bool:
        requires = getattr(cls, 'requires', []) or []
        for dep in requires:
            try:
                __import__(dep)
            except ImportError:
                return False
        return True

    def _display_targets_summary(self, targets: List[Dict[str, Any]]):
        self.emit_log(
            f"\n{Colors.GREEN}[+] {len(targets)} exploitable target(s) detected:"
            f"{Colors.RESET}\n"
        )

        for i, target in enumerate(targets, 1):
            risk_color = {
                'critical': Colors.RED,
                'high': Colors.RED,
                'medium': Colors.YELLOW,
                'low': Colors.BLUE,
                'info': Colors.WHITE,
            }.get(target['risk'], Colors.WHITE)

            exploit_names = ', '.join(e['name'][:35] for e in target['exploits'][:3])
            if len(target['exploits']) > 3:
                exploit_names += f" (+{len(target['exploits']) - 3} more)"

            self.emit_log(
                f"  {Colors.BOLD}{i}. {target['host']}:{target['port']}{Colors.RESET} "
                f"[{target['service']}]"
            )
            self.emit_log(
                f"     Risk: {risk_color}{target['risk'].upper()}{Colors.RESET} | "
                f"Vulns known: {target['vulns_count']} | "
                f"Exploits: {len(target['exploits'])}"
            )
            self.emit_log(f"     → {exploit_names}")
            self.emit_log("")

    async def _execute_exploits(self, targets):
        results = []
        total_exploits = sum(len(t['exploits']) for t in targets)
        completed = 0
        successful_exploits = []
        failed_exploits = []
        
        self.emit_log(f"{Colors.BLUE}[*] Starting {total_exploits} exploitation attempt(s)...{Colors.RESET}\n")
        self.emit_log(f"{Colors.BOLD}{'─'*70}{Colors.RESET}")
        
        for target_idx, target in enumerate(targets, 1):
            self.emit_log(f"\n{Colors.BOLD}{Colors.CYAN}🎯 TARGET {target_idx}/{len(targets)}: {target['host']}:{target['port']}{Colors.RESET}")
            self.emit_log(f"{Colors.WHITE}   Service: {target['service_display']} | Risk: {target['risk'].upper()}{Colors.RESET}")
            self.emit_log(f"{Colors.BOLD}{'─'*70}{Colors.RESET}")
            
            for exploit_info in target['exploits']:
                exploit_class = exploit_info['class']
                exploit_name = exploit_info['name']
                severity = exploit_info['severity']
                
                completed += 1
                progress_pct = int((completed / total_exploits) * 100)
                
                self.emit_progress(progress_pct, f"Exploitation: {exploit_name}")
                
                self.emit_log(f"\n  {Colors.BOLD}[{completed}/{total_exploits}] {exploit_name}{Colors.RESET}")
                self.emit_log(f"  {Colors.WHITE}  Severity: {severity.upper()} | Progress: {progress_pct}%{Colors.RESET}")
                
                try:
                    exploit = exploit_class(target['host'], target['port'])
                    
                    self.emit_log(f"  {Colors.BLUE}[*] Checking vulnerability...{Colors.RESET}")
                    is_vuln, reason = await asyncio.wait_for(
                        exploit.check(),
                        timeout=30
                    )
                    
                    if not is_vuln:
                        self.emit_log(f"  {Colors.YELLOW}[-] Not vulnerable: {reason}{Colors.RESET}")
                        failed_exploits.append({
                            'target': f"{target['host']}:{target['port']}",
                            'exploit': exploit_name,
                            'reason': reason,
                            'status': 'not_vulnerable'
                        })
                        continue
                    
                    self.emit_log(f"  {Colors.GREEN}[+] Vulnerability confirmed!{Colors.RESET}")
                    self.emit_log(f"  {Colors.BLUE}[*] Starting exploitation...{Colors.RESET}")
                    
                    result = await asyncio.wait_for(
                        exploit.exploit(),
                        timeout=self.exploit_timeout
                    )
                    
                    results.append(result)
                    
                    if result.success:
                        self.emit_log(f"\n  {Colors.RED}{'='*50}{Colors.RESET}")
                        self.emit_log(f"  {Colors.BOLD}{Colors.RED}[+] EXPLOIT SUCCEEDED{Colors.RESET}")
                        self.emit_log(f"  {Colors.RED}{'='*50}{Colors.RESET}")
                        self.emit_log(f"  {Colors.GREEN}✓ {result.description}{Colors.RESET}")
                        
                        if result.credentials:
                            self.emit_log(f"  {Colors.RED}- Credentials: {result.credentials[0]}:{result.credentials[1]}{Colors.RESET}")
                        
                        if result.shell_url:
                            self.emit_log(f"  {Colors.CYAN}- Shell URL: {result.shell_url}{Colors.RESET}")
                        
                        if result.proof:
                            self.emit_log(f"  {Colors.WHITE}- Evidence: {result.proof[:300]}{Colors.RESET}")
                        
                        target_key = f"{target['host']}:{target['port']}"
                        exploit_finding = {
                            'name': f"EXPLOIT SUCCEEDED: {exploit_name}",
                            'severity': 'critical',
                            'target': target_key,
                            'evidence': result.proof or str(result.output),
                            'recommendation': '[SUCCESS] SYSTEM COMPROMISED - Immediate action required',
                            'exploit_details': result.as_dict()
                        }
                        
                        existing = self.results['vulnerabilities'].get(target_key, [])
                        if exploit_finding not in existing:
                            self.results['vulnerabilities'].setdefault(target_key, []).append(exploit_finding)
                        
                        current_risk = self.results['risks'].get(target_key, {'score': 'info', 'factors': []})
                        current_risk['score'] = 'critical'
                        self.results['risks'][target_key] = current_risk
                        
                        successful_exploits.append({
                            'target': f"{target['host']}:{target['port']}",
                            'exploit': exploit_name,
                            'credentials': result.credentials,
                            'shell_url': result.shell_url,
                            'proof': result.proof[:200]
                        })
                        
                    else:
                        self.emit_log(f"  {Colors.YELLOW}[-] Exploitation failed: {result.error or 'Unknown reason'}{Colors.RESET}")
                        failed_exploits.append({
                            'target': f"{target['host']}:{target['port']}",
                            'exploit': exploit_name,
                            'reason': result.error or 'Unknown failure',
                            'status': 'failed'
                        })
                    
                except asyncio.TimeoutError:
                    self.emit_log(f"  {Colors.RED}[!] TIMEOUT - Exploitation exceeded the time limit{Colors.RESET}")
                    failed_exploits.append({
                        'target': f"{target['host']}:{target['port']}",
                        'exploit': exploit_name,
                        'reason': 'Timeout (60s)',
                        'status': 'timeout'
                    })
                    
                except Exception as e:
                    self.emit_log(f"  {Colors.RED}[!] ERROR: {e}{Colors.RESET}")
                    failed_exploits.append({
                        'target': f"{target['host']}:{target['port']}",
                        'exploit': exploit_name,
                        'reason': str(e),
                        'status': 'error'
                    })
                    self.record_error('exploit', f"{target['host']}:{target['port']}", e)
        
        self._exploit_summary = {
            'total_exploits': total_exploits,
            'successful': successful_exploits,
            'failed': failed_exploits,
            'results': results
        }
        
        return results

    def _display_exploitation_summary(self, results, start_time):
        from datetime import datetime
        duration = datetime.now() - start_time
        
        successful = [r for r in results if r.success]
        failed = [r for r in results if not r.success]
        
        self.emit_log(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}")
        self.emit_log(f"{Colors.BOLD}{Colors.PURPLE}    [+] EXPLOITATION REPORT - COMPLETE SUMMARY{Colors.RESET}")
        self.emit_log(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}")
        
        self.emit_log(f"\n{Colors.WHITE}-  Total duration: {duration.total_seconds():.2f}s{Colors.RESET}")
        self.emit_log(f"{Colors.WHITE}- Exploits attempted: {len(results)}{Colors.RESET}")
        self.emit_log(f"{Colors.GREEN}- Successful exploits: {len(successful)}{Colors.RESET}")
        self.emit_log(f"{Colors.RED}- Failed exploits: {len(failed)}{Colors.RESET}")
        
        if successful:
            self.emit_log(f"\n{Colors.BOLD}{Colors.RED}[SUCCESS] SUCCESSFUL COMPROMISES:{Colors.RESET}")
            self.emit_log(f"{Colors.BOLD}{'─'*70}{Colors.RESET}")
            
            for i, result in enumerate(successful, 1):
                self.emit_log(f"\n  {Colors.BOLD}{i}. {result.target}{Colors.RESET}")
                self.emit_log(f"     Exploit: {result.description}")
                
                if result.credentials:
                    self.emit_log(f"     {Colors.RED}- Credentials: {result.credentials[0]}:{result.credentials[1]}{Colors.RESET}")
                
                if result.shell_url:
                    self.emit_log(f"     {Colors.CYAN}- Shell: {result.shell_url}{Colors.RESET}")
                
                if result.proof:
                    self.emit_log(f"     {Colors.WHITE}- Evidence: {result.proof[:150]}{Colors.RESET}")
                
                if result.metadata:
                    self.emit_log(f"     - Metadata:")
                    for key, value in result.metadata.items():
                        if isinstance(value, str) and len(value) > 100:
                            value = value[:100] + "..."
                        self.emit_log(f"        • {key}: {value}")
        
        if failed:
            self.emit_log(f"\n{Colors.BOLD}{Colors.YELLOW}- FAILURES:{Colors.RESET}")
            self.emit_log(f"{Colors.BOLD}{'─'*70}{Colors.RESET}")
            
            for i, result in enumerate(failed[:10], 1):
                self.emit_log(f"\n  {i}. {result.target}")
                self.emit_log(f"     Exploit: {result.description}")
                self.emit_log(f"     {Colors.YELLOW}Error: {result.error or 'Unknown reason'}{Colors.RESET}")
        
        if not successful:
            self.emit_log(f"\n{Colors.YELLOW}[!]  No successful compromises. The targets appear to be properly secured.{Colors.RESET}")
        
        self.emit_log(f"\n{Colors.BOLD}{Colors.CYAN}{'─'*70}{Colors.RESET}")
        if successful:
            self.emit_log(f"{Colors.BOLD}{Colors.RED}[] URGENT RECOMMENDATIONS:{Colors.RESET}")
            self.emit_log(f"  • Review active sessions on compromised systems")
            self.emit_log(f"  • Analyze logs for possible interesting datas")
            self.emit_log(f"  • Try to identify the exploited vulnerability and use it")
        else:
            self.emit_log(f"{Colors.GREEN}[+] No compromise detected. Continue following good security practices.{Colors.RESET}")
        
        self.emit_log(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}")
        self.emit_log(f"{Colors.WHITE}[-] Detailed report saved in the 'reports/' directory{Colors.RESET}")
        self.emit_log(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}\n")

    def _save_exploit_results(self, results):
        import json
        import os
        from datetime import datetime
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(self.output_dir, f"exploit_results_{timestamp}.json")
        
        exploit_report = {
            'timestamp': timestamp,
            'target': self.target,
            'total_exploits': len(results),
            'successful': [],
            'failed': [],
            'detailed_results': []
        }
        
        for result in results:
            result_dict = result.as_dict() if hasattr(result, 'as_dict') else vars(result)
            if result.success:
                exploit_report['successful'].append(result_dict)
            else:
                exploit_report['failed'].append(result_dict)
            exploit_report['detailed_results'].append(result_dict)
        
        exploit_report['metrics'] = {
            'success_rate': f"{len(exploit_report['successful'])}/{len(results)} ({ (len(exploit_report['successful'])/len(results)*100 if results else 0):.1f}%)",
            'credentials_found': len([r for r in results if r.success and r.credentials]),
            'shells_obtained': len([r for r in results if r.success and r.shell_url])
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(exploit_report, f, indent=2, ensure_ascii=False)
        
        self.emit_log(f"{Colors.GREEN}[+] Exploitation report saved: {filename}{Colors.RESET}")