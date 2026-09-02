#!/usr/bin/env python3
"""BlackScan network scanner CLI."""

import argparse
import csv
import html
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from network_scanner import settings
from network_scanner.modules import (
    external_tools,
    os_detection,
    ping_sweep,
    port_scanner,
    report_diff,
    risk,
    service_scan,
    vulnerability,
)


class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def parse_ports(value):
    """Parse comma-separated ports and ranges such as 22,80,8000-8100."""
    ports = set()
    for chunk in value.split(','):
        chunk = chunk.strip()
        if not chunk:
            continue
        if '-' in chunk:
            start, end = chunk.split('-', 1)
            start_port = int(start)
            end_port = int(end)
            if start_port > end_port:
                raise ValueError(f'invalid port range: {chunk}')
            ports.update(range(start_port, end_port + 1))
        else:
            ports.add(int(chunk))

    invalid = [port for port in ports if port < 1 or port > 65535]
    if invalid:
        raise ValueError(f'invalid port number: {invalid[0]}')
    return sorted(ports)


class NetworkScanner:
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
        self.results = {
            'hosts': [],
            'open_ports': {},
            'services': {},
            'os': {},
            'vulnerabilities': {},
            'risks': {},
        }
        self.start_time = datetime.now(timezone.utc)

    def scan_network(self):
        self.print_banner()

        print(f"{Colors.BLUE}[*] Step 1: host discovery...{Colors.RESET}")
        hosts = ping_sweep.sweep(self.target, self.threads, self.timeout, self.max_hosts)

        if not hosts:
            print(f"{Colors.RED}[!] No hosts found on {self.target}{Colors.RESET}")
            return None

        self.results['hosts'] = sorted(hosts)
        print(f"{Colors.GREEN}[+] {len(hosts)} host(s) found{Colors.RESET}")
        print(f"\n{Colors.BLUE}[*] Step 2: scanning {len(self.ports)} port(s)...{Colors.RESET}")

        scan_results = {}
        workers = min(self.host_workers, len(self.results['hosts']))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self.scan_host, host): host for host in self.results['hosts']}
            for future in as_completed(futures):
                host = futures[future]
                try:
                    host_result = future.result()
                except (OSError, RuntimeError, ValueError) as exc:
                    print(f"{Colors.RED}[!] Failed to scan {host}: {exc}{Colors.RESET}")
                    continue
                if host_result:
                    scan_results[host] = host_result

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

        return self.generate_report()

    def scan_host(self, host):
        print(f"\n{Colors.CYAN}[*] Scanning {host}{Colors.RESET}")
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
                print(f"    {Colors.PURPLE}[+] Probable OS: {label}{Colors.RESET}")

        workers = min(self.service_workers, len(open_ports))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self.scan_service, host, port): port for port in open_ports}
            for future in as_completed(futures):
                port = futures[future]
                try:
                    service, vulns, risk_info = future.result()
                except (OSError, RuntimeError, ValueError) as exc:
                    print(f"    {Colors.RED}[!] Failed to fingerprint {host}:{port}: {exc}{Colors.RESET}")
                    service = {'name': 'unknown', 'banner': '', 'http': {}, 'tls': {}}
                    vulns = []
                    risk_info = risk.score_service(host, port, service, vulns)
                host_result['services'][str(port)] = service
                if vulns:
                    host_result['vulnerabilities'][f"{host}:{port}"] = vulns
                host_result['risks'][f"{host}:{port}"] = risk_info

        return host_result

    def scan_service(self, host, port):
        service = service_scan.detect_service(host, port, self.timeout)

        service_name = service.get('name', 'unknown')
        banner = service.get('banner', '').replace('\n', ' ')[:80]
        banner_display = f" ({banner})" if banner else ""
        print(f"    {Colors.GREEN}[+] Port {port}/tcp: {service_name}{banner_display}{Colors.RESET}")

        vulns = vulnerability.check_vulnerabilities(host, port, service, self.intrusive_checks) if self.aggressive else []
        if vulns:
            for vuln in vulns:
                print(f"    {Colors.RED}[!] {vuln['severity'].upper()}: {vuln['name']}{Colors.RESET}")

        risk_info = risk.score_service(host, port, service, vulns)
        if risk_info['score'] in {'medium', 'high'}:
            print(f"    {Colors.YELLOW}[!] {risk_info['score']} risk: {host}:{port}{Colors.RESET}")

        return service, vulns, risk_info

    def generate_report(self):
        print(f"\n{Colors.BLUE}[*] Generating reports...{Colors.RESET}")
        os.makedirs(self.output_dir, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_filename = os.path.join(self.output_dir, f"scan_report_{timestamp}.json")
        html_filename = os.path.join(self.output_dir, f"scan_report_{timestamp}.html")
        csv_filename = os.path.join(self.output_dir, f"scan_report_{timestamp}.csv")
        markdown_filename = os.path.join(self.output_dir, f"scan_report_{timestamp}.md")
        end_time = datetime.now(timezone.utc)

        report = {
            'scan_info': {
                'target': self.target,
                'start_time': self.start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration': str(end_time - self.start_time),
                'threads': self.threads,
                'timeout': self.timeout,
                'aggressive': self.aggressive,
                'profile': self.profile,
                'max_hosts': self.max_hosts,
                'host_workers': self.host_workers,
                'service_workers': self.service_workers,
                'intrusive_checks': self.intrusive_checks,
                'ports': self.ports,
                'external_tools': external_tools.detect_external_tools(),
            },
            'results': self.results
        }

        if self.compare_report:
            old_report = report_diff.load_report(self.compare_report)
            report['comparison'] = report_diff.compare_reports(old_report, report)

        with open(report_filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"{Colors.GREEN}[+] JSON report: {report_filename}{Colors.RESET}")

        self.generate_html_report(report, html_filename)
        self.generate_csv_report(report, csv_filename)
        self.generate_markdown_report(report, markdown_filename)
        self.show_summary()
        return report_filename, html_filename, csv_filename, markdown_filename

    def generate_csv_report(self, report, filename):
        rows = []
        results = report['results']
        for host in results['hosts']:
            for port in results['open_ports'].get(host, []):
                service = results['services'].get(host, {}).get(str(port), {})
                http = service.get('http') or {}
                vulns = results['vulnerabilities'].get(f'{host}:{port}', [])
                risk_info = results.get('risks', {}).get(f'{host}:{port}', {})
                rows.append({
                    'host': host,
                    'port': port,
                    'service': service.get('name', 'unknown'),
                    'http_status': http.get('status', ''),
                    'http_title': http.get('title', ''),
                    'risk': risk_info.get('score', 'info'),
                    'technologies': '; '.join(http.get('technologies', [])),
                    'favicon_hash': http.get('favicon_hash', ''),
                    'vulnerabilities': '; '.join(vuln.get('name', 'unknown') for vuln in vulns),
                })

        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    'host',
                    'port',
                    'service',
                    'http_status',
                    'http_title',
                    'risk',
                    'technologies',
                    'favicon_hash',
                    'vulnerabilities',
                ],
            )
            writer.writeheader()
            writer.writerows(rows)
        print(f"{Colors.GREEN}[+] CSV report: {filename}{Colors.RESET}")

    def generate_html_report(self, report, filename):
        safe = html.escape
        result = report['results']
        total_ports = sum(len(ports) for ports in result['open_ports'].values())
        total_vulns = sum(len(vulns) for vulns in result['vulnerabilities'].values())
        risk_counts = self.count_risks(result)

        parts = [
            '<!DOCTYPE html>',
            '<html lang="en"><head><meta charset="utf-8">',
            '<title>BlackScan Report</title>',
            '<style>',
            'body{font-family:Arial,sans-serif;margin:0;background:#f5f7fb;color:#18202a}',
            '.container{max-width:1180px;margin:0 auto;padding:24px}',
            '.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:18px 0}',
            '.metric{background:#fff;border:1px solid #d9e2ec;border-radius:8px;padding:14px}.metric strong{display:block;font-size:24px}',
            'h1,h2{color:#1f3349}.host{border-left:4px solid #2673b9;background:#fff;padding:14px;margin:12px 0;border-radius:8px}',
            '.port,.vuln,.severity{display:inline-block;color:#fff;padding:3px 8px;margin:2px;border-radius:4px;font-size:12px}',
            '.port{background:#22863a}.vuln{background:#b42318}.low{background:#6b7280}.medium{background:#b45309}.high{background:#b42318}',
            'table{width:100%;border-collapse:collapse;background:#fff}td,th{padding:8px;border-bottom:1px solid #d9e2ec;text-align:left;vertical-align:top}',
            '</style></head><body><main class="container">',
            '<h1>BlackScan Report</h1>',
            f"<p><strong>Target:</strong> {safe(report['scan_info']['target'])}</p>",
            f"<p><strong>Started:</strong> {safe(report['scan_info']['start_time'])}</p>",
            f"<p><strong>Duration:</strong> {safe(report['scan_info']['duration'])}</p>",
            f"<p><strong>Profile:</strong> {safe(report['scan_info'].get('profile', 'quick'))}</p>",
            '<h2>Summary</h2>',
            '<section class="summary">',
            f"<div class=\"metric\"><span>Hosts</span><strong>{len(result['hosts'])}</strong></div>",
            f"<div class=\"metric\"><span>Open ports</span><strong>{total_ports}</strong></div>",
            f"<div class=\"metric\"><span>Vulnerabilities</span><strong>{total_vulns}</strong></div>",
            f"<div class=\"metric\"><span>High risk</span><strong>{risk_counts.get('high', 0)}</strong></div>",
            '</section>',
            '<h2>Details</h2>',
        ]

        for host in result['hosts']:
            parts.append('<section class="host">')
            parts.append(f'<h3>{safe(host)}</h3>')
            if host in result['open_ports']:
                parts.append('<p><strong>Open ports:</strong><br>')
                for port in result['open_ports'][host]:
                    service = result['services'].get(host, {}).get(str(port), {})
                    service_name = service.get('name', 'unknown')
                    http_info = service.get('http') or {}
                    risk_info = result.get('risks', {}).get(f'{host}:{port}', {})
                    detail = ''
                    if http_info.get('status'):
                        detail = f" HTTP {http_info.get('status')}"
                    if http_info.get('title'):
                        detail += f" - {http_info.get('title')}"
                    risk_label = f" [{risk_info.get('score', 'info')}]"
                    parts.append(f'<span class="port">{port}: {safe(service_name)}{safe(detail)}{safe(risk_label)}</span> ')
                    if http_info.get('technologies'):
                        parts.append(f'<br><small>Technologies: {safe(", ".join(http_info["technologies"]))}</small>')
                    if http_info.get('redirects'):
                        redirects = ', '.join(item.get('location', '') for item in http_info['redirects'])
                        parts.append(f'<br><small>Redirects: {safe(redirects)}</small>')
                    if http_info.get('common_paths'):
                        paths = ', '.join(
                            f"{item['path']}={item['status']}" for item in http_info['common_paths'] if item.get('interesting')
                        )
                        if paths:
                            parts.append(f'<br><small>Common paths: {safe(paths)}</small>')
                parts.append('</p>')

            if host in result['os']:
                parts.append(f"<p><strong>Probable OS:</strong> {safe(self.format_os(result['os'][host]))}</p>")

            for key, vulns in result['vulnerabilities'].items():
                if key.startswith(f'{host}:'):
                    parts.append('<p><strong>Vulnerabilities:</strong><br>')
                    for vuln in vulns:
                        label = f"{vuln.get('severity', 'info').upper()}: {vuln.get('name', 'unknown')}"
                        severity = safe(vuln.get('severity', 'info'))
                        parts.append(f'<span class="vuln {severity}">{safe(label)}</span> ')
                        if vuln.get('recommendation'):
                            parts.append(f'<br><small>{safe(vuln.get("recommendation", ""))}</small><br>')
                    parts.append('</p>')
            parts.append('</section>')

        if report.get('comparison'):
            parts.append('<h2>Comparison</h2>')
            parts.append(self.comparison_html(report['comparison']))

        parts.append('</main></body></html>')

        with open(filename, 'w', encoding='utf-8') as f:
            f.write('\n'.join(parts))
        print(f"{Colors.GREEN}[+] HTML report: {filename}{Colors.RESET}")

    def generate_markdown_report(self, report, filename):
        result = report['results']
        lines = [
            '# BlackScan Report',
            '',
            f"- Target: `{report['scan_info']['target']}`",
            f"- Started: `{report['scan_info']['start_time']}`",
            f"- Duration: `{report['scan_info']['duration']}`",
            f"- Profile: `{report['scan_info'].get('profile', 'quick')}`",
            '',
            '## Summary',
            '',
            f"- Hosts: {len(result['hosts'])}",
            f"- Open ports: {sum(len(ports) for ports in result['open_ports'].values())}",
            f"- Vulnerabilities: {sum(len(vulns) for vulns in result['vulnerabilities'].values())}",
            '',
            '## Services',
            '',
            '| Host | Port | Service | HTTP | Risk | Technologies |',
            '| --- | ---: | --- | --- | --- | --- |',
        ]

        for host in result['hosts']:
            for port in result['open_ports'].get(host, []):
                service = result['services'].get(host, {}).get(str(port), {})
                http = service.get('http') or {}
                risk_info = result.get('risks', {}).get(f'{host}:{port}', {})
                technologies = ', '.join(http.get('technologies', []))
                http_label = ''
                if http:
                    http_label = f"{http.get('status', '')} {http.get('title', '')}".strip()
                lines.append(
                    f"| `{host}` | {port} | {service.get('name', 'unknown')} | "
                    f"{http_label} | {risk_info.get('score', 'info')} | {technologies} |"
                )

        lines.extend(['', '## Vulnerabilities', ''])
        if result['vulnerabilities']:
            for target, findings in result['vulnerabilities'].items():
                for finding in findings:
                    lines.extend([
                        f"### {finding.get('severity', 'info').upper()} - {finding.get('name', 'unknown')}",
                        '',
                        f"- Target: `{target}`",
                        f"- Evidence: {finding.get('evidence', '')}",
                        f"- Recommendation: {finding.get('recommendation', '')}",
                        '',
                    ])
        else:
            lines.append('No vulnerabilities detected by the enabled checks.')

        if report.get('comparison'):
            lines.extend(['', '## Comparison', ''])
            lines.extend(self.comparison_markdown(report['comparison']))

        with open(filename, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        print(f"{Colors.GREEN}[+] Markdown report: {filename}{Colors.RESET}")

    def show_summary(self):
        total_ports = sum(len(ports) for ports in self.results['open_ports'].values())
        total_vulns = sum(len(vulns) for vulns in self.results['vulnerabilities'].values())
        risk_counts = self.count_risks(self.results)
        print(f"\n{Colors.PURPLE}{'=' * 60}{Colors.RESET}")
        print(f"{Colors.YELLOW}SCAN SUMMARY{Colors.RESET}")
        print(f"{Colors.PURPLE}{'=' * 60}{Colors.RESET}")
        print(f"{Colors.WHITE}Hosts found: {len(self.results['hosts'])}{Colors.RESET}")
        print(f"{Colors.WHITE}Open ports: {total_ports}{Colors.RESET}")
        print(f"{Colors.WHITE}Services identified: {sum(len(services) for services in self.results['services'].values())}{Colors.RESET}")
        print(f"{Colors.WHITE}High risks: {risk_counts.get('high', 0)}{Colors.RESET}")
        if total_vulns:
            print(f"{Colors.RED}{total_vulns} potential vulnerability/vulnerabilities found{Colors.RESET}")
        else:
            print(f"{Colors.GREEN}No major vulnerabilities detected{Colors.RESET}")
        print(f"{Colors.PURPLE}{'=' * 60}{Colors.RESET}\n")

    @staticmethod
    def count_risks(results):
        counts = {'info': 0, 'low': 0, 'medium': 0, 'high': 0}
        for risk_info in results.get('risks', {}).values():
            score = risk_info.get('score', 'info')
            counts[score] = counts.get(score, 0) + 1
        return counts

    @staticmethod
    def format_os(os_info):
        if isinstance(os_info, dict):
            family = os_info.get('family', 'Unknown')
            confidence = os_info.get('confidence', 'low')
            ttl = os_info.get('observed_ttl')
            initial = os_info.get('probable_initial_ttl')
            if ttl is None:
                return f'{family} ({confidence} confidence)'
            return f'{family} ({confidence} confidence, TTL {ttl}, initial {initial})'
        return str(os_info)

    @staticmethod
    def comparison_markdown(comparison):
        lines = []
        sections = [
            ('New hosts', comparison.get('new_hosts', [])),
            ('Removed hosts', comparison.get('removed_hosts', [])),
            ('New vulnerabilities', [
                f"{item['target']} {item['severity']} {item['name']}" for item in comparison.get('new_vulnerabilities', [])
            ]),
            ('Resolved vulnerabilities', [
                f"{item['target']} {item['severity']} {item['name']}" for item in comparison.get('resolved_vulnerabilities', [])
            ]),
        ]
        for title, items in sections:
            lines.append(f'### {title}')
            lines.append('')
            lines.extend(f"- `{item}`" for item in items)
            if not items:
                lines.append('- No changes')
            lines.append('')

        lines.append('### Added ports')
        lines.append('')
        for host, ports in comparison.get('added_ports', {}).items():
            lines.append(f"- `{host}`: {', '.join(str(port) for port in ports)}")
        if not comparison.get('added_ports'):
            lines.append('- No changes')

        lines.extend(['', '### Closed ports', ''])
        for host, ports in comparison.get('removed_ports', {}).items():
            lines.append(f"- `{host}`: {', '.join(str(port) for port in ports)}")
        if not comparison.get('removed_ports'):
            lines.append('- No changes')
        return lines

    @staticmethod
    def comparison_html(comparison):
        safe = html.escape
        lines = ['<section class="host">']
        for title, items in (
            ('New hosts', comparison.get('new_hosts', [])),
            ('Removed hosts', comparison.get('removed_hosts', [])),
        ):
            lines.append(f'<h3>{safe(title)}</h3>')
            if items:
                lines.append('<ul>')
                lines.extend(f'<li>{safe(item)}</li>' for item in items)
                lines.append('</ul>')
            else:
                lines.append('<p>No changes</p>')

        for title, changes in (
            ('Added ports', comparison.get('added_ports', {})),
            ('Closed ports', comparison.get('removed_ports', {})),
        ):
            lines.append(f'<h3>{safe(title)}</h3>')
            if changes:
                lines.append('<ul>')
                for host, ports in changes.items():
                    lines.append(f'<li>{safe(host)}: {safe(", ".join(str(port) for port in ports))}</li>')
                lines.append('</ul>')
            else:
                lines.append('<p>No changes</p>')

        for title, items in (
            ('New vulnerabilities', comparison.get('new_vulnerabilities', [])),
            ('Resolved vulnerabilities', comparison.get('resolved_vulnerabilities', [])),
        ):
            lines.append(f'<h3>{safe(title)}</h3>')
            if items:
                lines.append('<ul>')
                for item in items:
                    label = f"{item['target']} {item['severity']} {item['name']}"
                    lines.append(f'<li>{safe(label)}</li>')
                lines.append('</ul>')
            else:
                lines.append('<p>No changes</p>')
        lines.append('</section>')
        return '\n'.join(lines)

    @staticmethod
    def print_banner():
        print(f"{Colors.BOLD}{Colors.CYAN}BlackScan - Network Vulnerability Scanner{Colors.RESET}")
        print(f"{Colors.YELLOW}Use this tool only on systems you are authorized to assess.{Colors.RESET}\n")


def build_parser():
    parser = argparse.ArgumentParser(description='BlackScan network vulnerability scanner')
    parser.add_argument('-t', '--target', help='Authorized target: IP, DNS name, or CIDR range')
    parser.add_argument('--threads', type=int, default=100, help='Number of worker threads/concurrent tasks (default: 100)')
    parser.add_argument('--timeout', type=int, default=2, help='Timeout in seconds (default: 2)')
    parser.add_argument('-a', '--aggressive', action='store_true', help='Aggressive mode: wider ports and additional checks')
    parser.add_argument('--profile', choices=sorted(settings.SCAN_PROFILES), default='quick', help='Scan profile (default: quick)')
    parser.add_argument('--ports', help='Ports to scan, for example: 22,80,443,8000-8100')
    parser.add_argument('-o', '--output-dir', default='reports', help='Report output directory')
    parser.add_argument('--max-hosts', type=int, default=4096, help='Maximum number of addresses allowed in a CIDR range')
    parser.add_argument('--host-workers', type=int, default=10, help='Maximum hosts scanned in parallel')
    parser.add_argument('--service-workers', type=int, default=32, help='Maximum services fingerprinted in parallel per host')
    parser.add_argument('--compare', help='Previous JSON report to compare with the new scan')
    parser.add_argument('--list-external-tools', action='store_true', help='List available external integrations')
    parser.add_argument('--intrusive-checks', action='store_true', help='Enable checks that attempt application-level interactions')
    parser.add_argument('--authorized', action='store_true', help='Confirm that you are authorized to scan the target')
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.list_external_tools:
        for name, info in external_tools.detect_external_tools().items():
            status = 'available' if info['available'] else 'missing'
            version = f" - {info['version']}" if info['version'] else ''
            print(f"{name}: {status}{version}")
        return

    if not args.target:
        parser.error("required argument: -t/--target")

    if not args.authorized:
        parser.error("add --authorized to confirm that the target is in your authorized scope")

    try:
        ports = parse_ports(args.ports) if args.ports else None
    except ValueError as exc:
        parser.error(str(exc))

    scanner = NetworkScanner(
        args.target,
        args.threads,
        args.timeout,
        args.aggressive,
        ports,
        args.output_dir,
        args.profile,
        args.max_hosts,
        args.compare,
        args.intrusive_checks,
        args.host_workers,
        args.service_workers,
    )

    try:
        scanner.scan_network()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by the user")
        sys.exit(0)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"[!] Error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
