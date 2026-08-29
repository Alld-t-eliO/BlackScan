#!/usr/bin/env python3
"""BlackScan network scanner CLI."""

import argparse
import csv
import html
import json
import os
import sys
from datetime import datetime, timezone

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

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 27017]
AGGRESSIVE_PORTS = list(range(1, 1025)) + [3306, 3389, 5432, 6379, 8080, 8443, 27017, 27018, 27019, 9200, 9300, 11211]
WEB_PORTS = {80, 443, 8000, 8080, 8443}
SCAN_PROFILES = {
    'quick': DEFAULT_PORTS,
    'web': [80, 443, 8000, 8080, 8443, 8888],
    'internal': sorted(set(DEFAULT_PORTS + [135, 137, 138, 389, 636, 5900, 5985, 5986, 9200, 11211])),
    'full': AGGRESSIVE_PORTS,
    'stealth': [22, 80, 443],
}


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
    ):
        self.target = target
        self.threads = max(1, threads)
        self.timeout = max(1, timeout)
        self.profile = 'full' if aggressive else profile
        self.aggressive = aggressive or self.profile in {'full', 'internal', 'web'}
        self.ports = ports or SCAN_PROFILES[self.profile]
        self.output_dir = output_dir
        self.max_hosts = max(1, max_hosts)
        self.compare_report = compare_report
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

        print(f"{Colors.BLUE}[*] Étape 1: découverte des hôtes...{Colors.RESET}")
        hosts = ping_sweep.sweep(self.target, self.threads, self.timeout, self.max_hosts)

        if not hosts:
            print(f"{Colors.RED}[!] Aucun hôte trouvé sur {self.target}{Colors.RESET}")
            return None

        self.results['hosts'] = sorted(hosts)
        print(f"{Colors.GREEN}[+] {len(hosts)} hôte(s) trouvé(s){Colors.RESET}")
        print(f"\n{Colors.BLUE}[*] Étape 2: scan de {len(self.ports)} port(s)...{Colors.RESET}")

        for host in self.results['hosts']:
            print(f"\n{Colors.CYAN}[*] Scan de {host}{Colors.RESET}")
            open_ports = port_scanner.scan_ports(host, self.ports, self.threads, self.timeout)

            if not open_ports:
                continue

            self.results['open_ports'][host] = open_ports
            self.results['services'][host] = {}

            for port in open_ports:
                service = service_scan.detect_service(host, port, self.timeout)
                self.results['services'][host][str(port)] = service

                service_name = service.get('name', 'unknown')
                banner = service.get('banner', '').replace('\n', ' ')[:80]
                banner_display = f" ({banner})" if banner else ""
                print(f"    {Colors.GREEN}[+] Port {port}/tcp: {service_name}{banner_display}{Colors.RESET}")

                if self.aggressive and port in WEB_PORTS.union({22}):
                    os_info = os_detection.detect_os(host, self.timeout)
                    if os_info:
                        self.results['os'][host] = os_info
                        print(f"    {Colors.PURPLE}[+] OS probable: {os_info}{Colors.RESET}")

                vulns = vulnerability.check_vulnerabilities(host, port, service) if self.aggressive else []
                if vulns:
                    self.results['vulnerabilities'][f"{host}:{port}"] = vulns
                    for vuln in vulns:
                        print(f"    {Colors.RED}[!] {vuln['severity'].upper()}: {vuln['name']}{Colors.RESET}")

                risk_info = risk.score_service(host, port, service, vulns)
                self.results['risks'][f"{host}:{port}"] = risk_info
                if risk_info['score'] in {'medium', 'high'}:
                    print(f"    {Colors.YELLOW}[!] Risque {risk_info['score']}: {host}:{port}{Colors.RESET}")

        return self.generate_report()

    def generate_report(self):
        print(f"\n{Colors.BLUE}[*] Génération du rapport...{Colors.RESET}")
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
        print(f"{Colors.GREEN}[+] Rapport JSON: {report_filename}{Colors.RESET}")

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
        print(f"{Colors.GREEN}[+] Rapport CSV: {filename}{Colors.RESET}")

    def generate_html_report(self, report, filename):
        safe = html.escape
        result = report['results']
        total_ports = sum(len(ports) for ports in result['open_ports'].values())
        total_vulns = sum(len(vulns) for vulns in result['vulnerabilities'].values())
        risk_counts = self.count_risks(result)

        parts = [
            '<!DOCTYPE html>',
            '<html lang="fr"><head><meta charset="utf-8">',
            '<title>Rapport BlackScan</title>',
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
            '<h1>Rapport BlackScan</h1>',
            f"<p><strong>Cible:</strong> {safe(report['scan_info']['target'])}</p>",
            f"<p><strong>Début:</strong> {safe(report['scan_info']['start_time'])}</p>",
            f"<p><strong>Durée:</strong> {safe(report['scan_info']['duration'])}</p>",
            f"<p><strong>Profil:</strong> {safe(report['scan_info'].get('profile', 'quick'))}</p>",
            '<h2>Résumé</h2>',
            '<section class="summary">',
            f"<div class=\"metric\"><span>Hôtes</span><strong>{len(result['hosts'])}</strong></div>",
            f"<div class=\"metric\"><span>Ports ouverts</span><strong>{total_ports}</strong></div>",
            f"<div class=\"metric\"><span>Vulnérabilités</span><strong>{total_vulns}</strong></div>",
            f"<div class=\"metric\"><span>Risque high</span><strong>{risk_counts.get('high', 0)}</strong></div>",
            '</section>',
            '<h2>Détails</h2>',
        ]

        for host in result['hosts']:
            parts.append('<section class="host">')
            parts.append(f'<h3>{safe(host)}</h3>')
            if host in result['open_ports']:
                parts.append('<p><strong>Ports ouverts:</strong><br>')
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
                            parts.append(f'<br><small>Chemins communs: {safe(paths)}</small>')
                parts.append('</p>')

            if host in result['os']:
                parts.append(f"<p><strong>OS probable:</strong> {safe(result['os'][host])}</p>")

            for key, vulns in result['vulnerabilities'].items():
                if key.startswith(f'{host}:'):
                    parts.append('<p><strong>Vulnérabilités:</strong><br>')
                    for vuln in vulns:
                        label = f"{vuln.get('severity', 'info').upper()}: {vuln.get('name', 'unknown')}"
                        severity = safe(vuln.get('severity', 'info'))
                        parts.append(f'<span class="vuln {severity}">{safe(label)}</span> ')
                        if vuln.get('recommendation'):
                            parts.append(f'<br><small>{safe(vuln.get("recommendation", ""))}</small><br>')
                    parts.append('</p>')
            parts.append('</section>')

        if report.get('comparison'):
            parts.append('<h2>Comparaison</h2>')
            parts.append(self.comparison_html(report['comparison']))

        parts.append('</main></body></html>')

        with open(filename, 'w', encoding='utf-8') as f:
            f.write('\n'.join(parts))
        print(f"{Colors.GREEN}[+] Rapport HTML: {filename}{Colors.RESET}")

    def generate_markdown_report(self, report, filename):
        result = report['results']
        lines = [
            '# Rapport BlackScan',
            '',
            f"- Cible: `{report['scan_info']['target']}`",
            f"- Début: `{report['scan_info']['start_time']}`",
            f"- Durée: `{report['scan_info']['duration']}`",
            f"- Profil: `{report['scan_info'].get('profile', 'quick')}`",
            '',
            '## Résumé',
            '',
            f"- Hôtes: {len(result['hosts'])}",
            f"- Ports ouverts: {sum(len(ports) for ports in result['open_ports'].values())}",
            f"- Vulnérabilités: {sum(len(vulns) for vulns in result['vulnerabilities'].values())}",
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

        lines.extend(['', '## Vulnérabilités', ''])
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
            lines.append('Aucune vulnérabilité détectée par les checks actifs.')

        if report.get('comparison'):
            lines.extend(['', '## Comparaison', ''])
            lines.extend(self.comparison_markdown(report['comparison']))

        with open(filename, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        print(f"{Colors.GREEN}[+] Rapport Markdown: {filename}{Colors.RESET}")

    def show_summary(self):
        total_ports = sum(len(ports) for ports in self.results['open_ports'].values())
        total_vulns = sum(len(vulns) for vulns in self.results['vulnerabilities'].values())
        risk_counts = self.count_risks(self.results)
        print(f"\n{Colors.PURPLE}{'=' * 60}{Colors.RESET}")
        print(f"{Colors.YELLOW}RÉSUMÉ DU SCAN{Colors.RESET}")
        print(f"{Colors.PURPLE}{'=' * 60}{Colors.RESET}")
        print(f"{Colors.WHITE}Hôtes trouvés: {len(self.results['hosts'])}{Colors.RESET}")
        print(f"{Colors.WHITE}Ports ouverts: {total_ports}{Colors.RESET}")
        print(f"{Colors.WHITE}Services identifiés: {sum(len(services) for services in self.results['services'].values())}{Colors.RESET}")
        print(f"{Colors.WHITE}Risques high: {risk_counts.get('high', 0)}{Colors.RESET}")
        if total_vulns:
            print(f"{Colors.RED}{total_vulns} vulnérabilité(s) potentielle(s) trouvée(s){Colors.RESET}")
        else:
            print(f"{Colors.GREEN}Aucune vulnérabilité majeure détectée{Colors.RESET}")
        print(f"{Colors.PURPLE}{'=' * 60}{Colors.RESET}\n")

    @staticmethod
    def count_risks(results):
        counts = {'info': 0, 'low': 0, 'medium': 0, 'high': 0}
        for risk_info in results.get('risks', {}).values():
            score = risk_info.get('score', 'info')
            counts[score] = counts.get(score, 0) + 1
        return counts

    @staticmethod
    def comparison_markdown(comparison):
        lines = []
        sections = [
            ('Nouveaux hôtes', comparison.get('new_hosts', [])),
            ('Hôtes disparus', comparison.get('removed_hosts', [])),
            ('Nouvelles vulnérabilités', [
                f"{item['target']} {item['severity']} {item['name']}" for item in comparison.get('new_vulnerabilities', [])
            ]),
            ('Vulnérabilités résolues', [
                f"{item['target']} {item['severity']} {item['name']}" for item in comparison.get('resolved_vulnerabilities', [])
            ]),
        ]
        for title, items in sections:
            lines.append(f'### {title}')
            lines.append('')
            lines.extend(f"- `{item}`" for item in items)
            if not items:
                lines.append('- Aucun changement')
            lines.append('')

        lines.append('### Ports ajoutés')
        lines.append('')
        for host, ports in comparison.get('added_ports', {}).items():
            lines.append(f"- `{host}`: {', '.join(str(port) for port in ports)}")
        if not comparison.get('added_ports'):
            lines.append('- Aucun changement')

        lines.extend(['', '### Ports fermés', ''])
        for host, ports in comparison.get('removed_ports', {}).items():
            lines.append(f"- `{host}`: {', '.join(str(port) for port in ports)}")
        if not comparison.get('removed_ports'):
            lines.append('- Aucun changement')
        return lines

    @staticmethod
    def comparison_html(comparison):
        safe = html.escape
        lines = ['<section class="host">']
        for title, items in (
            ('Nouveaux hôtes', comparison.get('new_hosts', [])),
            ('Hôtes disparus', comparison.get('removed_hosts', [])),
        ):
            lines.append(f'<h3>{safe(title)}</h3>')
            if items:
                lines.append('<ul>')
                lines.extend(f'<li>{safe(item)}</li>' for item in items)
                lines.append('</ul>')
            else:
                lines.append('<p>Aucun changement</p>')

        for title, changes in (
            ('Ports ajoutés', comparison.get('added_ports', {})),
            ('Ports fermés', comparison.get('removed_ports', {})),
        ):
            lines.append(f'<h3>{safe(title)}</h3>')
            if changes:
                lines.append('<ul>')
                for host, ports in changes.items():
                    lines.append(f'<li>{safe(host)}: {safe(", ".join(str(port) for port in ports))}</li>')
                lines.append('</ul>')
            else:
                lines.append('<p>Aucun changement</p>')

        for title, items in (
            ('Nouvelles vulnérabilités', comparison.get('new_vulnerabilities', [])),
            ('Vulnérabilités résolues', comparison.get('resolved_vulnerabilities', [])),
        ):
            lines.append(f'<h3>{safe(title)}</h3>')
            if items:
                lines.append('<ul>')
                for item in items:
                    label = f"{item['target']} {item['severity']} {item['name']}"
                    lines.append(f'<li>{safe(label)}</li>')
                lines.append('</ul>')
            else:
                lines.append('<p>Aucun changement</p>')
        lines.append('</section>')
        return '\n'.join(lines)

    @staticmethod
    def print_banner():
        print(f"{Colors.BOLD}{Colors.CYAN}BlackScan - Network Vulnerability Scanner{Colors.RESET}")
        print(f"{Colors.YELLOW}Utilise cet outil uniquement sur des systèmes autorisés.{Colors.RESET}\n")


def build_parser():
    parser = argparse.ArgumentParser(description='BlackScan network vulnerability scanner')
    parser.add_argument('-t', '--target', help='Cible autorisée: IP, nom DNS ou CIDR')
    parser.add_argument('--threads', type=int, default=100, help='Nombre de threads (défaut: 100)')
    parser.add_argument('--timeout', type=int, default=2, help='Timeout en secondes (défaut: 2)')
    parser.add_argument('-a', '--aggressive', action='store_true', help='Mode agressif: ports étendus + checks basiques')
    parser.add_argument('--profile', choices=sorted(SCAN_PROFILES), default='quick', help='Profil de scan (défaut: quick)')
    parser.add_argument('--ports', help='Ports à scanner, ex: 22,80,443,8000-8100')
    parser.add_argument('-o', '--output-dir', default='reports', help='Dossier de sortie des rapports')
    parser.add_argument('--max-hosts', type=int, default=4096, help='Nombre maximum d’adresses dans une plage CIDR')
    parser.add_argument('--compare', help='Ancien rapport JSON à comparer avec le nouveau scan')
    parser.add_argument('--list-external-tools', action='store_true', help='Liste les intégrations externes disponibles')
    parser.add_argument('--authorized', action='store_true', help='Confirme que tu as l’autorisation de scanner la cible')
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
        parser.error("argument requis: -t/--target")

    if not args.authorized:
        parser.error("ajoute --authorized pour confirmer que la cible est dans ton périmètre autorisé")

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
    )

    try:
        scanner.scan_network()
    except KeyboardInterrupt:
        print("\n[!] Scan interrompu par l'utilisateur")
        sys.exit(0)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"[!] Erreur: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
