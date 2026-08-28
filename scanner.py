#!/usr/bin/env python3
"""BlackScan network scanner CLI."""

import argparse
import html
import json
import os
import sys
from datetime import datetime

from network_scanner.modules import os_detection, ping_sweep, port_scanner, service_scan, vulnerability


DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 27017]
AGGRESSIVE_PORTS = list(range(1, 1025)) + [3306, 3389, 5432, 6379, 8080, 8443, 27017, 27018, 27019, 9200, 9300, 11211]
WEB_PORTS = {80, 443, 8000, 8080, 8443}


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
    def __init__(self, target, threads=100, timeout=2, aggressive=False, ports=None, output_dir='reports'):
        self.target = target
        self.threads = max(1, threads)
        self.timeout = max(1, timeout)
        self.aggressive = aggressive
        self.ports = ports or (AGGRESSIVE_PORTS if aggressive else DEFAULT_PORTS)
        self.output_dir = output_dir
        self.results = {
            'hosts': [],
            'open_ports': {},
            'services': {},
            'os': {},
            'vulnerabilities': {}
        }
        self.start_time = datetime.now()

    def scan_network(self):
        self.print_banner()

        print(f"{Colors.BLUE}[*] Étape 1: découverte des hôtes...{Colors.RESET}")
        hosts = ping_sweep.sweep(self.target, self.threads, self.timeout)

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

                if self.aggressive:
                    vulns = vulnerability.check_vulnerabilities(host, port, service)
                    if vulns:
                        self.results['vulnerabilities'][f"{host}:{port}"] = vulns
                        for vuln in vulns:
                            print(f"    {Colors.RED}[!] {vuln['severity'].upper()}: {vuln['name']}{Colors.RESET}")

        return self.generate_report()

    def generate_report(self):
        print(f"\n{Colors.BLUE}[*] Génération du rapport...{Colors.RESET}")
        os.makedirs(self.output_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = os.path.join(self.output_dir, f"scan_report_{timestamp}.json")
        html_filename = os.path.join(self.output_dir, f"scan_report_{timestamp}.html")
        end_time = datetime.now()

        report = {
            'scan_info': {
                'target': self.target,
                'start_time': self.start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration': str(end_time - self.start_time),
                'threads': self.threads,
                'timeout': self.timeout,
                'aggressive': self.aggressive,
                'ports': self.ports
            },
            'results': self.results
        }

        with open(report_filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"{Colors.GREEN}[+] Rapport JSON: {report_filename}{Colors.RESET}")

        self.generate_html_report(report, html_filename)
        self.show_summary()
        return report_filename, html_filename

    def generate_html_report(self, report, filename):
        safe = html.escape
        result = report['results']
        total_ports = sum(len(ports) for ports in result['open_ports'].values())
        total_vulns = sum(len(vulns) for vulns in result['vulnerabilities'].values())

        parts = [
            '<!DOCTYPE html>',
            '<html lang="fr"><head><meta charset="utf-8">',
            '<title>Rapport BlackScan</title>',
            '<style>',
            'body{font-family:Arial,sans-serif;margin:24px;background:#f5f7fb;color:#18202a}',
            '.container{max-width:1180px;margin:0 auto;background:#fff;padding:24px;border-radius:8px}',
            'h1,h2{color:#1f3349}.host{border-left:4px solid #2673b9;background:#eef4fb;padding:12px;margin:12px 0}',
            '.port,.vuln{display:inline-block;color:#fff;padding:3px 8px;margin:2px;border-radius:4px;font-size:12px}',
            '.port{background:#22863a}.vuln{background:#b42318}table{width:100%;border-collapse:collapse}td,th{padding:8px;border-bottom:1px solid #d9e2ec;text-align:left}',
            '</style></head><body><main class="container">',
            '<h1>Rapport BlackScan</h1>',
            f"<p><strong>Cible:</strong> {safe(report['scan_info']['target'])}</p>",
            f"<p><strong>Début:</strong> {safe(report['scan_info']['start_time'])}</p>",
            f"<p><strong>Durée:</strong> {safe(report['scan_info']['duration'])}</p>",
            '<h2>Résumé</h2>',
            f"<p><strong>Hôtes:</strong> {len(result['hosts'])}</p>",
            f"<p><strong>Ports ouverts:</strong> {total_ports}</p>",
            f"<p><strong>Vulnérabilités:</strong> {total_vulns}</p>",
            '<h2>Détails</h2>',
        ]

        for host in result['hosts']:
            parts.append('<section class="host">')
            parts.append(f'<h3>{safe(host)}</h3>')
            if host in result['open_ports']:
                parts.append('<p><strong>Ports ouverts:</strong><br>')
                for port in result['open_ports'][host]:
                    service = result['services'].get(host, {}).get(str(port), {}).get('name', 'unknown')
                    parts.append(f'<span class="port">{port}: {safe(service)}</span> ')
                parts.append('</p>')

            if host in result['os']:
                parts.append(f"<p><strong>OS probable:</strong> {safe(result['os'][host])}</p>")

            for key, vulns in result['vulnerabilities'].items():
                if key.startswith(f'{host}:'):
                    parts.append('<p><strong>Vulnérabilités:</strong><br>')
                    for vuln in vulns:
                        label = f"{vuln.get('severity', 'info').upper()}: {vuln.get('name', 'unknown')}"
                        parts.append(f'<span class="vuln">{safe(label)}</span> ')
                    parts.append('</p>')
            parts.append('</section>')

        parts.append('</main></body></html>')

        with open(filename, 'w', encoding='utf-8') as f:
            f.write('\n'.join(parts))
        print(f"{Colors.GREEN}[+] Rapport HTML: {filename}{Colors.RESET}")

    def show_summary(self):
        total_ports = sum(len(ports) for ports in self.results['open_ports'].values())
        total_vulns = sum(len(vulns) for vulns in self.results['vulnerabilities'].values())
        print(f"\n{Colors.PURPLE}{'=' * 60}{Colors.RESET}")
        print(f"{Colors.YELLOW}RÉSUMÉ DU SCAN{Colors.RESET}")
        print(f"{Colors.PURPLE}{'=' * 60}{Colors.RESET}")
        print(f"{Colors.WHITE}Hôtes trouvés: {len(self.results['hosts'])}{Colors.RESET}")
        print(f"{Colors.WHITE}Ports ouverts: {total_ports}{Colors.RESET}")
        print(f"{Colors.WHITE}Services identifiés: {sum(len(services) for services in self.results['services'].values())}{Colors.RESET}")
        if total_vulns:
            print(f"{Colors.RED}{total_vulns} vulnérabilité(s) potentielle(s) trouvée(s){Colors.RESET}")
        else:
            print(f"{Colors.GREEN}Aucune vulnérabilité majeure détectée{Colors.RESET}")
        print(f"{Colors.PURPLE}{'=' * 60}{Colors.RESET}\n")

    @staticmethod
    def print_banner():
        print(f"{Colors.BOLD}{Colors.CYAN}BlackScan - Network Vulnerability Scanner{Colors.RESET}")
        print(f"{Colors.YELLOW}Utilise cet outil uniquement sur des systèmes autorisés.{Colors.RESET}\n")


def build_parser():
    parser = argparse.ArgumentParser(description='BlackScan network vulnerability scanner')
    parser.add_argument('-t', '--target', required=True, help='Cible autorisée: IP, nom DNS ou CIDR')
    parser.add_argument('--threads', type=int, default=100, help='Nombre de threads (défaut: 100)')
    parser.add_argument('--timeout', type=int, default=2, help='Timeout en secondes (défaut: 2)')
    parser.add_argument('-a', '--aggressive', action='store_true', help='Mode agressif: ports étendus + checks basiques')
    parser.add_argument('--ports', help='Ports à scanner, ex: 22,80,443,8000-8100')
    parser.add_argument('-o', '--output-dir', default='reports', help='Dossier de sortie des rapports')
    parser.add_argument('--authorized', action='store_true', help='Confirme que tu as l’autorisation de scanner la cible')
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.authorized:
        parser.error("ajoute --authorized pour confirmer que la cible est dans ton périmètre autorisé")

    try:
        ports = parse_ports(args.ports) if args.ports else None
    except ValueError as exc:
        parser.error(str(exc))

    scanner = NetworkScanner(args.target, args.threads, args.timeout, args.aggressive, ports, args.output_dir)

    try:
        scanner.scan_network()
    except KeyboardInterrupt:
        print("\n[!] Scan interrompu par l'utilisateur")
        sys.exit(0)
    except Exception as exc:
        print(f"[!] Erreur: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
