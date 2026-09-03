import csv
import html
import json
import os
from datetime import datetime, timezone

from network_scanner.modules import external_tools, report_diff
from network_scanner.scanner.parser import mask_proxy_url


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


class ReportMixin:
    def generate_report(self):
        self.emit_log(f"\n{Colors.BLUE}[*] Generating reports...{Colors.RESET}")
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
                'external_enrichment_enabled': getattr(self, 'external_enrichment', False),
                'proxy': mask_proxy_url(self.proxy_url),
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
        self.emit_log(f"{Colors.GREEN}[+] JSON report: {report_filename}{Colors.RESET}")

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
                    'external_enrichment': 'enabled' if results.get('external_enrichment') else 'disabled',
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
                    'external_enrichment',
                ],
            )
            writer.writeheader()
            writer.writerows(rows)
        self.emit_log(f"{Colors.GREEN}[+] CSV report: {filename}{Colors.RESET}")

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

        enrichment = result.get('external_enrichment')
        if enrichment:
            parts.append('<h2>External Enrichment</h2>')
            parts.append(self.external_enrichment_html(enrichment))

        parts.append('</main></body></html>')

        with open(filename, 'w', encoding='utf-8') as f:
            f.write('\n'.join(parts))
        self.emit_log(f"{Colors.GREEN}[+] HTML report: {filename}{Colors.RESET}")

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

        enrichment = result.get('external_enrichment')
        if enrichment:
            lines.extend(['', '## External Enrichment', ''])
            lines.extend(self.external_enrichment_markdown(enrichment))

        with open(filename, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        self.emit_log(f"{Colors.GREEN}[+] Markdown report: {filename}{Colors.RESET}")

    def show_summary(self):
        total_ports = sum(len(ports) for ports in self.results['open_ports'].values())
        total_vulns = sum(len(vulns) for vulns in self.results['vulnerabilities'].values())
        risk_counts = self.count_risks(self.results)
        self.emit_log(f"\n{Colors.PURPLE}{'=' * 60}{Colors.RESET}")
        self.emit_log(f"{Colors.YELLOW}SCAN SUMMARY{Colors.RESET}")
        self.emit_log(f"{Colors.PURPLE}{'=' * 60}{Colors.RESET}")
        self.emit_log(f"{Colors.WHITE}Hosts found: {len(self.results['hosts'])}{Colors.RESET}")
        self.emit_log(f"{Colors.WHITE}Open ports: {total_ports}{Colors.RESET}")
        self.emit_log(f"{Colors.WHITE}Services identified: {sum(len(services) for services in self.results['services'].values())}{Colors.RESET}")
        self.emit_log(f"{Colors.WHITE}High risks: {risk_counts.get('high', 0)}{Colors.RESET}")
        if total_vulns:
            self.emit_log(f"{Colors.RED}{total_vulns} potential vulnerability/vulnerabilities found{Colors.RESET}")
        else:
            self.emit_log(f"{Colors.GREEN}No major vulnerabilities detected{Colors.RESET}")
        if self.results.get('external_enrichment'):
            self.emit_log(f"{Colors.CYAN}External enrichment: enabled{Colors.RESET}")
        self.emit_log(f"{Colors.PURPLE}{'=' * 60}{Colors.RESET}\n")

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
    def external_enrichment_markdown(enrichment):
        lines = []
        for section in ('domain', 'network', 'web', 'osint'):
            values = enrichment.get(section, {})
            lines.extend([f'### {section.title()}', ''])
            if not values:
                lines.extend(['- No data', ''])
                continue
            lines.extend(ReportMixin.external_value_markdown(values))
            lines.append('')
        return lines

    @staticmethod
    def external_value_markdown(value, prefix=''):
        lines = []
        if isinstance(value, dict) and {'status', 'executed'}.intersection(value):
            label = value.get('status', 'unknown')
            if value.get('reason'):
                label = f"{label}: {value.get('reason')}"
            lines.append(f"- {prefix or 'result'}: {label}")
            output = value.get('output', '')
            if output:
                lines.extend(['', '```text', output[:4000], '```'])
            return lines
        if isinstance(value, dict):
            for key, item in value.items():
                item_prefix = f'{prefix}.{key}' if prefix else str(key)
                lines.extend(ReportMixin.external_value_markdown(item, item_prefix))
            return lines
        if isinstance(value, list):
            for item in value[:50]:
                lines.append(f"- {prefix}: {item}")
            return lines
        lines.append(f"- {prefix or 'result'}: {value}")
        return lines

    @staticmethod
    def external_enrichment_html(enrichment):
        safe = html.escape
        parts = ['<section class="host">']
        for section in ('domain', 'network', 'web', 'osint'):
            parts.append(f'<h3>{safe(section.title())}</h3>')
            parts.append(ReportMixin.external_value_html(enrichment.get(section, {})))
        parts.append('</section>')
        return '\n'.join(parts)

    @staticmethod
    def external_value_html(value):
        safe = html.escape
        if isinstance(value, dict) and {'status', 'executed'}.intersection(value):
            label = value.get('status', 'unknown')
            if value.get('reason'):
                label = f"{label}: {value.get('reason')}"
            output = value.get('output', '')
            html_parts = [f'<p><strong>Status:</strong> {safe(str(label))}</p>']
            if output:
                html_parts.append(f'<pre>{safe(output[:4000])}</pre>')
            return '\n'.join(html_parts)
        if isinstance(value, dict):
            items = []
            for key, item in value.items():
                items.append(f'<details open><summary>{safe(str(key))}</summary>{ReportMixin.external_value_html(item)}</details>')
            return '\n'.join(items) if items else '<p>No data</p>'
        if isinstance(value, list):
            return '<ul>' + ''.join(f'<li>{safe(str(item))}</li>' for item in value[:50]) + '</ul>'
        return f'<p>{safe(str(value))}</p>'

    @staticmethod
    def print_banner():
        print(f"{Colors.BOLD}{Colors.CYAN}BlackScan - Network Vulnerability Scanner{Colors.RESET}")
        print(f"{Colors.YELLOW}Use this tool only on systems you are authorized to assess.{Colors.RESET}\n")
