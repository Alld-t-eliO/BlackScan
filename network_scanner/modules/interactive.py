from typing import Any


class InteractiveSession:

    def __init__(self, scan_results: dict[str, Any]):
        self.results = scan_results

    def get_prioritized_targets(self) -> list[dict[str, Any]]:
        targets = []
        for host, services in self.results.get('services', {}).items():
            for port_text, service in services.items():
                port = int(port_text)
                risk_info = self.results.get('risks', {}).get(f'{host}:{port}', {})
                targets.append({
                    'host': host,
                    'port': port,
                    'service': service.get('name', 'unknown'),
                    'risk': risk_info.get('score', 'info'),
                    'factors': risk_info.get('factors', []),
                    'vulnerabilities': self.results.get('vulnerabilities', {}).get(f'{host}:{port}', []),
                })

        risk_order = {'high': 0, 'medium': 1, 'low': 2, 'info': 3}
        return sorted(targets, key=lambda item: risk_order.get(item['risk'], 4))

    def render_summary(self) -> str:
        targets = self.get_prioritized_targets()
        lines = ['BlackScan prioritized targets']
        for target in targets:
            lines.append(
                f"{target['risk'].upper()} {target['host']}:{target['port']} "
                f"{target['service']} ({len(target['vulnerabilities'])} findings)"
            )
        if len(lines) == 1:
            lines.append('No reviewed services')
        return '\n'.join(lines)

    async def interactive_loop(self) -> str:
        return self.render_summary()
