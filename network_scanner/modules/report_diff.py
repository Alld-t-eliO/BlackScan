def load_report(path):
    import json

    with open(path, encoding='utf-8') as handle:
        return json.load(handle)


def _host_ports(report):
    results = report.get('results', {})
    return {
        host: set(ports)
        for host, ports in results.get('open_ports', {}).items()
    }


def _vuln_keys(report):
    keys = set()
    for target, findings in report.get('results', {}).get('vulnerabilities', {}).items():
        for finding in findings:
            keys.add((target, finding.get('name', 'unknown'), finding.get('severity', 'info')))
    return keys


def compare_reports(old_report, new_report):
    old_hosts = set(old_report.get('results', {}).get('hosts', []))
    new_hosts = set(new_report.get('results', {}).get('hosts', []))
    old_ports = _host_ports(old_report)
    new_ports = _host_ports(new_report)

    added_ports = {}
    removed_ports = {}
    for host in sorted(old_hosts | new_hosts):
        added = sorted(new_ports.get(host, set()) - old_ports.get(host, set()))
        removed = sorted(old_ports.get(host, set()) - new_ports.get(host, set()))
        if added:
            added_ports[host] = added
        if removed:
            removed_ports[host] = removed

    old_vulns = _vuln_keys(old_report)
    new_vulns = _vuln_keys(new_report)

    return {
        'new_hosts': sorted(new_hosts - old_hosts),
        'removed_hosts': sorted(old_hosts - new_hosts),
        'added_ports': added_ports,
        'removed_ports': removed_ports,
        'new_vulnerabilities': [
            {'target': target, 'name': name, 'severity': severity}
            for target, name, severity in sorted(new_vulns - old_vulns)
        ],
        'resolved_vulnerabilities': [
            {'target': target, 'name': name, 'severity': severity}
            for target, name, severity in sorted(old_vulns - new_vulns)
        ],
    }
