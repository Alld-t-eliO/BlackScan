def load_report(path):
    import json

    with open(path, encoding='utf-8') as handle:
        report = json.load(handle)
    if not isinstance(report, dict) or not isinstance(report.get('results'), dict):
        raise ValueError(f'{path}: expected a BlackScan JSON report with a results object')  # noqa: TRY004 -- invalid file format
    return report


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


def _scan_time(report):
    return report.get('scan_info', {}).get('start_time') or report.get('scan_info', {}).get('end_time') or ''


def _report_label(report, index):
    scan_info = report.get('scan_info', {})
    target = scan_info.get('target', 'unknown-target')
    timestamp = _scan_time(report) or f'snapshot-{index + 1}'
    return f'{timestamp} {target}'


def compare_reports(old_report, new_report):
    validate_comparable(old_report, new_report)
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

    uncertain = new_report.get('results', {}).get('scan_status') in {'partial', 'no_hosts', 'running', 'interrupted'}
    uncertain = uncertain or bool(new_report.get('results', {}).get('errors'))
    return {
        'resolution_verified': not uncertain,
        'new_hosts': sorted(new_hosts - old_hosts),
        'removed_hosts': [] if uncertain else sorted(old_hosts - new_hosts),
        'added_ports': added_ports,
        'removed_ports': {} if uncertain else removed_ports,
        'new_vulnerabilities': [
            {'target': target, 'name': name, 'severity': severity}
            for target, name, severity in sorted(new_vulns - old_vulns)
        ],
        'resolved_vulnerabilities': [
            {'target': target, 'name': name, 'severity': severity}
            for target, name, severity in sorted(old_vulns - new_vulns) if not uncertain
        ],
    }


def analyze_vulnerability_trends(reports):
    for report in reports:
        validate_comparable(reports[0], report)
        if report.get('results', {}).get('scan_status') in {'partial', 'no_hosts', 'running', 'interrupted'} or report.get('results', {}).get('errors'):
            raise ValueError('trend analysis requires complete scans; incomplete results cannot establish resolution')
    ordered_reports = sorted(enumerate(reports), key=lambda item: (_scan_time(item[1]), item[0]))
    snapshots = []
    previous_keys = set()
    first_seen = {}
    last_seen = {}
    all_keys = set()

    for ordered_index, (_original_index, report) in enumerate(ordered_reports):
        keys = _vuln_keys(report)
        all_keys.update(keys)
        for key in keys:
            first_seen.setdefault(key, ordered_index)
            last_seen[key] = ordered_index

        severity_counts = {}
        for _target, _name, severity in keys:
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        new_keys = keys - previous_keys if ordered_index else keys
        resolved_keys = previous_keys - keys if ordered_index else set()
        persistent_keys = keys & previous_keys if ordered_index else set()

        snapshots.append({
            'label': _report_label(report, ordered_index),
            'target': report.get('scan_info', {}).get('target', ''),
            'timestamp': _scan_time(report),
            'total_vulnerabilities': len(keys),
            'severity_counts': dict(sorted(severity_counts.items())),
            'new_vulnerabilities': _format_vuln_keys(new_keys),
            'resolved_vulnerabilities': _format_vuln_keys(resolved_keys),
            'persistent_vulnerabilities': _format_vuln_keys(persistent_keys),
        })
        previous_keys = keys

    latest_keys = previous_keys
    resolved_overall = all_keys - latest_keys
    unresolved_overall = latest_keys

    return {
        'report_count': len(reports),
        'snapshots': snapshots,
        'summary': {
            'first_total': snapshots[0]['total_vulnerabilities'] if snapshots else 0,
            'latest_total': snapshots[-1]['total_vulnerabilities'] if snapshots else 0,
            'net_change': (
                snapshots[-1]['total_vulnerabilities'] - snapshots[0]['total_vulnerabilities']
                if snapshots else 0
            ),
            'unique_vulnerabilities_seen': len(all_keys),
            'currently_unresolved': len(unresolved_overall),
            'resolved_overall': len(resolved_overall),
        },
        'currently_unresolved': _format_vuln_keys(unresolved_overall),
        'resolved_overall': _format_vuln_keys(resolved_overall),
        'lifecycle': [
            {
                'target': target,
                'name': name,
                'severity': severity,
                'first_seen_snapshot': first_seen[key] + 1,
                'last_seen_snapshot': last_seen[key] + 1,
                'currently_present': key in latest_keys,
            }
            for key in sorted(all_keys)
            for target, name, severity in [key]
        ],
    }


def _format_vuln_keys(keys):
    return [
        {'target': target, 'name': name, 'severity': severity}
        for target, name, severity in sorted(keys)
    ]


def validate_comparable(old_report, new_report):
    old = old_report.get('scan_info', {})
    new = new_report.get('scan_info', {})
    for key in ('target', 'profile', 'ports', 'intrusive_checks', 'external_enrichment_enabled', 'checks_enabled'):
        if key in old and key in new and old[key] != new[key]:
            raise ValueError(f'reports have different {key}; compare scans with matching scope and checks')
