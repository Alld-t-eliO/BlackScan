import json
import os
from datetime import datetime, timezone

from network_scanner.modules import report_diff


def generate_trend_reports(report_paths, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    reports = [report_diff.load_report(path) for path in report_paths]
    trend = report_diff.analyze_vulnerability_trends(reports)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    json_filename = os.path.join(output_dir, f"vulnerability_trend_{timestamp}.json")
    markdown_filename = os.path.join(output_dir, f"vulnerability_trend_{timestamp}.md")

    with open(json_filename, 'w', encoding='utf-8') as handle:
        json.dump(trend, handle, indent=2, ensure_ascii=False)

    with open(markdown_filename, 'w', encoding='utf-8') as handle:
        handle.write(format_trend_markdown(trend))

    return json_filename, markdown_filename, trend


def format_trend_markdown(trend):
    summary = trend.get('summary', {})
    lines = [
        '# BlackScan Vulnerability Trend',
        '',
        f"- Reports analyzed: {trend.get('report_count', 0)}",
        f"- First total: {summary.get('first_total', 0)}",
        f"- Latest total: {summary.get('latest_total', 0)}",
        f"- Net change: {summary.get('net_change', 0)}",
        f"- Unique vulnerabilities seen: {summary.get('unique_vulnerabilities_seen', 0)}",
        f"- Currently unresolved: {summary.get('currently_unresolved', 0)}",
        f"- Resolved overall: {summary.get('resolved_overall', 0)}",
        '',
        '## Timeline',
        '',
    ]

    for index, snapshot in enumerate(trend.get('snapshots', []), start=1):
        lines.extend([
            f"### Snapshot {index}",
            '',
            f"- Label: `{snapshot.get('label', '')}`",
            f"- Total vulnerabilities: {snapshot.get('total_vulnerabilities', 0)}",
            f"- Severity counts: {format_severity_counts(snapshot.get('severity_counts', {}))}",
            f"- New: {len(snapshot.get('new_vulnerabilities', []))}",
            f"- Resolved: {len(snapshot.get('resolved_vulnerabilities', []))}",
            f"- Persistent: {len(snapshot.get('persistent_vulnerabilities', []))}",
            '',
        ])

    lines.extend(['## Currently Unresolved', ''])
    lines.extend(format_finding_list(trend.get('currently_unresolved', [])))
    lines.extend(['', '## Resolved Overall', ''])
    lines.extend(format_finding_list(trend.get('resolved_overall', [])))
    return '\n'.join(lines)


def format_severity_counts(counts):
    if not counts:
        return 'none'
    return ', '.join(f'{severity}={count}' for severity, count in sorted(counts.items()))


def format_finding_list(findings):
    if not findings:
        return ['- No entries']
    return [
        f"- `{finding.get('target', '')}` {finding.get('severity', 'info')} {finding.get('name', 'unknown')}"
        for finding in findings
    ]
