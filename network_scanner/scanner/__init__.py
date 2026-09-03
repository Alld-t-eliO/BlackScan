from network_scanner.scanner.comparaison import (
    format_finding_list,
    format_severity_counts,
    format_trend_markdown,
    generate_trend_reports,
)
from network_scanner.scanner.parser import build_parser, mask_proxy_url, parse_ports, validate_proxy_url
from network_scanner.scanner.report import Colors, ReportMixin
from network_scanner.scanner.scan import NetworkScanner


def main():
    from network_scanner.scanner.main import main as run_main

    return run_main()


__all__ = [
    'Colors',
    'NetworkScanner',
    'ReportMixin',
    'build_parser',
    'format_finding_list',
    'format_severity_counts',
    'format_trend_markdown',
    'generate_trend_reports',
    'main',
    'mask_proxy_url',
    'parse_ports',
    'validate_proxy_url',
]
