"""Shared, explicit scan options for CLI, TUI and remote execution."""
from network_scanner.scanner.parser import parse_ports

SCAN_DEFAULTS = {
    'threads': 100, 'timeout': 2, 'aggressive': False, 'ports': None,
    'output_dir': 'reports', 'profile': 'quick', 'max_hosts': 4096,
    'compare_report': None, 'intrusive_checks': False, 'host_workers': 10,
    'service_workers': 32, 'external_enrichment': False, 'skip_discovery': False,
    'no_external_enrichment': False, 'external_timeout': 120,
}


def scanner_options(options):
    if options.get('exploit') or options.get('exploit_mode'):
        raise ValueError('Experimental exploitation is unavailable in the supported scanner')
    result = {key: options.get(key, value) for key, value in SCAN_DEFAULTS.items()}
    if isinstance(result['ports'], str):
        result['ports'] = parse_ports(result['ports']) if result['ports'] else None
    result['proxy_url'] = options.get('proxy') or options.get('proxy_url') or None
    result['socks_proxy_url'] = options.get('socks_proxy') or options.get('socks_proxy_url') or None
    return result
