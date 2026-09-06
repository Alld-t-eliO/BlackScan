import argparse
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from network_scanner import settings


def parse_ports(value):
    ports = set()
    for chunk in value.split(','):
        chunk = chunk.strip()
        if not chunk:
            continue
        if '-' in chunk:
            start, end = chunk.split('-', 1)
            start_port = int(start)
            end_port = int(end)
            if not 1 <= start_port <= end_port <= 65535:
                raise ValueError(f'invalid port range: {chunk}')
            ports.update(range(start_port, end_port + 1))
        else:
            ports.add(int(chunk))

    invalid = [port for port in ports if port < 1 or port > 65535]
    if invalid:
        raise ValueError(f'invalid port number: {invalid[0]}')
    if not ports:
        raise ValueError('at least one port is required')
    return sorted(ports)


def validate_target(value):
    value = str(value).strip()
    try:
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError:
        pass
    if len(value) > 253 or not value or any(
        not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
        for label in value.rstrip('.').split('.')
    ):
        raise ValueError('target must be an IP, DNS name, or CIDR (without URL, path, or port)')
    return value


def positive_int(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError('value must be >= 1')
    return number


def validate_proxy_url(value):
    if not value:
        return None
    parsed = urlsplit(value)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
        raise ValueError('proxy must be an http:// or https:// URL')
    if parsed.port == 0 or parsed.path not in {'', '/'} or parsed.query or parsed.fragment:
        raise ValueError('proxy must contain only a host, optional credentials, and a valid port')
    return value


def mask_proxy_url(value):
    if not value:
        return ''
    parsed = urlsplit(value)
    if '@' not in parsed.netloc:
        return value
    _credentials, host = parsed.netloc.rsplit('@', 1)
    return urlunsplit((parsed.scheme, f'***:***@{host}', parsed.path, parsed.query, parsed.fragment))


def build_parser():
    parser = argparse.ArgumentParser(description='BlackScan network vulnerability scanner')
    parser.add_argument('-t', '--target', help='Authorized target: IP, DNS name, or CIDR range')
    parser.add_argument('--threads', type=positive_int, default=100, help='Number of worker threads/concurrent tasks (default: 100)')
    parser.add_argument('--timeout', type=positive_int, default=2, help='Timeout in seconds (default: 2)')
    parser.add_argument('-a', '--aggressive', action='store_true', help='Aggressive mode: wider ports and additional checks')
    parser.add_argument('--profile', choices=sorted(settings.SCAN_PROFILES), default='quick', help='Scan profile (default: quick)')
    parser.add_argument('--ports', help='Ports to scan, for example: 22,80,443,8000-8100')
    parser.add_argument('-o', '--output-dir', default='reports', help='Report output directory')
    parser.add_argument('--max-hosts', type=positive_int, default=4096, help='Maximum number of addresses allowed in a CIDR range')
    parser.add_argument('--host-workers', type=positive_int, default=10, help='Maximum hosts scanned in parallel')
    parser.add_argument('--service-workers', type=positive_int, default=32, help='Maximum services fingerprinted in parallel per host')
    parser.add_argument('--proxy', help='HTTP(S) proxy URL used for HTTP/HTTPS fingerprinting requests')
    parser.add_argument('--compare', help='Previous JSON report to compare with the new scan')
    parser.add_argument('--trend', nargs='+', help='Analyze vulnerability evolution across JSON reports')
    parser.add_argument(
        '--tui',
        nargs='?',
        const='latest',
        help='Open the interactive TUI, or pass a JSON report path to open the report viewer directly',
    )
    parser.add_argument('--list-external-tools', action='store_true', help='List available external integrations')
    parser.add_argument('--external-enrichment', action='store_true', help='Run available external tools and include their output in reports')
    parser.add_argument('--intrusive-checks', action='store_true', help='Enable checks that attempt application-level interactions')
    parser.add_argument('--authorized', action='store_true', help='Confirm that you are authorized to scan the target')
    parser.add_argument('--skip-discovery', action='store_true', help='Scan every target even when discovery probes fail')
    parser.add_argument('--no-external-enrichment', action='store_true', help='Disable external tools, including for full scans')
    parser.add_argument('--external-timeout', type=positive_int, default=120, help='Maximum seconds per external command (default: 120)')
    return parser
