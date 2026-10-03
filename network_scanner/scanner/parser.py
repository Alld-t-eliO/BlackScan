import argparse
import os
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
    parser = argparse.ArgumentParser(description='BlackScan network scanner')
    parser.add_argument('-t', '--target', help='Target: IP, DNS name, or CIDR range')
    parser.add_argument('--threads', type=positive_int, default=100)
    parser.add_argument('--timeout', type=positive_int, default=2)
    parser.add_argument('-a', '--aggressive', action='store_true')
    parser.add_argument('--profile', choices=sorted(settings.SCAN_PROFILES), default='quick')
    parser.add_argument('--ports')
    parser.add_argument('-o', '--output-dir', default='reports')
    parser.add_argument('--max-hosts', type=positive_int, default=4096)
    parser.add_argument('--host-workers', type=positive_int, default=10)
    parser.add_argument('--service-workers', type=positive_int, default=32)
    parser.add_argument('--proxy')
    parser.add_argument('--compare')
    parser.add_argument('--trend', nargs='+')
    parser.add_argument('--tui', nargs='?', const='latest')
    parser.add_argument('--list-external-tools', action='store_true')
    parser.add_argument('--external-enrichment', action='store_true')
    parser.add_argument('--intrusive-checks', action='store_true')
    parser.add_argument('--skip-discovery', action='store_true')
    parser.add_argument('--no-external-enrichment', action='store_true')
    parser.add_argument('--external-timeout', type=positive_int, default=120)
    parser.add_argument(
        '--authorized',
        action='store_true',
        help='(optional, deprecated) Mark scan as authorized',
    )
    exploit_group = parser.add_argument_group('Unavailable legacy options')
    exploit_group.add_argument('--exploit', action='store_true', help='Unavailable: retained only to explain legacy invocations')
    exploit_group.add_argument('--exploit-timeout', type=positive_int, default=60, help=argparse.SUPPRESS)
    exploit_group.add_argument('--exploit-targets', help=argparse.SUPPRESS)
    exploit_group.add_argument('--exploit-auto-confirm', action='store_true', default=False, help=argparse.SUPPRESS)
    exploit_group.add_argument(
        '--exploit-module',
        choices=['ssh', 'web', 'database', 'all'],
        default='all', help=argparse.SUPPRESS,
    )

    execution = parser.add_argument_group('Execution and transport')
    execution.add_argument('--execution-mode', '--mode', choices=['local', 'proxy', 'vps'],
                           default=os.environ.get('BLACKSCAN_EXECUTION_MODE', 'local'))
    execution.add_argument('--socks-proxy', default=os.environ.get('BLACKSCAN_SOCKS_PROXY'),
                           help='SOCKS4/5 URL for TCP discovery and service collection')
    for name, description in {
        'vps-host': 'SSH hostname', 'vps-user': 'SSH username',
        'vps-key': 'SSH private key path (or use the SSH agent)',
        'vps-known-hosts': 'Additional trusted known_hosts file',
        'vps-directory': 'Absolute remote BlackScan project directory',
        'vps-python': 'Remote Python executable, preferably the venv Python',
        'vps-reports': 'Absolute remote directory for scan reports',
    }.items():
        execution.add_argument('--' + name, default=os.environ.get('BLACKSCAN_' + name.upper().replace('-', '_')), help=description)
    for name in ('vps-port', 'vps-timeout', 'vps-scan-timeout'):
        execution.add_argument('--' + name, type=positive_int,
                               default=os.environ.get('BLACKSCAN_' + name.upper().replace('-', '_')))

    return parser
