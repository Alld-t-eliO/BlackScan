from urllib.parse import quote

from . import config


def _build_socks_url():
    if not config.PROXY_ENABLED:
        raise RuntimeError("Proxy mode selected but PROXY_ENABLED=False.")
    if not config.PROXY_HOST:
        raise RuntimeError("PROXY_HOST is not configured.")
    if not config.PROXY_PORT:
        raise RuntimeError("PROXY_PORT is not configured.")

    scheme = config.PROXY_TYPE if config.PROXY_TYPE in {'socks5', 'socks4'} else 'socks5'
    auth = ''
    if config.PROXY_USERNAME:
        auth = quote(config.PROXY_USERNAME, safe='')
        if config.PROXY_PASSWORD:
            auth += f":{quote(config.PROXY_PASSWORD, safe='')}"
        auth += '@'

    return f"{scheme}://{auth}{config.PROXY_HOST}:{config.PROXY_PORT}"


class ProxyManager:
    def __init__(self):
        self.connected = False
        self.socks_url = None

    def connect(self):
        self.socks_url = _build_socks_url()
        self.connected = True
        print(f"[Proxy] Configuration loaded: {config.PROXY_TYPE}://{config.PROXY_HOST}:{config.PROXY_PORT}")
        return True

    def run(self, target, options=None):
        options = options or {}

        if not options.get('authorized'):
            raise ValueError(
                "Proxy scan requires 'authorized' to confirm the target is in your authorized scope."
            )

        if not self.connected:
            self.connect()

        from network_scanner.scanner.scan import NetworkScanner
        from network_scanner.scanner.parser import parse_ports, validate_proxy_url

        print(f"[Proxy] Execution requested for: {target}")

        ports = parse_ports(options['ports']) if options.get('ports') else None
        http_proxy_url = validate_proxy_url(options.get('proxy')) if options.get('proxy') else None

        scanner = NetworkScanner(
            target,
            threads=options.get('threads', 100),
            timeout=options.get('timeout', 2),
            aggressive=options.get('aggressive', False),
            ports=ports,
            output_dir=options.get('output_dir', 'reports'),
            profile=options.get('profile', 'quick'),
            max_hosts=options.get('max_hosts', 4096),
            compare_report=options.get('compare_report'),
            intrusive_checks=options.get('intrusive_checks', False),
            host_workers=options.get('host_workers', 10),
            service_workers=options.get('service_workers', 32),
            proxy_url=http_proxy_url,
            external_enrichment=options.get('external_enrichment', False),
            skip_discovery=options.get('skip_discovery', False),
            no_external_enrichment=options.get('no_external_enrichment', False),
            external_timeout=options.get('external_timeout', 120),
            socks_proxy_url=self.socks_url,
        )

        report_paths = scanner.scan_network()

        return {
            "mode": "proxy",
            "target": target,
            "status": scanner.results.get("scan_status", "unknown"),
            "options": options,
            "reports": list(report_paths),
        }

    def disconnect(self):
        self.connected = False
        self.socks_url = None
        print("[Proxy] Disconnected.")
