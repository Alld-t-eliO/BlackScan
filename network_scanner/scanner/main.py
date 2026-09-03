import json
import sys

from network_scanner.core import ui
from network_scanner.modules import external_tools
from network_scanner.scanner.comparaison import generate_trend_reports
from network_scanner.scanner.parser import build_parser, parse_ports, validate_proxy_url
from network_scanner.scanner.report import Colors
from network_scanner.scanner.scan import NetworkScanner


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.list_external_tools:
        for name, info in external_tools.detect_external_tools().items():
            status = 'available' if info['available'] else 'missing'
            version = f" - {info['version']}" if info['version'] else ''
            print(f"{name}: {status}{version}")
        return

    if args.tui is not None:
        try:
            if args.tui == 'latest':
                tui_action = ui.run_app(args.output_dir)
            else:
                ui.run_report_viewer(args.tui)
                return
        except (OSError, RuntimeError, json.JSONDecodeError, ValueError) as exc:
            parser.error(str(exc))
        if tui_action.get('action') == 'quit':
            return
        if tui_action.get('action') == 'list_external_tools':
            for name, info in external_tools.detect_external_tools().items():
                status = 'available' if info['available'] else 'missing'
                version = f" - {info['version']}" if info['version'] else ''
                print(f"{name}: {status}{version}")
            return
        if tui_action.get('action') == 'scan':
            options = tui_action['options']
            args.target = options['target']
            args.profile = options['profile']
            args.ports = options['ports']
            args.timeout = options['timeout']
            args.threads = options['threads']
            args.output_dir = options['output_dir']
            args.proxy = options['proxy']
            args.compare = options['compare_report']
            args.max_hosts = options['max_hosts']
            args.host_workers = options['host_workers']
            args.service_workers = options['service_workers']
            args.intrusive_checks = options['intrusive_checks']
            args.authorized = options['authorized']
            args.aggressive = False
            args.trend = None
        else:
            parser.error('unknown TUI action')

    if args.trend:
        if len(args.trend) < 2:
            parser.error("--trend requires at least two JSON reports")
        try:
            json_report, markdown_report, trend = generate_trend_reports(args.trend, args.output_dir)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            parser.error(str(exc))
        summary = trend.get('summary', {})
        print(f"{Colors.GREEN}[+] Trend JSON report: {json_report}{Colors.RESET}")
        print(f"{Colors.GREEN}[+] Trend Markdown report: {markdown_report}{Colors.RESET}")
        print(
            f"{Colors.WHITE}Latest vulnerabilities: {summary.get('latest_total', 0)} "
            f"(net change: {summary.get('net_change', 0)}){Colors.RESET}"
        )
        return

    if not args.target:
        parser.error("required argument: -t/--target")

    if not args.authorized:
        parser.error("add --authorized to confirm that the target is in your authorized scope")

    try:
        ports = parse_ports(args.ports) if args.ports else None
        proxy_url = validate_proxy_url(args.proxy)
    except ValueError as exc:
        parser.error(str(exc))

    scanner = NetworkScanner(
        args.target,
        args.threads,
        args.timeout,
        args.aggressive,
        ports,
        args.output_dir,
        args.profile,
        args.max_hosts,
        args.compare,
        args.intrusive_checks,
        args.host_workers,
        args.service_workers,
        proxy_url,
    )

    try:
        scanner.scan_network()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by the user")
        sys.exit(0)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"[!] Error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
