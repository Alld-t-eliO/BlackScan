
try:
    import curses
except ImportError:  
    curses = None
import json
import shutil
from pathlib import Path

RISK_ORDER = {'high': 0, 'medium': 1, 'low': 2, 'info': 3}
PROFILES = ('quick', 'web', 'internal', 'full', 'stealth')
PROFILE_DESCRIPTIONS = {
    'quick': 'common services',
    'web': 'http services',
    'internal': 'internal services',
    'full': 'extended tcp range',
    'stealth': 'low-noise services',
}
EXTERNAL_TOOLS = ('nmap', 'nuclei', 'httpx', 'subfinder', 'dnsx')
MAIN_MENU = ('New scan', 'Open latest report', 'Open report path', 'List external tools', 'Quit')
LOGO = (
    r'__________.__                 __      _________                     ',
    r'\______   \  | _____    ____ |  | __ /   _____/ ____ _____    ____  ',
    r' |    |  _/  | \__  \ _/ ___\|  |/ / \_____  \_/ ___\\__  \  /    \ ',
    r' |    |   \  |__/ __ \\  \___|    <  /        \  \___ / __ \|   |  \ ',
    r' |______  /____(____  /\___  >__|_ \/_______  /\___  >____  /___|  /',
    r'        \/          \/     \/     \/        \/     \/     \/     \/ ',
)
SIGNATURE = 'By Aegon'
THEME = {
    'header': 1,
    'accent': 2,
    'selection': 3,
    'error': 4,
    'muted': 5,
    'risk_high': 4,
    'risk_medium': 6,
    'risk_low': 2,
    'risk_info': 5,
}
EDITABLE_FIELDS = {
    'target',
    'ports',
    'timeout',
    'threads',
    'output_dir',
    'proxy',
    'compare_report',
    'max_hosts',
    'host_workers',
    'service_workers',
}


def default_scan_form(output_dir='reports'):
    return {
        'target': '',
        'profile': 'quick',
        'ports': '',
        'timeout': '2',
        'threads': '100',
        'output_dir': output_dir,
        'proxy': '',
        'compare_report': '',
        'max_hosts': '4096',
        'host_workers': '10',
        'service_workers': '32',
        'intrusive_checks': False,
        'authorized': False,
    }


def build_scan_options(form):
    return {
        'target': form['target'].strip(),
        'profile': form['profile'],
        'ports': form['ports'].strip() or None,
        'timeout': int(form['timeout']),
        'threads': int(form['threads']),
        'output_dir': form['output_dir'].strip() or 'reports',
        'proxy': form['proxy'].strip() or None,
        'compare_report': form['compare_report'].strip() or None,
        'max_hosts': int(form['max_hosts']),
        'host_workers': int(form['host_workers']),
        'service_workers': int(form['service_workers']),
        'intrusive_checks': bool(form['intrusive_checks']),
        'authorized': bool(form['authorized']),
    }


def validate_scan_form(form):
    errors = []
    if not form['target'].strip():
        errors.append('Target is required')
    if not form['authorized']:
        errors.append('Confirm authorized scope before scanning')
    for field in ('timeout', 'threads', 'max_hosts', 'host_workers', 'service_workers'):
        try:
            if int(form[field]) < 1:
                errors.append(f'{field} must be >= 1')
        except ValueError:
            errors.append(f'{field} must be a number')
    return errors


def find_latest_report(report_dir='reports'):
    reports = sorted(Path(report_dir).glob('scan_report_*.json'), key=lambda path: path.stat().st_mtime, reverse=True)
    if not reports:
        raise FileNotFoundError(f'no scan_report_*.json files found in {report_dir}')
    return str(reports[0])


def report_inventory(report_dir='reports'):
    reports = sorted(Path(report_dir).glob('scan_report_*.json'), key=lambda path: path.stat().st_mtime, reverse=True)
    return {
        'count': len(reports),
        'latest': reports[0].name if reports else None,
        'reports': [path.name for path in reports],
    }


def external_tool_inventory():
    available = []
    missing = []
    for name in EXTERNAL_TOOLS:
        if shutil.which(name):
            available.append(name)
        else:
            missing.append(name)
    return {'available': available, 'missing': missing}


def profile_status_lines(active_profile):
    """Return display rows for scan profiles."""
    rows = []
    for profile in PROFILES:
        marker = '>' if profile == active_profile else ' '
        rows.append((f'{marker} {profile.upper()}', PROFILE_DESCRIPTIONS[profile]))
    return rows


def load_report(path):
    """Load a BlackScan JSON report."""
    with open(path, encoding='utf-8') as handle:
        return json.load(handle)


def flatten_services(report):
    """Flatten report services into sorted rows for the TUI."""
    results = report.get('results', {})
    rows = []
    for host, ports in results.get('services', {}).items():
        for port_text, service in ports.items():
            target = f'{host}:{port_text}'
            risk_info = results.get('risks', {}).get(target, {})
            vulns = results.get('vulnerabilities', {}).get(target, [])
            http = service.get('http') or {}
            rows.append({
                'host': host,
                'port': int(port_text),
                'service': service.get('name', 'unknown'),
                'risk': risk_info.get('score', 'info'),
                'findings': len(vulns),
                'title': http.get('title', ''),
                'target': target,
            })
    return sorted(rows, key=lambda row: (RISK_ORDER.get(row['risk'], 9), row['host'], row['port']))


def report_summary(report):
    """Return high-level report metrics."""
    results = report.get('results', {})
    return {
        'target': report.get('scan_info', {}).get('target', ''),
        'profile': report.get('scan_info', {}).get('profile', ''),
        'started': report.get('scan_info', {}).get('start_time', ''),
        'hosts': len(results.get('hosts', [])),
        'ports': sum(len(ports) for ports in results.get('open_ports', {}).values()),
        'vulnerabilities': sum(len(vulns) for vulns in results.get('vulnerabilities', {}).values()),
    }


def service_detail_lines(report, row):
    """Build detail lines for a selected service row."""
    results = report.get('results', {})
    service = results.get('services', {}).get(row['host'], {}).get(str(row['port']), {})
    risk_info = results.get('risks', {}).get(row['target'], {})
    vulns = results.get('vulnerabilities', {}).get(row['target'], [])
    http = service.get('http') or {}
    tls = service.get('tls') or {}

    lines = [
        f"Target: {row['target']}",
        f"Service: {service.get('name', 'unknown')}",
        f"Risk: {risk_info.get('score', 'info')}",
    ]
    if service.get('banner'):
        lines.extend(['', 'Banner:', service.get('banner', '').replace('\r', ' ').replace('\n', ' ')[:220]])

    if http:
        lines.extend(['', 'HTTP:'])
        lines.append(f"URL: {http.get('url', '')}")
        lines.append(f"Status: {http.get('status', '')}")
        if http.get('title'):
            lines.append(f"Title: {http.get('title')}")
        if http.get('server'):
            lines.append(f"Server: {http.get('server')}")
        if http.get('technologies'):
            lines.append(f"Technologies: {', '.join(http.get('technologies', []))}")
        sensitive = [
            f"{item.get('path')} HTTP {item.get('status')}"
            for item in http.get('sensitive_paths', [])
            if item.get('status')
        ]
        if sensitive:
            lines.append(f"Sensitive paths: {', '.join(sensitive)}")

    if tls and tls.get('sha256_fingerprint'):
        verification = tls.get('verification', {})
        lines.extend(['', 'TLS:'])
        lines.append(f"Fingerprint: {tls.get('sha256_fingerprint')}")
        lines.append(f"Verified: {verification.get('verified')}")
        if tls.get('not_after'):
            lines.append(f"Expires: {tls.get('not_after')}")

    if risk_info.get('factors'):
        lines.extend(['', 'Risk factors:'])
        for factor in risk_info.get('factors', []):
            lines.append(f"- {factor.get('severity', 'info')} {factor.get('name', 'unknown')}")

    if vulns:
        lines.extend(['', 'Findings:'])
        for vuln in vulns:
            lines.append(f"- {vuln.get('severity', 'info').upper()} {vuln.get('name', 'unknown')}")
            if vuln.get('evidence'):
                lines.append(f"  Evidence: {vuln.get('evidence')}")
            if vuln.get('recommendation'):
                lines.append(f"  Fix: {vuln.get('recommendation')}")
    else:
        lines.extend(['', 'Findings: none'])

    return lines


def run_app(output_dir='reports'):
    """Open the main interactive TUI and return the selected action."""
    if curses is None:
        raise RuntimeError('the interactive TUI requires a terminal with curses support')
    return curses.wrapper(_run_main_menu, output_dir)


def run_report_viewer(report_path):
    """Open the report browser directly."""
    if curses is None:
        raise RuntimeError('the interactive TUI requires a terminal with curses support')
    report = load_report(report_path)
    rows = flatten_services(report)
    summary = report_summary(report)
    return curses.wrapper(_run_report_viewer, report_path, report, rows, summary)


def run_tui(report_path):
    """Backward-compatible alias for the report browser."""
    return run_report_viewer(report_path)


def _run_main_menu(stdscr, output_dir):
    curses.curs_set(0)
    stdscr.keypad(True)
    _init_theme()
    message = ''

    while True:
        height, width = stdscr.getmaxyx()
        stdscr.erase()
        _draw_logo(stdscr, 1, 2, width - 4, compact=height < 20)
        menu_y = 10 if height >= 20 else 5
        _draw_section_title(stdscr, menu_y, 2, 'MAIN MENU', width - 4)
        _safe_addnstr(stdscr, menu_y + 1, 2, '[authorized reconnaissance interface]', width - 4, _color_attr('muted'))
        if message:
            _draw_message(stdscr, menu_y + 3, 2, message, width - 4, is_error=True)

        start_y = menu_y + 5
        for index, item in enumerate(MAIN_MENU, start=start_y):
            menu_index = index - start_y
            if index >= height - 2:
                break
            _safe_addnstr(stdscr, index, 4, f'[{menu_index + 1}] {item.upper()}', width - 8, _color_attr('accent'))

        _safe_addnstr(stdscr, height - 2, 2, 'Type a number and press Enter. 5 or q quits.', width - 4, _color_attr('muted'))
        stdscr.refresh()

        choice_text = _prompt(stdscr, 'Choice')
        if choice_text.lower() in {'q', 'quit', 'exit'}:
            return {'action': 'quit'}
        if not choice_text.isdigit() or not 1 <= int(choice_text) <= len(MAIN_MENU):
            message = 'Invalid choice'
            continue

        choice = MAIN_MENU[int(choice_text) - 1]
        if choice == 'New scan':
            result = _run_scan_form(stdscr, output_dir)
            if result.get('action') != 'back':
                return result
            message = ''
        elif choice == 'Open latest report':
            try:
                report_path = find_latest_report(output_dir)
                _open_report_inside_tui(stdscr, report_path)
                message = ''
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                message = str(exc)
        elif choice == 'Open report path':
            report_path = _prompt(stdscr, 'JSON report path')
            if report_path:
                try:
                    _open_report_inside_tui(stdscr, report_path)
                    message = ''
                except (OSError, json.JSONDecodeError, ValueError) as exc:
                    message = str(exc)
        elif choice == 'List external tools':
            return {'action': 'list_external_tools'}
        elif choice == 'Quit':
            return {'action': 'quit'}


def _run_scan_form(stdscr, output_dir):
    _init_theme()
    form = default_scan_form(output_dir)
    fields = list(form)
    message = ''

    while True:
        height, width = stdscr.getmaxyx()
        stdscr.erase()
        _draw_compact_logo(stdscr, 1, 2, width - 4)
        _draw_section_title(stdscr, 4, 2, 'CONFIGURE SCAN', width - 4)
        _safe_addnstr(stdscr, 5, 2, '[type a field number to edit or toggle it]', width - 4, _color_attr('muted'))
        if message:
            _draw_message(stdscr, 6, 2, message, width - 4, is_error=True)

        start_y = 8
        for index, field in enumerate(fields, start=start_y):
            if index >= height - 5:
                break
            field_number = index - start_y + 1
            attr = _field_attr(field, form[field])
            value = _field_display_value(field, form[field])
            label = field.replace('_', ' ').title()
            _safe_addnstr(stdscr, index, 4, f'[{field_number:02}] {label:18} {value}', width - 8, attr)

        command_y = min(height - 4, start_y + len(fields) + 1)
        _safe_addnstr(stdscr, command_y, 4, '[98] Start scan', width - 8, _color_attr('accent', curses.A_BOLD))
        _safe_addnstr(stdscr, command_y + 1, 4, '[99] Cycle profile', width - 8, _color_attr('accent'))
        _safe_addnstr(stdscr, command_y + 2, 4, '[00] Back', width - 8, _color_attr('muted'))
        stdscr.refresh()

        choice_text = _prompt(stdscr, 'Choice')
        if choice_text.lower() in {'q', 'quit', 'exit'}:
            return {'action': 'quit'}
        if choice_text.lower() in {'b', 'back'} or choice_text in {'0', '00'}:
            return {'action': 'back'}
        if choice_text == '99':
            form['profile'] = _next_profile(form['profile'])
            message = ''
            continue
        if choice_text == '98':
            errors = validate_scan_form(form)
            if errors:
                message = '; '.join(errors[:3])
                continue
            return {'action': 'scan', 'options': build_scan_options(form)}
        if not choice_text.isdigit() or not 1 <= int(choice_text) <= len(fields):
            message = 'Invalid field number'
            continue

        field = fields[int(choice_text) - 1]
        if field == 'profile':
            form[field] = _next_profile(form[field])
        elif isinstance(form[field], bool):
            form[field] = not form[field]
        elif field in EDITABLE_FIELDS:
            form[field] = _prompt(stdscr, field.replace('_', ' ').title(), str(form[field]))
        message = ''


def _open_report_inside_tui(stdscr, report_path):
    report = load_report(report_path)
    rows = flatten_services(report)
    summary = report_summary(report)
    _run_report_viewer(stdscr, report_path, report, rows, summary)


def _run_report_viewer(stdscr, report_path, report, rows, summary):
    curses.curs_set(0)
    stdscr.keypad(True)
    _init_theme()
    selected = 0
    offset = 0
    message = ''

    while True:
        height, width = stdscr.getmaxyx()
        list_width = max(36, min(58, width // 2))
        visible_height = max(1, height - 7)

        offset = min(offset, selected)
        if selected >= offset + visible_height:
            offset = selected - visible_height + 1

        stdscr.erase()
        _draw_header(stdscr, report_path, summary, width)
        _draw_services(stdscr, rows, selected, offset, visible_height, list_width)
        _draw_details(stdscr, report, rows, selected, list_width, width, height)
        if message:
            _draw_message(stdscr, height - 3, 2, message, width - 4, is_error=True)
        _safe_addnstr(stdscr, height - 2, 2, 'Type service number, n/p for page, 0 or q to go back.', width - 4, _color_attr('muted'))
        stdscr.refresh()

        choice_text = _prompt(stdscr, 'Choice')
        if choice_text.lower() in {'q', 'quit', 'exit', 'b', 'back'} or choice_text in {'0', '00'}:
            break
        if choice_text.lower() == 'n':
            selected = min(len(rows) - 1, selected + visible_height)
            message = ''
            continue
        if choice_text.lower() == 'p':
            selected = max(0, selected - visible_height)
            message = ''
            continue
        if choice_text.isdigit() and 1 <= int(choice_text) <= len(rows):
            selected = int(choice_text) - 1
            message = ''
        else:
            message = 'Invalid service number'


def _next_profile(profile):
    index = PROFILES.index(profile) if profile in PROFILES else 0
    return PROFILES[(index + 1) % len(PROFILES)]


def _field_display_value(field, value):
    if isinstance(value, bool):
        return 'yes' if value else 'no'
    if field == 'ports' and not value:
        return '<profile defaults>'
    if field in {'proxy', 'compare_report'} and not value:
        return '<none>'
    return str(value)


def _prompt(stdscr, label, current=''):
    height, width = stdscr.getmaxyx()
    prompt = f'{label}: '
    curses.echo()
    curses.curs_set(1)
    stdscr.move(height - 2, 0)
    stdscr.clrtoeol()
    _safe_addnstr(stdscr, height - 2, 0, prompt, width, _color_attr('accent', curses.A_BOLD))
    if current:
        _safe_addnstr(stdscr, height - 2, len(prompt), current, width - len(prompt), _color_attr('muted'))
    stdscr.refresh()
    try:
        raw = stdscr.getstr(height - 2, len(prompt), 240)
    finally:
        curses.noecho()
        curses.curs_set(0)
    value = raw.decode(errors='ignore').strip()
    return value if value else current


def _draw_header(stdscr, report_path, summary, width):
    title = f"BLACKSCAN // REPORT VIEWER // {Path(report_path).name}"
    _safe_addnstr(stdscr, 0, 0, title, width, _color_attr('accent', curses.A_BOLD))
    _safe_addnstr(stdscr, 1, 0, SIGNATURE, width, _color_attr('header', curses.A_BOLD))
    meta = (
        f"Target: {summary['target']} | Profile: {summary['profile']} | Hosts: {summary['hosts']} | "
        f"Open ports: {summary['ports']} | Findings: {summary['vulnerabilities']}"
    )
    _safe_addnstr(stdscr, 2, 0, meta.ljust(width), width, _color_attr('muted'))


def _draw_services(stdscr, rows, selected, offset, visible_height, list_width):
    _draw_section_title(stdscr, 4, 0, 'SERVICES', list_width)
    if not rows:
        _safe_addnstr(stdscr, 5, 0, 'No services in this report'.ljust(list_width), list_width, _color_attr('muted'))
        return
    for screen_index, row in enumerate(rows[offset:offset + visible_height], start=5):
        absolute_index = offset + screen_index - 5
        marker = '>>' if absolute_index == selected else '  '
        text = (
            f"{marker} [{absolute_index + 1:02}] {row['risk'].upper():6} {row['host']}:{row['port']} "
            f"{row['service']} ({row['findings']})"
        )
        attr = _color_attr('selection', curses.A_REVERSE | curses.A_BOLD) if absolute_index == selected else _risk_attr(row['risk'])
        _safe_addnstr(stdscr, screen_index, 0, text.ljust(list_width), list_width, attr)


def _draw_details(stdscr, report, rows, selected, list_width, width, height):
    start_x = list_width + 2
    detail_width = max(1, width - start_x)
    _draw_section_title(stdscr, 4, start_x, 'DETAILS', detail_width)
    if not rows:
        return
    lines = service_detail_lines(report, rows[selected])
    for index, line in enumerate(lines[:max(0, height - 6)], start=5):
        _safe_addnstr(stdscr, index, start_x, line, detail_width, _detail_line_attr(line))


def _init_theme():
    if not curses.has_colors():
        return
    try:
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(THEME['header'], curses.COLOR_MAGENTA, -1)
        curses.init_pair(THEME['accent'], curses.COLOR_CYAN, -1)
        curses.init_pair(THEME['selection'], curses.COLOR_CYAN, curses.COLOR_MAGENTA)
        curses.init_pair(THEME['error'], curses.COLOR_RED, -1)
        curses.init_pair(THEME['muted'], curses.COLOR_MAGENTA, -1)
        curses.init_pair(THEME['risk_medium'], curses.COLOR_CYAN, -1)
    except curses.error:
        pass


def _color_attr(name, extra=0):
    if curses.has_colors():
        try:
            return curses.color_pair(THEME[name]) | extra
        except curses.error:
            return extra
    return extra


def _draw_section_title(stdscr, y, x, title, width):
    _safe_addnstr(stdscr, y, x, f'[{title}]'.ljust(width), width, _color_attr('accent', curses.A_BOLD))


def _draw_logo(stdscr, y, x, width, compact=False):
    if compact:
        _draw_compact_logo(stdscr, y, x, width)
        return
    for offset, line in enumerate(LOGO):
        attr = _color_attr('accent' if offset < 3 else 'header', curses.A_BOLD)
        _safe_addnstr(stdscr, y + offset, x, line, width, attr)
    _safe_addnstr(stdscr, y + len(LOGO), x + 2, f'==== {SIGNATURE} ====', width - 2, _color_attr('header', curses.A_BOLD))


def _draw_compact_logo(stdscr, y, x, width):
    _safe_addnstr(stdscr, y, x, 'BLACKSCAN'.ljust(width, '-'), width, _color_attr('accent', curses.A_BOLD))
    _safe_addnstr(stdscr, y + 1, x, SIGNATURE, width, _color_attr('header', curses.A_BOLD))


def _draw_message(stdscr, y, x, message, width, is_error=False):
    prefix = '[ERROR] ' if is_error else '[INFO] '
    attr = _color_attr('error' if is_error else 'accent', curses.A_BOLD)
    _safe_addnstr(stdscr, y, x, f'{prefix}{message}', width, attr)


def _field_attr(field, value):
    if isinstance(value, bool) and not value and field == 'authorized':
        return _color_attr('error', curses.A_BOLD)
    if isinstance(value, bool) and value:
        return _color_attr('accent', curses.A_BOLD)
    return _color_attr('muted')


def _risk_attr(risk):
    return _color_attr(f'risk_{risk}' if f'risk_{risk}' in THEME else 'muted', curses.A_BOLD)


def _detail_line_attr(line):
    normalized = line.lower()
    if normalized.startswith('- high') or normalized.startswith('risk: high'):
        return _color_attr('error', curses.A_BOLD)
    if normalized.endswith(':'):
        return _color_attr('accent', curses.A_BOLD)
    return _color_attr('muted')


def _safe_addnstr(stdscr, y, x, text, max_width, attr=0):
    height, width = stdscr.getmaxyx()
    if y < 0 or y >= height or x < 0 or x >= width:
        return
    available = min(max_width, width - x)
    if y == height - 1:
        available = min(available, max(0, width - x - 1))
    if available <= 0:
        return
    try:
        stdscr.addnstr(y, x, text, available, attr)
    except curses.error:
        pass
