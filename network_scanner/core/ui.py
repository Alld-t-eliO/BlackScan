try:
    import curses
except ImportError:  
    curses = None
import json
import os
import queue
import re
import shutil
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from network_scanner.payloads import WordlistManager

RISK_ORDER = {'critical': -1, 'high': 0, 'medium': 1, 'low': 2, 'info': 3}
PROFILES = ('quick', 'web', 'internal', 'full', 'stealth')
PROFILE_DESCRIPTIONS = {
    'quick': 'common services',
    'web': 'http services',
    'internal': 'internal services',
    'full': 'extended tcp range',
    'stealth': 'low-noise services',
}
EXTERNAL_TOOLS = ('nmap', 'nuclei', 'httpx', 'subfinder', 'dnsx', 'whois', 'dig', 'ffuf', 'feroxbuster', 'naabu', 'katana', 'sherlock', 'recon-ng')
MAIN_MENU = ('New scan', 'Profiles', 'Payloads', 'Open latest report', 'Open report path', 'List external tools', 'Quit')
ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')
VIOLET_COLOR = 99
PROFILE_STORE = Path.home() / '.blackscan' / 'profiles.json'
LOGO = (
    r'__________.__                 __      _________                     ',
    r'\______   \  | _____    ____ |  | __ /   _____/ ____ _____    ____  ',
    r' |    |  _/  | \__  \ _/ ___\|  |/ / \_____  \_/ ___\\__  \  /    \ ',
    r' |    |   \  |__/ __ \\  \___|    <  /        \  \___ / __ \|   |  \ ',
    r' |______  /____(____  /\___  >__|_ \/_______  /\___  >____  /___|  /',
    r'        \/          \/     \/     \/        \/     \/     \/     \/ ',
)
SIGNATURE = 'By Aegon'
UI_VERSION = '2.0-cyberpunk'
PANEL_GAP = 1
MIN_WIDTH = 58
MIN_HEIGHT = 16
BOX_CHARS = {'tl':'╭','tr':'╮','bl':'╰','br':'╯','h':'─','v':'│'}
ASCII_BOX_CHARS = {'tl':'+','tr':'+','bl':'+','br':'+','h':'-','v':'|'}
MENU_ICONS = ('>','#','*','@','+','?','x')
STATUS_LABELS = {'ready':'READY','scanning':'SCANNING','complete':'COMPLETE','failed':'FAILED'}
THEME = {
    'header': 1,
    'accent': 2,
    'selection': 3,
    'error': 4,
    'muted': 5,
    'text': 7,
    'risk_high': 4,
    'risk_critical': 4,
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
    'external_timeout',
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
        'external_enrichment': False,
        'authorized': False,
        'skip_discovery': False,
        'no_external_enrichment': False,
        'external_timeout': '120',
        'execution_mode': os.environ.get('BLACKSCAN_EXECUTION_MODE', 'local'),
        'socks_proxy': os.environ.get('BLACKSCAN_SOCKS_PROXY', ''),
        **{key: os.environ.get('BLACKSCAN_' + key.upper(), '') for key in (
            'vps_host', 'vps_user', 'vps_port', 'vps_key', 'vps_known_hosts',
            'vps_directory', 'vps_python', 'vps_reports', 'vps_timeout', 'vps_scan_timeout',
        )},
    }


def build_scan_options(form):
    return {
        'target': clean_input(form['target']).strip(),
        'profile': form['profile'],
        'ports': clean_input(form['ports']).strip() or None,
        'timeout': int(clean_input(form['timeout'])),
        'threads': int(clean_input(form['threads'])),
        'output_dir': clean_input(form['output_dir']).strip() or 'reports',
        'proxy': clean_input(form['proxy']).strip() or None,
        'compare_report': clean_input(form['compare_report']).strip() or None,
        'max_hosts': int(clean_input(form['max_hosts'])),
        'host_workers': int(clean_input(form['host_workers'])),
        'service_workers': int(clean_input(form['service_workers'])),
        'intrusive_checks': bool(form['intrusive_checks']),
        'external_enrichment': bool(form['external_enrichment']),
        'authorized': bool(form['authorized']),
        'skip_discovery': bool(form.get('skip_discovery')),
        'no_external_enrichment': bool(form.get('no_external_enrichment')),
        'external_timeout': int(form.get('external_timeout', '120')),
        'execution_mode': form.get('execution_mode', 'local'),
        'socks_proxy': clean_input(form.get('socks_proxy')).strip() or None,
        **{key: clean_input(value).strip() or None for key, value in form.items() if key.startswith('vps_')},
    }


def load_target_profiles(path=PROFILE_STORE):
    path = Path(clean_input(path))
    if not path.exists():
        return []
    with open(path, encoding='utf-8') as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or not isinstance(data.get('profiles'), list):
        raise ValueError('Invalid profiles file: expected an object containing a profiles list')
    profiles = data['profiles']
    return [normalize_target_profile(profile) for profile in profiles if isinstance(profile, dict)]


def save_target_profiles(profiles, path=PROFILE_STORE):
    path = Path(clean_input(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    normalized = [normalize_target_profile(profile) for profile in profiles]
    from network_scanner.scanner.report import write_json_atomic

    write_json_atomic(str(path), {'profiles': normalized})


def normalize_target_profile(profile):
    return {
        'name': clean_input(profile.get('name', '')).strip(),
        'ip': clean_input(profile.get('ip', '')).strip(),
        'url': clean_input(profile.get('url', '')).strip(),
    }


def target_from_profile(profile):
    normalized = normalize_target_profile(profile)
    if normalized['ip']:
        return normalized['ip']
    if normalized['url']:
        parsed = urlsplit(normalized['url'])
        return parsed.hostname or normalized['url']
    return ''


def profile_display_target(profile):
    normalized = normalize_target_profile(profile)
    parts = []
    if normalized['ip']:
        parts.append(normalized['ip'])
    if normalized['url']:
        parts.append(normalized['url'])
    return ' | '.join(parts) if parts else '<empty>'


def apply_target_profile(form, profile):
    target = target_from_profile(profile)
    if target:
        form['target'] = target
    normalized = normalize_target_profile(profile)
    if normalized['name']:
        form['loaded_profile'] = normalized['name']
    if normalize_target_profile(profile)['url'] and form['profile'] == 'quick':
        form['profile'] = 'web'
    return form


def validate_target_profile(profile):
    errors = []
    if not profile['name']:
        errors.append('Profile name is required')
    if not profile['ip'] and not profile['url']:
        errors.append('Add an IP, host, CIDR, or HTTPS URL')
    if profile['url']:
        parsed = urlsplit(profile['url'])
        if parsed.scheme != 'https' or not parsed.netloc:
            errors.append('HTTPS URL must start with https://')
    return errors


def validate_scan_form(form):
    from network_scanner.scanner.parser import parse_ports, validate_proxy_url, validate_target

    errors = []
    if not clean_input(form['target']).strip():
        errors.append('Target is required')
    if not form['authorized']:
        errors.append('Confirm authorized scope before scanning')
    limits = {'timeout': 3600, 'threads': 512, 'max_hosts': 65536,
              'host_workers': 64, 'service_workers': 128, 'external_timeout': 3600}
    if form.get('profile') not in PROFILES:
        errors.append('Unknown scan profile')
    for field, limit in limits.items():
        try:
            if not 1 <= int(clean_input(form.get(field, '120'))) <= limit:
                errors.append(f'{field} must be between 1 and {limit}')
        except ValueError:
            errors.append(f'{field} must be a number')
    try:
        validate_target(form['target'])
        validate_proxy_url(form.get('proxy'))
        if form.get('ports'):
            parse_ports(form['ports'])
        if int(form.get('external_timeout', '120')) < 1:
            errors.append('external_timeout must be >= 1')
    except ValueError as exc:
        errors.append(str(exc))
    mode = form.get('execution_mode', 'local')
    if mode not in {'local', 'proxy', 'vps'}:
        errors.append('Unknown execution mode')
    try:
        from network_scanner.modules.socks_transport import validate_socks_url
        if form.get('socks_proxy'):
            validate_socks_url(form['socks_proxy'])
            if form.get('proxy'):
                errors.append('Choose either HTTP or SOCKS proxy')
            if form.get('intrusive_checks') or form.get('external_enrichment'):
                errors.append('SOCKS does not support intrusive checks or external enrichment')
        if mode == 'proxy' and not (form.get('socks_proxy') or form.get('proxy')):
            from network_scanner.vps_proxy.proxy.manager import configured_proxy_url
            configured_proxy_url()
        if mode == 'vps':
            from network_scanner.vps_proxy.vps import config
            if not (form.get('vps_host') or config.VPS_HOST) or not (form.get('vps_user') or config.VPS_USERNAME):
                errors.append('VPS host and SSH username are required in connection settings')
            for key, limit in (('vps_port', 65535), ('vps_timeout', 86400), ('vps_scan_timeout', 86400)):
                if form.get(key) and not 1 <= int(form[key]) <= limit:
                    errors.append(f'{key} must be between 1 and {limit}')
    except ValueError as exc:
        errors.append(str(exc))
    return errors


def clean_input(value):
    if value is None:
        return ''
    return ''.join(char for char in str(value).replace('\x00', '') if char == '\n' or char == '\t' or ord(char) >= 32)


def find_latest_report(report_dir='reports'):
    reports = sorted(Path(clean_input(report_dir)).rglob('scan_report_*.json'), key=lambda path: path.stat().st_mtime, reverse=True)
    if not reports:
        raise FileNotFoundError(f'no scan_report_*.json files found in {report_dir}')
    return str(reports[0])


def report_inventory(report_dir='reports'):
    reports = sorted(Path(clean_input(report_dir)).rglob('scan_report_*.json'), key=lambda path: path.stat().st_mtime, reverse=True)
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
    rows = []
    for profile in PROFILES:
        marker = '>' if profile == active_profile else ' '
        rows.append((f'{marker} {profile.upper()}', PROFILE_DESCRIPTIONS[profile]))
    return rows


def load_report(path):
    from network_scanner.modules.report_diff import load_report as read_report

    return read_report(clean_input(path))


def flatten_services(report):
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


def run_app(output_dir='reports', initial_options=None):
    if curses is None:
        raise RuntimeError('the interactive TUI requires a terminal with curses support')
    try:
        return curses.wrapper(_run_main_menu, output_dir, initial_options) or {'action': 'quit'}
    except curses.error as exc:
        raise RuntimeError(f'Unable to initialize terminal: {exc}') from exc


def run_report_viewer(report_path):
    if curses is None:
        raise RuntimeError('the interactive TUI requires a terminal with curses support')
    report = load_report(report_path)
    rows = flatten_services(report)
    summary = report_summary(report)
    try:
        return curses.wrapper(_run_report_viewer, report_path, report, rows, summary)
    except curses.error as exc:
        raise RuntimeError(f'Unable to initialize terminal: {exc}') from exc


def run_tui(report_path):
    return run_report_viewer(report_path)


def _run_main_menu(stdscr, output_dir='reports', initial_options=None):
    _init_theme()
    selected = 0

    while True:
        height, width = stdscr.getmaxyx()
        if width < MIN_WIDTH or height < MIN_HEIGHT:
            stdscr.erase()
            msg = f'Terminal too small: {width}x{height}  |  minimum {MIN_WIDTH}x{MIN_HEIGHT}'
            _safe_addnstr(stdscr, max(0, height//2), 1, msg, max(1, width-2), _color_attr('error'))
            _safe_addnstr(stdscr, max(0, height//2)+1, 1,
                          'Resize the terminal or press q to quit.',
                          max(1, width-2), _color_attr('muted'))
            stdscr.refresh()
            if stdscr.getch() in (ord('q'), ord('Q')):
                return
            continue

        stdscr.erase()
        _draw_logo(stdscr, 0, width, compact=width < 86)
        status_y = 7 if width >= 86 else 4
        _draw_status_bar(stdscr, status_y, 1, width-2, 'ready', 'SCAN / AUDIT')
        panel_y = status_y + 2
        panel_h = max(8, height-panel_y-3)
        _box(stdscr, panel_y, 2, panel_h, width-4, 'BLACKSCAN // MAIN')

        items = list(MAIN_MENU)
        icons = ('>','#','*','@','+','?','x')
        for i, item in enumerate(items):
            y = panel_y + 2 + i
            attr = _color_attr('selection') | curses.A_BOLD if i == selected else _color_attr('text')
            marker = '>>' if i == selected else '  '
            line = f'{marker} {icons[i]}  {i+1:02d}  {item}'
            _safe_addnstr(stdscr, y, 5, line, max(1, width-10), attr)

        _safe_addnstr(stdscr, panel_y+panel_h-3, 5,
                      'Authorized reconnaissance interface',
                      max(1, width-10), _color_attr('muted'))
        _draw_footer(stdscr, height-1, 0, width)
        stdscr.refresh()

        key = stdscr.getch()
        if key in (curses.KEY_UP, ord('k')):
            selected = (selected-1) % len(MAIN_MENU)
            continue
        if key in (curses.KEY_DOWN, ord('j')):
            selected = (selected+1) % len(MAIN_MENU)
            continue
        if key in (10, 13, curses.KEY_ENTER):
            choice = selected + 1
        elif ord('1') <= key <= ord('7'):
            choice = key - ord('0')
            selected = choice - 1
        elif key in (ord('q'), ord('Q'), 27):
            return
        else:
            continue

        try:
            if choice == 1:
                result = _run_scan_form(stdscr, output_dir, initial_options=initial_options)
                if result and result.get('action') == 'quit':
                    return
            elif choice == 2:
                result = _run_profiles_viewer(stdscr, output_dir)
                if result and result.get('action') == 'load_profile':
                    result = _run_scan_form(stdscr, output_dir, result['profile'], initial_options=initial_options)
                if result and result.get('action') == 'quit':
                    return
            elif choice == 3:
                _run_payloads_viewer(stdscr)
            elif choice == 4:
                _open_report_inside_tui(stdscr, find_latest_report(output_dir))
            elif choice == 5:
                report = _prompt(stdscr, 'Report JSON path')
                if report and report not in {'0', '00'}:
                    _open_report_inside_tui(stdscr, report)
            elif choice == 6:
                _run_external_tools_viewer(stdscr)
            elif choice == 7:
                return
        except (OSError, ValueError, RuntimeError) as exc:
            _draw_message(stdscr, height - 2, 2, str(exc), width - 4, is_error=True)
            stdscr.refresh()
            stdscr.getch()
        finally:
            stdscr.timeout(-1)


def _run_scan_form(stdscr, output_dir, target_profile=None, initial_options=None):
    _init_theme()
    form = default_scan_form(output_dir)
    for key, value in (initial_options or {}).items():
        if key in form and value is not None:
            form[key] = str(value) if isinstance(form[key], str) else value
    if target_profile:
        apply_target_profile(form, target_profile)
    fields = [field for field in form if field != 'loaded_profile' and not field.startswith('vps_') and field not in {'execution_mode', 'socks_proxy'}]
    message = ''

    while True:
        height, width = stdscr.getmaxyx()
        stdscr.erase()
        _draw_compact_logo(stdscr, 1, 2, width - 4)
        _draw_section_title(stdscr, 4, 2, 'CONFIGURE SCAN', width - 4)
        _safe_addnstr(stdscr, 5, 2, f"Mode: {form['execution_mode']} | [95] connection settings", width - 4, _color_attr('muted'))
        if form.get('loaded_profile'):
            _safe_addnstr(stdscr, 6, 2, f'[loaded profile: {form["loaded_profile"]}]', width - 4, _color_attr('accent'))
        if message:
            _draw_message(stdscr, 7, 2, message, width - 4, is_error=True)

        start_y = 8
        two_columns = width >= 72
        column_width = (width - 10) // 2 if two_columns else width - 8
        rows_per_column = (len(fields) + 1) // 2 if two_columns else len(fields)
        for field_index, field in enumerate(fields):
            column = field_index // rows_per_column if two_columns else 0
            row = field_index % rows_per_column
            y = start_y + row
            x = 4 + (column * (column_width + 2))
            if y >= height - 5:
                break
            field_number = field_index + 1
            value = _field_display_value(field, form[field])
            label = field.replace('_', ' ').title()
            attr = _field_attr(field, form[field])
            _draw_numbered_row(stdscr, y, x, f'{field_number:02}', f'{label:18} {value}', column_width, attr)

        command_y = min(height - 4, start_y + rows_per_column + 1)
        _draw_numbered_row(stdscr, command_y, 4, '95/97', 'Connection settings / Load profile', width - 8, _color_attr('text'))
        _draw_numbered_row(stdscr, command_y + 1, 4, '98', 'Start scan', width - 8, _color_attr('text', curses.A_BOLD))
        _draw_numbered_row(stdscr, command_y + 2, 4, '99', 'Cycle scan type', width - 8, _color_attr('text'))
        _draw_numbered_row(stdscr, command_y + 3, 4, '00', 'Back', width - 8, _color_attr('text'))
        stdscr.refresh()

        choice_text = _prompt(stdscr, 'Choice')
        if choice_text.lower() in {'q', 'quit', 'exit'}:
            return {'action': 'quit'}
        if choice_text.lower() in {'b', 'back'} or choice_text in {'0', '00'}:
            return {'action': 'back'}
        if choice_text == '95':
            _edit_connection_settings(stdscr, form)
            message = ''
            continue
        if choice_text == '97':
            profiles = load_target_profiles()
            loaded = _choose_target_profile(stdscr, profiles, 'LOAD PROFILE')
            if loaded:
                apply_target_profile(form, loaded)
                message = ''
            else:
                message = ''
            continue
        if choice_text == '99':
            form['profile'] = _next_profile(form['profile'])
            message = ''
            continue
        if choice_text == '98':
            errors = validate_scan_form(form)
            if errors:
                message = '; '.join(errors[:3])
                continue
            result = _run_scan_session(stdscr, build_scan_options(form))
            if result.get('action') != 'back':
                return result
            message = ''
            continue
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


def _edit_connection_settings(stdscr, form):
    fields = ['execution_mode', 'proxy', 'socks_proxy'] + [key for key in form if key.startswith('vps_')]
    page = 0
    while True:
        height, width = stdscr.getmaxyx()
        size = max(1, height - 9)
        pages = max(1, (len(fields) + size - 1) // size)
        page = min(page, pages - 1)
        stdscr.erase()
        _draw_section_title(stdscr, 1, 2, 'CONNECTION SETTINGS', width - 4)
        _safe_addnstr(stdscr, 3, 2, 'Select a field; mode cycles local / proxy / vps.', width - 4)
        for index in range(page * size, min(len(fields), (page + 1) * size)):
            key = fields[index]
            value = _field_display_value(key, form.get(key, '')) or '<default>'
            _draw_numbered_row(stdscr, 5 + index - page * size, 2, str(index + 1),
                               f'{key}: {value}', width - 4, _color_attr('text'))
        _safe_addnstr(stdscr, height - 3, 2, f'Page {page + 1}/{pages} | n/p page | 0 back', width - 4)
        stdscr.refresh()
        choice = _prompt(stdscr, 'Choice')
        if choice.lower() in {'0', '00', 'q', 'back', 'b'}:
            return
        if choice.lower() in {'n', 'p'}:
            page = (page + (1 if choice.lower() == 'n' else -1)) % pages
        elif choice.isdigit() and 1 <= int(choice) <= len(fields):
            key = fields[int(choice) - 1]
            if key == 'execution_mode':
                modes = ('local', 'proxy', 'vps')
                current = form.get(key, 'local')
                form[key] = modes[(modes.index(current) + 1) % 3] if current in modes else 'local'
            else:
                form[key] = _prompt_clearable(stdscr, key, form.get(key, ''))


def _open_report_inside_tui(stdscr, report_path):
    report = load_report(report_path)
    rows = flatten_services(report)
    summary = report_summary(report)
    _run_report_viewer(stdscr, report_path, report, rows, summary)


def _run_payloads_viewer(stdscr):
    _init_theme()
    message = ''
    while True:
        payloads = WordlistManager.list_wordlists()
        height, width = stdscr.getmaxyx()
        stdscr.erase()
        _draw_compact_logo(stdscr, 1, 2, width - 4)
        _draw_section_title(stdscr, 4, 2, 'PAYLOADS', width - 4)
        if message:
            _draw_message(stdscr, 5, 2, message, width - 4, is_error=message.startswith('ERROR:'))

        y = 7
        _draw_numbered_choice(stdscr, y, 4, 1, 'VIEW PAYLOAD', width - 8)
        _draw_numbered_choice(stdscr, y + 1, 4, 2, 'ADD PAYLOAD', width - 8)
        _draw_numbered_choice(stdscr, y + 2, 4, 3, 'DELETE PAYLOAD', width - 8)
        _draw_numbered_row(stdscr, y + 3, 4, '0', 'Back', width - 8, _color_attr('text', curses.A_BOLD))

        list_y = y + 5
        _draw_section_title(stdscr, list_y, 2, 'AVAILABLE PAYLOADS', width - 4)
        if not payloads:
            _safe_addnstr(stdscr, list_y + 1, 4, 'No payloads available', width - 8, _color_attr('muted'))
        for index, payload in enumerate(payloads[:max(0, height - list_y - 3)], start=1):
            sources = ','.join(payload.get('sources', []))
            line = f'{payload["name"]} -> {payload.get("count", 0)} entries [{sources}]'
            _draw_numbered_row(stdscr, list_y + index, 4, f'{index:02}', line, width - 8, _color_attr('text'))

        _safe_addnstr(stdscr, height - 2, 2, 'Type a number and press Enter. 0 goes back.', width - 4, _color_attr('muted'))
        stdscr.refresh()
        choice_text = _prompt(stdscr, 'Choice')
        if choice_text in {'0', '00'} or choice_text.lower() in {'q', 'quit', 'exit', 'b', 'back'}:
            return {'action': 'back'}
        if choice_text == '1':
            _view_payload(stdscr, payloads)
            message = ''
        elif choice_text == '2':
            message = _add_payload(stdscr)
        elif choice_text == '3':
            message = _delete_payload(stdscr, payloads)
        else:
            message = 'ERROR: Invalid choice'


def _add_payload(stdscr):
    name = _prompt(stdscr, 'Payload name')
    if name in {'0', '00'} or name.lower() in {'b', 'back'}:
        return ''
    lines_text = _prompt(stdscr, 'Entries separated by comma')
    if lines_text in {'0', '00'} or lines_text.lower() in {'b', 'back'}:
        return ''
    entries = [entry.strip() for entry in lines_text.split(',') if entry.strip()]
    try:
        path = WordlistManager.save_wordlist(name, entries)
    except ValueError as exc:
        return f'ERROR: {exc}'
    return f'Saved payload: {path.stem}'


def _delete_payload(stdscr, payloads):
    selected = _choose_payload_index(stdscr, payloads, 'DELETE PAYLOAD')
    if selected is None:
        return ''
    payload = payloads[selected]
    if not payload.get('user_path') and not payload.get('drop_path'):
        return 'ERROR: Built-in payloads cannot be deleted'
    if WordlistManager.delete_wordlist(str(payload['name'])):
        return f'Deleted payload: {payload["name"]}'
    return 'ERROR: Payload not found'


def _view_payload(stdscr, payloads):
    selected = _choose_payload_index(stdscr, payloads, 'VIEW PAYLOAD')
    if selected is None:
        return
    payload = payloads[selected]
    entries = WordlistManager.get_wordlist(str(payload['name']))
    offset = 0
    while True:
        height, width = stdscr.getmaxyx()
        visible = max(1, height - 9)
        stdscr.erase()
        _draw_compact_logo(stdscr, 1, 2, width - 4)
        _draw_section_title(stdscr, 4, 2, f'PAYLOAD {payload["name"]}', width - 4)
        if not entries:
            _safe_addnstr(stdscr, 7, 4, 'No entries', width - 8, _color_attr('muted'))
        for index, entry in enumerate(entries[offset:offset + visible], start=1):
            _draw_numbered_row(stdscr, 6 + index, 4, f'{offset + index:02}', entry, width - 8, _color_attr('text'))
        _safe_addnstr(stdscr, height - 2, 2, 'n next, p previous, 0 back.', width - 4, _color_attr('muted'))
        stdscr.refresh()
        choice_text = _prompt(stdscr, 'Choice')
        if choice_text in {'0', '00'} or choice_text.lower() in {'q', 'quit', 'exit', 'b', 'back'}:
            return
        if choice_text.lower() == 'n':
            offset = min(max(0, len(entries) - visible), offset + visible)
        elif choice_text.lower() == 'p':
            offset = max(0, offset - visible)


def _choose_payload_index(stdscr, payloads, title):
    message = ''
    while True:
        height, width = stdscr.getmaxyx()
        stdscr.erase()
        _draw_compact_logo(stdscr, 1, 2, width - 4)
        _draw_section_title(stdscr, 4, 2, title, width - 4)
        if message:
            _draw_message(stdscr, 5, 2, message, width - 4, is_error=True)
        if not payloads:
            _safe_addnstr(stdscr, 7, 4, 'No payloads available', width - 8, _color_attr('muted'))
        for index, payload in enumerate(payloads[:max(0, height - 10)], start=1):
            sources = ','.join(payload.get('sources', []))
            line = f'{payload["name"]} -> {payload.get("count", 0)} entries [{sources}]'
            _draw_numbered_row(stdscr, 6 + index, 4, f'{index:02}', line, width - 8, _color_attr('text'))
        _safe_addnstr(stdscr, height - 2, 2, 'Type payload number. 0 goes back.', width - 4, _color_attr('muted'))
        stdscr.refresh()
        choice_text = _prompt(stdscr, 'Choice')
        if choice_text in {'0', '00'} or choice_text.lower() in {'q', 'quit', 'exit', 'b', 'back'}:
            return None
        if choice_text.isdigit() and 1 <= int(choice_text) <= len(payloads):
            return int(choice_text) - 1
        message = 'Invalid payload number'


def _run_profiles_viewer(stdscr, output_dir):
    _init_theme()
    message = ''
    while True:
        profiles = load_target_profiles()
        height, width = stdscr.getmaxyx()
        stdscr.erase()
        _draw_compact_logo(stdscr, 1, 2, width - 4)
        _draw_section_title(stdscr, 4, 2, 'PROFILES', width - 4)
        if message:
            _draw_message(stdscr, 5, 2, message, width - 4, is_error=message.startswith('ERROR:'))

        y = 7
        _draw_numbered_choice(stdscr, y, 4, 1, 'CREATE PROFILE', width - 8)
        _draw_numbered_choice(stdscr, y + 1, 4, 2, 'EDIT PROFILE', width - 8)
        _draw_numbered_choice(stdscr, y + 2, 4, 3, 'LOAD PROFILE FOR SCAN', width - 8)
        _draw_numbered_choice(stdscr, y + 3, 4, 4, 'DELETE PROFILE', width - 8)
        _draw_numbered_row(stdscr, y + 4, 4, '0', 'Back', width - 8, _color_attr('text', curses.A_BOLD))

        list_y = y + 6
        _draw_section_title(stdscr, list_y, 2, 'SAVED PROFILES', width - 4)
        if not profiles:
            _safe_addnstr(stdscr, list_y + 1, 4, 'No saved profiles', width - 8, _color_attr('muted'))
        for index, profile in enumerate(profiles[:max(0, height - list_y - 3)], start=1):
            _draw_numbered_row(
                stdscr,
                list_y + index,
                4,
                f'{index:02}',
                f'{profile["name"]} -> {profile_display_target(profile)}',
                width - 8,
                _color_attr('text'),
            )

        _safe_addnstr(stdscr, height - 2, 2, 'Type a number and press Enter. 0 goes back.', width - 4, _color_attr('muted'))
        stdscr.refresh()
        choice_text = _prompt(stdscr, 'Choice')
        if choice_text in {'0', '00'} or choice_text.lower() in {'q', 'quit', 'exit', 'b', 'back'}:
            return {'action': 'back'}
        if choice_text == '1':
            message = _create_target_profile(stdscr)
        elif choice_text == '2':
            message = _edit_target_profile(stdscr, profiles)
        elif choice_text == '3':
            loaded = _choose_target_profile(stdscr, profiles, 'LOAD PROFILE')
            if loaded:
                return {'action': 'load_profile', 'profile': loaded}
            message = ''
        elif choice_text == '4':
            selected = _choose_target_profile_index(stdscr, profiles, 'DELETE PROFILE')
            if selected is not None:
                deleted = profiles[selected]
                remaining = list(profiles)
                del remaining[selected]
                save_target_profiles(remaining)
                message = f'Deleted profile: {deleted["name"]}'
            else:
                message = ''
        else:
            message = 'ERROR: Invalid choice'


def _create_target_profile(stdscr):
    name = _prompt(stdscr, 'Profile name')
    if name in {'0', '00'} or name.lower() in {'b', 'back'}:
        return ''
    ip = _prompt(stdscr, 'IP, host, or CIDR')
    if ip in {'0', '00'} or ip.lower() in {'b', 'back'}:
        return ''
    url = _prompt(stdscr, 'HTTPS URL')
    if url in {'0', '00'} or url.lower() in {'b', 'back'}:
        return ''
    profile = normalize_target_profile({'name': name, 'ip': ip, 'url': url})
    errors = validate_target_profile(profile)
    if errors:
        return f'ERROR: {errors[0]}'
    profiles = [item for item in load_target_profiles() if item['name'] != profile['name']]
    profiles.append(profile)
    save_target_profiles(sorted(profiles, key=lambda item: item['name'].lower()))
    return f'Saved profile: {profile["name"]}'


def _edit_target_profile(stdscr, profiles):
    selected = _choose_target_profile_index(stdscr, profiles, 'EDIT PROFILE')
    if selected is None:
        return ''
    current = profiles[selected]
    name = _prompt(stdscr, 'Profile name', current['name'])
    if name in {'0', '00'} or name.lower() in {'b', 'back'}:
        return ''
    ip = _prompt_clearable(stdscr, 'IP, host, or CIDR', current['ip'])
    if ip is None:
        return ''
    url = _prompt_clearable(stdscr, 'HTTPS URL', current['url'])
    if url is None:
        return ''
    updated = normalize_target_profile({'name': name, 'ip': ip, 'url': url})
    errors = validate_target_profile(updated)
    if errors:
        return f'ERROR: {errors[0]}'
    remaining = [profile for index, profile in enumerate(profiles) if index != selected and profile['name'] != updated['name']]
    remaining.append(updated)
    save_target_profiles(sorted(remaining, key=lambda item: item['name'].lower()))
    return f'Updated profile: {updated["name"]}'


def _prompt_clearable(stdscr, label, current=''):
    value = _prompt(stdscr, f'{label} (- clears)', current)
    if value in {'0', '00'} or value.lower() in {'b', 'back'}:
        return None
    if value == '-':
        return ''
    return value


def _choose_target_profile(stdscr, profiles, title):
    selected = _choose_target_profile_index(stdscr, profiles, title)
    if selected is None:
        return None
    return profiles[selected]


def _choose_target_profile_index(stdscr, profiles, title):
    message = ''
    while True:
        height, width = stdscr.getmaxyx()
        stdscr.erase()
        _draw_compact_logo(stdscr, 1, 2, width - 4)
        _draw_section_title(stdscr, 4, 2, title, width - 4)
        if message:
            _draw_message(stdscr, 5, 2, message, width - 4, is_error=True)
        if not profiles:
            _safe_addnstr(stdscr, 7, 4, 'No saved profiles', width - 8, _color_attr('muted'))
        for index, profile in enumerate(profiles[:max(0, height - 10)], start=1):
            _draw_numbered_row(
                stdscr,
                6 + index,
                4,
                f'{index:02}',
                f'{profile["name"]} -> {profile_display_target(profile)}',
                width - 8,
                _color_attr('text'),
            )
        _safe_addnstr(stdscr, height - 2, 2, 'Type profile number. 0 goes back.', width - 4, _color_attr('muted'))
        stdscr.refresh()
        choice_text = _prompt(stdscr, 'Choice')
        if choice_text in {'0', '00'} or choice_text.lower() in {'q', 'quit', 'exit', 'b', 'back'}:
            return None
        if choice_text.isdigit() and 1 <= int(choice_text) <= len(profiles):
            return int(choice_text) - 1
        message = 'Invalid profile number'


def _run_external_tools_viewer(stdscr):
    _init_theme()
    tools = external_tool_inventory()
    while True:
        height, width = stdscr.getmaxyx()
        stdscr.erase()
        _draw_compact_logo(stdscr, 1, 2, width - 4)
        _draw_section_title(stdscr, 4, 2, 'EXTERNAL TOOLS', width - 4)
        y = 6
        for name in EXTERNAL_TOOLS:
            if y >= height - 3:
                break
            state = 'available' if name in tools['available'] else 'missing'
            attr = _color_attr('accent' if state == 'available' else 'error', curses.A_BOLD)
            _safe_addnstr(stdscr, y, 4, f'{name:10} {state}', width - 8, attr)
            y += 1
        _safe_addnstr(stdscr, height - 2, 2, 'Type 0 and press Enter to go back.', width - 4, _color_attr('muted'))
        stdscr.refresh()
        choice_text = _prompt(stdscr, 'Choice')
        if choice_text in {'0', '00'} or choice_text.lower() in {'q', 'quit', 'exit', 'b', 'back'}:
            return {'action': 'back'}


def _run_scan_session(stdscr, options):
    _init_theme()
    events = queue.Queue()
    progress = {'percent': 0, 'message': 'Waiting'}
    logs = []
    result = {'done': False, 'reports': None, 'error': None}

    def on_progress(percent, message=''):
        events.put(('progress', percent, message))

    def on_log(message):
        for line in _strip_ansi(str(message)).splitlines() or ['']:
            events.put(('log', line, None))

    def worker():
        try:
            from network_scanner.vps_proxy.main import Orchestrator
            runner = Orchestrator(options.get('execution_mode', 'local'), options,
                                  progress_callback=on_progress, log_callback=on_log)
            outcome = runner.run(options['target'])
            result['reports'] = outcome['reports']
            events.put(('done', outcome['status'], None))
        except Exception as exc:
            events.put(('error', str(exc), None))

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    stdscr.nodelay(True)

    try:
        while True:
            while True:
                try:
                    event = events.get_nowait()
                except queue.Empty:
                    break
                kind = event[0]
                value = event[1] if len(event) > 1 else None
                message = event[2] if len(event) > 2 else None
                if kind == 'progress':
                    progress['percent'] = value
                    progress['message'] = message
                elif kind == 'log':
                    logs.append(value)
                    logs[:] = logs[-500:]
                elif kind == 'done':
                    result['done'] = True
                    progress['percent'] = 100
                    progress['message'] = f'Scan {value}'
                elif kind == 'error':
                    result['done'] = True
                    result['error'] = value
                    progress['percent'] = 100
                    progress['message'] = 'Scan failed'
                    logs.append(f'ERROR: {value}')

            height, width = stdscr.getmaxyx()
            stdscr.erase()
            _draw_scan_layout(stdscr, options, progress, logs, result, width, height)
            stdscr.refresh()

            if result['done']:
                stdscr.nodelay(False)
                choice_text = _prompt(stdscr, 'Choice')
                if choice_text in {'0', '00'} or choice_text.lower() in {'b', 'back'}:
                    return {'action': 'back'}
                if choice_text == '5' or choice_text.lower() in {'q', 'quit', 'exit'}:
                    return {'action': 'quit'}
                stdscr.nodelay(True)
                logs.append('Type 0 to go back or 5 to quit.')
            time.sleep(0.1)
    finally:
        stdscr.nodelay(False)


def _run_report_viewer(stdscr, report_path, report, rows, summary):
    curses.curs_set(0)
    stdscr.keypad(True)
    stdscr.timeout(120)
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
            selected = max(0, min(len(rows) - 1, selected + visible_height))
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
    if field in {'proxy', 'socks_proxy'} and value:
        from network_scanner.scanner.parser import mask_proxy_url
        try:
            return mask_proxy_url(value)
        except ValueError:
            return '<invalid proxy URL>'
    if field == 'ports' and not value:
        return '<profile defaults>'
    if field in {'proxy', 'compare_report'} and not value:
        return '<none>'
    return str(value)


def _prompt(stdscr, label, current=''):
    height, width = stdscr.getmaxyx()
    prompt = f'{label}: '
    stdscr.timeout(-1)
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
    value = clean_input(raw.decode(errors='ignore')).strip()
    return value if value else current


def _draw_header(stdscr, report_path, summary, width):
    title = f"BLACKSCAN // REPORT VIEWER // {Path(clean_input(report_path)).name}"
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


def _draw_scan_layout(stdscr, options, progress, logs, result, width, height):
    split_x = max(38, min(width // 2, 62))
    right_x = min(width - 1, split_x + 2)
    left_width = max(1, split_x - 4)
    right_width = max(1, width - right_x - 1)

    _draw_compact_logo(stdscr, 1, 2, left_width)
    _draw_section_title(stdscr, 4, 2, 'SCAN CONTROLS', left_width)
    left_lines = [
        f"Target: {options['target']}",
        f"Profile: {options['profile']}",
        f"Execution: {options.get('execution_mode', 'local')}",
        f"Ports: {options['ports'] or '<profile defaults>'}",
        f"Output: {options['output_dir']}",
        '',
        '[0] Back to menu when finished',
        '[5] Quit when finished',
    ]
    for index, line in enumerate(left_lines, start=6):
        if index >= height - 2:
            break
        attr = _color_attr('header' if line.startswith('[') else 'text')
        _safe_addnstr(stdscr, index, 4, line, left_width, attr)

    _draw_vertical_rule(stdscr, split_x, height)
    _draw_section_title(stdscr, 1, right_x, 'SCAN PROGRESS', right_width)
    percent = int(progress['percent'])
    _safe_addnstr(stdscr, 3, right_x, f'{percent:3}% {progress["message"]}', right_width, _color_attr('accent', curses.A_BOLD))
    _draw_progress_bar(stdscr, 4, right_x, right_width, percent)
    _draw_section_title(stdscr, 6, right_x, 'OUTPUT', right_width)

    output_height = max(1, height - 9)
    for index, line in enumerate(logs[-output_height:], start=8):
        attr = _color_attr('error', curses.A_BOLD) if 'ERROR:' in line or '[!]' in line else _color_attr('text')
        _safe_addnstr(stdscr, index, right_x, line, right_width, attr)

    if result['done']:
        status = 'Done. Type 0 to go back or 5 to quit.'
        if result['error']:
            status = 'Failed. Type 0 to go back or 5 to quit.'
        _safe_addnstr(stdscr, height - 2, right_x, status, right_width, _color_attr('error' if result['error'] else 'accent', curses.A_BOLD))


def _draw_progress_bar(stdscr, y, x, width, percent):
    bar_width = max(10, min(40, width - 8))
    filled = int(bar_width * max(0, min(100, percent)) / 100)
    bar = '[' + ('=' * filled).ljust(bar_width) + ']'
    _safe_addnstr(stdscr, y, x, bar, width, _color_attr('header', curses.A_BOLD))


def _draw_vertical_rule(stdscr, x, height):
    for y in range(1, max(1, height - 1)):
        _safe_addnstr(stdscr, y, x, '|', 1, _color_attr('muted'))


def _init_theme():
    if not curses.has_colors():
        return
    try:
        curses.start_color()
        curses.use_default_colors()
        violet = _violet_color()
        curses.init_pair(THEME['header'], violet, -1)
        curses.init_pair(THEME['accent'], curses.COLOR_CYAN, -1)
        curses.init_pair(THEME['selection'], curses.COLOR_CYAN, violet)
        curses.init_pair(THEME['error'], curses.COLOR_RED, -1)
        curses.init_pair(THEME['muted'], violet, -1)
        curses.init_pair(THEME['risk_medium'], curses.COLOR_CYAN, -1)
        curses.init_pair(THEME['text'], curses.COLOR_WHITE, -1)
    except curses.error:
        pass


def _violet_color():
    try:
        if curses.COLORS > VIOLET_COLOR and curses.can_change_color():
            curses.init_color(VIOLET_COLOR, 840, 200, 1000)
            return VIOLET_COLOR
    except curses.error:
        pass
    return curses.COLOR_MAGENTA


def _color_attr(name, extra=0):
    if curses.has_colors():
        try:
            return curses.color_pair(THEME[name]) | extra
        except curses.error:
            return extra
    return extra


def _draw_section_title(stdscr, y, x, title, width):
    if width <= 0:
        return y
    label = f' {title.upper()} '
    _safe_addnstr(stdscr, y, x, label, min(width, len(label)), _color_attr('header') | curses.A_BOLD)
    if width > len(label):
        _safe_addnstr(stdscr, y, x + len(label), BOX_CHARS['h'] * (width - len(label)),
                      width - len(label), _color_attr('muted'))
    return y + 1


def _box(stdscr, y, x, height, width, title=None, attr=0):
    if height < 2 or width < 2:
        return
    chars = BOX_CHARS
    try:
        stdscr.addstr(y, x, chars['tl'], attr)
    except Exception:
        chars = ASCII_BOX_CHARS
    _safe_addnstr(stdscr, y, x,
                  chars['tl'] + chars['h'] * max(0, width-2) + chars['tr'],
                  width, attr)
    for row in range(y + 1, y + height - 1):
        _safe_addnstr(stdscr, row, x, chars['v'], 1, attr)
        _safe_addnstr(stdscr, row, x + width - 1, chars['v'], 1, attr)
    _safe_addnstr(stdscr, y + height - 1, x,
                  chars['bl'] + chars['h'] * max(0, width-2) + chars['br'],
                  width, attr)
    if title and width > len(title) + 6:
        _safe_addnstr(stdscr, y, x + 2, f' {title} ', len(title) + 2,
                      _color_attr('header') | curses.A_BOLD)


def _draw_status_bar(stdscr, y, x, width, status='ready', right_text=''):
    label = STATUS_LABELS.get(status, str(status).upper())
    attr = _color_attr('error') | curses.A_BOLD if status == 'failed' else (
        _color_attr('accent') | curses.A_BOLD if status == 'scanning' else _color_attr('header') | curses.A_BOLD
    )
    left = f' [{label}] '
    _safe_addnstr(stdscr, y, x, left, width, attr)
    if right_text:
        right = f' {right_text} '
        if len(right) < width - len(left):
            _safe_addnstr(stdscr, y, x + width - len(right), right, len(right), _color_attr('muted'))


def _draw_footer(stdscr, y, x, width, text='↑↓/jk Navigate   Enter Select   1-7 Quick Select   q Quit'):
    _safe_addnstr(stdscr, y, x, f' {text} '[:width].ljust(width), width, _color_attr('muted'))



def _draw_numbered_choice(stdscr, y, x, number, label, width):
    prefix = f'[{number}] '
    _safe_addnstr(stdscr, y, x, prefix, width, _color_attr('header', curses.A_BOLD))
    _safe_addnstr(stdscr, y, x + len(prefix), label, max(0, width - len(prefix)), _color_attr('text', curses.A_BOLD))


def _draw_numbered_row(stdscr, y, x, number, label, width, label_attr):
    prefix = f'[{number}] '
    _safe_addnstr(stdscr, y, x, prefix, width, _color_attr('header', curses.A_BOLD))
    _safe_addnstr(stdscr, y, x + len(prefix), label, max(0, width - len(prefix)), label_attr)


def _draw_logo(stdscr, y, width, compact=False):
    if compact or width < 86:
        return _draw_compact_logo(stdscr, y, 0, width)
    lines = [
        '██████╗ ██╗      █████╗  ██████╗██╗  ██╗███████╗ ██████╗ █████╗ ███╗   ██╗',
        '██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║',
        '██████╔╝██║     ███████║██║     █████╔╝ ███████╗██║     ███████║██╔██╗ ██║',
        '██╔══██╗██║     ██╔══██║██║     ██║ ██╔╝ ╚════██║██║     ██╔══██║██║╚██╗██║',
        '██████╔╝███████╗██║  ██║╚██████╗██║  ██╗███████║╚██████╗██║  ██║██║ ╚████║',
        '╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝',
    ]
    for i, line in enumerate(lines):
        _safe_addnstr(stdscr, y+i, max(0,(width-len(line))//2), line, width,
                      _color_attr('header') | curses.A_BOLD)
    sig = f'// {SIGNATURE} //'
    _safe_addnstr(stdscr, y+len(lines), max(0,(width-len(sig))//2), sig, width,
                  _color_attr('header') | curses.A_BOLD)
    return y+len(lines)+1


def _draw_compact_logo(stdscr, y, x, width):
    title = '<< BLACKSCAN // RECON INTERFACE >>'
    sig = f'[{SIGNATURE}]'
    _safe_addnstr(stdscr, y, x + max(0,(width-len(title))//2), title, width,
                  _color_attr('header') | curses.A_BOLD)
    _safe_addnstr(stdscr, y+1, x + max(0,(width-len(sig))//2), sig, width,
                  _color_attr('header') | curses.A_BOLD)
    return y+2


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
    if normalized.startswith(('- high', 'risk: high', '- critical', 'risk: critical')):
        return _color_attr('error', curses.A_BOLD)
    if normalized.endswith(':'):
        return _color_attr('accent', curses.A_BOLD)
    return _color_attr('muted')


def _strip_ansi(value):
    return clean_input(ANSI_RE.sub('', value))


def _safe_addnstr(stdscr, y, x, text, max_width, attr=0):
    text = clean_input(text)
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
