import ipaddress
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

SUPPORTED_TOOLS = (
    'nmap',
    'nuclei',
    'httpx',
    'subfinder',
    'dnsx',
    'whois',
    'dig',
    'ffuf',
    'feroxbuster',
    'naabu',
    'katana',
    'sherlock',
    'recon-ng',
)

VERSION_ARGS = {
    'nmap': ['nmap', '--version'],
    'nuclei': ['nuclei', '-version'],
    'httpx': ['httpx', '-version'],
    'subfinder': ['subfinder', '-version'],
    'dnsx': ['dnsx', '-version'],
    'dig': ['dig', '-v'],
    'ffuf': ['ffuf', '-V'],
    'feroxbuster': ['feroxbuster', '--version'],
    'naabu': ['naabu', '-version'],
    'katana': ['katana', '-version'],
    'sherlock': ['sherlock', '--version'],
    'recon-ng': ['recon-ng', '--version'],
}

ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')


def detect_external_tools():
    tools = {}
    for name in SUPPORTED_TOOLS:
        path = shutil.which(name)
        tools[name] = {
            'available': bool(path),
            'path': path or '',
            'version': get_tool_version(name) if path else '',
        }
    return tools


def get_tool_version(name):
    if name not in VERSION_ARGS:
        return ''
    try:
        result = subprocess.run(
            VERSION_ARGS[name],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, KeyError):
        return ''

    output = (result.stdout or result.stderr).strip().splitlines()
    for line in output:
        clean = ANSI_RE.sub('', line).strip()
        if clean and any(char.isdigit() for char in clean):
            return clean[:160]
    return ANSI_RE.sub('', output[0]).strip()[:160] if output else ''


def run_external_enrichment(target, hosts, services, timeout=2, proxy_url=None, log_callback=None):
    tools = detect_external_tools()
    result = {
        'enabled': True,
        'tools': tools,
        'pipeline': [],
        'summary': {
            'domains': [],
            'subdomains': [],
            'dns_records': [],
            'hosts': [],
            'ports': [],
            'urls': [],
            'endpoints': [],
            'paths': [],
            'findings': [],
            'technologies': [],
        },
        'domain': {},
        'network': {},
        'web': {},
        'osint': {},
        'notes': [],
    }
    domain = extract_domain_target(target)
    command_timeout = max(8, min(45, int(timeout) * 8))
    seed_hosts = unique_values(hosts)
    web_targets = unique_values(extract_web_targets(services))
    domains = [domain] if domain else []

    if domain:
        append_unique(result['summary']['domains'], domain)
    result['summary']['hosts'] = unique_values(seed_hosts)
    result['summary']['urls'] = unique_values(web_targets)

    whois_result = run_step(result, 'whois', ['whois', domain], tools, command_timeout, log_callback, skip_reason='' if domain else 'target is not a domain name')
    result['domain']['whois'] = whois_result

    dig_result = run_dig_pipeline(domain, tools, command_timeout, result, log_callback)
    result['domain']['dig'] = dig_result

    subfinder_result = run_step(result, 'subfinder', ['subfinder', '-d', domain, '-silent'], tools, command_timeout, log_callback, skip_reason='' if domain else 'target is not a domain name')
    result['domain']['subfinder'] = subfinder_result
    subdomains = parse_line_values(subfinder_result.get('output', '')) if subfinder_result.get('executed') else []
    extend_unique(result['summary']['subdomains'], subdomains)
    extend_unique(domains, subdomains)

    dns_targets = unique_values(domains or [domain])
    dnsx_result = run_list_step(result, 'dnsx', dns_targets, ['dnsx', '-l', '{input}', '-silent', '-a', '-aaaa'], tools, command_timeout, log_callback)
    result['domain']['dnsx'] = dnsx_result
    extend_unique(result['summary']['dns_records'], parse_line_values(dnsx_result.get('output', '')))

    network_targets = unique_values(seed_hosts + domains)
    naabu_result = run_list_step(result, 'naabu', network_targets, ['naabu', '-list', '{input}', '-silent'], tools, command_timeout, log_callback)
    result['network']['naabu'] = naabu_result
    ports = parse_host_ports(naabu_result.get('output', ''))
    extend_unique(result['summary']['ports'], ports)

    nmap_targets = unique_values(seed_hosts + [item.split(':', 1)[0] for item in ports if ':' in item])
    nmap_result = run_nmap_step(result, nmap_targets, tools, command_timeout, log_callback)
    result['network']['nmap'] = nmap_result

    httpx_targets = unique_values(web_targets + domains + seed_hosts + [item for item in nmap_targets if item])
    httpx_result = run_list_step(result, 'httpx', httpx_targets, ['httpx', '-l', '{input}', '-silent', '-json'], tools, command_timeout, log_callback, json_lines=True)
    result['web']['httpx'] = httpx_result
    httpx_urls = parse_httpx_urls(httpx_result)
    httpx_technologies = parse_httpx_technologies(httpx_result)
    extend_unique(result['summary']['urls'], httpx_urls)
    extend_unique(result['summary']['technologies'], httpx_technologies)

    web_urls = unique_values(result['summary']['urls'])
    result['web']['katana'] = run_web_map(result, 'katana', web_urls, tools, command_timeout, timeout, proxy_url, log_callback)
    for item in result['web']['katana'].values():
        extend_unique(result['summary']['endpoints'], parse_katana_endpoints(item))

    result['web']['ffuf'] = run_web_map(result, 'ffuf', web_urls, tools, command_timeout, timeout, proxy_url, log_callback)
    for item in result['web']['ffuf'].values():
        extend_unique(result['summary']['paths'], parse_ffuf_paths(item))

    result['web']['feroxbuster'] = run_web_map(result, 'feroxbuster', web_urls, tools, command_timeout, timeout, proxy_url, log_callback)
    for item in result['web']['feroxbuster'].values():
        extend_unique(result['summary']['paths'], parse_feroxbuster_paths(item))

    nuclei_result = run_list_step(result, 'nuclei', web_urls, ['nuclei', '-l', '{input}', '-jsonl', '-silent'], tools, command_timeout, log_callback, json_lines=True)
    result['web']['nuclei'] = nuclei_result
    extend_unique(result['summary']['findings'], parse_nuclei_findings(nuclei_result))

    sherlock_target = domain or extract_username_target(target)
    sherlock_result = run_step(result, 'sherlock', ['sherlock', sherlock_target, '--timeout', str(max(5, int(timeout)))], tools, command_timeout, log_callback, skip_reason='' if sherlock_target else 'target is not a domain or username-like value')
    result['osint']['sherlock'] = sherlock_result
    result['osint']['recon-ng'] = skipped('recon-ng', tools, 'interactive framework; detected but not auto-executed')
    append_pipeline(result, 'recon-ng', result['osint']['recon-ng'])
    normalize_summary(result['summary'])
    return result


def run_step(result, name, args, tools, timeout, log_callback=None, skip_reason=''):
    tool_name = name.split()[0]
    emit_tool_log(log_callback, name, 'starting')
    value = skipped(tool_name, tools, skip_reason) if skip_reason else run_tool(tool_name, args, tools, timeout)
    emit_tool_log(log_callback, name, value.get('status', 'unknown'))
    append_pipeline(result, name, value)
    return value


def run_list_step(result, name, values, args_template, tools, timeout, log_callback=None, json_output=False, json_lines=False):
    if not values:
        value = skipped(name, tools, 'no input targets')
        append_pipeline(result, name, value)
        emit_tool_log(log_callback, name, value.get('status', 'unknown'))
        return value
    path = write_temp_lines(values)
    try:
        args = [path if item == '{input}' else item for item in args_template]
        return run_step(result, name, args, tools, timeout, log_callback, '') if not json_output and not json_lines else run_json_step(result, name, args, tools, timeout, log_callback, json_output, json_lines)
    finally:
        Path(path).unlink(missing_ok=True)


def run_json_step(result, name, args, tools, timeout, log_callback=None, json_output=False, json_lines=False):
    emit_tool_log(log_callback, name, 'starting')
    value = run_tool(name, args, tools, timeout, json_output=json_output, json_lines=json_lines)
    emit_tool_log(log_callback, name, value.get('status', 'unknown'))
    append_pipeline(result, name, value)
    return value


def run_dig_pipeline(domain, tools, timeout, result, log_callback=None):
    if not domain:
        value = skipped('dig', tools, 'target is not a domain name')
        append_pipeline(result, 'dig', value)
        return value
    records = {}
    for record_type in ('A', 'AAAA', 'MX', 'NS', 'TXT'):
        records[record_type.lower()] = run_step(result, f'dig {record_type}', ['dig', '+short', domain, record_type], tools, timeout, log_callback)
    return records


def run_nmap_step(result, targets, tools, timeout, log_callback=None):
    if not targets:
        value = skipped('nmap', tools, 'no live hosts found')
        append_pipeline(result, 'nmap', value)
        return value
    args = ['nmap', '-sV', '-Pn', '--top-ports', '100', '-oX', '-', *targets[:20]]
    return run_step(result, 'nmap', args, tools, timeout, log_callback)


def run_web_map(result, name, urls, tools, command_timeout, timeout, proxy_url, log_callback=None):
    values = {}
    if not urls:
        value = skipped(name, tools, 'no HTTP or HTTPS services found')
        append_pipeline(result, name, value)
        return {'status': value}
    wordlist = write_web_wordlist()
    try:
        for url in urls[:10]:
            if name == 'katana':
                values[url] = run_json_step(result, name, ['katana', '-u', url, '-silent', '-json', '-d', '1'], tools, command_timeout, log_callback, json_lines=True)
            elif name == 'ffuf':
                values[url] = run_ffuf(url, wordlist, tools, command_timeout, timeout, proxy_url, result, log_callback)
            elif name == 'feroxbuster':
                values[url] = run_feroxbuster(url, wordlist, tools, command_timeout, timeout, result, log_callback)
    finally:
        Path(wordlist).unlink(missing_ok=True)
    return values


def run_ffuf(url, wordlist, tools, command_timeout, timeout, proxy_url=None, result=None, log_callback=None):
    target_url = url.rstrip('/') + '/FUZZ'
    args = ['ffuf', '-u', target_url, '-w', wordlist, '-of', 'json', '-s', '-t', '10', '-timeout', str(max(3, int(timeout)))]
    if proxy_url:
        args.extend(['-x', proxy_url])
    if result is None:
        return run_tool('ffuf', args, tools, command_timeout, json_output=True)
    return run_json_step(result, 'ffuf', args, tools, command_timeout, log_callback, json_output=True)


def run_feroxbuster(url, wordlist, tools, command_timeout, timeout, result=None, log_callback=None):
    args = [
        'feroxbuster',
        '-u',
        url,
        '-w',
        wordlist,
        '--json',
        '--silent',
        '--depth',
        '1',
        '--time-limit',
        f'{max(8, int(timeout) * 8)}s',
    ]
    if result is None:
        return run_tool('feroxbuster', args, tools, command_timeout, json_lines=True)
    return run_json_step(result, 'feroxbuster', args, tools, command_timeout, log_callback, json_lines=True)


def run_tool(name, args, tools, timeout, json_output=False, json_lines=False):
    if not tools.get(name, {}).get('available'):
        return skipped(name, tools, 'tool is not installed')
    args = clean_args(args)
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        return {
            'available': True,
            'executed': True,
            'status': 'timeout',
            'returncode': None,
            'output': trim_output((exc.stdout or '') + '\n' + (exc.stderr or '')),
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            'available': True,
            'executed': False,
            'status': 'error',
            'returncode': None,
            'output': str(exc)[:400],
        }

    output = (completed.stdout or completed.stderr or '').strip()
    parsed = parse_json_output(output, json_lines)
    return {
        'available': True,
        'executed': True,
        'status': 'ok' if completed.returncode == 0 else 'error',
        'returncode': completed.returncode,
        'output': trim_output(output),
        'json': parsed if json_output or json_lines else None,
    }


def skipped(name, tools, reason):
    return {
        'available': bool(tools.get(name, {}).get('available')),
        'executed': False,
        'status': 'skipped',
        'reason': reason,
    }


def parse_json_output(output, json_lines=False):
    output = clean_output(output)
    if not output:
        return None
    if json_lines:
        values = []
        for line in output.splitlines():
            try:
                values.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return values
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return None


def trim_output(value, limit=12000):
    value = clean_output(value).strip()
    return value[:limit] if len(value) > limit else value


def clean_args(args):
    return [clean_arg(arg) for arg in args]


def clean_arg(value):
    return ''.join(char for char in str(value).replace('\x00', '') if ord(char) >= 32)


def clean_output(value):
    return ''.join(char for char in str(value).replace('\x00', '') if char in {'\n', '\r', '\t'} or ord(char) >= 32)


def emit_tool_log(log_callback, name, status):
    if log_callback:
        log_callback(f'    [external] {name}: {status}')


def append_pipeline(result, name, value):
    result['pipeline'].append({
        'tool': name,
        'status': value.get('status', 'unknown'),
        'executed': bool(value.get('executed')),
        'available': bool(value.get('available')),
        'reason': value.get('reason', ''),
    })


def unique_values(values):
    output = []
    for value in values or []:
        text = clean_arg(value).strip()
        if text and text not in output:
            output.append(text)
    return output


def append_unique(values, value):
    text = clean_arg(value).strip()
    if text and text not in values:
        values.append(text)


def extend_unique(values, incoming):
    for value in incoming or []:
        append_unique(values, value)


def write_temp_lines(values):
    handle = tempfile.NamedTemporaryFile('w', encoding='utf-8', delete=False)
    try:
        for value in unique_values(values):
            handle.write(value)
            handle.write('\n')
        return handle.name
    finally:
        handle.close()


def parse_line_values(output):
    return unique_values(line.strip() for line in clean_output(output).splitlines() if line.strip())


def parse_host_ports(output):
    values = []
    for line in parse_line_values(output):
        match = re.search(r'([A-Za-z0-9_.:-]+):([0-9]{1,5})', line)
        if not match:
            continue
        host = match.group(1).strip('[]')
        port = int(match.group(2))
        if 1 <= port <= 65535:
            append_unique(values, f'{host}:{port}')
    return values


def parse_httpx_urls(result):
    urls = []
    for item in result.get('json') or []:
        if isinstance(item, dict):
            append_unique(urls, item.get('url', ''))
    if not urls:
        for line in parse_line_values(result.get('output', '')):
            if line.startswith(('http://', 'https://')):
                append_unique(urls, line.split()[0])
    return urls


def parse_httpx_technologies(result):
    values = []
    for item in result.get('json') or []:
        if not isinstance(item, dict):
            continue
        technologies = item.get('tech') or item.get('technologies') or []
        if isinstance(technologies, str):
            append_unique(values, technologies)
        else:
            extend_unique(values, technologies)
    return values


def parse_katana_endpoints(result):
    values = []
    for item in result.get('json') or []:
        if isinstance(item, dict):
            append_unique(values, item.get('request', {}).get('endpoint', '') if isinstance(item.get('request'), dict) else '')
            append_unique(values, item.get('url', ''))
    if not values:
        for line in parse_line_values(result.get('output', '')):
            if line.startswith(('http://', 'https://')):
                append_unique(values, line)
    return values


def parse_ffuf_paths(result):
    values = []
    data = result.get('json')
    entries = data.get('results', []) if isinstance(data, dict) else []
    for item in entries:
        if isinstance(item, dict):
            append_unique(values, item.get('url', ''))
    return values


def parse_feroxbuster_paths(result):
    values = []
    for item in result.get('json') or []:
        if isinstance(item, dict):
            append_unique(values, item.get('url', '') or item.get('target', ''))
    if not values:
        for line in parse_line_values(result.get('output', '')):
            if line.startswith(('http://', 'https://')):
                append_unique(values, line)
    return values


def parse_nuclei_findings(result):
    values = []
    for item in result.get('json') or []:
        if not isinstance(item, dict):
            continue
        info = item.get('info') if isinstance(item.get('info'), dict) else {}
        name = info.get('name') or item.get('template-id') or 'finding'
        severity = info.get('severity') or 'info'
        matched = item.get('matched-at') or item.get('host') or ''
        append_unique(values, f'{severity} {name} {matched}'.strip())
    return values


def normalize_summary(summary):
    for key, values in summary.items():
        summary[key] = unique_values(values)


def extract_domain_target(target):
    value = str(target or '').strip()
    if not value:
        return ''
    if '://' in value:
        value = urlsplit(value).hostname or ''
    if '/' in value:
        try:
            ipaddress.ip_network(value, strict=False)
            return ''
        except ValueError:
            return ''
    try:
        ipaddress.ip_address(value)
        return ''
    except ValueError:
        pass
    if '.' not in value:
        return ''
    return clean_arg(value.strip('[]'))


def extract_username_target(target):
    value = clean_arg(target).strip().strip('@')
    if not value or '/' in value or '.' in value or len(value) > 40:
        return ''
    if re.fullmatch(r'[A-Za-z0-9_.-]{3,40}', value):
        return value
    return ''


def extract_web_targets(services):
    urls = []
    for host, host_services in services.items():
        for port_text, service in host_services.items():
            http = service.get('http') or {}
            url = http.get('url')
            if not url:
                try:
                    port = int(port_text)
                except ValueError:
                    continue
                if service.get('name') not in {'HTTP', 'HTTPS', 'HTTP-Alt', 'HTTPS-Alt'}:
                    continue
                scheme = 'https' if port in {443, 8443} else 'http'
                url = f'{scheme}://{clean_arg(host)}:{port}/'
            if url not in urls:
                urls.append(url)
    return urls


def write_web_wordlist():
    entries = ('admin', 'login', 'api', 'swagger', 'docs', 'backup', 'config', '.git', '.env')
    handle = tempfile.NamedTemporaryFile('w', encoding='utf-8', delete=False)
    try:
        handle.write('\n'.join(entries))
        handle.write('\n')
        return handle.name
    finally:
        handle.close()
