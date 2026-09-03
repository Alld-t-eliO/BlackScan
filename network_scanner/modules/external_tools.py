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


def run_external_enrichment(target, hosts, services, timeout=2, proxy_url=None):
    tools = detect_external_tools()
    result = {
        'enabled': True,
        'tools': tools,
        'domain': {},
        'network': {},
        'web': {},
        'osint': {},
        'notes': [],
    }
    domain = extract_domain_target(target)
    web_targets = extract_web_targets(services)
    command_timeout = max(8, min(45, int(timeout) * 8))

    if domain:
        result['domain']['whois'] = run_tool('whois', ['whois', domain], tools, command_timeout)
        result['domain']['dig'] = {
            'a': run_tool('dig', ['dig', '+short', domain, 'A'], tools, command_timeout),
            'aaaa': run_tool('dig', ['dig', '+short', domain, 'AAAA'], tools, command_timeout),
            'mx': run_tool('dig', ['dig', '+short', domain, 'MX'], tools, command_timeout),
            'ns': run_tool('dig', ['dig', '+short', domain, 'NS'], tools, command_timeout),
        }
        result['osint']['sherlock'] = run_tool('sherlock', ['sherlock', domain, '--timeout', str(max(5, timeout))], tools, command_timeout)
        result['osint']['recon-ng'] = skipped('recon-ng', tools, 'interactive framework; detected but not auto-executed')
    else:
        result['domain']['whois'] = skipped('whois', tools, 'target is not a domain name')
        result['domain']['dig'] = skipped('dig', tools, 'target is not a domain name')
        result['osint']['sherlock'] = skipped('sherlock', tools, 'target is not a domain or username-like value')
        result['osint']['recon-ng'] = skipped('recon-ng', tools, 'interactive framework; detected but not auto-executed')

    if hosts:
        result['network']['naabu'] = run_tool('naabu', ['naabu', '-host', ','.join(hosts), '-silent'], tools, command_timeout)
    else:
        result['network']['naabu'] = skipped('naabu', tools, 'no live hosts found')

    result['web']['katana'] = {}
    result['web']['ffuf'] = {}
    result['web']['feroxbuster'] = {}
    if web_targets:
        wordlist = write_web_wordlist()
        try:
            for url in web_targets[:10]:
                result['web']['katana'][url] = run_tool('katana', ['katana', '-u', url, '-silent', '-json', '-d', '1'], tools, command_timeout)
                result['web']['ffuf'][url] = run_ffuf(url, wordlist, tools, command_timeout, timeout, proxy_url)
                result['web']['feroxbuster'][url] = run_feroxbuster(url, wordlist, tools, command_timeout, timeout)
        finally:
            Path(wordlist).unlink(missing_ok=True)
    else:
        result['web']['katana']['status'] = skipped('katana', tools, 'no HTTP or HTTPS services found')
        result['web']['ffuf']['status'] = skipped('ffuf', tools, 'no HTTP or HTTPS services found')
        result['web']['feroxbuster']['status'] = skipped('feroxbuster', tools, 'no HTTP or HTTPS services found')

    return result


def run_ffuf(url, wordlist, tools, command_timeout, timeout, proxy_url=None):
    target_url = url.rstrip('/') + '/FUZZ'
    args = ['ffuf', '-u', target_url, '-w', wordlist, '-of', 'json', '-s', '-t', '10', '-timeout', str(max(3, int(timeout)))]
    if proxy_url:
        args.extend(['-x', proxy_url])
    return run_tool('ffuf', args, tools, command_timeout, json_output=True)


def run_feroxbuster(url, wordlist, tools, command_timeout, timeout):
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
    return run_tool('feroxbuster', args, tools, command_timeout, json_lines=True)


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
    value = value.strip()
    return value[:limit] if len(value) > limit else value


def clean_args(args):
    return [clean_arg(arg) for arg in args]


def clean_arg(value):
    return ''.join(char for char in str(value).replace('\x00', '') if ord(char) >= 32)


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
