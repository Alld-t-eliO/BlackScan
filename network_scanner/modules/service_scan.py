import hashlib
import ipaddress
import os
import socket
import ssl
import tempfile
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


def web_url(host, port, scheme):
    host = f'[{host}]' if ':' in host and not host.startswith('[') else host
    return f'{scheme}://{host}:{port}/'

COMMON_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    6379: 'Redis',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
    27017: 'MongoDB',
}

HTTP_PORTS = {80, 8080, 8000, 8888}
HTTPS_PORTS = {443, 8443}
COMMON_WEB_PATHS = ('/admin', '/login', '/api', '/swagger', '/docs')
SENSITIVE_WEB_PATHS = ('/.git/', '/.env', '/backup.zip', '/backup.tar.gz', '/config.php.bak')
SECURITY_HEADERS = (
    'strict-transport-security',
    'content-security-policy',
    'x-content-type-options',
    'x-frame-options',
    'referrer-policy',
    'permissions-policy',
)


class TitleParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_title = False
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.parts.append(data.strip())

    @property
    def title(self):
        return " ".join(part for part in self.parts if part)[:120]


def detect_service(ip, port, timeout=2, proxy_url=None):
    service_info = {
        'name': COMMON_PORTS.get(port, 'unknown'),
        'banner': '',
        'http': {},
        'tls': {},
        'errors': [],
    }

    if port in HTTP_PORTS or port in HTTPS_PORTS:
        service_info['http'] = detect_http(ip, port, timeout, proxy_url)
        if service_info['http'].get('error'):
            service_info['errors'].append(service_info['http']['error'])
        if service_info['http'].get('status'):
            service_info['name'] = 'HTTPS' if port in HTTPS_PORTS else 'HTTP'
            service_info['banner'] = service_info['http'].get('server', '')

    if port in HTTPS_PORTS:
        service_info['tls'] = detect_tls(ip, port, timeout)

    # HTTP servers wait for a request, and TLS sockets wait for a handshake.
    # A second passive connection adds only delay and cannot provide a banner.
    if port in HTTP_PORTS | HTTPS_PORTS:
        return service_info

    sock = None

    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        if port in HTTP_PORTS and not service_info['http']:
            sock.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        if banner:
            service_info['banner'] = banner[:200]
    except OSError:
        pass
    finally:
        if sock:
            sock.close()

    if service_info['banner']:
        if 'SSH' in service_info['banner']:
            service_info['name'] = 'SSH'
        elif 'MySQL' in service_info['banner']:
            service_info['name'] = 'MySQL'
        elif 'HTTP' in service_info['banner'] or 'Apache' in service_info['banner'] or 'nginx' in service_info['banner'].lower():
            service_info['name'] = 'HTTP'
        elif 'FTP' in service_info['banner']:
            service_info['name'] = 'FTP'

    if not service_info['banner'] and port not in COMMON_PORTS:
        http = detect_http(ip, port, timeout, proxy_url)
        if http.get('status'):
            service_info.update(name='HTTP', http=http, banner=http.get('server', ''))
    return service_info


def detect_http(ip, port, timeout=2, proxy_url=None):
    scheme = 'https' if port in HTTPS_PORTS else 'http'
    url = web_url(ip, port, scheme)
    try:
        redirects = fetch_redirects(url, timeout, proxy_url=proxy_url)
        request = Request(url, headers={'User-Agent': 'BlackScan/1.0'})
        response = None
        try:
            response = open_url(request, timeout, proxy_url)
        except HTTPError as exc:
            response = exc
        try:
            body = response.read(8192).decode('utf-8', errors='ignore')
            parser = TitleParser()
            parser.feed(body)
            headers = dict(response.headers.items())
            normalized_headers = {key.lower(): value for key, value in headers.items()}
            cookies = parse_cookies(get_header_values(response.headers, 'Set-Cookie'))
            return {
                'url': url,
                'status': getattr(response, 'status', None) or getattr(response, 'code', 0),
                'proxy': redact_proxy(proxy_url),
                'final_url': response.geturl() if hasattr(response, 'geturl') else url,
                'redirects': redirects,
                'server': normalized_headers.get('server', ''),
                'powered_by': normalized_headers.get('x-powered-by', ''),
                'title': parser.title,
                'directory_listing': 'index of /' in body.lower() and (
                    'parent directory' in body.lower() or '<title>index of' in body.lower()
                ),
                'headers': headers,
                'security_headers': summarize_security_headers(headers),
                'cookies': cookies,
                'favicon_hash': fetch_favicon_hash(url, timeout, proxy_url=proxy_url),
                'technologies': detect_technologies(headers, body),
                'common_paths': probe_common_paths(url, timeout, proxy_url=proxy_url),
                'sensitive_paths': probe_paths(url, SENSITIVE_WEB_PATHS, timeout, proxy_url=proxy_url),
            }
        finally:
            if response:
                response.close()
    except (OSError, URLError, ValueError, ssl.SSLError) as exc:
        return {'url': url, 'error': f'HTTP collection failed: {type(exc).__name__}'}


def redact_proxy(value):
    if not value:
        return ''
    parsed = urlsplit(value)
    return parsed._replace(netloc='***:***@' + parsed.netloc.rsplit('@', 1)[1]).geturl() if '@' in parsed.netloc else value


class ScopedRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).hostname != urlsplit(req.full_url).hostname:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def open_url(request, timeout=2, proxy_url=None):
    opener = build_proxy_opener(proxy_url)
    return opener.open(request, timeout=timeout)


def build_proxy_opener(proxy_url):
    return build_opener(ScopedRedirectHandler(), *http_handlers(proxy_url))


def http_handlers(proxy_url=None):
    # Explicit empty proxies prevent environment variables from changing the selected route.
    handlers = [ProxyHandler({'http': proxy_url, 'https': proxy_url} if proxy_url else {})]
    return handlers


def build_no_redirect_opener(proxy_url=None):
    handlers = [NoRedirectHandler(), *http_handlers(proxy_url)]
    return build_opener(*handlers)


def fetch_redirects(url, timeout=2, limit=5, proxy_url=None):
    redirects = []
    current_url = url
    opener = build_no_redirect_opener(proxy_url)

    for _ in range(limit):
        try:
            request = Request(current_url, headers={'User-Agent': 'BlackScan/1.0'})
            with opener.open(request, timeout=timeout):
                pass
            break
        except URLError as exc:
            response = exc if isinstance(exc, HTTPError) else None
            code = getattr(exc, 'code', None)
            headers = getattr(response, 'headers', {}) if response else {}
            location = headers.get('Location') if headers else None
            if response is not None:
                response.close()
            if code not in {301, 302, 303, 307, 308} or not location:
                break
            next_url = urljoin(current_url, location)
            redirects.append({'status': code, 'location': next_url})
            if urlsplit(next_url).hostname != urlsplit(url).hostname:
                break
            current_url = next_url
        except OSError:
            break

    return redirects


def parse_cookies(cookies):
    parsed = []
    for raw_cookie in cookies:
        parts = [part.strip() for part in raw_cookie.split(';') if part.strip()]
        if not parts:
            continue
        name = parts[0].split('=', 1)[0]
        flags = {part.lower() for part in parts[1:]}
        parsed.append({
            'name': name[:80],
            'secure': 'secure' in flags,
            'httponly': 'httponly' in flags,
            'samesite': next((part.split('=', 1)[1] for part in flags if part.startswith('samesite=')), ''),
        })
    return parsed


def get_header_values(headers, name):
    if hasattr(headers, 'get_all'):
        return headers.get_all(name, [])
    value = headers.get(name, '') if headers else ''
    if not value:
        return []
    return [value]


def summarize_security_headers(headers):
    normalized = {key.lower(): value for key, value in headers.items()}
    return {
        header: {
            'present': header in normalized,
            'value': normalized.get(header, '')[:160],
        }
        for header in SECURITY_HEADERS
    }


def fetch_favicon_hash(base_url, timeout=2, proxy_url=None):
    try:
        request = Request(urljoin(base_url, '/favicon.ico'), headers={'User-Agent': 'BlackScan/1.0'})
        with open_url(request, timeout, proxy_url) as response:
            data = response.read(65536)
        if not data:
            return ''
        return hashlib.sha256(data).hexdigest()
    except (OSError, URLError, ValueError):
        return ''


def detect_technologies(headers, body):
    signatures = {
        'Apache': ['apache'],
        'nginx': ['nginx'],
        'IIS': ['microsoft-iis', 'asp.net'],
        'PHP': ['php', 'x-powered-by: php'],
        'Express': ['express'],
        'WordPress': ['wp-content', 'wp-includes'],
        'Drupal': ['drupal'],
        'Django': ['csrftoken', 'django'],
        'Laravel': ['laravel'],
        'React': ['react', '__react'],
        'Vue': ['vue', '__vue__'],
        'Swagger/OpenAPI': ['swagger-ui', 'openapi'],
    }
    haystack = '\n'.join(f'{key}: {value}' for key, value in headers.items()).lower()
    haystack = f'{haystack}\n{body[:8192].lower()}'
    return sorted(name for name, needles in signatures.items() if any(needle in haystack for needle in needles))


def probe_common_paths(base_url, timeout=2, proxy_url=None):
    return probe_paths(base_url, COMMON_WEB_PATHS, timeout, proxy_url=proxy_url)


def probe_paths(base_url, paths, timeout=2, proxy_url=None):
    results = []
    opener = build_no_redirect_opener(proxy_url)
    for path in paths:
        url = urljoin(base_url, path)
        try:
            request = Request(url, headers={'User-Agent': 'BlackScan/1.0'})
            with opener.open(request, timeout=timeout) as response:
                status = response.status
                content_type = response.headers.get('Content-Type', '').lower()
                # File exposure must have file-like evidence, not just a wildcard 200 page.
                body = response.read(2048) if path in SENSITIVE_WEB_PATHS else b''
        except URLError as exc:
            status = getattr(exc, 'code', 0) or 0
            body, content_type = b'', ''
            if isinstance(exc, HTTPError):
                exc.close()
        except OSError:
            status = 0
            body, content_type = b'', ''

        if status:
            results.append({
                'path': path,
                'status': status,
                'interesting': status not in {404, 410},
                'confirmed_content': sensitive_content(path, body, content_type),
            })
    return results


def sensitive_content(path, body, content_type):
    if not body:
        return False
    if path == '/backup.zip':
        return body.startswith(b'PK\x03\x04')
    if path == '/backup.tar.gz':
        return body.startswith(b'\x1f\x8b')
    text = body.decode('utf-8', errors='ignore').lower()
    if path == '/.git/':
        return 'index of' in text and ('head' in text or 'objects/' in text)
    if 'text/html' in content_type or '<html' in text or '<!doctype' in text:
        return False
    if path == '/.env':
        return any('=' in line and not line.lstrip().startswith('#') for line in text.splitlines())
    return path == '/config.php.bak' and '<?php' in text


def detect_tls(ip, port, timeout=2):
    tls_info = {
        'sha256_fingerprint': '',
        'not_before': '',
        'not_after': '',
        'verification': {
            'verified': False,
            'identity_checked': False,
            'trust_chain_checked': False,
            'target_type': target_type(ip),
            'error': '',
        },
    }

    try:
        pem_cert = ssl.get_server_certificate((ip, port), timeout=timeout)
        der_cert = ssl.PEM_cert_to_DER_cert(pem_cert)
        tls_info['sha256_fingerprint'] = hashlib.sha256(der_cert).hexdigest()
    except (OSError, ssl.SSLError, ValueError):
        return tls_info

    verification = verify_tls_identity(ip, port, timeout)
    tls_info['verification'] = verification
    tls_info['not_before'] = verification.pop('not_before', '')
    tls_info['not_after'] = verification.pop('not_after', '')
    if not tls_info['not_before'] or not tls_info['not_after']:
        decoded = decode_pem_certificate(pem_cert)
        tls_info['not_before'] = decoded.get('notBefore', '')
        tls_info['not_after'] = decoded.get('notAfter', '')

    return tls_info


def verify_tls_identity(hostname, port, timeout=2):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock, context.wrap_socket(
            sock,
            server_hostname=hostname,
        ) as tls_sock:
            cert = tls_sock.getpeercert()
            return {
                'verified': True,
                'identity_checked': True,
                'trust_chain_checked': True,
                'target_type': target_type(hostname),
                'error': '',
                'not_before': cert.get('notBefore', ''),
                'not_after': cert.get('notAfter', ''),
                'version': tls_sock.version(),
                'cipher': tls_sock.cipher(),
            }
    except (OSError, ssl.SSLError, ValueError) as exc:
        return {
            'verified': False,
            'identity_checked': True,
            'trust_chain_checked': True,
            'target_type': target_type(hostname),
            'error': str(exc)[:200],
        }


def verify_tls_hostname(hostname, port, timeout=2):
    return verify_tls_identity(hostname, port, timeout)


def decode_pem_certificate(pem_cert):
    temp_name = ''
    try:
        with tempfile.NamedTemporaryFile('w', encoding='utf-8', delete=False) as handle:
            temp_name = handle.name
            handle.write(pem_cert)
        return ssl._ssl._test_decode_cert(temp_name)
    except (OSError, ssl.SSLError, ValueError):
        return {}
    finally:
        if temp_name:
            try:
                os.unlink(temp_name)
            except OSError:
                pass


def target_type(hostname):
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return 'dns'
    return 'ip'
