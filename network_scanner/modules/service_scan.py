import hashlib
import ipaddress
import os
import socket
import ssl
import tempfile
from html.parser import HTMLParser
from urllib.error import URLError
from urllib.parse import urljoin
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

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


def detect_service(ip, port, timeout=2):
    service_info = {
        'name': COMMON_PORTS.get(port, 'unknown'),
        'banner': '',
        'http': {},
        'tls': {},
    }

    if port in HTTP_PORTS or port in HTTPS_PORTS:
        service_info['http'] = detect_http(ip, port, timeout)
        if service_info['http']:
            service_info['name'] = 'HTTPS' if port in HTTPS_PORTS else 'HTTP'
            service_info['banner'] = service_info['http'].get('server', '')

    if port in HTTPS_PORTS:
        service_info['tls'] = detect_tls(ip, port, timeout)

    sock = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
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

    return service_info


def detect_http(ip, port, timeout=2):
    scheme = 'https' if port in HTTPS_PORTS else 'http'
    url = f'{scheme}://{ip}:{port}/'
    try:
        redirects = fetch_redirects(url, timeout)
        request = Request(url, headers={'User-Agent': 'BlackScan/1.0'})
        with urlopen(request, timeout=timeout) as response:
            body = response.read(8192).decode('utf-8', errors='ignore')
            parser = TitleParser()
            parser.feed(body)
            headers = dict(response.headers.items())
            cookies = parse_cookies(response.headers.get_all('Set-Cookie', []))
            return {
                'url': url,
                'status': response.status,
                'redirects': redirects,
                'server': headers.get('Server', ''),
                'powered_by': headers.get('X-Powered-By', ''),
                'title': parser.title,
                'headers': headers,
                'security_headers': summarize_security_headers(headers),
                'cookies': cookies,
                'favicon_hash': fetch_favicon_hash(url, timeout),
                'technologies': detect_technologies(headers, body),
                'common_paths': probe_common_paths(url, timeout),
                'sensitive_paths': probe_paths(url, SENSITIVE_WEB_PATHS, timeout),
            }
    except (OSError, URLError, ValueError, ssl.SSLError):
        return {}


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_redirects(url, timeout=2, limit=5):
    redirects = []
    current_url = url
    opener = build_opener(NoRedirectHandler)

    for _ in range(limit):
        try:
            request = Request(current_url, headers={'User-Agent': 'BlackScan/1.0'})
            opener.open(request, timeout=timeout)
            break
        except URLError as exc:
            response = getattr(exc, 'file', None)
            code = getattr(exc, 'code', None)
            headers = getattr(response, 'headers', {}) if response else {}
            location = headers.get('Location') if headers else None
            if code not in {301, 302, 303, 307, 308} or not location:
                break
            next_url = urljoin(current_url, location)
            redirects.append({'status': code, 'location': next_url})
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


def summarize_security_headers(headers):
    normalized = {key.lower(): value for key, value in headers.items()}
    return {
        header: {
            'present': header in normalized,
            'value': normalized.get(header, '')[:160],
        }
        for header in SECURITY_HEADERS
    }


def fetch_favicon_hash(base_url, timeout=2):
    try:
        request = Request(urljoin(base_url, '/favicon.ico'), headers={'User-Agent': 'BlackScan/1.0'})
        with urlopen(request, timeout=timeout) as response:
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


def probe_common_paths(base_url, timeout=2):
    return probe_paths(base_url, COMMON_WEB_PATHS, timeout)


def probe_paths(base_url, paths, timeout=2):
    results = []
    opener = build_opener(NoRedirectHandler)
    for path in paths:
        url = urljoin(base_url, path)
        try:
            request = Request(url, headers={'User-Agent': 'BlackScan/1.0'})
            with opener.open(request, timeout=timeout) as response:
                status = response.status
        except URLError as exc:
            status = getattr(exc, 'code', 0) or 0
        except OSError:
            status = 0

        if status:
            results.append({
                'path': path,
                'status': status,
                'interesting': status not in {404, 410},
            })
    return results


def detect_tls(ip, port, timeout=2):
    """Collect TLS metadata and verify trust plus identity, including IP SANs."""
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
    """Backward-compatible alias for TLS identity verification."""
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
