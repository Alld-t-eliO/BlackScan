import socket
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import ClassVar
from urllib.error import URLError
from urllib.request import Request, urlopen

from network_scanner.checks.base import Check, Finding


class FTPAnonymousLogin(Check):
    name = 'FTP Anonymous Login'
    ports = (21,)
    severity = 'medium'
    intrusive = True
    recommendation = 'Disable anonymous FTP or restrict it to a dedicated read-only directory.'

    def run(self, host, port, service):
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((host, port))
            sock.sendall(b'USER anonymous\r\n')
            response = sock.recv(1024).decode(errors='ignore')
            if '331' in response:
                sock.sendall(b'PASS anonymous\r\n')
                response = sock.recv(1024).decode(errors='ignore')
                if '230' in response:
                    return self.finding(host, port, service.get('banner', 'anonymous login accepted'))
        except OSError:
            return None
        finally:
            if sock:
                sock.close()
        return None


class DirectoryListing(Check):
    name = 'Directory Listing'
    ports = (80, 443, 8080, 8443)
    severity = 'medium'
    recommendation = 'Disable directory listing unless the listing is intentional.'

    def run(self, host, port, service):
        scheme = 'https' if port in (443, 8443) else 'http'
        url = f'{scheme}://{host}:{port}/'
        try:
            request = Request(url, headers={'User-Agent': 'BlackScan/1.0'})
            with urlopen(request, timeout=2) as response:
                body = response.read(4096).decode('utf-8', errors='ignore').lower()
            if 'index of /' in body and ('parent directory' in body or '<title>index of' in body):
                return self.finding(host, port, url)
        except (OSError, URLError, ValueError):
            return None
        return None


class MySQLEmptyRootPassword(Check):
    name = 'MySQL Empty Root Password'
    ports = (3306,)
    severity = 'high'
    intrusive = True
    recommendation = 'Set a strong root password and restrict network access to MySQL.'

    def run(self, host, port, service):
        try:
            import mysql.connector
        except ImportError:
            return None

        try:
            conn = mysql.connector.connect(
                host=host,
                port=port,
                user='root',
                password='',
                connect_timeout=2,
            )
            conn.close()
            return self.finding(host, port, 'root login accepted with an empty password')
        except mysql.connector.Error:
            return None


class UnauthenticatedRedis(Check):
    name = 'Unauthenticated Redis'
    ports = (6379,)
    severity = 'high'
    intrusive = True
    recommendation = 'Require Redis authentication and bind Redis to trusted interfaces only.'

    def run(self, host, port, service):
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((host, port))
            sock.sendall(b'INFO\r\n')
            response = sock.recv(256).decode(errors='ignore')
            if response.startswith('$') or 'redis_version' in response:
                return self.finding(host, port, 'Redis INFO command returned without authentication')
        except OSError:
            return None
        finally:
            if sock:
                sock.close()
        return None


class MissingHTTPSecurityHeaders(Check):
    name = 'Missing HTTP Security Headers'
    ports = (80, 443, 8000, 8080, 8443)
    severity = 'low'
    recommendation = 'Add the missing security headers where appropriate for the application.'

    def run(self, host, port, service):
        http = service.get('http', {})
        headers = {key.lower(): value for key, value in http.get('headers', {}).items()}
        if not headers:
            return None

        missing = []
        if 'strict-transport-security' not in headers and port in (443, 8443):
            missing.append('Strict-Transport-Security')
        if 'x-content-type-options' not in headers:
            missing.append('X-Content-Type-Options')
        if 'content-security-policy' not in headers:
            missing.append('Content-Security-Policy')

        if missing:
            return self.finding(host, port, ', '.join(missing))
        return None


class HTTPWithoutTLS(Check):
    name = 'HTTP Service Without TLS'
    ports = (80, 8000, 8080, 8888)
    severity = 'low'
    recommendation = 'Expose sensitive applications over HTTPS and redirect HTTP to HTTPS.'

    def run(self, host, port, service):
        if service.get('http'):
            return self.finding(host, port, service.get('http', {}).get('url', ''))
        return None


class TLSCertificateExpiry(Check):
    name = 'TLS Certificate Expiry'
    ports = (443, 8443)
    severity = 'low'
    recommendation = 'Renew or replace the certificate before users are affected.'

    def run(self, host, port, service):
        not_after = service.get('tls', {}).get('not_after')
        if not not_after:
            return None

        try:
            expires_at = parsedate_to_datetime(not_after)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            return None

        days_left = (expires_at - datetime.now(timezone.utc)).days
        if days_left < 0:
            return Finding(
                'Expired TLS Certificate',
                'medium',
                f'{host}:{port}',
                f'expired {-days_left} day(s) ago: {not_after}',
                self.recommendation,
            ).as_dict()
        if days_left <= 30:
            return Finding(
                'TLS Certificate Expires Soon',
                'low',
                f'{host}:{port}',
                f'expires in {days_left} day(s): {not_after}',
                self.recommendation,
            ).as_dict()
        return None


class SensitiveWebPathExposure(Check):
    name = 'Sensitive Web Path Exposed'
    ports = (80, 443, 8000, 8080, 8443)
    severity = 'high'
    recommendation = 'Remove sensitive files from the web root and restrict access to backup or metadata paths.'
    sensitive_paths: ClassVar[dict[str, str]] = {
        '/.git/': 'Git metadata path responded',
        '/.env': 'Environment file path responded',
        '/backup.zip': 'Backup archive path responded',
        '/backup.tar.gz': 'Backup archive path responded',
        '/config.php.bak': 'Backup configuration path responded',
    }

    def run(self, host, port, service):
        for item in service.get('http', {}).get('sensitive_paths', []):
            status = item.get('status', 0)
            if 200 <= status < 300 and item.get('path') in self.sensitive_paths:
                evidence = f"{item['path']} HTTP {item['status']} - {self.sensitive_paths[item['path']]}"
                return self.finding(host, port, evidence)
        return None


BUILTIN_CHECKS = (
    FTPAnonymousLogin,
    DirectoryListing,
    MySQLEmptyRootPassword,
    UnauthenticatedRedis,
    MissingHTTPSecurityHeaders,
    HTTPWithoutTLS,
    TLSCertificateExpiry,
    SensitiveWebPathExposure,
)
