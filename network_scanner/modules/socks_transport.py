"""SOCKS transport with explicit failures and proxy-side DNS resolution."""
from urllib.parse import unquote, urlsplit

try:
    from python_socks import ProxyError, ProxyConnectionError, ProxyTimeoutError, ProxyType
    from python_socks.async_.asyncio import Proxy as AsyncProxy
    from python_socks.sync import Proxy as SyncProxy
    PROXY_EXCEPTIONS = (ProxyError, ProxyConnectionError, ProxyTimeoutError, OSError)
except ImportError:
    ProxyType = AsyncProxy = SyncProxy = None
    PROXY_EXCEPTIONS = (OSError,)


class SocksProxyError(RuntimeError):
    """The proxy could not carry the request; never retry directly."""


class SocksTargetUnavailable(OSError):
    """The proxy reports that the destination is unreachable or refused."""


def validate_socks_url(url):
    parsed = urlsplit(url)
    if parsed.scheme not in {'socks5', 'socks4'} or not parsed.hostname:
        raise ValueError('SOCKS proxy must use socks5:// or socks4:// with a host')
    if parsed.port == 0 or parsed.path not in {'', '/'} or parsed.query or parsed.fragment:
        raise ValueError('SOCKS proxy must contain only host, port and optional credentials')
    if parsed.scheme == 'socks4' and parsed.password:
        raise ValueError('SOCKS4 does not support password authentication; use SOCKS5')
    for value in (parsed.username, parsed.password):
        if value and len(unquote(value).encode()) > 255:
            raise ValueError('SOCKS credentials must be at most 255 bytes')
    return url


def parse_socks_url(url):
    validate_socks_url(url)
    if ProxyType is None:
        raise SocksProxyError('SOCKS requires python-socks: install BlackScan with the network extra')
    parsed = urlsplit(url)
    return {
        'proxy_type': ProxyType.SOCKS5 if parsed.scheme == 'socks5' else ProxyType.SOCKS4,
        'host': parsed.hostname,
        'port': parsed.port or 1080,
        'username': unquote(parsed.username) if parsed.username is not None else None,
        'password': unquote(parsed.password) if parsed.password is not None else None,
        'rdns': True,
    }


def _raise_proxy_error(exc, proxy_url):
    # Destination rejection differs from a broken proxy/authentication failure.
    code = getattr(exc, 'error_code', None)
    scheme = urlsplit(proxy_url).scheme
    if (scheme == 'socks5' and code in {3, 4, 5, 6}) or (scheme == 'socks4' and code == 91):
        raise SocksTargetUnavailable('Destination unreachable through SOCKS proxy') from exc
    raise SocksProxyError('SOCKS connection failed; verify proxy address, credentials and availability') from exc


async def open_socks_connection(proxy_url, host, port, timeout=2):
    settings = parse_socks_url(proxy_url)
    proxy = AsyncProxy.create(**settings)
    try:
        return await proxy.connect(dest_host=host, dest_port=port, timeout=timeout)
    except PROXY_EXCEPTIONS as exc:
        _raise_proxy_error(exc, proxy_url)


def socks_connect(proxy_url, host, port, timeout=2):
    settings = parse_socks_url(proxy_url)
    proxy = SyncProxy.create(**settings)
    try:
        return proxy.connect(dest_host=host, dest_port=port, timeout=timeout)
    except PROXY_EXCEPTIONS as exc:
        _raise_proxy_error(exc, proxy_url)
