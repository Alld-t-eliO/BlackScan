from urllib.parse import urlsplit

from python_socks import ProxyError, ProxyType
from python_socks.async_.asyncio import Proxy as AsyncProxy
from python_socks.sync import Proxy as SyncProxy

_PROXY_TYPES = {
    'socks5': ProxyType.SOCKS5,
    'socks4': ProxyType.SOCKS4,
}

# Re-exported so callers can catch a single exception type without importing python_socks directly.
SocksProxyError = ProxyError


def parse_socks_url(url):
    parsed = urlsplit(url)
    scheme = (parsed.scheme or 'socks5').lower()
    if scheme not in _PROXY_TYPES:
        raise ValueError(f'unsupported proxy scheme: {scheme!r} (use socks5:// or socks4://)')
    if not parsed.hostname:
        raise ValueError('proxy URL is missing a host')
    return {
        'proxy_type': _PROXY_TYPES[scheme],
        'host': parsed.hostname,
        'port': parsed.port or 1080,
        'username': parsed.username,
        'password': parsed.password,
    }


async def open_socks_connection(proxy_url, host, port, timeout=2):
    """Open a raw connected socket to (host, port) through a SOCKS proxy, asyncio-side."""
    settings = parse_socks_url(proxy_url)
    proxy = AsyncProxy.create(
        proxy_type=settings['proxy_type'],
        host=settings['host'],
        port=settings['port'],
        username=settings['username'],
        password=settings['password'],
    )
    return await proxy.connect(dest_host=host, dest_port=port, timeout=timeout)


def socks_connect(proxy_url, host, port, timeout=2):
    """Open a raw connected (blocking) socket to (host, port) through a SOCKS proxy."""
    settings = parse_socks_url(proxy_url)
    proxy = SyncProxy.create(
        proxy_type=settings['proxy_type'],
        host=settings['host'],
        port=settings['port'],
        username=settings['username'],
        password=settings['password'],
    )
    return proxy.connect(dest_host=host, dest_port=port, timeout=timeout)
