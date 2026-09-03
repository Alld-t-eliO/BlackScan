
import asyncio
import socket
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from itertools import islice
from typing import Any

from ...payloads.base import Credentials, WordlistManager


class SafetyError(RuntimeError):
    pass


@dataclass(frozen=True)
class BruteForcePolicy:

    authorized: bool = False
    intrusive_checks: bool = False
    max_attempts: int = 10
    stop_on_success: bool = True

    def validate(self) -> None:
        if not self.authorized or not self.intrusive_checks:
            raise SafetyError('credential-audit workflows require authorized=True and intrusive_checks=True')
        if self.max_attempts < 1 or self.max_attempts > 25:
            raise SafetyError('credential-audit workflows are capped between 1 and 25 attempts')


@dataclass
class BruteForceResult:

    success: bool
    credentials: Credentials | None = None
    service: str = ''
    target: str = ''
    port: int = 0
    error: str | None = None
    attempts: int = 0
    duration: float = 0.0
    evidence: str = ''

    def as_dict(self) -> dict[str, Any]:
        return {
            'success': self.success,
            'service': self.service,
            'target': self.target,
            'port': self.port,
            'username': self.credentials.username if self.credentials else '',
            'password': self.credentials.password if self.credentials else '',
            'attempts': self.attempts,
            'duration': round(self.duration, 2),
            'evidence': self.evidence,
            'error': self.error or '',
        }


class BruteForceBase(ABC):

    def __init__(self, host: str, port: int, timeout: int = 3, max_threads: int = 2):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.max_threads = min(max(1, max_threads), 4)
        self._attempts = 0

    @abstractmethod
    async def try_credentials(self, credentials: Credentials) -> bool:
        pass

    @abstractmethod
    def get_default_username_list(self) -> list[str]:
        pass

    @abstractmethod
    def get_default_password_list(self) -> list[str]:
        pass

    async def attack(
        self,
        username_list: list[str] | None = None,
        password_list: list[str] | None = None,
        policy: BruteForcePolicy | None = None,
    ) -> BruteForceResult:

        policy = policy or BruteForcePolicy()
        try:
            policy.validate()
        except SafetyError as exc:
            return self._result(False, 0, 0.0, error=str(exc))

        start_time = time.time()
        credentials_iter = islice(WordlistManager.get_credentials(
            username_list or self.get_default_username_list(),
            password_list or self.get_default_password_list(),
        ), policy.max_attempts)

        successful_creds = None
        attempts = 0
        semaphore = asyncio.Semaphore(self.max_threads)

        async def try_with_semaphore(creds: Credentials) -> Credentials | None:
            nonlocal attempts
            async with semaphore:
                if attempts >= policy.max_attempts:
                    return None
                attempts += 1
                self._attempts += 1
                try:
                    if await self.try_credentials(creds):
                        return creds
                except (OSError, asyncio.TimeoutError):
                    return None
                return None

        tasks = []
        for creds in credentials_iter:
            tasks.append(asyncio.create_task(try_with_semaphore(creds)))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Credentials):
                successful_creds = result
                if policy.stop_on_success:
                    break

        duration = time.time() - start_time
        return self._result(
            successful_creds is not None,
            attempts,
            duration,
            credentials=successful_creds,
        )

    def _result(
        self,
        success: bool,
        attempts: int,
        duration: float,
        credentials: Credentials | None = None,
        error: str | None = None,
    ) -> BruteForceResult:
        return BruteForceResult(
            success=success,
            credentials=credentials,
            service=self.__class__.__name__.replace('BruteForce', ''),
            target=self.host,
            port=self.port,
            attempts=attempts,
            duration=duration,
            error=error,
            evidence=f'{attempts} attempts in {duration:.2f}s',
        )

    def create_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        return sock
