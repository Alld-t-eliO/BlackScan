"""Brute force module - unrestricted

The SafetyError policy has been removed. The module now runs
unconditionally with caller-controlled limits.
"""

import asyncio
import socket
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from itertools import islice
from typing import Any

from ...payloads.base import Credentials, WordlistManager


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

    def as_dict(self, include_secrets=True) -> dict[str, Any]:
        return {
            'success': self.success,
            'service': self.service,
            'target': self.target,
            'port': self.port,
            'username': self.credentials.username if self.credentials else '',
            'password': (self.credentials.password if include_secrets else '[redacted]') if self.credentials else '',
            'attempts': self.attempts,
            'duration': round(self.duration, 2),
            'evidence': self.evidence,
            'error': self.error or '',
        }


class BruteForceBase(ABC):
    """Abstract base for credential attacks (no policy restrictions)"""

    def __init__(
        self,
        host: str,
        port: int,
        timeout: int = 3,
        max_threads: int = 8,
    ):
        if not host or not 1 <= port <= 65535 or not 0 < timeout <= 300:
            raise ValueError('host, port, and timeout (0-300s) required')
        self.host = host
        self.port = port
        self.timeout = timeout
        self.max_threads = max(1, max_threads)
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
        max_attempts: int = 0,
        stop_on_success: bool = True,
    ) -> BruteForceResult:
        """Run credential attack. No policy checks.

        Args:
            username_list: users to try (None = defaults)
            password_list: passwords to try (None = defaults)
            max_attempts: 0 = no limit (use full wordlist)
            stop_on_success: stop at first success
        """
        start_time = time.monotonic()
        self._attempts = 0

        creds_iter = WordlistManager.get_credentials(
            self.get_default_username_list() if username_list is None else username_list,
            self.get_default_password_list() if password_list is None else password_list,
            use_defaults=False,
        )

        if max_attempts > 0:
            creds_iter = islice(creds_iter, max_attempts)

        successful_creds = None
        attempts = 0
        semaphore = asyncio.Semaphore(self.max_threads)
        stopped = asyncio.Event()
        errors: list[str] = []

        async def try_with_semaphore(creds: Credentials) -> Credentials | None:
            nonlocal attempts
            async with semaphore:
                if stopped.is_set():
                    return None
                attempts += 1
                self._attempts += 1
                try:
                    ok = await asyncio.wait_for(
                        self.try_credentials(creds),
                        timeout=self.timeout * 3 + 1,
                    )
                    if ok:
                        if stop_on_success:
                            stopped.set()
                        return creds
                except Exception as exc:
                    errors.append(f'{type(exc).__name__}: {exc}')
                    return None
                return None

        tasks = [asyncio.create_task(try_with_semaphore(c)) for c in creds_iter]

        try:
            results = await asyncio.gather(*tasks)
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, Credentials):
                successful_creds = r
                if stop_on_success:
                    break

        duration = time.monotonic() - start_time
        return self._result(
            successful_creds is not None,
            attempts,
            duration,
            credentials=successful_creds,
            error='; '.join(dict.fromkeys(errors)) if errors else None,
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


# Compat: certains modules importent SafetyError
class SafetyError(RuntimeError):
    """Deprecated — kept for backward compat. No longer raised."""
    pass


__all__ = [
    'BruteForceBase',
    'BruteForceResult',
    'SafetyError',  # backward compat
]