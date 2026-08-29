"""Base classes for brute-force workflows."""

import asyncio
import socket
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from ...payloads.base import Credentials, WordlistManager


@dataclass
class BruteForceResult:
    """Result of a brute-force attempt."""
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
            'evidence': self.evidence
        }


class BruteForceBase(ABC):
    """Abstract base class for brute-force workflows."""
    
    def __init__(self, host: str, port: int, timeout: int = 3, max_threads: int = 10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.max_threads = max_threads
        self._lock = asyncio.Lock()
        self._attempts = 0
        
    @abstractmethod
    async def try_credentials(self, credentials: Credentials) -> bool:
        """Try a login with the provided credentials."""
    
    @abstractmethod
    def get_default_username_list(self) -> list[str]:
        """Return the default username list."""
    
    @abstractmethod
    def get_default_password_list(self) -> list[str]:
        """Return the default password list."""
    
    async def attack(self, 
                    username_list: list[str] | None = None,
                    password_list: list[str] | None = None,
                    max_attempts: int = 1000,
                    stop_on_success: bool = True) -> BruteForceResult:
        """Run the brute-force workflow."""
        
        start_time = time.time()
        credentials_iter = WordlistManager.get_credentials(
            username_list or self.get_default_username_list(),
            password_list or self.get_default_password_list()
        )
        
        successful_creds = None
        attempts = 0
        
        semaphore = asyncio.Semaphore(self.max_threads)
        
        async def try_with_semaphore(creds: Credentials) -> Credentials | None:
            nonlocal attempts
            async with semaphore:
                self._attempts += 1
                attempts += 1
                if attempts > max_attempts:
                    return None
                
                try:
                    if await self.try_credentials(creds):
                        return creds
                except (OSError, asyncio.TimeoutError):
                    # Ignore failed attempts and continue.
                    pass
                return None
        
        tasks = []
        for creds in credentials_iter:
            if attempts >= max_attempts:
                break
            
            task = asyncio.create_task(try_with_semaphore(creds))
            tasks.append(task)
            
            # Stop scheduling new work after the first success.
            if stop_on_success and successful_creds:
                break
        
        # Wait for all scheduled tasks to finish.
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Check results.
        for result in results:
            if isinstance(result, Credentials):
                successful_creds = result
                break
        
        duration = time.time() - start_time
        
        return BruteForceResult(
            success=successful_creds is not None,
            credentials=successful_creds,
            service=self.__class__.__name__.replace('BruteForce', ''),
            target=self.host,
            port=self.port,
            attempts=attempts,
            duration=duration,
            evidence=f"{attempts} attempts in {duration:.2f}s"
        )
    
    def create_socket(self) -> socket.socket:
        """Create a TCP socket."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        return sock
