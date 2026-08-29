"""Payload and wordlist management."""

import random
import string
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Credentials:
    """Represent a username/password pair."""
    username: str
    password: str

    def __str__(self):
        return f"{self.username}:{self.password}"


class WordlistManager:
    """Manager for built-in and custom wordlists."""

    PAYLOAD_DIR = Path(__file__).parent
    WORDLISTS_DIR = PAYLOAD_DIR / "wordlists"

    @classmethod
    def get_wordlist(cls, name: str) -> list[str]:
        """Load a built-in wordlist."""
        path = cls.WORDLISTS_DIR / f"{name}.txt"
        if not path.exists():
            return []

        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]

    @classmethod
    def get_credentials(cls,
                       username_list: list[str] | None = None,
                       password_list: list[str] | None = None,
                       use_defaults: bool = True) -> Iterator[Credentials]:
        """Generate credential combinations."""

        if username_list is None and use_defaults:
            username_list = cls.get_wordlist('usernames')
            password_list = cls.get_wordlist('common_passwords') if password_list is None else password_list

        if not username_list or not password_list:
            return

        # Standard combinations.
        for username in username_list:
            for password in password_list:
                yield Credentials(username, password)

        # Username equals password combinations.
        for word in username_list:
            yield Credentials(word, word)

        # Default credentials
        if use_defaults:
            defaults = [('root', 'root'), ('admin', 'admin'), ('admin', 'password')]
            for user, pwd in defaults:
                yield Credentials(user, pwd)


class PayloadGenerator:
    """Dynamic payload generation."""

    @staticmethod
    def generate_password(length: int = 8) -> str:
        """Generate a random password."""
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(chars) for _ in range(length))

    @staticmethod
    def generate_username_variations(base: str) -> list[str]:
        """Generate username variations."""
        variations = [base, base.lower(), base.upper(), base.capitalize()]

        # Add numbers.
        for i in range(1, 10):
            variations.append(f"{base}{i}")
            variations.append(f"{base}_{i}")

        # Common prefixes.
        prefixes = ['admin_', 'user_', 'test_', 'dev_']
        for prefix in prefixes:
            variations.append(f"{prefix}{base}")

        return list(set(variations))  # Uniqueness.

    @staticmethod
    def password_permutations(base: str, max_length: int = 16) -> list[str]:
        """Generate password-based permutations."""
        variations = [base, base.lower(), base.upper(), base.capitalize()]

        # Add special characters.
        specials = ['!', '@', '#', '$', '%', '?', '*']
        for i, char in enumerate(specials[:3]):  # Limited for performance.
            variations.extend([
                f"{base}{char}",
                f"{char}{base}",
                f"{base}{i+1}{char}",
                f"{base.capitalize()}{char}"
            ])

        return [v for v in list(set(variations)) if len(v) <= max_length]
