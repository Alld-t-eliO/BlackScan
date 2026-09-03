
import random
import string
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Credentials:
    username: str
    password: str

    def __str__(self):
        return f"{self.username}:{self.password}"


class WordlistManager:

    PAYLOAD_DIR = Path(__file__).parent
    WORDLISTS_DIR = PAYLOAD_DIR / "wordlists"

    @classmethod
    def get_wordlist(cls, name: str) -> list[str]:
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

        if username_list is None and use_defaults:
            username_list = cls.get_wordlist('usernames')
            password_list = cls.get_wordlist('common_passwords') if password_list is None else password_list

        if not username_list or not password_list:
            return


        for username in username_list:
            for password in password_list:
                yield Credentials(username, password)


        for word in username_list:
            yield Credentials(word, word)


        if use_defaults:
            defaults = [('root', 'root'), ('admin', 'admin'), ('admin', 'password')]
            for user, pwd in defaults:
                yield Credentials(user, pwd)


class PayloadGenerator:

    @staticmethod
    def generate_password(length: int = 8) -> str:
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(chars) for _ in range(length))

    @staticmethod
    def generate_username_variations(base: str) -> list[str]:
        variations = [base, base.lower(), base.upper(), base.capitalize()]


        for i in range(1, 10):
            variations.append(f"{base}{i}")
            variations.append(f"{base}_{i}")


        prefixes = ['admin_', 'user_', 'test_', 'dev_']
        for prefix in prefixes:
            variations.append(f"{prefix}{base}")

        return list(set(variations))

    @staticmethod
    def password_permutations(base: str, max_length: int = 16) -> list[str]:
        variations = [base, base.lower(), base.upper(), base.capitalize()]


        specials = ['!', '@', '#', '$', '%', '?', '*']
        for i, char in enumerate(specials[:3]):
            variations.extend([
                f"{base}{char}",
                f"{char}{base}",
                f"{base}{i+1}{char}",
                f"{base.capitalize()}{char}"
            ])

        return [v for v in list(set(variations)) if len(v) <= max_length]
