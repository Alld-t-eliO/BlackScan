
import os
import secrets
import string
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Credentials:
    username: str
    password: str = field(repr=False)

    def __str__(self):
        return f"{self.username}:[redacted]"


class WordlistManager:

    PAYLOAD_DIR = Path(__file__).parent
    WORDLISTS_DIR = PAYLOAD_DIR / "wordlists"
    DROP_PAYLOADS_DIR = PAYLOAD_DIR / "payloads"
    USER_WORDLISTS_DIR = Path.home() / ".blackscan" / "payloads"
    IGNORED_PAYLOAD_SUFFIXES = frozenset({'.py', '.pyc', '.pyo'})
    MAX_FILE_BYTES = 8 * 1024 * 1024
    MAX_ENTRIES = 100000

    @classmethod
    def get_wordlist(cls, name: str) -> list[str]:
        entries = []
        for path in cls.wordlist_paths(name):
            entries.extend(cls.read_wordlist_path(path))
            if len(entries) > cls.MAX_ENTRIES:
                raise ValueError('combined wordlist exceeds 100000 entries')
        return list(dict.fromkeys(entries))

    @classmethod
    def wordlist_paths(cls, name: str) -> list[Path]:
        paths = []
        for directory in (cls.WORDLISTS_DIR, cls.DROP_PAYLOADS_DIR, cls.USER_WORDLISTS_DIR):
            for path in cls.wordlist_files(directory):
                if cls.wordlist_name(path) == name:
                    paths.append(path)
        return paths

    @classmethod
    def wordlist_files(cls, directory: Path) -> list[Path]:
        if not directory.exists():
            return []
        paths = []
        for path in directory.iterdir():
            if not path.is_symlink() and path.is_file() and not path.name.startswith('.') and path.suffix.lower() not in cls.IGNORED_PAYLOAD_SUFFIXES:
                paths.append(path)
        return sorted(paths, key=lambda item: cls.wordlist_name(item).lower())

    @staticmethod
    def wordlist_name(path: Path) -> str:
        return path.stem if path.suffix else path.name

    @classmethod
    def list_wordlists(cls) -> list[dict[str, object]]:
        found = {}
        for source, directory in (
            ('builtin', cls.WORDLISTS_DIR),
            ('drop', cls.DROP_PAYLOADS_DIR),
            ('user', cls.USER_WORDLISTS_DIR),
        ):
            for path in cls.wordlist_files(directory):
                name = cls.wordlist_name(path)
                payload = found.setdefault(
                    name,
                    {'name': name, 'sources': [], 'count': 0, 'user_path': None, 'drop_path': None},
                )
                payload['sources'].append(source)
                if source == 'user':
                    payload['user_path'] = str(path)
                if source == 'drop':
                    payload['drop_path'] = str(path)
        for name, payload in found.items():
            payload['count'] = len(cls.get_wordlist(name))
        return sorted(found.values(), key=lambda item: str(item['name']).lower())

    @classmethod
    def read_wordlist_path(cls, path: Path) -> list[str]:
        if path.is_symlink() or path.stat().st_size > cls.MAX_FILE_BYTES:
            raise ValueError(f'wordlist must be a regular file of at most {cls.MAX_FILE_BYTES} bytes: {path.name}')
        with open(path, 'r', encoding='utf-8-sig') as f:
            text = f.read(cls.MAX_FILE_BYTES + 1)
        if '\x00' in text or len(text) > cls.MAX_FILE_BYTES:
            raise ValueError(f'invalid text wordlist: {path.name}')
        entries = [line.strip() for line in text.splitlines() if line.strip()]
        if len(entries) > cls.MAX_ENTRIES:
            raise ValueError('wordlist exceeds 100000 entries')
        return entries

    @classmethod
    def save_wordlist(cls, name: str, entries: list[str]) -> Path:
        safe_name = cls.safe_wordlist_name(name)
        if not safe_name:
            raise ValueError('payload name is required')
        cls.USER_WORDLISTS_DIR.mkdir(parents=True, exist_ok=True)
        path = cls.USER_WORDLISTS_DIR / f'{safe_name}.txt'
        values = [entry.strip() for entry in entries if entry.strip()]
        if any(any(char in entry for char in '\r\n\x00') for entry in entries):
            raise ValueError('entries must not contain line breaks or NUL bytes')
        values = list(dict.fromkeys(values))
        content = '\n'.join(values) + ('\n' if values else '')
        if len(values) > cls.MAX_ENTRIES or len(content.encode('utf-8')) > cls.MAX_FILE_BYTES:
            raise ValueError('wordlist is too large')
        temporary = None
        try:
            with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=cls.USER_WORDLISTS_DIR, delete=False) as f:
                temporary = Path(f.name)
                f.write(content)
            os.replace(temporary, path)
        finally:
            if temporary:
                temporary.unlink(missing_ok=True)
        return path

    @classmethod
    def delete_wordlist(cls, name: str) -> bool:
        safe_name = cls.safe_wordlist_name(name)
        if not safe_name:
            return False
        paths = [path for directory in (cls.USER_WORDLISTS_DIR, cls.DROP_PAYLOADS_DIR)
                 for path in cls.wordlist_files(directory) if cls.wordlist_name(path) == name]
        if not paths:
            paths = [path for directory in (cls.USER_WORDLISTS_DIR, cls.DROP_PAYLOADS_DIR)
                     for path in cls.wordlist_files(directory) if cls.wordlist_name(path) == safe_name]
        if not paths:
            return False
        for path in paths:
            path.unlink()
        return True

    @staticmethod
    def safe_wordlist_name(name: str) -> str:
        cleaned = ''.join(char if char.isalnum() or char in {'-', '_'} else '_' for char in name.strip())
        return cleaned.strip('._-')

    @classmethod
    def get_credentials(cls,
                       username_list: list[str] | None = None,
                       password_list: list[str] | None = None,
                       use_defaults: bool = True) -> Iterator[Credentials]:

        if use_defaults:
            username_list = cls.get_wordlist('usernames') if username_list is None else username_list
            password_list = cls.get_wordlist('common_passwords') if password_list is None else password_list

        if not username_list or not password_list:
            return


        for username in dict.fromkeys(username_list):
            for password in dict.fromkeys(password_list):
                yield Credentials(username, password)


class PayloadGenerator:

    @staticmethod
    def generate_password(length: int = 8) -> str:
        if not isinstance(length, int) or not 1 <= length <= 4096:
            raise ValueError('password length must be between 1 and 4096')
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(chars) for _ in range(length))

    @staticmethod
    def generate_username_variations(base: str) -> list[str]:
        variations = [base, base.lower(), base.upper(), base.capitalize()]


        for i in range(1, 10):
            variations.append(f"{base}{i}")
            variations.append(f"{base}_{i}")


        prefixes = ['admin_', 'user_', 'test_', 'dev_']
        for prefix in prefixes:
            variations.append(f"{prefix}{base}")

        return list(dict.fromkeys(variations))

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

        if max_length < 1:
            raise ValueError('max_length must be positive')
        return [v for v in dict.fromkeys(variations) if len(v) <= max_length]
