
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
    DROP_PAYLOADS_DIR = PAYLOAD_DIR / "payloads"
    USER_WORDLISTS_DIR = Path.home() / ".blackscan" / "payloads"
    IGNORED_PAYLOAD_SUFFIXES = frozenset({'.py', '.pyc', '.pyo'})

    @classmethod
    def get_wordlist(cls, name: str) -> list[str]:
        entries = []
        for path in cls.wordlist_paths(name):
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                entries.extend(line.strip() for line in f if line.strip())
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
            if path.is_file() and not path.name.startswith('.') and path.suffix not in cls.IGNORED_PAYLOAD_SUFFIXES:
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
                payload['count'] += len(cls.read_wordlist_path(path))
                if source == 'user':
                    payload['user_path'] = str(path)
                if source == 'drop':
                    payload['drop_path'] = str(path)
        return sorted(found.values(), key=lambda item: str(item['name']).lower())

    @staticmethod
    def read_wordlist_path(path: Path) -> list[str]:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]

    @classmethod
    def save_wordlist(cls, name: str, entries: list[str]) -> Path:
        safe_name = cls.safe_wordlist_name(name)
        if not safe_name:
            raise ValueError('payload name is required')
        cls.USER_WORDLISTS_DIR.mkdir(parents=True, exist_ok=True)
        path = cls.USER_WORDLISTS_DIR / f'{safe_name}.txt'
        values = [entry.strip() for entry in entries if entry.strip()]
        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(dict.fromkeys(values)))
            if values:
                f.write('\n')
        return path

    @classmethod
    def delete_wordlist(cls, name: str) -> bool:
        safe_name = cls.safe_wordlist_name(name)
        if not safe_name:
            return False
        for directory in (cls.USER_WORDLISTS_DIR, cls.DROP_PAYLOADS_DIR):
            for path in cls.wordlist_files(directory):
                if cls.safe_wordlist_name(cls.wordlist_name(path)) != safe_name:
                    continue
                path.unlink()
                return True
        return False

    @staticmethod
    def safe_wordlist_name(name: str) -> str:
        cleaned = ''.join(char if char.isalnum() or char in {'-', '_'} else '_' for char in name.strip())
        return cleaned.strip('._-')

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
