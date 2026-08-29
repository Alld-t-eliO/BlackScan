"""MySQL credential-audit workflow placeholder."""

from .base import BruteForceBase, SafetyError


class MySQLBruteForce(BruteForceBase):
    """Disabled MySQL credential-audit workflow."""

    def get_default_username_list(self) -> list[str]:
        return ['root']

    def get_default_password_list(self) -> list[str]:
        return ['']

    async def try_credentials(self, credentials) -> bool:
        raise SafetyError('MySQL credential-audit workflow is not implemented')
