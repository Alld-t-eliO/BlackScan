from .ssh import SSHConnection
from . import config


class VPSManager:

    def __init__(self):
        self.ssh = None

    def connect(self):
        self.ssh = SSHConnection(
            host=config.VPS_HOST,
            port=config.VPS_PORT,
            username=config.VPS_USERNAME,
            key_file=config.VPS_IDENTITY_FILE or None,
        )

        self.ssh.connect()

        print("[VPS] Connexion SSH established.")

    def run(self, target, options=None):
        if self.ssh is None:
            self.connect()

        options = options or {}

        return {
            "mode": "vps",
            "target": target,
            "options": options,
        }

    def disconnect(self):
        if self.ssh:
            self.ssh.close()
            self.ssh = None

        print("[VPS] Connexion ended.")