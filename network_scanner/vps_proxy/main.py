from config import EXECUTION_MODE

class Orchestrator:
    def __init__(self):
        self.mode = EXECUTION_MODE
        self.backend = self._load_backend()

    def _load_backend(self):

        if self.mode == "local":
            from network_scanner.local import LocalBackend
            return LocalBackend()

        if self.mode == "proxy":
            from network_scanner.vps_proxy.proxy.manager import ProxyManager
            return ProxyManager()

        if self.mode == "vps":
            from network_scanner.vps_proxy.vps.manager import VPSManager
            return VPSManager()

        raise ValueError(
            f"Unknown execution mode : {self.mode}"
        )

    def connect(self):
        if hasattr(self.backend, "connect"):
            return self.backend.connect()

    def run(self, target, options=None):
        options = options or {}

        return self.backend.run(
            target=target,
            options=options
        )

    def disconnect(self):
        if hasattr(self.backend, "disconnect"):
            return self.backend.disconnect()