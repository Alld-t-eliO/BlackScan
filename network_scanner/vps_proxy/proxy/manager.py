from . import config

class ProxyManager:
    def __init__(self):
        self.connected = False

    def connect(self):
        if not config.PROXY_ENABLED:
            raise RuntimeError(
                "Proxy mode selectioned "
                "mais PROXY_ENABLED=False."
            )

        if not config.PROXY_HOST:
            raise RuntimeError("PROXY_HOST is not configured.")

        if not config.PROXY_PORT:
            raise RuntimeError("PROXY_PORT is not configured.")

        self.connected = True

        print(
            f"[Proxy] Configuration loaded : "
            f"{config.PROXY_TYPE}://"
            f"{config.PROXY_HOST}:{config.PROXY_PORT}"
        )

        return True

    def run(self, target, options=None):
        if not self.connected:
            self.connect()

        options = options or {}

        print(f"[Proxy] Execution requested for : {target}")

        return {
            "mode": "proxy",
            "target": target,
            "status": "ready",
            "options": options,
        }

    def disconnect(self):
        self.connected = False
        print("[Proxy] Deconnexion.")