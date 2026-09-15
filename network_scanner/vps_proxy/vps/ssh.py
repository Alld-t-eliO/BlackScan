from pathlib import Path
import paramiko

class SSHConnection:
    def __init__(
        self,
        host,
        port=22,
        username=None,
        key_file=None,
        timeout=15,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.key_file = key_file
        self.timeout = timeout

        self.client = None
        self.sftp = None

    def connect(self):
        if self.client is not None:
            return True

        if not self.host:
            raise ValueError("SSH host is not configured.")

        if not self.username:
            raise ValueError("SSH username is not configured.")

        self.client = paramiko.SSHClient()

        self.client.load_system_host_keys()

        self.client.set_missing_host_key_policy(
            paramiko.RejectPolicy()
        )

        self.client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username,
            key_filename=self.key_file or None,
            timeout=self.timeout,
            auth_timeout=self.timeout,
            banner_timeout=self.timeout,
        )

        self.sftp = self.client.open_sftp()

        return True

    def execute(self, command, timeout=None):
        if self.client is None:
            raise RuntimeError("SSH not connected.")

        if not command:
            raise ValueError("Command cannot be empty.")

        stdin, stdout, stderr = self.client.exec_command(
            command,
            timeout=timeout or self.timeout,
        )

        stdout_data = stdout.read().decode(
            "utf-8",
            errors="replace",
        )

        stderr_data = stderr.read().decode(
            "utf-8",
            errors="replace",
        )

        exit_code = stdout.channel.recv_exit_status()

        return {
            "stdout": stdout_data,
            "stderr": stderr_data,
            "exit_code": exit_code,
        }
    
    def upload(self, local_path, remote_path):

        if self.sftp is None:
            raise RuntimeError("SFTP not connected.")

        local_path = Path(local_path)

        if not local_path.is_file():
            raise FileNotFoundError(
                f"Local file not found: {local_path}"
            )

        self.sftp.put(
            str(local_path),
            remote_path,
        )

        return True

    def download(self, remote_path, local_path):

        if self.sftp is None:
            raise RuntimeError("SFTP not connected.")

        local_path = Path(local_path)

        local_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.sftp.get(
            remote_path,
            str(local_path),
        )

        return True

    def exists(self, remote_path):

        if self.sftp is None:
            raise RuntimeError("SFTP not connected.")

        try:
            self.sftp.stat(remote_path)
            return True

        except FileNotFoundError:
            return False

    def close(self):
        if self.sftp is not None:
            self.sftp.close()
            self.sftp = None

        if self.client is not None:
            self.client.close()
            self.client = None