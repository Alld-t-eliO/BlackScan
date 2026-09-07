import paramiko

class SSHConnection:
    def __init__(self, host, port=22, username=None, key_file=None):
        self.host = host
        self.port = port
        self.username = username
        self.key_file = key_file
        self.client = None

    def connect(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(
            paramiko.AutoAddPolicy()
        )

        self.client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username,
            key_filename=self.key_file or None,
            timeout=15,
        )

        return True

    def execute(self, command):
        if self.client is None:
            raise RuntimeError("SSH not connected.")

        stdin, stdout, stderr = self.client.exec_command(command)

        return {
            "stdout": stdout.read().decode(),
            "stderr": stderr.read().decode(),
            "exit_code": stdout.channel.recv_exit_status(),
        }

    def close(self):
        if self.client:
            self.client.close()
            self.client = None