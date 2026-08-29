import re
import subprocess
import sys


def detect_os(ip, timeout=2):
    try:
        wait_value = str(int(timeout * 1000)) if sys.platform == 'darwin' else str(timeout)
        result = subprocess.run(
            ['ping', '-c', '1', '-W', wait_value, ip],
            capture_output=True,
            timeout=timeout,
            check=False,
        )

        output = result.stdout.decode('utf-8')

        match = re.search(r'ttl=(\d+)', output.lower())
        if match:
            ttl = int(match.group(1))

            if ttl <= 64:
                return "Linux/Unix"
            if ttl <= 128:
                return "Windows"
            if ttl <= 255:
                return "Solaris/Cisco"
            return f"Unknown (TTL={ttl})"

        return "Unknown"
    except (OSError, subprocess.SubprocessError):
        return "Unknown"
