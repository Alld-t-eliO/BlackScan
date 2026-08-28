import subprocess
import re
import sys

def detect_os(ip, timeout=2):
    try:
        timeout_arg = '-t' if sys.platform == 'darwin' else '-W'
        result = subprocess.run(
            ['ping', '-c', '1', timeout_arg, str(timeout), ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout
        )
        
        output = result.stdout.decode('utf-8')
        
        match = re.search(r'ttl=(\d+)', output.lower())
        if match:
            ttl = int(match.group(1))
            
            if ttl <= 64:
                return "Linux/Unix"
            elif ttl <= 128:
                return "Windows"
            elif ttl <= 255:
                return "Solaris/Cisco"
            else:
                return f"Unknown (TTL={ttl})"
        
        return "Unknown"
    except (OSError, subprocess.SubprocessError):
        return "Unknown"
