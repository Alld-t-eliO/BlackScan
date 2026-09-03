import re
import subprocess
import sys

INITIAL_TTLS = (32, 64, 128, 255)


def detect_os(ip, timeout=2):
    ttl = read_ttl(ip, timeout)
    if ttl is None:
        return {
            'family': 'Unknown',
            'method': 'icmp_ttl',
            'observed_ttl': None,
            'probable_initial_ttl': None,
            'hop_distance': None,
            'confidence': 'low',
            'reason': 'No TTL found in ping response',
        }

    initial_ttl = infer_initial_ttl(ttl)
    hop_distance = initial_ttl - ttl if initial_ttl else None
    family = ttl_family(initial_ttl)
    confidence = ttl_confidence(hop_distance)
    return {
        'family': family,
        'method': 'icmp_ttl',
        'observed_ttl': ttl,
        'probable_initial_ttl': initial_ttl,
        'hop_distance': hop_distance,
        'confidence': confidence,
        'reason': f'Observed TTL {ttl}, probable initial TTL {initial_ttl}',
    }


def read_ttl(ip, timeout=2):
    try:
        wait_value = str(int(timeout * 1000)) if sys.platform == 'darwin' else str(timeout)
        result = subprocess.run(
            ['ping', '-c', '1', '-W', wait_value, ip],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    output = result.stdout.decode('utf-8', errors='ignore')
    match = re.search(r'ttl=(\d+)', output.lower())
    return int(match.group(1)) if match else None


def infer_initial_ttl(observed_ttl):
    for initial_ttl in INITIAL_TTLS:
        if observed_ttl <= initial_ttl:
            return initial_ttl
    return None


def ttl_family(initial_ttl):
    if initial_ttl == 32:
        return 'Embedded/legacy network device'
    if initial_ttl == 64:
        return 'Linux/Unix/macOS'
    if initial_ttl == 128:
        return 'Windows'
    if initial_ttl == 255:
        return 'Network device/Unix'
    return 'Unknown'


def ttl_confidence(hop_distance):
    if hop_distance is None:
        return 'low'
    if hop_distance <= 16:
        return 'high'
    if hop_distance <= 32:
        return 'medium'
    return 'low'
