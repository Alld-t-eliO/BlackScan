import ipaddress
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from network_scanner.modules.port_scanner import scan_port
from network_scanner.scanner.parser import validate_target

TCP_DISCOVERY_PORTS = (80, 443, 22, 445, 3389)


def ping_host(ip, timeout=2):
    try:
        wait_value = str(int(timeout * 1000)) if sys.platform == 'darwin' else str(timeout)
        result = subprocess.run(
            ['ping', '-c', '1', '-W', wait_value, ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def is_host_active(ip, timeout=2, tcp_ports=TCP_DISCOVERY_PORTS):
    if ping_host(ip, timeout):
        return True
    return any(scan_port(ip, port, timeout) for port in tcp_ports)


def sweep(target, threads=100, timeout=2, max_hosts=4096, tcp_ports=TCP_DISCOVERY_PORTS,
          skip_discovery=False, log_callback=print):
    target = validate_target(target)
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        if skip_discovery or is_host_active(target, timeout, tcp_ports):
            return [target]
        return []

    if network.num_addresses > max_hosts + 2:
        raise ValueError(f"target range is too large ({network.num_addresses} addresses); use --max-hosts to allow it")

    if network.num_addresses == 1:
        address = str(network.network_address)
        if skip_discovery or is_host_active(address, timeout, tcp_ports):
            log_callback(f"[+] {address} selected" if skip_discovery else f"[+] {address} is active")
            return [address]
        return []
    else:
        addresses = [str(ip) for ip in network.hosts()]
    if not addresses:
        return []
    if len(addresses) > max_hosts:
        raise ValueError('target range exceeds --max-hosts')
    if skip_discovery:
        return addresses

    results = []
    workers = min(max(1, threads), len(addresses))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(is_host_active, ip, timeout, tcp_ports): ip for ip in addresses}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                active = future.result()
            except OSError:
                active = False
            if active:
                results.append(ip)
                log_callback(f"[+] {ip} is active")

    return results
