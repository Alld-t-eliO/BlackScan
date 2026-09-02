import ipaddress
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from network_scanner.modules.port_scanner import scan_port

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


def sweep(target, threads=100, timeout=2, max_hosts=4096, tcp_ports=TCP_DISCOVERY_PORTS):
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        if is_host_active(target, timeout, tcp_ports):
            return [target]
        return []

    if network.num_addresses > max_hosts + 2:
        raise ValueError(f"target range is too large ({network.num_addresses} addresses); use --max-hosts to allow it")

    if network.num_addresses == 1:
        address = str(network.network_address)
        if is_host_active(address, timeout, tcp_ports):
            print(f"[+] {address} is active")
            return [address]
        return []
    else:
        addresses = [str(ip) for ip in network.hosts()]
    if not addresses:
        return []

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
                print(f"[+] {ip} is active")

    return results
