import subprocess
import ipaddress
import threading
import queue
import sys

def ping_host(ip, timeout=2):
    try:
        timeout_arg = '-t' if sys.platform == 'darwin' else '-W'
        result = subprocess.run(
            ['ping', '-c', '1', timeout_arg, str(timeout), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False

def sweep(target, threads=100, timeout=2):
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        if ping_host(target, timeout):
            return [target]
        return []
    
    ip_queue = queue.Queue()
    for ip in network.hosts():
        ip_queue.put(str(ip))
    if ip_queue.empty():
        return []
    
    results = []
    lock = threading.Lock()
    
    def worker():
        while True:
            try:
                ip = ip_queue.get_nowait()
            except queue.Empty:
                break
            if ping_host(ip, timeout):
                with lock:
                    results.append(ip)
                    print(f"[+] {ip} est actif")
            ip_queue.task_done()
    
    thread_list = []
    for _ in range(min(max(1, threads), ip_queue.qsize())):
        t = threading.Thread(target=worker)
        t.start()
        thread_list.append(t)
    
    ip_queue.join()
    for t in thread_list:
        t.join()
    
    return results
