import socket
import threading
import queue


def scan_port(ip, port, timeout=2):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        return result == 0
    except OSError:
        return False
    finally:
        if sock:
            sock.close()


def scan_ports(ip, ports, threads=100, timeout=2):
    open_ports = []
    port_queue = queue.Queue()
    
    for port in ports:
        port_queue.put(port)
    if port_queue.empty():
        return []
    
    lock = threading.Lock()
    
    def worker():
        while True:
            try:
                port = port_queue.get_nowait()
            except queue.Empty:
                break
            if scan_port(ip, port, timeout):
                with lock:
                    open_ports.append(port)
            port_queue.task_done()
    
    thread_list = []
    for _ in range(min(max(1, threads), port_queue.qsize())):
        t = threading.Thread(target=worker)
        t.start()
        thread_list.append(t)
    
    port_queue.join()
    for t in thread_list:
        t.join()
    
    return sorted(open_ports)
