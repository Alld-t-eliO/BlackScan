import asyncio
import socket
import threading


async def scan_port_async(ip, port, timeout=2):
    try:
        future = asyncio.open_connection(ip, port)
        _reader, writer = await asyncio.wait_for(future, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return True
    except (asyncio.TimeoutError, OSError):
        return False


async def scan_ports_async(ip, ports, concurrency=100, timeout=2):
    semaphore = asyncio.Semaphore(max(1, concurrency))
    open_ports = []

    async def bounded_scan(port):
        async with semaphore:
            if await scan_port_async(ip, port, timeout):
                open_ports.append(port)

    await asyncio.gather(*(bounded_scan(port) for port in ports))
    return sorted(open_ports)


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
    if not ports:
        return []
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(scan_ports_async(ip, ports, threads, timeout))

    result = []
    error = None

    def runner():
        nonlocal result, error
        try:
            result = asyncio.run(scan_ports_async(ip, ports, threads, timeout))
        except RuntimeError as exc:
            error = exc

    thread = threading.Thread(target=runner)
    thread.start()
    thread.join()
    if error:
        raise error
    return result
