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

    # Only create a bounded batch of tasks, even for a 65535-port scan.
    ports = iter(ports)

    async def worker():
        for port in ports:
            await bounded_scan(port)

    await asyncio.gather(*(worker() for _ in range(max(1, concurrency))))
    return sorted(open_ports)


def scan_port(ip, port, timeout=2):
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        return True
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
        except Exception as exc:  # noqa: BLE001 -- propagate worker failure to the caller
            error = exc

    thread = threading.Thread(target=runner)
    thread.start()
    thread.join()
    if error:
        raise error
    return result
