import socket

COMMON_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    6379: 'Redis',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
    27017: 'MongoDB',
}

HTTP_PORTS = {80, 8080, 8000, 8888}

def detect_service(ip, port, timeout=2):
    service_info = {'name': COMMON_PORTS.get(port, 'unknown'), 'banner': ''}
    sock = None
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        if port in HTTP_PORTS:
            sock.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        service_info['banner'] = banner[:200]
    except OSError:
        pass
    finally:
        if sock:
            sock.close()
    
    if service_info['banner']:
        if 'SSH' in service_info['banner']:
            service_info['name'] = 'SSH'
        elif 'MySQL' in service_info['banner']:
            service_info['name'] = 'MySQL'
        elif 'HTTP' in service_info['banner'] or 'Apache' in service_info['banner'] or 'nginx' in service_info['banner'].lower():
            service_info['name'] = 'HTTP'
        elif 'FTP' in service_info['banner']:
            service_info['name'] = 'FTP'
    
    return service_info
