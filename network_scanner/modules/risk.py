SEVERITY_ORDER = {'info': 0, 'low': 1, 'medium': 2, 'high': 3}
SENSITIVE_PORTS = {
    22: ('SSH exposed', 'medium'),
    23: ('Telnet exposed', 'high'),
    445: ('SMB exposed', 'high'),
    3306: ('MySQL exposed', 'high'),
    3389: ('RDP exposed', 'high'),
    5432: ('PostgreSQL exposed', 'high'),
    6379: ('Redis exposed', 'high'),
    27017: ('MongoDB exposed', 'high'),
}
DB_PORTS = {3306, 5432, 6379, 27017}


def max_severity(severities):
    current = 'info'
    for severity in severities:
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER[current]:
            current = severity
    return current


def score_service(host, port, service, vulnerabilities):
    factors = []

    if port in SENSITIVE_PORTS:
        label, severity = SENSITIVE_PORTS[port]
        factors.append({
            'name': label,
            'severity': severity,
            'evidence': f'{host}:{port}',
            'recommendation': 'Restrict access to trusted networks, VPNs, or bastion hosts.',
        })

    if port in DB_PORTS:
        factors.append({
            'name': 'Database Service Reachable',
            'severity': 'high',
            'evidence': f'{host}:{port}',
            'recommendation': 'Do not expose database services directly to untrusted networks.',
        })

    banner = service.get('banner', '')
    if banner and any(char.isdigit() for char in banner):
        factors.append({
            'name': 'Version Information Exposed',
            'severity': 'low',
            'evidence': banner[:160],
            'recommendation': 'Avoid exposing precise product versions where possible.',
        })

    http = service.get('http') or {}
    admin_paths = [
        path for path in http.get('common_paths', [])
        if path.get('interesting') and path.get('path') in {'/admin', '/login', '/api', '/swagger', '/docs'}
    ]
    if admin_paths:
        factors.append({
            'name': 'Interesting Web Interface Exposed',
            'severity': 'medium',
            'evidence': ', '.join(f"{item['path']} HTTP {item['status']}" for item in admin_paths),
            'recommendation': 'Verify authorization, authentication, and intended exposure for these endpoints.',
        })

    return {
        'score': max_severity([item.get('severity', 'info') for item in vulnerabilities + factors]),
        'factors': factors,
    }
