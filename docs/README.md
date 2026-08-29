# BlackScan

BlackScan is a Python CLI for authorized network discovery, TCP port scanning, service fingerprinting, lightweight exposure checks, and JSON/HTML/CSV reporting.

Use it only on systems and networks where you have explicit authorization.

## Features

- Host discovery with ICMP plus TCP fallback for hosts that block ping.
- Fast TCP connect scans with bounded async concurrency.
- Scan profiles: `quick`, `web`, `internal`, `full`, and `stealth`.
- Service fingerprints for common ports.
- HTTP metadata capture: status, server header, title, selected headers.
- Web fingerprinting: redirects, cookie flags, favicon hash, probable technologies, and common paths.
- TLS certificate metadata on HTTPS ports.
- Risk scoring for exposed sensitive ports, database services, missing hardening, exposed versions, and interesting web interfaces.
- Non-destructive exposure checks:
  - directory listing
  - missing HTTP security headers
  - HTTP without TLS
  - expired or soon-to-expire TLS certificate
  - sensitive web paths such as `/.git/`, `/.env`, and backup archives
- Optional intrusive checks, disabled by default:
  - anonymous FTP
  - empty MySQL root password
  - unauthenticated Redis
- Reports in JSON, HTML, CSV, and Markdown.
- Report comparison for recurring recon.
- Optional external tool detection for `nmap`, `nuclei`, `httpx`, `subfinder`, and `dnsx`.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,mysql]"
```

The `mysql` extra is optional. Without it, the MySQL empty-password check is skipped.

## Usage

```bash
blackscan --target 192.168.1.0/24 --profile quick --authorized
```

Run from source without installing:

```bash
python scanner.py --target 192.168.1.10 --profile web --authorized
```

Useful options:

```bash
python scanner.py --target 10.0.0.0/24 --profile internal --threads 200 --timeout 1 --authorized
python scanner.py --target example.com --ports 22,80,443,8000-8100 --authorized
python scanner.py --target 192.168.1.0/20 --max-hosts 8192 --profile stealth --authorized
python scanner.py --target 10.0.0.0/24 --compare reports/old_scan.json --authorized
python scanner.py --list-external-tools
python scanner.py --target 10.0.0.5 --profile internal --intrusive-checks --authorized
```

Reports are written to `reports/` by default.

`--intrusive-checks` enables checks that send application-level commands or login attempts, such as anonymous FTP, empty MySQL root password, and unauthenticated Redis detection. Leave it disabled unless the rules of engagement explicitly allow those checks.

TLS certificate handling records a SHA-256 certificate fingerprint. Hostname verification is performed for DNS targets. For raw IP targets, hostname verification is marked as skipped because the certificate name usually cannot match the IP; use the fingerprint and certificate metadata for manual validation.

## Profiles

| Profile | Purpose |
| --- | --- |
| `quick` | Common infrastructure and database ports. |
| `web` | HTTP/HTTPS-focused scan and web exposure checks. |
| `internal` | Common internal network services. |
| `full` | Ports 1-1024 plus common application ports. |
| `stealth` | Small low-noise set: SSH, HTTP, HTTPS. |

`--aggressive` remains available and maps to the broader `full` behavior.

## Risk Scoring

BlackScan assigns a simple score to every open service:

| Score | Meaning |
| --- | --- |
| `info` | Open service without an obvious exposure factor. |
| `low` | Hardening issue or visible version metadata. |
| `medium` | Sensitive management surface or interesting web interface. |
| `high` | Database, RDP, SMB, Redis, MongoDB, or confirmed high-impact exposure. |

The score is stored in JSON, HTML, CSV, and Markdown output.

## Checks as Plugins

Checks live under `network_scanner/checks/`. A check only needs to inherit from `Check` and be registered in `BUILTIN_CHECKS`:

```python
from network_scanner.checks.base import Check


class MissingHSTS(Check):
    name = "Missing HSTS"
    ports = (443, 8443)
    severity = "low"

    def run(self, host, port, service):
        ...
```

Checks should stay non-destructive and should return clear evidence plus remediation.

Port profiles live in `network_scanner/settings.py`.

## Comparing Scans

Use `--compare` with an older JSON report:

```bash
blackscan --target 10.0.0.0/24 --compare reports/scan_report_old.json --authorized
```

The new report includes new hosts, removed hosts, added ports, removed ports, new vulnerabilities, and resolved vulnerabilities.

## External Tools

BlackScan detects whether common recon tools are installed:

```bash
blackscan --list-external-tools
```

External tools are optional. They are not launched automatically by scans.

## Development

```bash
python -m unittest
python -m ruff check .
```

## GitHub Checklist

- Keep generated reports out of commits; `.gitignore` already excludes them.
- Open PRs with tests for scanner logic, parsing, and report generation.
- Do not add destructive checks, password spraying, brute force, or exploit execution.
