# BlackScan

BlackScan is an educational, authorized network scanner written in Python. It is designed for lab use, VM ranges, and owned infrastructure where you have explicit permission to test.

It performs host discovery, TCP port scanning, lightweight service fingerprinting, basic HTTP/TLS checks, risk scoring, and report generation. It is not a replacement for mature tools such as Nmap or commercial vulnerability scanners.

## Scope and Safety

- Use BlackScan only on systems you own or are explicitly authorized to assess.
- The CLI requires `--authorized` before scanning.
- Intrusive checks are disabled by default and require `--intrusive-checks`.
- Automatic exploitation is disabled. The legacy `auto_exploit` module only returns review context or raises a safety error.
- Credential-audit helpers are guarded, capped, and not exposed by the main CLI.

## Features

- Host discovery by ICMP ping with TCP fallback probes.
- Concurrent TCP port scanning.
- Scan profiles: `quick`, `web`, `internal`, `full`, and `stealth`.
- HTTP fingerprinting: status, title, redirects, selected headers, cookies, favicon hash, common paths, and sensitive path probes.
- TLS metadata and certificate verification summary.
- Optional proxy support for HTTP/HTTPS fingerprinting requests.
- Lightweight vulnerability checks for common exposure patterns.
- Risk scoring per service.
- Reports in JSON, HTML, CSV, and Markdown.
- Interactive TUI for configuring scans and reviewing generated JSON reports.
- Optional comparison against a previous JSON report.
- Vulnerability trend analysis across multiple JSON reports.
- Detection of external tools such as `nmap`, `nuclei`, `httpx`, `subfinder`, and `dnsx`.

## Installation

Python 3.10, 3.11, or 3.12 is the supported range declared by the project metadata.

For core scanner use:

```bash
python -m pip install -e .
```

For development and all optional credential-audit dependencies:

```bash
python -m pip install -r requirements.txt
```

Optional extras are also available:

```bash
python -m pip install -e ".[dev]"
python -m pip install -e ".[audit]"
python -m pip install -e ".[ssh]"
python -m pip install -e ".[http]"
python -m pip install -e ".[mysql]"
```

## Usage

Show the CLI help:

```bash
python -m network_scanner --help
```

Run a small authorized scan:

```bash
python -m network_scanner -t 192.168.56.0/24 --authorized --profile quick
```

Scan selected ports:

```bash
python -m network_scanner -t 192.168.56.10 --authorized --ports 22,80,443,8000-8010
```

Run web-focused checks:

```bash
python -m network_scanner -t 192.168.56.10 --authorized --profile web
```

Route HTTP/HTTPS fingerprinting through a proxy:

```bash
python -m network_scanner -t 192.168.56.10 --authorized --profile web --proxy http://127.0.0.1:8080
```

Enable intrusive checks only inside an authorized lab:

```bash
python -m network_scanner -t 192.168.56.10 --authorized --profile internal --intrusive-checks
```

Compare with an older JSON report:

```bash
python -m network_scanner -t 192.168.56.0/24 --authorized --compare reports/scan_report_previous.json
```

Analyze vulnerability evolution across existing reports:

```bash
python -m network_scanner --trend reports/scan_report_old.json reports/scan_report_new.json
```

List optional external tools detected on the machine:

```bash
python -m network_scanner --list-external-tools
```

Open the interactive terminal UI:

```bash
python -m network_scanner --tui
```

From the TUI you can start a new scan, confirm authorized scope, set target/profile/ports/proxy/options, list external tools, or open reports.

Open a specific JSON report directly in the report viewer:

```bash
python -m network_scanner --tui reports/scan_report_20260902_173005.json
```

## Reports

By default reports are written to `reports/`:

- `scan_report_<timestamp>.json`
- `scan_report_<timestamp>.html`
- `scan_report_<timestamp>.csv`
- `scan_report_<timestamp>.md`

Use `-o` or `--output-dir` to choose another output directory.

Trend analysis writes:

- `vulnerability_trend_<timestamp>.json`
- `vulnerability_trend_<timestamp>.md`

## Project Layout

- `network_scanner/scanner.py`: main CLI and report generation.
- `network_scanner/core/ui.py`: interactive TUI for scan setup and JSON report review.
- `network_scanner/settings.py`: scan profile and port defaults.
- `network_scanner/modules/ping_sweep.py`: host discovery.
- `network_scanner/modules/port_scanner.py`: TCP port scanner.
- `network_scanner/modules/service_scan.py`: service, HTTP, and TLS fingerprinting.
- `network_scanner/checks/`: vulnerability check framework and built-in checks.
- `network_scanner/modules/risk.py`: service risk scoring.
- `network_scanner/modules/report_diff.py`: report comparison and vulnerability trend analysis.
- `network_scanner/modules/brute_force/`: guarded credential-audit helpers for lab use.
- `config/exploit_config.yaml`: compatibility config documenting disabled offensive workflows.
- `tests/`: unit tests.

## Development

Run tests:

```bash
python -m unittest discover -s tests -v
```

Run lint:

```bash
python -m ruff check .
```

The repository CI runs both commands across Python 3.10, 3.11, and 3.12.

## VM Lab Notes

For educational testing, use an isolated host-only or NAT VM network. Good test targets are intentionally vulnerable lab machines or small services you start yourself. Keep scans limited at first:

```bash
python -m network_scanner -t 192.168.56.0/24 --authorized --profile quick --timeout 1
```

Increase scope only after confirming the target range and VM network are correct.
