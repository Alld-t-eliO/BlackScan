BlackScan

BlackScan is an authorized network security scanner written in Python for infrastructure where you have explicit permission to scan.

It performs host discovery, TCP port scanning, lightweight service fingerprinting, HTTP/TLS checks, vulnerability checks, risk scoring, optional external enrichment, and report generation.

BlackScan is designed as a modular scanner rather than a replacement for mature tools such as Nmap or commercial vulnerability-management platforms.

Scope and Safety

Use BlackScan only on systems you own or are explicitly authorized to assess.

The CLI requires --authorized before scanning.

Intrusive application-level checks are disabled by default and require --intrusive-checks.

Automatic exploitation is disabled in the normal scanner workflow.

Legacy or experimental exploitation-oriented sources are kept separate from the production scanning path.

Credential-audit compatibility helpers are guarded and are not exposed as automatic actions by the main CLI.

A completed scan does not prove that a target has no vulnerabilities.

Features

Network scanning

Host discovery using ICMP with TCP fallback probes.

Concurrent TCP port scanning.

Scan profiles:

quick

web

internal

full

stealth

Custom TCP port ranges.

Optional --skip-discovery mode.

Service names and banner collection.

Lightweight OS detection when sufficient information is available.

HTTP / HTTPS / TLS

HTTP status and title detection.

Redirect detection.

Selected HTTP headers and cookies.

Favicon hashing.

Common path probing.

Sensitive-path checks using content evidence rather than HTTP status alone.

TLS metadata and certificate verification summary.

Optional HTTP/HTTPS proxy support.

Vulnerability and risk analysis

Modular vulnerability-check framework.

Built-in exposure checks.

Severity and confidence-oriented findings.

Per-service risk scoring.

External findings can be incorporated into vulnerability totals and risk scoring when enrichment is enabled.

External enrichment

BlackScan can detect and optionally use external tools already installed on the machine, including:

nmap

nuclei

ProjectDiscovery httpx

subfinder

dnsx

whois

dig

ffuf

feroxbuster

naabu

katana

sherlock

recon-ng

The enrichment pipeline is designed to pass useful output from one step to the next:

whois
  -> dig
  -> subfinder
  -> dnsx
  -> naabu
  -> nmap
  -> httpx
  -> katana
  -> ffuf
  -> feroxbuster
  -> nuclei
  -> sherlock (inventory only)

recon-ng and sherlock are detected and reported but are not automatically executed as normal network-scanning steps. Discovered subdomains are inventory data and are not silently converted into additional scan targets.

External tools, templates and databases are installed separately from BlackScan.

Interactive TUI

Start the terminal interface with:

blackscan --tui

The TUI can be used to:

configure a scan;

select a target and profile;

configure ports;

configure HTTP/HTTPS proxy settings;

confirm the authorized scope;

manage saved target profiles;

manage payload wordlists;

enable external enrichment;

list detected external tools;

open generated JSON reports.

A JSON report can also be opened directly:

blackscan --tui reports/scan_report_<timestamp>.json

Installation

Python 3.10 or newer is required.

git clone <repository-url>
cd BlackScan
chmod +x install.sh
./install.sh
source venv/bin/activate
blackscan --help

The installer creates a local virtual environment, installs BlackScan in editable mode, creates the local report/payload directories, and verifies that the CLI starts.

Development installation

./install.sh --dev

This installs the development dependencies declared by the project.

If a specific Python executable must be used:

PYTHON=/path/to/python3 ./install.sh

Usage

Basic authorized scan

blackscan -t 192.168.56.0/24 --authorized --profile quick

Scan selected ports

blackscan -t 192.168.56.10 --authorized --ports 22,80,443,8000-8010

Web-focused scan

blackscan -t 192.168.56.10 --authorized --profile web

HTTP/HTTPS fingerprinting through a proxy

blackscan -t 192.168.56.10 --authorized --profile web --proxy http://127.0.0.1:8080

The --proxy option currently applies to the HTTP/HTTPS fingerprinting layer. It should not be confused with the newer global execution-routing layer described below.

Application-level checks

blackscan -t 192.168.56.10 --authorized --profile internal --intrusive-checks

Only use intrusive checks when the authorization explicitly covers them.

External enrichment

blackscan -t example.com --authorized --profile web --external-enrichment

External enrichment is enabled automatically by the profiles that request it and can be disabled with:

blackscan -t example.com --authorized --profile full --no-external-enrichment

Compare reports

blackscan -t 192.168.56.0/24   --authorized   --compare reports/scan_report_previous.json

Trend analysis

blackscan --trend   reports/scan_report_old.json   reports/scan_report_new.json

List detected external tools

blackscan --list-external-tools

Run without activating the virtual environment

venv/bin/python -m network_scanner --help

Execution routing: LOCAL / PROXY / VPS

A separate execution-routing layer is currently being developed under:

network_scanner/vps_proxy/

Its purpose is to let BlackScan select where an execution backend should operate:

                         BlackScan
                            |
                            v
                  vps_proxy/main.py
                    Orchestrator
                            |
              +-------------+-------------+
              |             |             |
            LOCAL         PROXY           VPS
              |             |             |
              v             v             v
        LocalBackend    ProxyManager   VPSManager
                                            |
                                            v
                                     SSHConnection

The global mode is selected from config.py:

EXECUTION_MODE = "local"

Supported values are:

local
proxy
vps

LOCAL

Uses the local execution backend.

PROXY

Uses the proxy backend defined under:

network_scanner/vps_proxy/proxy/

This is separate from the existing --proxy option used specifically by HTTP/HTTPS fingerprinting.

VPS

Uses:

network_scanner/vps_proxy/vps/

The VPS backend uses an SSH connection configured in vps_proxy/vps/config.py.

The Mac and the VPS are expected to have SSH access configured beforehand, for example with an SSH key.

Current state of the routing layer

The LOCAL/PROXY/VPS layer is currently an orchestration foundation.

The backend interface is designed around:

connect()
run(target, options=None)
disconnect()

The current ProxyManager and VPSManager validate/select their backend and expose this common interface. Full migration of the scanner pipeline so that all scan stages actually execute remotely through a proxy or VPS is a separate integration step.

In other words:

Scanner logic
     !=
Execution location

The goal is to keep the scanner modules independent from whether execution happens locally, through a proxy, or on a VPS.

Project Layout

BlackScan/
├── config/
│   └── exploit_config.yaml
├── docs/
├── reports/
├── tests/
│   ├── __init__.py
│   └── test_scanner.py
├── network_scanner/
│   ├── __init__.py
│   ├── __main__.py
│   ├── main.py
│   ├── local.py
│   ├── settings.py
│   ├── core/
│   │   └── ui.py
│   ├── checks/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   └── builtin.py
│   ├── modules/
│   │   ├── auto_exploit.py
│   │   ├── external_tools.py
│   │   ├── interactive.py
│   │   ├── os_detection.py
│   │   ├── ping_sweep.py
│   │   ├── port_scanner.py
│   │   ├── report_diff.py
│   │   ├── risk.py
│   │   ├── service_scan.py
│   │   ├── vulnerability.py
│   │   └── brute_force/
│   ├── payloads/
│   │   ├── base.py
│   │   ├── payloads/
│   │   └── exploits/
│   ├── scanner/
│   │   ├── main.py
│   │   ├── scan.py
│   │   ├── parser.py
│   │   ├── report.py
│   │   └── comparaison.py
│   ├── utils/
│   │   ├── logger.py
│   │   └── utils.py
│   └── vps_proxy/
│       ├── __init__.py
│       ├── main.py
│       ├── local/
│       ├── proxy/
│       │   ├── __init__.py
│       │   ├── config.py
│       │   └── manager.py
│       └── vps/
│           ├── __init__.py
│           ├── config.py
│           ├── manager.py
│           └── ssh.py
├── .gitignore
├── CONTRIBUTING.md
├── LICENSE
├── README.md
├── SECURITY.md
├── config.py
├── install.sh
├── pyproject.toml
├── requirements.txt
└── struct.txt

Main Components

Component

Role

network_scanner/scanner/main.py

CLI entry point

network_scanner/scanner/scan.py

Scan orchestration

network_scanner/scanner/parser.py

CLI argument parsing and validation

network_scanner/scanner/report.py

JSON/HTML/CSV/Markdown reports

network_scanner/scanner/comparaison.py

Report comparison/trend analysis

network_scanner/modules/ping_sweep.py

Host discovery

network_scanner/modules/port_scanner.py

TCP scanning

network_scanner/modules/service_scan.py

Service/HTTP/TLS fingerprinting

network_scanner/checks/

Vulnerability-check framework

network_scanner/modules/vulnerability.py

Vulnerability-check execution

network_scanner/modules/risk.py

Risk scoring

network_scanner/modules/external_tools.py

External-tool enrichment

network_scanner/core/ui.py

Interactive TUI

network_scanner/local.py

Local execution backend

network_scanner/vps_proxy/main.py

Execution orchestrator

network_scanner/vps_proxy/proxy/

Proxy backend

network_scanner/vps_proxy/vps/

VPS backend and SSH

config.py

Global configuration

tests/

Automated tests

Reports

Reports are normally written to:

reports/

Each scan can generate:

scan_report_<timestamp>.json
scan_report_<timestamp>.html
scan_report_<timestamp>.csv
scan_report_<timestamp>.md

Trend analysis generates:

vulnerability_trend_<timestamp>.json
vulnerability_trend_<timestamp>.md

Reports preserve scan status and errors instead of turning failed discovery or incomplete execution into a false "no vulnerability" result.

Execution and Result Integrity

--skip-discovery can scan the supplied target even when discovery probes fail, while the configured host limit still applies.

--no-external-enrichment disables external commands even for profiles that normally enable enrichment.

--external-timeout controls the time budget for external commands independently from socket timeouts.

HTTPS certificate verification remains enabled.

Discovery uses selected TCP probes as a fallback to ICMP.

The full profile is an extended TCP selection, not an automatic scan of all 65535 TCP ports.

UDP scanning is not implemented.

HTTP protocol detection on unknown ports is heuristic.

Sensitive-path findings require content evidence rather than a simple HTTP 200 response.

External findings are normalized before being incorporated into the final report.

External tools have explicit target/URL limits to prevent uncontrolled expansion of a scan.

Missing tools, errors and timeouts are retained in enrichment results.

User payload wordlists do not automatically create new actions.

Proxy credentials and authentication headers must be redacted from structured reports.

A partial or interrupted scan must not be interpreted as proof that the target is secure.

Development

Activate the environment:

source venv/bin/activate

Run tests:

python -m pytest

Run lint:

ruff check .

The project is configured for Python 3.10+.

Troubleshooting

If blackscan is not found:

source venv/bin/activate

If the installer is not executable on macOS:

chmod +x install.sh

Then:

./install.sh

If you need a specific Python executable:

PYTHON=/path/to/python3 ./install.sh

Design Direction

The project is intentionally moving toward a clean separation between:

Scanner
   |
   +--> discovery
   +--> ports
   +--> services
   +--> checks
   +--> risk
   +--> reporting

and:

Execution backend
   |
   +--> LOCAL
   +--> PROXY
   +--> VPS

This allows the scanner logic to remain independent from the machine or network path used to perform an authorized scan.
