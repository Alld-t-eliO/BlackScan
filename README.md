# BlackScan

BlackScan is an authorized network scanner written in Python for infrastructure where you have explicit permission to scan. All scan results come from real network responses; there is no simulation mode.

It performs host discovery, TCP port scanning, lightweight service fingerprinting, basic HTTP/TLS checks, risk scoring, and report generation. It is not a replacement for mature tools such as Nmap or commercial vulnerability scanners.

## Screenshots

### Main Menu

![BlackScan TUI main menu](docs/images/blackscan-home.png)

### Scan Example

![BlackScan scan progress and results](docs/images/blackscan-scan-example.png)

## Scope and Safety

- Use BlackScan only on systems you own or are explicitly authorized to assess.
- The CLI requires `--authorized` before scanning.
- Intrusive checks are disabled by default and require `--intrusive-checks`.
- Automatic exploitation is disabled. The legacy `auto_exploit` module only returns review context or raises a safety error.
- Credential-audit compatibility helpers are guarded, capped, and not exposed by the main CLI. Experimental source files are separate from the scanner.

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
- Interactive TUI for configuring scans, saving reusable target profiles, managing payload wordlists, enabling external enrichment, and reviewing generated JSON reports.
- Optional comparison against a previous JSON report.
- Vulnerability trend analysis across multiple JSON reports.
- Detection of external tools such as `nmap`, `nuclei`, `httpx`, `subfinder`, `dnsx`, `whois`, `dig`, `ffuf`, `feroxbuster`, `naabu`, `katana`, `sherlock`, and `recon-ng`.
- Optional external enrichment during scans with structured output in JSON, HTML, CSV, and Markdown reports.

## Installation

Python 3.10 or newer is required.

Recommended setup after cloning:

```bash
git clone <repository-url>
cd BlackScan
chmod +x install.sh
./install.sh
source venv/bin/activate
blackscan --help
```

The installer creates a local `venv`, upgrades the build tools, installs BlackScan in editable mode, creates `reports/` and `network_scanner/payloads/payloads/`, and verifies that the CLI can start.

For optional credential-audit dependencies:

```bash
./install.sh --audit
```

For development and tests:

```bash
./install.sh --dev
```

If `python3` is not the Python executable you want to use:

```bash
PYTHON=/path/to/python3 ./install.sh
```

## Update

To get the latest version after cloning:

```bash
cd BlackScan
git pull
./install.sh
source venv/bin/activate
blackscan --help
```

If the virtual environment is already active, you can also refresh the editable install:

```bash
pip install -e .
```

## Usage

Show the CLI help:

```bash
blackscan --help
```

Run a small authorized scan:

```bash
blackscan -t 192.168.56.0/24 --authorized --profile quick
```

Scan selected ports:

```bash
blackscan -t 192.168.56.10 --authorized --ports 22,80,443,8000-8010
```

Run web-focused checks:

```bash
blackscan -t 192.168.56.10 --authorized --profile web
```

Route HTTP/HTTPS fingerprinting through a proxy:

```bash
blackscan -t 192.168.56.10 --authorized --profile web --proxy http://127.0.0.1:8080
```

Enable application-level checks on authorized targets:

```bash
blackscan -t 192.168.56.10 --authorized --profile internal --intrusive-checks
```

Run available external enrichment tools and include their output in the final reports:

```bash
blackscan -t example.com --authorized --profile web --external-enrichment
```

External enrichment is automatic for `--profile full` and `-a` scans. For other profiles, enable it with `--external-enrichment` or the TUI `External Enrichment` field. It uses only tools already installed on the machine.

The enrichment pipeline runs tools sequentially and lets each step feed the next one:

```text
whois -> dig -> subfinder -> dnsx -> naabu -> nmap -> httpx -> katana -> ffuf -> feroxbuster -> nuclei -> sherlock (inventory only)
```

`recon-ng` and `sherlock` are detected and reported but not auto-executed: the former is interactive and the latter searches usernames, not network services. Discovered subdomains are inventory only; they require a separate explicit scan target. Final reports keep raw tool output and also include a normalized summary of domains, subdomains, DNS records, hosts, ports, URLs, endpoints, paths, technologies, and findings.

Compare with an older JSON report:

```bash
blackscan -t 192.168.56.0/24 --authorized --compare reports/scan_report_previous.json
```

Analyze vulnerability evolution across existing reports:

```bash
blackscan --trend reports/scan_report_old.json reports/scan_report_new.json
```

List optional external tools detected on the machine:

```bash
blackscan --list-external-tools
```

Open the interactive terminal UI:

```bash
blackscan --tui
```

From the TUI you can start a new scan, create, edit, delete, or load saved target profiles, view/add/delete payload wordlists, confirm authorized scope, set target/profile/ports/proxy/options, enable external enrichment, list external tools, or open reports. Saved target profiles can be loaded from the `Profiles` page or directly from the `New Scan` settings with `[97] Load saved profile`. The TUI uses numbered choices: type the number shown on screen and press Enter.

You can drop payload wordlists directly into the repository `network_scanner/payloads/payloads/` folder. Text payload files appear in the TUI `Payloads` page using their filename without the extension as the payload name. Python files and hidden files are ignored.

Open a specific JSON report directly in the report viewer:

```bash
blackscan --tui reports/scan_report_20260902_173005.json
```

You can also run the module directly without activating the environment:

```bash
venv/bin/python -m network_scanner --help
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

- `network_scanner/scanner/main.py`: CLI entry point.
- `network_scanner/scanner/scan.py`: scan orchestration and `NetworkScanner`.
- `network_scanner/scanner/report.py`: JSON, HTML, CSV, and Markdown report generation.
- `network_scanner/scanner/comparaison.py`: vulnerability trend report generation.
- `network_scanner/scanner/parser.py`: CLI parser, port parsing, and proxy validation.
- `network_scanner/core/ui.py`: interactive TUI for scan setup, target profiles, payload wordlists, and JSON report review.
- `network_scanner/settings.py`: scan profile and port defaults.
- `network_scanner/modules/ping_sweep.py`: host discovery.
- `network_scanner/modules/port_scanner.py`: TCP port scanner.
- `network_scanner/modules/service_scan.py`: service, HTTP, and TLS fingerprinting.
- `network_scanner/checks/`: vulnerability check framework and built-in checks.
- `network_scanner/modules/risk.py`: service risk scoring.
- `network_scanner/modules/report_diff.py`: report comparison and vulnerability trend analysis.
- `network_scanner/modules/brute_force/`: guarded credential-audit compatibility helpers.
- `network_scanner/payloads/base.py`: payload wordlist loading, user payload storage, and generated payload helpers.
- `network_scanner/payloads/payloads/`: brute-force compatibility modules and drop-in folder for user-provided `.txt` payload wordlists.
- `config/exploit_config.yaml`: compatibility config documenting disabled offensive workflows.
- `tests/`: unit tests.

## Development

Run tests:

```bash
source venv/bin/activate
python -m unittest discover -s tests -v
```

Run lint:

```bash
ruff check .
```

The repository CI runs both commands across Python 3.10, 3.11, and 3.12.

## Troubleshooting

If `blackscan` is not found, activate the virtual environment:

```bash
source venv/bin/activate
```

If installation fails while downloading packages, check internet access and rerun:

```bash
./install.sh
```

If macOS blocks execution of the installer, restore the executable bit:

```bash
chmod +x install.sh
```

## Execution and result integrity

- `--skip-discovery` scans the supplied IP/name/range even when ICMP and discovery probes fail. The maximum host limit still applies.
- `--no-external-enrichment` disables external commands even for the `full` profile.
- `--external-timeout 120` sets the time budget for each external command independently of socket timeouts.
- HTTPS verification stays enabled. Configure the appropriate CA trust and target hostname for your infrastructure; verification failures remain visible.
- Host discovery also probes selected ports, up to 32 discovery ports. For exhaustive coverage of filtered hosts, use `--skip-discovery`.
- The `full` profile is an extended TCP selection, not all 65535 ports. Use `--ports 1-65535` for all TCP ports. UDP scanning is not implemented.
- HTTP on an unknown port is probed when no passive banner is received; protocol detection remains heuristic.
- Sensitive-path findings require content evidence, not only an HTTP 200 response.
- External findings from Nuclei are included in vulnerability totals and risk scoring, including `critical` severity.
- Nmap covers at most 20 targets and the web mapping tools at most 10 URLs per scan; report notes identify these limits.
- External binaries and their data/templates must be installed separately. `httpx` must be the ProjectDiscovery tool, not the Python HTTP client executable.
- `ffuf` output is consumed as JSON lines. Missing tools, errors, and timeouts are listed per step.
- Adding payload wordlists does not register them as automatic actions or change external tool wordlists.

Each run writes a uniquely named JSON, HTML, CSV, and Markdown report, including when no hosts are discovered. JSON is written atomically. Scan status distinguishes `complete`, `partial`, `no_hosts`, and `interrupted`; errors are retained with their target and stage. A completed run does not establish that a target has no vulnerabilities.

CLI exit codes: `0` completed, `1` execution error, `2` invalid arguments/incomplete scan/no hosts, `130` interrupted. No synthetic findings are added. Unit-test fixtures live under `tests/` and are never loaded into scans.

Comparisons require matching target, ports, profile, and check settings. Partial scans cannot mark findings resolved. Trend analysis rejects incomplete scans. Proxy credentials and authentication headers are redacted from structured reports.

Experimental exploitation sources remain in `network_scanner/payloads/exploits/`. They are not part of the automatic scanner and are not validated production integrations. The original conflicting snippets are preserved under `docs/learning/`; the compatibility imports no longer execute them. The YAML file documents legacy settings and is not a runtime execution policy.
