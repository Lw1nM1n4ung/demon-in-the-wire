# Demon in the Wire

Automated security scanning orchestration toolkit. Chains multiple tools into a parallel async pipeline — discovers hosts, scans ports (with fallback scanners), detects web services, runs vulnerability scans, and generates multi-format reports.

## Pipeline

```
Phase 1: Host Discovery      nmap -sn + fping → merge + dedupe
Phase 2: Port Scanning        nmap → naabu → masscan (fallback chain)
Phase 3: Web Detection        async HTTP/HTTPS probing on all open ports
Phase 4: Vuln Scanning        nuclei + nmap --script=vuln (concurrent per host)
Phase 5: Report Generation    DOCX, XLSX, static HTML, interactive dashboard
```

If nmap finds no open ports on a host, the tool automatically falls back to **naabu**, then **masscan**. As soon as any scanner finds ports, the normal pipeline continues.

## Install

```bash
git clone https://github.com/Lw1nM1n4ung/demon-in-the-wire.git
cd demon-in-the-wire
pip install -e ".[dev]"
```

### System Dependencies

**Required:** `nmap`, `fping`

**Optional (auto-detected):** `nuclei`, `naabu`, `masscan`, `httpx`

```bash
# Debian/Ubuntu
sudo apt install nmap fping

# nuclei (ProjectDiscovery)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# naabu (ProjectDiscovery)
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# masscan
sudo apt install masscan
```

## Usage

### Full Scan

```bash
wireghost scan 192.168.1.0/24
```

### With Options

```bash
wireghost scan 10.0.0.0/24 \
    --output-dir ./results \
    --parallelism 20 \
    --formats html,docx,dashboard \
    --timeout 1800 \
    --verbose
```

### Generate Reports from Existing Scan Data

```bash
wireghost report ./output/192.168.1.0_24 --formats dashboard,docx,xlsx
```

### Configuration

```bash
# Create config file
wireghost config init

# View resolved config
wireghost config show
```

Edit `wireghost.yml` to set defaults:

```yaml
output_dir: ./output
parallelism: 10
tool_timeout: 3600
report_formats:
  - html
  - docx
  - xlsx
report_title: "Security Assessment Summary Report"
```

Config priority: CLI flags > environment variables > wireghost.yml > defaults.

### CLI Reference

```
wireghost scan <target>
    -o, --output PATH          Output directory (default: ./output)
    -j, --parallelism INT      Max concurrent scans (default: 10)
    --skip-nuclei              Skip nuclei web scanning
    --skip-vuln                Skip nmap vuln scanning
    -t, --timeout FLOAT        Per-tool timeout in seconds (default: 3600)
    -f, --formats TEXT         Report formats: html,docx,xlsx,dashboard
    --title TEXT               Report title
    -v, --verbose              Debug logging
    -c, --config PATH          Path to wireghost.yml

wireghost report <scan-dir>
    -o, --output PATH          Override report output directory
    -f, --formats TEXT         Report formats (default: html,docx,xlsx)
    --title TEXT               Report title

wireghost config [show|init]
```

## Docker

```bash
# Build and run
docker compose run wireghost scan 192.168.1.0/24

# Or build standalone
docker build -t demon-in-the-wire .
docker run --net=host -v $(pwd)/output:/data/output demon-in-the-wire scan 10.0.0.1
```

## Reports

| Format | File | Description |
|--------|------|-------------|
| **HTML** | `summary.html` | Static self-contained report with severity stats, findings table, host details |
| **Dashboard** | `dashboard.html` | Interactive report with Chart.js severity chart, filterable table, search, collapsible host panels |
| **DOCX** | `security_report.docx` | Professional Word document with executive summary, vulnerability breakdown, recommendations |
| **XLSX** | `ports_summary.xlsx` | Excel workbook with host/port summary and detailed port sheets |

## Output Structure

```
output/<target>/
    all/
        live_host/live.txt         # Discovered IPs
        web/web.txt                # Web service URLs
    ip/<IP>/
        nmap/xml/                  # Nmap scan results
        web/nuclei/                # Nuclei findings
        vuln/                      # Vulnerability scan output
    reports/
        summary.html
        dashboard.html
        security_report.docx
        ports_summary.xlsx
```

## Architecture

```
src/wireghost/
    cli.py                  # Typer CLI (scan, report, config)
    config.py               # ScanConfig with YAML/env/CLI layering
    models/                 # Typed dataclasses: Severity, Host, Port, Finding, ScanReport
    parsers/                # nmap XML, nuclei JSON, naabu JSON, masscan XML
    pipeline/               # Async phases: discovery, portscan, webdetect, vulnscan, orchestrator
    reports/                # ReportEngine + renderers (DOCX, XLSX, HTML, Dashboard)
    utils/                  # Subprocess runner, network helpers, output tree, logging
```

All parsers produce the same typed model objects. All renderers consume a single `ScanReport`. No duplication.

## Tests

```bash
python -m pytest tests/ -v
```

## License

For authorized security testing, penetration testing engagements, and educational purposes only.
