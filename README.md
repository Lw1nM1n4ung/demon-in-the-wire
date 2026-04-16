# Wire_Ghost

Automated security scanning orchestration toolkit. Chains multiple tools into an 8-phase async pipeline -- discovers hosts, scans ports (with fallback scanners), detects web services and CMS platforms, enumerates services, runs vulnerability scans, maps known exploits, and generates multi-format reports.

**v2.0.0** | Python 3.11+ | Docker

## Features

- **8-phase async pipeline** -- discovery, port scan, web detect, CMS scan, service enum, vuln scan, exploit detection, reporting
- **Scanner fallback chain** -- nmap → naabu → masscan (auto-fallback when a scanner finds no ports)
- **18-service enumeration** -- SSH, FTP, Redis, MongoDB, MySQL, PostgreSQL, SMTP, VNC, RDP, LDAP, Memcached, Elasticsearch, Docker API, Telnet, and more (pure Python, no brute force)
- **CMS detection** -- auto-triggers WPScan when WordPress is detected
- **External nuclei templates** -- configurable template directories with batched execution (5000/batch) to limit resource usage
- **Version-aware exploit detection** -- searchsploit per detected software version, linked to Exploit-DB
- **4 report formats** -- HTML, DOCX, XLSX, Interactive Dashboard
- **Interactive dashboard** -- Chart.js charts, severity filtering, real-time search, CVE/CWE/CVSS badges, HTTP request/response evidence, curl reproduce commands
- **Web portal** -- Django REST API + SPA frontend with authentication, scan management, scheduled scans, scan policies, report builder
- **Docker Compose stack** -- MySQL, Redis, Celery workers, Nginx reverse proxy
- **Pre-built Docker image** -- `callmedemon/wireghost` on Docker Hub
- **Layered configuration** -- CLI flags > environment variables (WIREGHOST_*) > wireghost.yml > defaults

## Pipeline

```
Phase 1: Host Discovery        nmap -sn + fping → merge + dedupe
Phase 2: Port Scanning         nmap -sV -sC -O → naabu → masscan (fallback chain)
Phase 3: Web Detection         async HTTP/HTTPS probing + httpx tech-detect
Phase 4: CMS Scanning          WordPress detection → WPScan (auto-trigger)
Phase 5: Service Enumeration   18 services, pure Python (no brute force)
Phase 6: Vuln Scanning         nuclei + nmap --script=vuln (parallel per host)
Phase 7: Exploit Detection     searchsploit per detected version → Exploit-DB
Phase 8: Report Generation     DOCX, XLSX, HTML, Interactive Dashboard
```

If nmap finds no open ports on a host, the tool automatically falls back to **naabu**, then **masscan**. As soon as any scanner finds ports, the normal pipeline continues.

## Quick Start

### CLI

```bash
git clone https://github.com/Lw1nM1n4ung/demon-in-the-wire.git
cd demon-in-the-wire
pip install -e .
wireghost scan 192.168.1.0/24
```

### Docker (standalone scanner)

```bash
docker pull callmedemon/wireghost
docker run --net=host -v $(pwd)/output:/data/output callmedemon/wireghost scan 192.168.1.0/24
```

### Docker Compose (full stack with web portal)

```bash
cp .env.example .env       # fill in passwords and secret key
docker compose up -d       # starts MySQL, Redis, API, worker, beat, portal
```

Web portal at **http://localhost:9995** -- create an account on first launch.

## Install

```bash
git clone https://github.com/Lw1nM1n4ung/demon-in-the-wire.git
cd demon-in-the-wire
pip install -e ".[dev]"
```

### System Dependencies

**Required:** `nmap`, `fping`

**Optional (auto-detected):** `nuclei`, `naabu`, `masscan`, `httpx`, `wpscan`, `searchsploit`, `scannerctl`

```bash
# Debian/Ubuntu
sudo apt install nmap fping masscan

# nuclei (ProjectDiscovery)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# naabu (ProjectDiscovery)
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# httpx (ProjectDiscovery)
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# searchsploit (Exploit-DB)
git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb
ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

# wpscan (WordPress scanner)
gem install wpscan
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

### External Nuclei Templates

```bash
# Run both default + external templates
wireghost scan 10.0.0.1 --nuclei-templates /path/to/templates/

# Run external templates only (skip defaults)
wireghost scan 10.0.0.1 --nuclei-templates /path/to/templates/ --no-nuclei-default-templates
```

Large template sets (37K+) are automatically batched into chunks of 5000 to limit CPU/RAM usage.

### Generate Reports from Existing Scan Data

```bash
wireghost report ./output/192.168.1.0_24 --formats dashboard,docx,xlsx
```

### Update Tools & Feeds

```bash
wireghost update            # update everything
wireghost update --tools    # nuclei, naabu, httpx binaries + apt packages
wireghost update --feeds    # nuclei templates + searchsploit db + OpenVAS NASL
wireghost update --self     # git pull + pip install
```

### Configuration

```bash
wireghost config init       # create wireghost.yml from template
wireghost config show       # display resolved configuration
```

Edit `wireghost.yml` to set defaults:

```yaml
output_dir: ./output
parallelism: 10
skip_nuclei: false
skip_vuln: false
tool_timeout: 3600
report_formats:
  - html
  - docx
  - xlsx
report_title: "Security Assessment Summary Report"
verbose: false
```

Config priority: **CLI flags > environment variables (`WIREGHOST_*`) > wireghost.yml > defaults**.

## CLI Reference

### `wireghost scan <target>`

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output PATH` | Output directory | `./output` |
| `-j, --parallelism INT` | Max concurrent host scans | `10` |
| `--skip-nuclei` | Skip nuclei web scanning | off |
| `--skip-vuln` | Skip nmap vuln scanning | off |
| `--skip-openvas / --no-skip-openvas` | Skip/enable OpenVAS scanning | skip |
| `--nuclei-templates PATH` | External nuclei template directory | none |
| `--nuclei-default-templates / --no-nuclei-default-templates` | Include default nuclei templates | on |
| `-t, --timeout FLOAT` | Per-tool timeout (seconds) | `3600` |
| `-f, --formats TEXT` | Report formats: html, docx, xlsx, dashboard | `html,docx,xlsx` |
| `--title TEXT` | Report title | auto |
| `-v, --verbose` | Debug logging | off |
| `-c, --config PATH` | Path to wireghost.yml | auto-detect |

### `wireghost report <scan-dir>`

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output PATH` | Report output directory | `<scan-dir>/reports` |
| `-f, --formats TEXT` | Report formats | `html,docx,xlsx` |
| `--title TEXT` | Report title | auto |

### `wireghost update`

| Flag | Description |
|------|-------------|
| `--tools` | Update security tool binaries |
| `--feeds` | Update vulnerability feeds |
| `--self` | Update wireghost (git pull + pip install) |
| *(no flags)* | Update everything |

### `wireghost config [show|init]`

## Web Portal

Django REST API backend + JavaScript SPA frontend. Managed entirely through Docker Compose.

### Pages

Dashboard, Scans, Scan Detail, Findings, Finding Detail, Hosts, Host Detail, Reports, Report Builder, New Scan, Scan Policies, Scheduled Scans, Scan Queue, Settings, Users, Network Topology

### API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/dashboard/` | Aggregate scan statistics |
| `GET/POST /api/scans/` | List and create scans |
| `GET /api/scans/<id>/` | Scan detail with hosts and findings |
| `GET /api/hosts/` | Discovered hosts |
| `GET /api/findings/` | Vulnerability findings (filterable) |
| `POST /api/auth/login/` | User authentication |
| `GET/POST /api/site-config/` | Site configuration |
| `GET /api/report-config/` | Report customization |

Full API documentation in [API.md](API.md).

## Docker

### Pre-built Image

```bash
docker pull callmedemon/wireghost
docker run --net=host -v $(pwd)/output:/data/output callmedemon/wireghost scan <target>
```

The Docker image includes all tools pre-installed: nmap, nuclei, naabu, masscan, httpx, fping, searchsploit, scannerctl.

### Docker Compose Stack

```bash
cp .env.example .env       # fill in MYSQL_PASSWORD, REDIS_PASSWORD, DJANGO_SECRET_KEY
docker compose up -d
```

| Service | Image | Description | Port |
|---------|-------|-------------|------|
| `db` | mysql:8.0 | MySQL database | 3306 (localhost) |
| `redis` | redis:7-alpine | Celery broker + result backend | 6379 (localhost) |
| `api` | web_portal/Dockerfile | Django REST API (Gunicorn) | 8000 (localhost) |
| `worker` | web_portal/Dockerfile | Celery worker (scan execution) | -- |
| `beat` | web_portal/Dockerfile | Celery Beat (scheduled scans) | -- |
| `portal` | nginx:alpine | Web portal (Nginx reverse proxy) | **9995** |
| `wireghost` | callmedemon/wireghost | Standalone scanner (tools profile) | host network |

### External Nuclei Templates

Place `.tar.gz` template archives in the `templates/` directory. They are automatically extracted when Docker containers start.

```bash
ls templates/
# filtered-templates.tar.gz   new-templates.tar.gz   README
```

### Standalone Tool Containers

```bash
docker compose run --rm wireghost scan 10.0.0.0/24
docker compose run --rm nmap -sV -p- 10.0.0.1
docker compose run --rm nuclei -u http://10.0.0.1
```

## Reports

| Format | File | Description |
|--------|------|-------------|
| **HTML** | `summary.html` | Static self-contained report with severity stats, findings table, host details |
| **Dashboard** | `dashboard.html` | Interactive report -- Chart.js severity/source charts, severity filter toggles, real-time search, sort by severity/host, CVE/CWE/CVSS badges, HTTP request/response evidence, curl reproduce commands, expandable host panels, known exploits table, detected technologies, web services, print-friendly |
| **DOCX** | `security_report.docx` | Professional Word document -- cover page, executive summary, target subnets, live hosts, open ports, identified issues with evidence, host details |
| **XLSX** | `ports_summary.xlsx` | Excel workbook with host/port summary and detailed port sheets |

## Output Structure

```
output/<target>/
    all/
        live_host/live.txt         # Discovered IPs
        web/web.txt                # Web service URLs
    ips/<IP>/
        nmap_xml/portscan.xml      # Nmap scan results
        web/
            endpoints.txt          # Detected web endpoints
            tech_detect.json       # Technology detection (httpx)
            nuclei.json            # Nuclei web findings
        vuln/
            nmap_vuln.xml          # Nmap vuln script output
            nuclei.json            # Nuclei vuln findings
            searchsploit_*.json    # Exploit-DB matches
        service_enum/              # Service enumeration results
        cms/                       # CMS scan results (WPScan)
    reports/
        summary.html
        dashboard.html
        security_report.docx
        ports_summary.xlsx
```

## Architecture

```
src/wireghost/
    cli.py                  # Typer CLI (scan, report, config, update)
    config.py               # ScanConfig with YAML/env/CLI layering
    models/                 # Typed dataclasses: Severity, Host, Port, Finding, ScanReport
    parsers/                # nmap, nuclei, naabu, masscan, openvas, searchsploit, wpscan
    pipeline/
        orchestrator.py     # Async pipeline coordinator
        discovery.py        # Host discovery (nmap -sn + fping)
        portscan.py         # Port scanning with fallback chain
        webdetect.py        # Web service detection + httpx tech-detect
        cms_scan.py         # CMS detection + WPScan
        service_enum.py     # 18-service enumeration (pure Python)
        vulnscan.py         # nuclei + nmap --script=vuln + searchsploit
    reports/
        engine.py           # Report dispatcher
        html_renderer.py    # Static HTML report
        dashboard.py        # Interactive dashboard (Jinja2 + Chart.js)
        docx_renderer.py    # Professional DOCX report
        xlsx_renderer.py    # Excel workbook
    utils/                  # Subprocess runner, network helpers, output tree, logging

web_portal/                 # Django REST API + Celery tasks
web/                        # Frontend SPA (HTML/CSS/JS)
```

All parsers produce the same typed model objects. All renderers consume a single `ScanReport`. No duplication.

## Tests

```bash
python -m pytest tests/ -v
```

## License

For authorized security testing, penetration testing engagements, and educational purposes only.
