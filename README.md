# Wire\_Ghost

Automated vulnerability scanner and attack surface management platform. Chains **nmap, nuclei, naabu, masscan, httpx, gowitness, wpscan, and searchsploit** into an 8-phase async pipeline — discovers hosts, scans ports (with fallback scanners), detects web services and CMS platforms, enumerates 18 services, runs vulnerability scans, maps known exploits, captures screenshots, and generates professional reports. Ships as both a standalone CLI tool and a full web portal with Django REST API, Telegram bot, scheduled scans, and role-based access control.

**v2.0** · Python 3.12 · Docker · MySQL · Redis · Celery

---

## Table of Contents

- [Features](#features)
- [System Requirements](#system-requirements)
- [Quick Start — Docker Compose](#quick-start--docker-compose)
- [Quick Start — CLI](#quick-start--cli)
- [Quick Start — Docker Hub](#quick-start--docker-hub)
- [CLI Reference](#cli-reference)
- [Web Portal](#web-portal)
- [Telegram Bot](#telegram-bot)
- [Notifications](#notifications)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Management (wg-ctl)](#management-wg-ctl)
- [Updating](#updating-tools-and-feeds)
- [Backup & Restore](#backup--restore)
- [Security Model](#security-model)
- [Logging & Support](#logging--support)
- [Tests](#tests)
- [Project Layout](#project-layout)
- [Uninstall](#uninstall)
- [License](#license)

---

## Features

### Scanning Pipeline

- **8-phase async pipeline** — discovery, port scan, web detect, CMS scan, service enumeration, vulnerability scan, exploit detection, report generation
- **Scanner fallback chain** — nmap → naabu → masscan (auto-fallback when a scanner finds zero ports)
- **18-service enumeration** — SSH, FTP, Redis, MongoDB, MySQL, PostgreSQL, SMTP, VNC, RDP, LDAP, Memcached, Elasticsearch, Docker API, Telnet, and more (pure Python, no brute force)
- **CMS detection** — auto-triggers WPScan when WordPress is detected
- **External nuclei templates** — configurable template directories with batched execution (5000/batch) to limit resource usage
- **Version-aware exploit detection** — searchsploit per detected software version, linked to Exploit-DB
- **Web screenshots** — gowitness captures of discovered web services
- **SSRF-safe target validation** — blocks loopback, link-local, multicast, reserved, cloud metadata IPs; detects hex/octal/short-form IP encoding; resolves hostnames via getaddrinfo (IPv4+IPv6) against full blocklist

### Web Portal

- Django REST API + vanilla-JS SPA, served by nginx, orchestrated via Docker Compose (MySQL + Redis + Celery worker + Celery beat + Telegram bot)
- **Attack Surface Management dashboard** — KPIs (total assets, critical exposures, newly-discovered hosts, CVE count, attack surface score 0-100), severity trend chart (30-day stacked area), risk-by-source donut, newly-discovered list, top exposures, top technologies, filterable asset inventory
- **Asset inventory** — deduplicated `(ip, port, protocol)` records with `first_seen` / `last_seen` timestamps and computed `risk_score` (0-100), populated by every scan
- **Setup wizard** — first-launch admin creation flow with site branding, logo upload, and tool health check
- **Scan management** — launch, list, cancel, re-run; per-scan detail view with findings, hosts, screenshots, and topology
- **Scan policies** — reusable configuration templates (target, scan type, parallelism, timeouts, tool toggles)
- **Scheduled scans** — daily / weekly / biweekly / monthly, with timezone-aware execution times
- **Reports** — DOCX, XLSX, HTML, and interactive dashboard per scan
- **Network topology** — D3 force-directed graph visualization per scan

### Telegram Bot

- Full remote control — start/stop scans, check status, view results, download reports, manage schedules
- Inline keyboard navigation with role-gated menus and pagination
- Real-time notifications — scan completions, failures, critical findings, report delivery
- Account linking via 6-digit one-time codes
- No polling the web UI required — manage everything from Telegram

### Access Control

- **Three roles** — Owner (exactly one, created by setup wizard), Engineer (operator), Viewer (read-only)
- **Data-driven permissions** — 15 permission codes stored in MySQL, mapped to roles via `RolePermission` table
- **API tokens** — SHA-256 hashed, revocable, role-scoped, `wg_` prefixed for secret scanner detection
- Session auth with CSRF + optional token auth for programmatic access

### Reports

| Format | Description |
|--------|-------------|
| **DOCX** | Professional Word document — cover page, executive summary, target subnets, live hosts, open ports, identified issues, host details with evidence |
| **XLSX** | Excel workbook with host/port summary and detailed per-port sheets |
| **HTML** | Self-contained static report |
| **Dashboard** | Interactive per-scan Chart.js dashboard — severity stats, findings table, CVE/CWE/CVSS badges, HTTP request/response evidence, curl reproduce commands |

---

## System Requirements

### Minimum (small lab, single /24)

| Resource | Value |
|----------|-------|
| CPU | 4 cores |
| RAM | 8 GB |
| Disk | 40 GB SSD |
| OS | Linux (Ubuntu 22.04+ / Debian 12+ tested) |
| Network | Outbound HTTPS for tool/feed updates; inbound TCP 443 for the portal |

### Recommended (regular /16 scans, multiple concurrent)

| Resource | Value |
|----------|-------|
| CPU | 8 cores |
| RAM | 16 GB |
| Disk | 100 GB NVMe |
| Network | 1 Gbps |

### Software — Docker Compose (recommended)

| Tool | Version |
|------|---------|
| Docker Engine | 24+ |
| Docker Compose v2 | 2.20+ |
| A POSIX shell | bash or zsh |

Everything else — Python, Django, Celery, MySQL, Redis, nginx, nmap, nuclei, naabu, masscan, httpx, gowitness, searchsploit, fping — ships inside the compose stack.

### Software — CLI-only / bare-metal

| Tool | Version | Required? |
|------|---------|-----------|
| Python | 3.11+ | yes |
| nmap | 7.80+ | yes |
| fping | 5+ | yes |
| nuclei | v3+ | recommended |
| naabu | v2+ | optional (fallback scanner) |
| masscan | 1.3+ | optional (second fallback) |
| httpx (ProjectDiscovery) | any | optional (tech detection) |
| gowitness | v3+ | optional (web screenshots) |
| wpscan | 3.8+ | optional (WordPress CMS) |
| searchsploit | any | optional (exploit DB lookup) |

```bash
sudo apt install nmap fping masscan
pip install -e ".[dev]"
```

### Network Ports

| Port | Direction | Purpose |
|------|-----------|---------|
| 443/tcp | inbound | Web portal (nginx, HTTPS) |
| 80/tcp | inbound | HTTP → HTTPS redirect |
| 8000/tcp | loopback only | Django API (gunicorn) |
| 6379/tcp | container only | Redis |
| 3306/tcp | container only | MySQL |
| outbound HTTPS | egress | Nuclei templates, searchsploit DB updates |

---

## Quick Start — Docker Compose

### One-line Remote Install

```bash
curl -fsSL https://raw.githubusercontent.com/Lw1nM1n4ung/demon-in-the-wire/rewrite-v2/scripts/install-wireghost.sh | sudo bash
```

This auto-installs Docker + Compose if missing, clones the repo to `/opt/wireghost`, and runs the interactive installer.

### Manual Install

```bash
git clone https://github.com/Lw1nM1n4ung/demon-in-the-wire.git
cd demon-in-the-wire
sudo bash scripts/install.sh
```

The installer:
1. Checks prerequisites (Docker, Compose, disk, RAM)
2. Auto-generates cryptographic secrets (Django key, MySQL passwords, Redis password)
3. Prompts for hostname, port, protocol (all with sensible defaults)
4. Generates a self-signed TLS certificate (10-year RSA 2048)
5. Writes `.env` and `nginx.conf`
6. Builds and starts the Docker stack
7. Waits for health checks (DB, Redis, Django)

Portal is live at **`https://<hostname>:<port>/setup`**.

First visit runs the setup wizard — create the Owner account, set site branding, done. The Owner can then create Engineer and Viewer users from the Users page.

### Pre-built Images (fastest)

If you just want to pull pre-built images instead of building from source:

```bash
git clone https://github.com/Lw1nM1n4ung/demon-in-the-wire.git
cd demon-in-the-wire && git checkout rewrite-v2

# Create .env and certs/ (run the installer or copy from .env.example)
sudo bash scripts/install.sh

# Or if you already have .env and certs:
docker compose pull && docker compose up -d
```

Pre-built images on Docker Hub:

| Image | Size | Contains |
|-------|------|----------|
| `callmedemon/wireghost:web` | ~180 MB | Django API, Celery beat, Telegram bot |
| `callmedemon/wireghost:worker` | ~700 MB | Celery worker with all scan tools (nmap, nuclei, naabu, masscan, httpx, gowitness, searchsploit, fping) |
| `callmedemon/wireghost:latest` | ~700 MB | Standalone CLI scanner |

---

## Quick Start — CLI

```bash
git clone https://github.com/Lw1nM1n4ung/demon-in-the-wire.git
cd demon-in-the-wire
pip install -e ".[dev]"

wireghost scan 192.168.1.0/24
```

---

## Quick Start — Docker Hub

Run a single scan without cloning the repo:

```bash
docker pull callmedemon/wireghost
docker run --net=host -v $(pwd)/output:/data/output callmedemon/wireghost scan 192.168.1.0/24
```

---

## CLI Reference

```
wireghost scan <target>                          # Run full pipeline
wireghost report <scan-dir>                      # Regenerate reports from existing output
wireghost update [--tools | --feeds | --self]    # Update binaries, vuln feeds, or wireghost itself
wireghost config [show | init]                   # Show resolved config / create wireghost.yml
```

### `wireghost scan` Flags

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

### External Nuclei Templates

```bash
# Run both default + external templates
wireghost scan 10.0.0.1 --nuclei-templates /path/to/templates/

# Run external templates only
wireghost scan 10.0.0.1 --nuclei-templates /path/to/templates/ --no-nuclei-default-templates
```

Large template sets (37K+) are automatically batched into chunks of 5000.

For Docker Compose: drop `.tar.gz` archives into `templates/` and they'll be extracted into the worker container on start.

### Output Structure

```
output/<target>/
    all/
        live_host/live.txt           # Discovered IPs
        web/web.txt                  # Web service URLs
    ips/<IP>/
        nmap_xml/portscan.xml
        web/
            endpoints.txt
            tech_detect.json
            nuclei.json
        vuln/
            nmap_vuln.xml
            nuclei.json
            searchsploit_*.json
        service_enum/
        cms/
    reports/
        summary.html
        dashboard.html
        security_report.docx
        ports_summary.xlsx
```

When run from the portal, output lives under `/data/output/<target>/` inside the worker container (via the `scan_output` Docker volume).

---

## Web Portal

### Pages

| Page | Role | Description |
|------|------|-------------|
| **Dashboard** | All | Attack Surface Management — KPIs, trend charts, top exposures, technologies |
| **Scans** | Viewer+ | Scan list with status, target, findings count, duration |
| **Scan Detail** | Viewer+ | Per-scan findings, hosts, screenshots, topology, reports |
| **Findings** | All | Global vulnerability list with severity/source/search filters |
| **Finding Detail** | All | Full evidence — HTTP request/response, curl command, CVE/CWE/CVSS, references |
| **Hosts** | Viewer+ | Discovered hosts with port counts and technology fingerprints |
| **Host Detail** | Viewer+ | Ports, services, technologies, associated findings |
| **Assets** | Viewer+ | Deduplicated asset inventory with risk scores |
| **Topology** | Viewer+ | D3 force-directed network graph per scan |
| **New Scan** | Engineer+ | Launch a scan with target, type, parallelism, timeout, tool toggles |
| **Scan Queue** | Engineer+ | Active and pending scan tasks |
| **Scheduled Scans** | Engineer+ | Create/edit/toggle recurring scans |
| **Scan Policies** | Engineer+ | Reusable scan configuration templates |
| **Reports** | Viewer+ | Browse and download generated reports |
| **Report Builder** | Engineer+ | Configure report branding (logo, title, company, color, sections) |
| **Settings** | All | User profile, API tokens, notification preferences, Telegram linking |
| **Users** | Owner | Create/edit/delete users, assign roles |
| **Audit Log** | Owner | Full activity trail with actor, action, IP, timestamp |
| **Site Config** | Owner | Portal settings, schedule timezone, setup state |

### Roles

| Role | Permissions |
|------|-------------|
| **Owner** | Everything. Exactly one per install, created by setup wizard. Cannot be deleted or demoted. |
| **Engineer** | Run/cancel scans, manage policies and schedules, view all data, download reports, upload logos, manage own API keys. Cannot manage users or site config. |
| **Viewer** | Read-only: Dashboard, Scans, Hosts, Findings, Assets, Reports. Cannot create scans, manage users, or change settings. |

### Permission Codes

15 named permission codes backed by `Permission` + `RolePermission` tables in MySQL:

| Permission | Owner | Engineer | Viewer |
|------------|:-----:|:--------:|:------:|
| `dashboard:view` | x | x | x |
| `finding:read` | x | x | x |
| `scan:read` | x | x | x |
| `host:read` | x | x | x |
| `report:download` | x | x | x |
| `scan:write` | x | x | |
| `policy:read` | x | x | |
| `policy:write` | x | x | |
| `schedule:read` | x | x | |
| `schedule:write` | x | x | |
| `report:config:write` | x | x | |
| `report:logo:upload` | x | x | |
| `user:manage` | x | | |
| `site:config` | x | | |
| `site:reset` | x | | |
| `audit:view` | x | | |
| `support:export` | x | | |

Every API endpoint consults `request.user.has_permission(code)` — no hardcoded role strings in business logic. Permission lookups are cached in Redis (1-hour TTL per role).

---

## Telegram Bot

Wire\_Ghost includes a full-featured Telegram bot for remote control. The bot runs as a separate service in the Docker Compose stack, using long-polling to receive commands.

### Setup

1. Create a bot with [@BotFather](https://t.me/BotFather) on Telegram
2. Copy the bot token
3. In the Wire\_Ghost web portal: **Settings → Notifications → Bot Token** — paste the token
4. Optionally set a shared channel ID for site-wide notifications
5. The bot service auto-starts with the Docker stack

### Linking Your Account

Every Wire\_Ghost user links their Telegram account to receive DMs and use bot commands:

1. In the web portal: **Settings → Telegram → Generate Link Code**
2. A 6-digit code appears (valid for 5 minutes)
3. Send `/link <code>` to the bot in Telegram
4. Your Telegram account is now linked — the bot inherits your portal role and permissions

To unlink: send `/unlink` to the bot.

### Commands

#### Available to All Linked Users

| Command | Description |
|---------|-------------|
| `/start` | Initialize bot interaction |
| `/menu` | Main control panel with inline keyboard navigation |
| `/status` | Dashboard overview — active/completed scans, severity breakdown, next scheduled scan |
| `/scans` | List 10 most recent scans with status, target, findings, duration |
| `/scan <id>` | Scan detail — findings, screenshots, reports, cancel button (if running) |
| `/findings [severity]` | Browse findings with severity filter (critical/high/medium/low/info) |
| `/assets` | Discovered hosts with port counts and findings |
| `/help` | Command reference |
| `/link <code>` | Link Telegram to Wire\_Ghost account |
| `/unlink` | Disconnect Telegram account |

#### Engineer+ Only

| Command | Description |
|---------|-------------|
| `/newscan` | Create a new scan — select type (full/quick/port/web/service), enter target |
| `/cancel <id>` | Cancel a running scan with confirmation prompt |
| `/schedule` | List scheduled scans, enable/disable, trigger immediate run |
| `/report <id>` | Download scan reports (DOCX, XLSX, dashboard) as Telegram documents |

#### Owner Only

| Command | Description |
|---------|-------------|
| `/users` | List and manage user accounts |
| `/config` | View/edit site configuration |
| `/health` | System health — service status, DB, Redis, disk usage |

### Inline Keyboard Navigation

The bot uses inline keyboards for rich navigation instead of requiring typed commands:

```
Main Menu
├── Dashboard          → KPIs, severity stats, recent activity
├── Scans              → Paginated scan list (5/page)
│   └── Scan Detail    → Findings, Screenshots, Report, Cancel
├── Findings           → Severity filter buttons → paginated results
├── Assets             → Paginated host list → host detail
├── Schedules*         → List, toggle enable/disable, run-now
├── New Scan*          → Type selection → target input
├── Health**           → Service status, disk, DB
├── Config**           → Site settings
├── Users**            → User management
└── Help               → Command reference

* Engineer+ only    ** Owner only
```

Every menu button includes a Back button for navigation. Lists paginate at 5 items per page with Previous/Next controls.

### Bot Screenshots

When a scan captures web screenshots (via gowitness), the bot can send them as photo albums directly in the chat from the Scan Detail menu.

---

## Notifications

Wire\_Ghost sends real-time notifications through Telegram when important events occur.

### Event Types

| Event | Trigger | Content |
|-------|---------|---------|
| **Scan Complete** | Scan finishes successfully | Host count, findings count, severity breakdown, duration |
| **Scan Failed** | Scan errors out | Error message (truncated to 200 chars) |
| **Critical Found** | Critical-severity finding discovered | Finding details with severity badge |
| **Report Ready** | Report generation complete | Report type, download available via bot |

### Delivery Channels

1. **Shared Channel** — site-wide notifications to a configured Telegram channel/group (set by Owner in Settings)
2. **User DMs** — personal notifications to the scan creator's linked Telegram account
3. **Per-user toggles** — each user can enable/disable specific event types in Settings → Notifications

### Configuration

In the web portal under **Settings → Notifications**:

- **Bot Token** — the BotFather token (stored server-side only, never exposed to clients)
- **Shared Chat ID** — channel/group for site-wide alerts (format: `-1001234567890` for groups, `@channel_name` for public channels)
- **Per-user preferences** — each user toggles: scan complete, scan failed, critical findings

---

## API Reference

Base URL: `https://<host>:<port>/api/`

Authentication: Session cookie (browser) or `Authorization: Token wg_...` header (programmatic).

### Core Endpoints

| Method | Endpoint | Permission | Description |
|--------|----------|------------|-------------|
| GET | `/api/dashboard/` | `dashboard:view` | ASM KPIs, severity trends, top exposures, technologies |
| GET | `/api/assets/` | `host:read` | Deduplicated asset inventory (filterable: status, min_risk, has_cve, service) |
| GET/POST | `/api/scans/` | `scan:read` / `scan:write` | List and create scans |
| GET | `/api/scans/<id>/` | `scan:read` | Scan detail with hosts and findings |
| POST | `/api/scans/<id>/cancel/` | `scan:write` | Cancel a running scan |
| POST | `/api/scans/<id>/regenerate_reports/` | `scan:write` | Re-render reports with current branding |
| GET | `/api/hosts/` | `host:read` | Discovered hosts (global) |
| GET | `/api/hosts/<id>/` | `host:read` | Host detail with ports and technologies |
| GET | `/api/findings/` | `finding:read` | All findings (filterable: severity, source, scan, search) |
| GET | `/api/findings/<id>/` | `finding:read` | Finding detail with evidence, CVE/CWE, references |
| GET | `/api/reports/<id>/download/` | `report:download` | Download report file |
| GET/PUT | `/api/report-config/` | `report:config:write` | Report branding (title, company, logo, color, sections) |
| POST | `/api/report-config/logo/` | `report:logo:upload` | Upload custom logo |
| GET/POST | `/api/policies/` | `policy:read` / `policy:write` | Scan policies |
| GET/POST | `/api/schedules/` | `schedule:read` / `schedule:write` | Scheduled scans |
| POST | `/api/auth/login/` | public | Session authentication |
| POST | `/api/auth/logout/` | authenticated | End session |
| GET | `/api/auth/check/` | authenticated | Session validity check (204/401) |
| GET/POST | `/api/auth/users/` | `user:manage` | User management |
| GET/PUT | `/api/site-config/` | `site:config` | Site configuration |
| GET | `/api/audit-log/` | `audit:view` | Activity audit trail |
| GET | `/api/auth/tokens/` | authenticated | List own API tokens |
| POST | `/api/auth/tokens/` | authenticated | Create API token |
| DELETE | `/api/auth/tokens/<id>/revoke/` | authenticated | Revoke API token |
| GET/PUT | `/api/notifications/config/` | authenticated | Notification preferences |
| POST | `/api/notifications/test/` | authenticated | Send test notification |
| POST | `/api/auth/telegram-link-code/` | authenticated | Generate Telegram link code |

### Creating a Scan (POST /api/scans/)

```json
{
  "target": "192.168.1.0/24",
  "name": "Internal Sweep",
  "scan_type": "full",
  "parallelism": 10,
  "timeout": 3600,
  "report_formats": "dashboard,docx,xlsx",
  "version_detect": true,
  "os_detect": true,
  "service_enum": true,
  "skip_nuclei": false,
  "skip_openvas": true
}
```

Scan types: `full`, `quick`, `port`, `web`, `service`

### API Token Usage

```bash
# Create a token in the web portal: Settings → API Tokens → Create

# Use with any endpoint
curl -H "Authorization: Token wg_your_token_here" https://wireghost.local/api/scans/

# Tokens inherit the creating user's role permissions
# A Viewer token gets 403 on POST /api/scans/ (no scan:write)
# An Engineer token can create scans but not manage users
```

Full API documentation in [API.md](API.md).

---

## Configuration

### `.env` — Secrets and Deployment

Generated by `scripts/install.sh`. Template at `config/.env.example`.

| Variable | Default | Description |
|----------|---------|-------------|
| `DJANGO_SECRET_KEY` | auto-generated | Django session signing key |
| `MYSQL_ROOT_PASSWORD` | auto-generated | MySQL root password |
| `MYSQL_DATABASE` | `wireghost` | Database name |
| `MYSQL_USER` | `wireghost` | Database user |
| `MYSQL_PASSWORD` | auto-generated | Database password |
| `REDIS_PASSWORD` | auto-generated | Redis auth password |
| `WIREGHOST_PROTO` | `https` | Protocol (affects cookie security flags) |
| `WIREGHOST_HOST` | `localhost` | Hostname/IP for portal access |
| `WIREGHOST_PORT` | `443` | HTTPS listening port |
| `WIREGHOST_HTTP_PORT` | `80` | HTTP redirect port |
| `SESSION_COOKIE_SECURE` | `true` | HTTPS-only session cookie |
| `CSRF_COOKIE_SECURE` | `true` | HTTPS-only CSRF cookie |
| `CSRF_TRUSTED_ORIGINS` | auto-generated | Allowed POST origins |
| `WIREGHOST_LOG_DIR` | `./logs` | Host path for log files |
| `WIREGHOST_LOG_LEVEL` | `INFO` | Log verbosity (DEBUG/INFO/WARNING/ERROR) |

### `wireghost.yml` — Scan Defaults (CLI)

```yaml
output_dir: ./output
parallelism: 10
skip_nuclei: false
skip_vuln: false
tool_timeout: 3600
report_formats: [html, docx, xlsx]
report_title: "Security Assessment Summary Report"
verbose: false
```

Config priority: **CLI flags > `WIREGHOST_*` env vars > `wireghost.yml` > defaults.**

---

## Architecture

### System Overview

```
┌─ CLI (wireghost) ──────────────────────────────────┐
│  Typer commands: scan / report / update / config    │
│      │                                              │
│      └──► pipeline.orchestrator.run_pipeline()      │
└─────────────────────────┬──────────────────────────┘
                          │  same async pipeline
┌─ Docker Compose stack ──┴──────────────────────────┐
│                                                     │
│  nginx:443 ──► django api:8000 ──► mysql:3306       │
│       ▲              │                              │
│       │              ├─► celery worker ──┐          │
│       │              │                   │          │
│       │              ├─► celery beat ────┤          │
│       │              │                   │          │
│       │              └─► telegram bot    │          │
│       │                                  │          │
│  static SPA (web/)     redis:6379 ◄──────┘          │
└─────────────────────────────────────────────────────┘
```

### Docker Compose Services

| Service | Image | Role | Resources |
|---------|-------|------|-----------|
| **db** | `mysql:8.0` | Database | 1 GB mem limit |
| **redis** | `redis:7-alpine` | Celery broker + cache | 256 MB maxmemory, LRU eviction |
| **api** | `callmedemon/wireghost:web` | Django REST API (gunicorn, 4 workers) | 1 GB mem limit |
| **worker** | `callmedemon/wireghost:worker` | Celery scan executor (4 concurrent tasks) | 2 GB mem limit, NET_RAW + NET_ADMIN caps |
| **beat** | `callmedemon/wireghost:web` | Celery scheduler (60s tick) | 512 MB mem limit |
| **bot** | `callmedemon/wireghost:web` | Telegram bot (long-polling) | 256 MB mem limit |
| **portal** | `nginx:alpine` | Reverse proxy + SPA frontend | Serves static files, proxies `/api/` |

### Pipeline Phases

```
Phase 1  Host Discovery        nmap -sn + fping → merge + dedupe
Phase 2  Port Scanning         nmap -sV -sC -O → naabu → masscan (fallback chain)
Phase 3  Web Detection         async HTTP/HTTPS probing + httpx tech-detect
Phase 4  CMS Scanning          WordPress detection → WPScan
Phase 5  Service Enumeration   18 services, pure Python (no brute force)
Phase 6  Vuln Scanning         nuclei + nmap --script=vuln (parallel per host)
Phase 7  Exploit Detection     searchsploit per detected version → Exploit-DB
Phase 8  Report Generation     DOCX, XLSX, HTML, Interactive Dashboard
Phase 9  Asset Sync            upsert Asset rows keyed by (ip, port, protocol)
```

`pipeline.orchestrator.run_pipeline()` is the single async entry point for both CLI and the Celery `run_scan` task. Per-host parallelism is controlled via `asyncio.Semaphore(config.parallelism)`.

---

## Management (wg-ctl)

All day-2 operations go through `scripts/wg-ctl`:

```bash
./scripts/wg-ctl status                     # Service health, cert info, disk usage
./scripts/wg-ctl start | stop | restart     # Service lifecycle
./scripts/wg-ctl logs [service]             # Stream logs (all or api/worker/beat/db/redis/portal)
./scripts/wg-ctl backup                     # Full backup (DB + volumes + config + certs)
./scripts/wg-ctl restore <file> --confirm   # Restore from backup tarball
./scripts/wg-ctl update                     # Pull latest, rebuild, migrate
./scripts/wg-ctl reset-password <user>      # Reset a user's password
./scripts/wg-ctl certs status               # Certificate details and expiry
./scripts/wg-ctl certs renew                # Regenerate self-signed certificate
./scripts/wg-ctl shell                      # Django management shell
./scripts/wg-ctl uninstall --confirm        # Remove all data and configuration
```

### `wg-ctl status` Example Output

```
Wire_Ghost Status
═══════════════════════════════════════
Services:
  db        running   (healthy)
  redis     running   (healthy)
  api       running
  worker    running
  beat      running
  bot       running
  portal    running

TLS Certificate:
  CN: wireghost.local
  Expires: 2036-04-25 (3650 days)

Disk Usage:
  MySQL data:   142 MB
  Scan output:  1.2 GB
  Report assets: 4.5 MB
  Logs:         23 MB

Portal: https://wireghost.local:443
```

---

## Updating Tools and Feeds

### CLI

```bash
wireghost update              # update everything
wireghost update --tools      # nuclei, naabu, httpx binaries + apt packages
wireghost update --feeds      # nuclei templates + searchsploit db
wireghost update --self       # git pull + pip install
```

### Docker Compose

```bash
# Rebuild images with latest tool versions
docker compose build --no-cache worker

# Or use wg-ctl (creates backup first)
./scripts/wg-ctl update
```

The worker image downloads nuclei templates and tool binaries at build time. External template `.tar.gz` archives in `templates/` are extracted at container startup.

---

## Backup & Restore

### Create Backup

```bash
./scripts/wg-ctl backup
```

Creates a timestamped `.tar.gz` in `backups/` containing:
- MySQL database dump
- `scan_output` volume (all scan results)
- `report_assets` volume (logos, branding)
- `.env`, `nginx.conf`, TLS certificates

### Restore from Backup

```bash
./scripts/wg-ctl restore backups/wireghost-backup-2026-04-27.tar.gz --confirm
```

Stops the stack, restores everything, runs migrations, restarts all services.

---

## Security Model

- **Authentication** — Django session cookies (HttpOnly, SameSite=Lax) for browser access; SHA-256 hashed API tokens for programmatic access
- **Role enforcement** — `User.role` is a persisted field, not derived from flags. `User.save()` enforces Owner uniqueness at the ORM layer
- **Permissions in MySQL** — response manipulation on the client cannot grant access. Every API call consults the DB-backed `has_permission(code)` check
- **CSRF** — enabled for all mutating requests. SameSite=Lax on session + CSRF cookies
- **Content-Security-Policy** — via nginx: `script-src 'self' 'unsafe-inline'`, `connect-src 'self'`, `img-src 'self' data:`, `frame-ancestors 'none'`
- **Django admin blocked** — nginx returns 404 for `/admin` and all dotfiles
- **Two-tier static serving** — `web/js/public/` (login, setup) is served to everyone; `web/js/app/` (all page modules) requires a valid session via nginx `auth_request`
- **Path traversal protection** — all file-serving endpoints use `Path.is_relative_to()` to verify paths stay within allowed directories
- **SSRF protection** — scan targets validated against loopback, link-local, multicast, reserved IPs; hex/octal/short-form notation blocked; hostname resolution checked via `getaddrinfo` (IPv4+IPv6) against full blocklist
- **API tokens** — `wg_` prefix for secret scanner detection (TruffleHog, gitleaks, GitHub Secret Scanning); shown once at creation, stored as SHA-256 hash; revocation is instant
- **Atomic setup** — Owner creation + site config flip wrapped in `transaction.atomic()` to prevent partial state
- **Telegram security** — bot token stored server-side only; chat IDs regex-validated; notification failures never block scan pipeline

---

## Logging & Support

### Log Locations

With `WIREGHOST_LOG_DIR=./logs` (default):

```
./logs/
├── api/
│   ├── django.log           # Django + scanner logger (10 MB × 5 rotation)
│   ├── celery-worker.log    # Celery worker — scan pipeline execution
│   └── celery-beat.log      # Celery beat — scheduled scan dispatcher
└── nginx/
    ├── access.log           # Portal HTTP access log
    └── error.log            # Portal HTTP error log
```

Set `WIREGHOST_LOG_DIR=/var/log/wireghost` in `.env` for production. Change `WIREGHOST_LOG_LEVEL` to `DEBUG` / `WARNING` / `ERROR` to adjust verbosity.

### Log Rotation

Django uses `RotatingFileHandler` (10 MB × 5 backups). For production, delegate to logrotate:

```
# /etc/logrotate.d/wireghost
/var/log/wireghost/*/*.log {
    daily
    rotate 14
    compress
    missingok
    notifempty
    copytruncate
}
```

### Support Bundle (Owner Only)

**Settings → Support → Download support bundle** generates a `wireghost-support-*.tar.gz` containing:

- Log tails (capped at ~30 MB)
- System snapshot (versions, env var names, site config — no secrets)
- Role-permission matrix
- User/scan/host/finding/asset counts
- Last 500 audit rows (usernames hashed)
- Manifest with per-file byte counts

All log content passes through a redaction step that strips: Authorization headers, session/CSRF cookies, password/API key fields, and DSN-style credentials. Each export is audit-logged.

---

## Tests

```bash
# Full Django test suite (228 tests)
docker compose exec api python manage.py test scanner --verbosity=2

# CLI pipeline tests
python -m pytest tests/ -v
```

Test coverage includes:
- SSRF target validation (28 tests) — loopback, link-local, hex/octal/short-form IP, DNS rebinding domains, hostname resolution
- Authentication (12 tests) — token auth, CSRF exemption, revoked tokens
- Notification dispatch (23 tests) — chat ID validation, Telegram send, HTML escaping, error handling
- Role permissions (20+ tests) — viewer/engineer/owner access matrix across all endpoints
- Bot pub/sub (3 tests) — Redis message format, report delivery, failure resilience
- Scan policies, scheduled scans, report config, audit log, API tokens, setup wizard

---

## Project Layout

```
scripts/
    install.sh                  # Interactive on-premises installer
    install-wireghost.sh        # One-line remote installer (curl | bash)
    remove-wireghost.sh         # Complete Docker teardown
    wg-ctl                      # Management CLI (status, backup, restore, update, certs)

config/
    .env.example                # Environment variables template
    nginx.conf.tpl              # nginx template (rendered by installer)
    wireghost.example.yml       # Scan defaults template (CLI path)

src/wireghost/                  # Python package (standalone pipeline)
    cli.py                      # Typer CLI entry point
    config.py                   # ScanConfig (layered: yaml → env → overrides)
    models/                     # Severity, Host, Port, Finding, ScanReport
    parsers/                    # nmap, nuclei, naabu, masscan, searchsploit, wpscan
    pipeline/                   # orchestrator + phase modules
        orchestrator.py         # async run_pipeline (shared by CLI + Celery)
        portscan.py             # nmap → naabu → masscan fallback chain
        webdetect.py            # httpx probing + tech detection
        cms_scan.py             # WordPress detection → WPScan
        service_enum.py         # 18-service enumeration
        vulnscan.py             # nuclei + nmap + searchsploit
    reports/                    # html, docx, xlsx, dashboard renderers
    utils/                      # fs, log, process, updater, network helpers

web_portal/                     # Django REST API
    scanner/
        models.py               # User, Scan, Host, Port, Finding, Asset, Permission, ...
        views.py                # ViewSets + function views with HasPerm gates
        auth_views.py           # Auth, user management, site-config, audit log
        serializers.py          # DRF serializers with SSRF validation
        tasks.py                # Celery: run_scan, check_scheduled_scans, generate_report
        notifications.py        # Telegram notification dispatch
        bot/                    # Telegram bot
            callbacks/          # Inline keyboard handlers (scans, findings, assets, ...)
            menus.py            # Menu keyboard builders
            screenshots.py      # Screenshot album delivery
        migrations/             # 16 migrations (permissions, assets, viewer RBAC, ...)
    wireghost_web/
        settings.py             # Django config
        celery.py               # Celery app + beat schedule
        urls.py                 # URL routing

web/                            # Static SPA (vanilla JS + Chart.js + D3)
    app.html                    # Authenticated SPA shell (behind nginx auth_request)
    login.html                  # Login page (public)
    setup.html                  # Setup wizard (public)
    css/                        # Themes: light, dark, cyberpunk
    js/
        public/                 # Tier 0 — served before auth (login, theme, API wrapper)
        app/                    # Tier 1 — behind auth_request
            router.js           # History API router + role gates
            pages/              # One module per page
        lib/                    # Vendored: Chart.js, D3.js

docker-compose.yml              # 7 services: db, redis, api, worker, beat, bot, portal
docker-compose.dev.yml          # Dev overlay (bind mounts, debug ports)
Dockerfile                      # Standalone scanner image (all tools preinstalled)
web_portal/Dockerfile           # Worker image (Django + scan tools)
web_portal/Dockerfile.web       # Slim image (Django API / beat / bot)
```

---

## Uninstall

### Remove containers and data

```bash
./scripts/wg-ctl uninstall --confirm
```

Removes all containers, volumes, certs, logs, and `.env`. Source code is untouched.

### Complete removal

```bash
sudo bash scripts/remove-wireghost.sh              # Interactive — prompts before each step
sudo bash scripts/remove-wireghost.sh --force       # Non-interactive — removes everything
sudo bash scripts/remove-wireghost.sh --keep-data   # Remove containers/images but keep volumes
```

---

## License

For authorized security testing, penetration testing engagements, and educational use only. See [LICENSE](LICENSE) if present in the repo.
