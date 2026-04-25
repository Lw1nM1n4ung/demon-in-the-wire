# Wire_Ghost

Automated security-scanning orchestration toolkit with a full web portal. Chains nmap, nuclei, naabu, masscan, httpx, wpscan, and searchsploit into an 8-phase async pipeline — discovers hosts, scans ports (with fallback scanners), detects web services and CMS platforms, enumerates services, runs vulnerability scans, maps known exploits, and generates reports. Ships with a Django REST API + JS SPA portal for scan management, Attack Surface Management dashboard, scheduled scans, and role-based access control.

**v2.0** · Python 3.11+ · Docker · MySQL · Redis · Celery

---

## Features

**Scanning pipeline**
- 8-phase async pipeline — discovery, port scan, web detect, CMS scan, service enum, vuln scan, exploit detection, reporting
- Scanner fallback chain — nmap → naabu → masscan (auto-fallback when a scanner finds no ports)
- 18-service enumeration — SSH, FTP, Redis, MongoDB, MySQL, PostgreSQL, SMTP, VNC, RDP, LDAP, Memcached, Elasticsearch, Docker API, Telnet, and more (pure Python, no brute force)
- CMS detection — auto-triggers WPScan when WordPress is detected
- External nuclei templates — configurable template directories with batched execution (5000/batch) to limit resource usage
- Version-aware exploit detection — searchsploit per detected software version, linked to Exploit-DB

**Web portal**
- Django REST API + vanilla-JS SPA, served by nginx, orchestrated via Docker Compose (MySQL + Redis + Celery worker + Celery beat)
- **Attack Surface Management dashboard** — KPIs (total assets, critical exposures, newly-discovered, CVEs, attack-surface score), severity trend (30-day stacked area chart), risk-by-source donut, newly-discovered list, top exposures, top technologies, filterable asset inventory. Chart.js vendored locally (CSP-safe).
- **Asset model** — deduped `(ip, port, protocol)` inventory with `first_seen` / `last_seen` and computed `risk_score` (0-100), populated by every scan
- Setup wizard — first-launch admin creation flow, site branding, tool check
- Scan management — launch, list, cancel, re-run; per-scan detail view
- Scan policies — reusable configuration templates
- Scheduled scans — daily / weekly / biweekly / monthly, with timezone-aware "Run At" times (Owner picks the zone)
- Reports page + report builder — DOCX, XLSX, HTML, interactive dashboard
- Network topology — D3 force-directed graph per scan

**Access control**
- **Three roles** — Owner (one account, created by setup wizard), Engineer (operator), Viewer (read-only: Dashboard + Findings only)
- **Data-driven permissions** — 15 permission codes stored in MySQL, mapped to roles via a `RolePermission` table; Owner uniqueness enforced at both endpoint and model-save time
- Session auth with CSRF (Django `SameSite=Lax`); Nginx blocks `/admin` + dotfiles; strict Content-Security-Policy

**Reports**
- DOCX — professional Word document (cover page, executive summary, target subnets, live hosts, open ports, identified issues, host details)
- XLSX — Excel workbook with host/port summary and detailed port sheets
- HTML — self-contained static report
- Dashboard — interactive per-scan Chart.js dashboard (severity stats, findings table, CVE/CWE/CVSS badges, HTTP request/response evidence, curl reproduce commands)

---

## System requirements

### Minimum (small lab, single /24)

| Resource | Value |
|----------|-------|
| CPU | 4 cores |
| RAM | 8 GB |
| Disk | 40 GB SSD (templates, scan output, reports) |
| OS | Linux (Ubuntu 22.04+ / Debian 12+ tested); macOS for dev only |
| Network | Outbound HTTPS for tool/feed updates; inbound TCP 443 (HTTPS) for the portal |

### Recommended (regular /16 scans, multiple concurrent)

| Resource | Value |
|----------|-------|
| CPU | 8 cores |
| RAM | 16 GB |
| Disk | 100 GB NVMe |
| Network | 1 Gbps |

### Software — Docker Compose path (recommended)

| Tool | Version |
|------|---------|
| Docker Engine | 24+ |
| Docker Compose v2 | 2.20+ |
| A POSIX shell | bash or zsh |

**That's it.** Every other dependency — Python, Django, Celery, MySQL, Redis, nginx, nmap, nuclei, naabu, masscan, httpx, searchsploit, scannerctl, fping — ships inside the compose stack.

### Software — CLI-only / bare-metal path

If you want to run `wireghost scan` without the portal:

| Tool | Version | Required? |
|------|---------|-----------|
| Python | 3.11+ | ✓ |
| pip | any modern | ✓ |
| nmap | 7.80+ | ✓ |
| fping | 5+ | ✓ |
| nuclei | v3+ | recommended |
| naabu | v2+ | optional (fallback scanner) |
| masscan | 1.3+ | optional (second fallback) |
| httpx (ProjectDiscovery) | any | optional (tech detection) |
| wpscan | 3.8+ | optional (WordPress CMS) |
| searchsploit | any | optional (exploit DB lookup) |
| scannerctl | 23+ | optional (OpenVAS vuln scripts) |

Debian/Ubuntu install line for the core deps:

```bash
sudo apt install nmap fping masscan
```

Python deps (declared in `pyproject.toml`): `typer`, `rich`, `python-docx`, `openpyxl`, `jinja2`, `aiohttp`, `pyyaml`, `defusedxml`.

### Network ports

| Port | Direction | Purpose |
|------|-----------|---------|
| 443/tcp | inbound (host → portal) | Web portal (nginx, HTTPS) |
| 80/tcp | inbound (host → portal) | HTTP → HTTPS redirect |
| 8000/tcp | loopback only | Django API (gunicorn) |
| 6379/tcp | loopback only | Redis |
| 3306/tcp | container-only by default | MySQL (host mapping disabled to avoid conflicts) |
| outbound HTTPS | egress | Nuclei templates, searchsploit DB, OpenVAS NASL updates |

---

## Quick start — Docker Compose (recommended)

### One-line remote install

```bash
curl -fsSL https://raw.githubusercontent.com/Lw1nM1n4ung/demon-in-the-wire/rewrite-v2/scripts/install-wireghost.sh | sudo bash
```

This auto-installs Docker + Compose if missing, clones the repo to `/opt/wireghost`, and runs the interactive installer.

### Manual install

```bash
git clone https://github.com/Lw1nM1n4ung/demon-in-the-wire.git
cd demon-in-the-wire
sudo bash scripts/install.sh
```

The installer interactively prompts for hostname, port, protocol, database credentials, and secrets (all auto-generated by default). It generates a self-signed TLS cert, writes `.env`, builds and starts the Docker stack.

Portal is live at **https://\<hostname\>:\<port\>/setup**.

First visit runs the setup wizard — create the Owner account, set site branding, done. The Owner can then create Engineer and Viewer users from the Users page.

### Standalone scanner (Docker)

```bash
docker pull callmedemon/wireghost
docker run --net=host -v $(pwd)/output:/data/output callmedemon/wireghost scan 192.168.1.0/24
```

---

## Quick start — CLI (bare-metal)

```bash
git clone https://github.com/Lw1nM1n4ung/demon-in-the-wire.git
cd demon-in-the-wire
pip install -e ".[dev]"

wireghost scan 192.168.1.0/24
```

---

## CLI reference

```bash
wireghost scan <target>                    # Run full pipeline
wireghost report <scan-dir>                # Regenerate reports from existing output
wireghost update [--tools | --feeds | --self]   # Update binaries, vuln feeds, or wireghost itself
wireghost config [show | init]             # Show resolved config / create wireghost.yml
```

### `wireghost scan` flags

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

### External nuclei templates

```bash
# Run both default + external templates
wireghost scan 10.0.0.1 --nuclei-templates /path/to/templates/

# Run external templates only
wireghost scan 10.0.0.1 --nuclei-templates /path/to/templates/ --no-nuclei-default-templates
```

Large template sets (37K+) are automatically batched into chunks of 5000.

For Docker Compose: drop `.tar.gz` archives into `templates/` and they'll be extracted into the api container on start.

---

## Web portal

### Pages

Dashboard (ASM view) · Scans · Scan Detail · Findings · Finding Detail · Hosts · Host Detail · Topology · New Scan · Scan Queue · Scheduled Scans · Scan Policies · Reports · Report Builder · Settings · Users (Owner only)

### Roles

| Role | Can do |
|------|--------|
| **Owner** | Everything. Exactly **one** Owner per install, created by the setup wizard. Cannot be deleted. Cannot be demoted. |
| **Engineer** | Run/cancel scans, manage scan policies and schedules, view all hosts/findings/assets, download reports, upload branding logo, manage their own API keys. Cannot manage users or site config. |
| **Viewer** | Read-only: Dashboard + Findings. Cannot see Scans / Hosts / Reports pages; deep-links are silently redirected to Dashboard. |

### Permission model

Backed by `Permission` + `RolePermission` tables in MySQL. **15 named permission codes** (e.g. `scan:write`, `user:manage`, `site:config`, `audit:view`) are seeded by migration. Every endpoint consults `request.user.has_permission(code)` — no hardcoded role strings in the business logic. Changing what a role can do = editing a migration, not a code file.

### Key API endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/dashboard/` | ASM KPIs + trend + top exposures + technologies |
| `GET /api/assets/` | Deduped asset inventory (filterable by status / min_risk / has_cve / service) |
| `GET/POST /api/scans/` | List and create scans |
| `GET /api/scans/<id>/` | Scan detail with hosts and findings |
| `GET /api/hosts/` | Discovered hosts |
| `GET /api/findings/` | Vulnerability findings (filterable) |
| `GET/POST /api/policies/` | Scan policies |
| `GET/POST /api/schedules/` | Scheduled scans |
| `POST /api/auth/login/` | User authentication (session cookie) |
| `GET/POST /api/site-config/` | Site configuration (setup state, `schedule_timezone`) |
| `PUT /api/site-config/update/` | Update site config (Owner only) |
| `GET /api/audit-log/` | Audit trail (Owner only) |
| `GET/POST /api/auth/users/` | User management (Owner only) |

Full API documentation in [API.md](API.md).

---

## Configuration

Two layers:

### `.env` — secrets + deployment

Generated automatically by `scripts/install.sh` at the repo root. Template at `config/.env.example`. All secrets are auto-generated; the installer prompts for hostname, port, and protocol.

```env
DJANGO_SECRET_KEY=<auto-generated>
MYSQL_ROOT_PASSWORD=<auto-generated>
MYSQL_PASSWORD=<auto-generated>
REDIS_PASSWORD=<auto-generated>
WIREGHOST_HOST=<prompted>
WIREGHOST_PORT=443
WIREGHOST_PROTO=https
```

### `wireghost.yml` — scan defaults (CLI path)

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

```
┌ CLI (wireghost) ───────────────────────────────┐
│  Typer cmds: scan / report / update / config   │
│      │                                         │
│      └─► pipeline.orchestrator.run_pipeline    │
└────────────────────────┬───────────────────────┘
                         │   same async pipeline
┌ Docker Compose stack ──┴───────────────────────┐
│                                                │
│  nginx:9995 ──► django api:8000 ──► mysql      │
│         ▲              │                       │
│         │              └─► celery worker ──┐   │
│         │                                  │   │
│         │              celery beat ────────┼───┤
│         │                                  │   │
│  static web/ SPA       redis ◄─────────────┘   │
└────────────────────────────────────────────────┘
```

`pipeline.orchestrator.run_pipeline()` is the single async entry point for both the CLI and the Celery `run_scan` task. Scans persist into Django ORM; the ASM dashboard and Asset inventory read from the same tables.

### Pipeline phases

```
1  Host Discovery        nmap -sn + fping → merge + dedupe
2  Port Scanning         nmap -sV -sC -O → naabu → masscan (fallback chain)
3  Web Detection         async HTTP/HTTPS probing + httpx tech-detect
4  CMS Scanning          WordPress detection → WPScan
5  Service Enumeration   18 services, pure Python (no brute force)
6  Vuln Scanning         nuclei + nmap --script=vuln (parallel per host)
7  Exploit Detection     searchsploit per detected version → Exploit-DB
8  Report Generation     DOCX, XLSX, HTML, Interactive Dashboard
9  Asset Sync            upsert `Asset` rows keyed by (ip, port, protocol)
```

---

## Output structure (CLI)

```
output/<target>/
    all/
        live_host/live.txt       # Discovered IPs
        web/web.txt              # Web service URLs
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

When run from the portal, output lives under `/data/output/<target>/` inside the api/worker container (via a Docker named volume `scan_output`).

---

## Security model

- **Authentication:** Django session cookie only (HttpOnly, SameSite=Lax). No JWTs, no client-sent auth headers.
- **Role = persisted field** on `scanner_user`, not derived from flags or hashes. `User.save()` enforces Owner uniqueness at the ORM layer.
- **Permissions live in MySQL**, not code. Response manipulation on the client cannot grant access — every API call consults the DB-backed `has_permission(code)` check.
- **CSRF:** enabled for all mutating requests. SameSite=Lax on session + CSRF cookies.
- **Content-Security-Policy** via nginx: `script-src 'self' 'unsafe-inline'`, `connect-src 'self'`, `img-src 'self' data:`, `frame-ancestors 'none'`.
- **Django admin is blocked** at the nginx layer (`/admin` → 404) and dotfiles return 404.
- **Static assets pinned** with `?v=N` cache-bust so updates land immediately after a deploy.
- **Public/authenticated tier boundary at the nginx layer.** `web/js/public/` (login boot, theme, state, api wrapper) is served to everyone — it's what powers `login.html` and `setup.html` before a session exists. `web/js/app/` (router, session helpers, components, every page module) sits behind `auth_request /_auth_check`, which forwards the `sessionid` cookie to Django's lightweight `/api/auth/check/` endpoint (204/401, no DB work beyond session middleware) and returns 403 for any file fetch without a valid session. An unauthenticated visitor can fetch `login.html` and `setup.html`, but `/js/app/pages/users.js`, `/js/app/pages/policies.js`, etc. all return 403 — the files never leave the server. Combined with History API routing (real URLs like `/dashboard`, `/scans/<uuid>` instead of `#dashboard`), this shrinks the pre-auth recon surface from ~20 page modules to a login form.
- **API tokens for programmatic access.** Every authenticated user can mint up to 20 named, revocable tokens under **Settings → API Tokens**. Each token is shown once at creation (`wg_<40 chars>` — the `wg_` prefix makes leaks scannable by TruffleHog / gitleaks / GitHub Secret Scanning) and stored as a SHA-256 hash from then on — a DB leak cannot yield usable tokens. Call any endpoint with `curl -H "Authorization: Token wg_…" http://…/api/scans/`; no cookie, no CSRF, no session lookup. Tokens inherit the issuing user's role permissions — a Viewer-issued token still gets 403 on `/api/scans/`, same as the Viewer would through the SPA. Revocation is instant (a single row update). Every create/revoke event is audit-logged.
- **Telegram notifications (hybrid routing).** Owner configures a bot (BotFather) + shared channel in **Settings → Notifications**; every user can optionally add their personal `chat_id` for DMs scoped to scans they created. Scan completions, scan failures, and critical-finding discoveries fire to the shared channel AND to the creator's DM (respecting that user's per-event toggles). Bot token is stored server-side only — `GET /api/notifications/config/` returns `{has_token, token_tail}` never the full value. `chat_id` values are regex-validated (`^-?\d+$|^@[\w]{5,}$`) before interpolation, no user-controlled URLs reach `api.telegram.org`. Dispatch failures never block the scan pipeline — they're logged and dropped.

---

## Support & logging

All Wire_Ghost services write logs to host-side files so they survive container rebuilds and can be rotated, tailed, or shipped with normal host tooling.

### Log locations

With `WIREGHOST_LOG_DIR=./logs` (default), after `docker compose up -d`:

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

Set `WIREGHOST_LOG_DIR=/var/log/wireghost` (or any absolute path) in `.env` for production. Change `WIREGHOST_LOG_LEVEL` to `DEBUG` / `WARNING` / `ERROR` to adjust Django/scanner verbosity without code changes.

### Rotation

Django uses `RotatingFileHandler` with a 10 MB × 5-backup policy. Under multiple gunicorn workers this can race at the rotation boundary — for heavy-logging deployments, delegate rotation to `logrotate` with `copytruncate` instead:

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

### Support bundle (Owner only)

Navigate to **Settings → Support** and click **Download support bundle** to generate a `wireghost-support-YYYY-MM-DD-HHMM.tar.gz` archive containing:

- `logs/api/*.log`, `logs/nginx/*.log` — recent log tails (capped at ~30 MB total)
- `data/snapshot.json` — versions, env var *names*, site config (no logo paths, no secrets)
- `data/permissions.json` — role → permission-code matrix
- `data/counts.json` — user/scan/host/finding/asset totals
- `data/audit-tail.json` — last 500 audit rows (usernames hashed to opaque refs)
- `data/site-config.json` — setup state + schedule timezone
- `manifest.json` — index of every file + per-file source vs. bundled byte counts
- `README.txt` — human-readable index

Before bundling, all log content passes through a redaction step that strips: HTTP `Authorization` headers (Bearer / Basic / Digest / Token), session / CSRF / `wg_user_info` cookies, JSON `password` / `api_key` / `secret` fields, `X-API-Key` / `X-Auth-Token` style headers, and DSN-style `proto://user:pass@host` credentials. IPs, usernames, file paths, and stack traces are preserved so the logs remain debuggable.

Each export is audit-logged as `support.export` with actor + IP + bundle size. Engineers and Viewers cannot export — the `support:export` permission is Owner-only by migration.

> **Extend redaction for your deployment:** the starter patterns in `web_portal/scanner/support.py::REDACTION_PATTERNS` cover standard session/auth tokens. If your deployment emits customer-specific tokens, partner API keys, or webhook signatures, add one-line regex entries in the `TODO(operator)` block so they're stripped before bundling.

---

## Tests

```bash
# Django + portal (50 tests)
docker compose exec api python manage.py test scanner.tests

# CLI pipeline
python -m pytest tests/ -v
```

---

## Project layout

```
scripts/                        # Management & deployment scripts
    install.sh                  # Interactive on-premises installer
    install-wireghost.sh        # One-line remote installer (curl | bash)
    remove-wireghost.sh         # Complete Docker teardown
    wg-ctl                      # Management CLI (status, backup, restore, update, certs)

config/                         # Configuration templates
    .env.example                # Environment variables template
    nginx.conf.tpl              # nginx template (rendered by installer)
    wireghost.example.yml       # Scan defaults template (CLI path)

src/wireghost/                  # Python package (pipeline, parsers, renderers)
    cli.py                      # Typer CLI entry point
    config.py                   # ScanConfig (layered: yaml → env → overrides)
    models/                     # Severity, Host, Port, Finding, ScanReport
    parsers/                    # nmap, nuclei, naabu, masscan, openvas, searchsploit, wpscan
    pipeline/                   # orchestrator + phase modules
    reports/                    # html, docx, xlsx, dashboard renderers
    utils/                      # fs, log, process, updater, network helpers

web_portal/                     # Django REST API
    scanner/models.py           # User, Scan, Host, Port, Finding, Asset, Permission, ...
    scanner/views.py            # ViewSets + function views with HasPerm gates
    scanner/auth_views.py       # Auth, user management, site-config, audit log
    scanner/tasks.py            # Celery: run_scan, check_scheduled_scans, generate_report
    wireghost_web/              # Django project config, Celery, URLs
    scanner/migrations/         # 10 migrations (incl. permission seed, asset backfill)

web/                            # Static SPA (no framework; vanilla JS + Chart.js + D3)
    app.html                    # Authenticated SPA shell (behind nginx auth_request)
    login.html                  # Login page (Tier 0, public)
    setup.html                  # Setup wizard (Tier 0, public)
    css/                        # variables, layout, components, animations, light, cyberpunk
    js/
        public/                 # Tier 0 — served to everyone (login, theme, API wrapper)
            api.js              # fetch wrapper, CSRF, token auth
            login-boot.js       # Login page controller
            setup-boot.js       # Setup wizard controller
            state.js            # localStorage user state
            theme.js            # Dark/light/cyberpunk theme switcher
        app/                    # Tier 1 — behind auth_request (SPA pages)
            router.js           # History API router + role gates
            auth.js             # Session helpers, logout
            components.js       # Shared UI components (modals, tables, badges)
            utils.js            # Formatting, escaping, date helpers
            pages/              # One module per page (dashboard, scans, findings, ...)
        lib/                    # Vendored libraries (Chart.js, D3.js)

docker-compose.yml              # db, redis, api, worker, beat, portal
docker-compose.dev.yml          # Developer overlay (bind mounts, debug ports)
Dockerfile                      # Standalone scanner image (tools preinstalled)
web_portal/Dockerfile           # Django/Celery image
```

---

## Management (wg-ctl)

All day-2 operations go through `scripts/wg-ctl`:

```bash
./scripts/wg-ctl status                    # Service health, cert info, disk usage
./scripts/wg-ctl backup                    # Full backup (DB + volumes + config + certs)
./scripts/wg-ctl restore <file> --confirm  # Restore from backup tarball
./scripts/wg-ctl update                    # Pull latest, rebuild, migrate
./scripts/wg-ctl logs [service]            # Stream logs (all or specific service)
./scripts/wg-ctl reset-password <user>     # Reset a user's password
./scripts/wg-ctl certs status              # Certificate details and expiry
./scripts/wg-ctl certs renew               # Regenerate self-signed certificate
./scripts/wg-ctl start | stop | restart    # Service lifecycle
./scripts/wg-ctl shell                     # Django management shell
./scripts/wg-ctl uninstall --confirm       # Remove all data and configuration
```

### Uninstall

For a complete Docker teardown (containers, volumes, images, network, local files):

```bash
sudo bash scripts/remove-wireghost.sh              # Interactive — prompts before each step
sudo bash scripts/remove-wireghost.sh --force       # Non-interactive — removes everything
sudo bash scripts/remove-wireghost.sh --keep-data   # Remove containers/images but keep volumes
```

---

## Updating tools and feeds

```bash
wireghost update            # update everything
wireghost update --tools    # nuclei, naabu, httpx binaries + apt packages
wireghost update --feeds    # nuclei templates + searchsploit db + OpenVAS NASL
wireghost update --self     # git pull + pip install
```

Inside the compose stack, the api container downloads nuclei templates and NASL feeds at image build time; rebuild with `docker compose build --no-cache api` to refresh.

---

## License

For authorized security testing, penetration testing engagements, and educational use only. See [LICENSE](LICENSE) if present in the repo.
