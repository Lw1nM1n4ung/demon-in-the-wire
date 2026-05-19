# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Wire_Ghost (v2.0) is a security scanning toolkit that orchestrates multiple tools (nmap, nuclei, nikto, naabu, masscan, httpx, wpscan, searchsploit, enum4linux, netexec, metasploit, impacket, kerbrute, bloodhound-python) through an async Python pipeline, persists results to typed models, and renders them into HTML / DOCX / XLSX / interactive dashboard reports. It ships in two modes:

- **Standalone CLI** — `wireghost scan <target>` (Typer-based, Python 3.11+)
- **Full web portal** — Django REST API + vanilla-JS SPA + Celery workers, orchestrated via Docker Compose (MySQL, Redis, Nginx)

Both paths call the same `wireghost.pipeline.orchestrator.run_pipeline()`. The portal wraps it with a Celery task that bridges Django ORM records to the pipeline's dataclasses. The portal also includes an **Active Directory reconnaissance tab** — credential management with Fernet encryption, 8-phase Celery task (Phase 0 connectivity gate → LDAP → BloodHound → AS-REP roasting → Kerberoasting → RPC → ADCS → Responder), and DRF API with RBAC — plus a **full Telegram bot** for remote control (inline keyboards, role-gated commands, real-time notifications).

## Common Commands

```bash
# Install in editable mode (with dev extras for tests)
pip install -e ".[dev]"

# Run a scan
wireghost scan 192.168.1.0/24
wireghost scan 10.0.0.1 --formats dashboard,docx --parallelism 20

# Re-render reports from existing scan output
wireghost report ./output/192.168.1.0_24 --formats dashboard,docx,xlsx

# Update tools / feeds / self
wireghost update --tools   # nuclei, naabu, httpx, apt packages
wireghost update --feeds   # nuclei templates, searchsploit DB
wireghost update --self    # git pull + pip install

# Config
wireghost config init      # copy wireghost.example.yml → wireghost.yml
wireghost config show      # print resolved config (after layering)

# Tests
python -m pytest tests/ -v
python -m pytest tests/test_parsers.py::test_parse_nuclei_json -v   # single test

# Django scanner tests (CI runs these via manage.py)
cd web_portal && DJANGO_SECRET_KEY=ci-secret python manage.py test scanner --verbosity=1

# AD recon tests only
cd web_portal && DJANGO_SECRET_KEY=ci-secret python manage.py test scanner.tests.test_ad_models scanner.tests.test_ad_tasks scanner.tests.test_ad_views scanner.tests.test_ad_integration --verbosity=1

# Frontend JS unit tests (pure logic, no browser)
node tests/test_frontend_js.js
node tests/test_topology_js.js

# Installer shell tests
bash tests/test_installers.sh

# Browser tests (Playwright, requires running Docker stack)
npm run test:js-regression       # 14 JS bug-fix regression tests
npm run test:xss-regression      # XSS hardening regression tests
npm run test:portal-e2e          # Full portal E2E with 3 RBAC accounts

# Full QA gate (disposable Docker stack, all suites)
bash scripts/run_qa.sh
bash scripts/run_qa.sh --fresh-clone   # clone from remote first

# Dev Docker stack (bind mounts, debug ports, HTTP mode)
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# Full stack (interactive installer generates .env, TLS certs, starts stack)
sudo bash scripts/install.sh

# Standalone scanner via Docker
docker compose run --rm wireghost scan 10.0.0.0/24
```

`.env` is required for `docker compose up` — the compose file uses `:?` fail-on-unset for required secrets.

Browser/live QA tests require `WG_BASE` env var (default: `https://localhost:18443`) and `WG_FAIL_ON_SKIP=1` to turn data skips into hard failures.

## Architecture

### Layered configuration (`src/wireghost/config.py`)

`ScanConfig.load()` resolves values in priority order: **CLI overrides > `WIREGHOST_*` env vars > `wireghost.yml` > dataclass defaults.** Never read env/yaml directly — use the config object.

### Pipeline (`src/wireghost/pipeline/`)

`orchestrator.run_pipeline()` is the single async entry point. All phases fan out per-host with `asyncio.Semaphore(config.parallelism)`:

1. Tool check
2. Host discovery — nmap `-sn` (enhanced: TCP SYN to 17 ports + UDP ping to 5 ports) + fping ICMP sweep + arp-scan/netdiscover L2 ARP + passive DNS sweep (`nmap -sL -R`). **Tools within each subnet run in parallel** (`asyncio.gather`). Large CIDRs (wider than /23) auto-partition into /24 subnets scanned concurrently. Also captures **fping ICMP Host Unreachable** responses from stderr — these are hosts the gateway confirms exist but which drop ICMP (firewall/WAF). They are always included in the scan regardless of `scan_unresponsive`. Results merge + dedupe into live IP set.
3. Per-host pipeline (parallel, semaphore-bounded):
   - Port scan — nmap → naabu → masscan **fallback chain** (if N finds 0 ports, try N+1), then targeted `nmap -sV -sC -O` on discovered ports, then **fingerprintx augmentation** (fills in service names where nmap was uncertain — benefits ALL downstream phases)
   - Web detection — **verification-driven, two-layer**: service-name filter (skip only confident non-web protocols from nmap/fingerprintx) → HTTP HEAD verification (HTTP then HTTPS on every candidate). httpx tech detect on confirmed endpoints
   - CMS scan — auto-triggers WPScan for WordPress
   - Service enumeration — 18 services, pure-Python, no brute force
   - Vulnerability scan — nuclei + nmap `--script=vuln` + searchsploit + getsploit (Vulners API) + nikto (all concurrent per host)
   - MSF scan — service-routed Metasploit auxiliary/scanner modules (skips gracefully if msfconsole not installed)
   - Screenshots via gowitness
4. Report generation — `ReportEngine.generate()` dispatches to all configured formats

### Models → Parsers → Renderers

All parsers in `src/wireghost/parsers/` produce the same typed objects: `Host`, `Port`, `WebTech`, `Finding` (with forensic fields: `request`, `response`, `curl_command`, `cvss`, `cwe`, `cve`, `references`), `Severity` (enum with consistent RGB colors), and `ScanReport` (the aggregate).

`reports/engine.py` dispatches one `ScanReport` into HTML (dashboard), DOCX, XLSX. Adding a format = add a renderer + register it. Don't duplicate parsing.

### Web portal (`web_portal/`)

Celery bridges Django ORM ↔ pipeline: `scanner/tasks/__init__.py::run_scan` loads a `Scan` ORM row (UUIDv7 PKs), builds `ScanConfig`, calls `asyncio.run(run_pipeline(config))`, then writes dataclasses back to ORM via `_persist_results()`.

Django REST routes in `web_portal/wireghost_web/urls.py`. Auth: session cookies + CSRF + API-key flow + first-launch setup wizard. Celery Beat drives scheduled scan dispatch.

Models, views, serializers, and tasks have each been split from single files into **packages**: `scanner/models/` (`__init__.py` + `ad_recon.py`), `scanner/views/`, `scanner/serializers/`, `scanner/tasks/`. The AD recon subsystem adds 11 encrypted models (Fernet AES-256-GCM), DRF ViewSets with RBAC, and an 8-phase Celery task (`ad_recon_task`, phase 0 connectivity gate + 7 tool phases).

**Telegram bot** (`scanner/bot/`) — full remote control via long-polling: 14 files including `handlers.py` (all `/command` handlers), `menus.py` (inline keyboard builders), `auth.py` (account linking, rate limiting, permission checks), and `callbacks/` (9 callback handler files for inline keyboard navigation). Role-gated with pagination, screenshot delivery, and report file delivery.

Frontend is vanilla JS in `web/`: hash-router in `web/js/app/router.js`, pages in `web/js/app/pages/` (including `ad-recon.js` — three-panel cockpit with session polling), `api.js` wraps fetch with CSRF. Stored XSS hardening applied — prefer `textContent` over `innerHTML` when injecting scan output into the DOM.

### Nginx (`nginx.conf`)

The portal container serves `/web` statically, proxies `/api/` to Django, blocks `/admin` and dotfiles with 404, and sets a strict CSP. The API service is not published outside the Docker network.

### Docker images

Two Dockerfiles in `web_portal/`:
- `Dockerfile` — worker image with all scan tools (nmap, nuclei, metasploit-framework, etc.). Pre-built: `callmedemon/wireghost`.
- `Dockerfile.web` — slim API/portal image (no scan tools, tools health dispatched to worker via Celery).

## Key Files

| File | Role |
|------|------|
| `src/wireghost/cli/dispatcher.py` | Typer CLI entry point; mounts all domain apps (auth, scan, scans, hosts, findings, exploits, policies, schedules, users, tokens, sessions, system, dashboard, reports, notifications, support) |
| `src/wireghost/cli/scan.py` | `scan` command — tmux session management (`--attach`, `--list`, `--kill`, `--no-tmux`) |
| `src/wireghost/cli/deploy.py` | Cloud deployment CLI (`aws`, `aws-serverless`, `aws-sam`) |
| `src/wireghost/config.py` | `ScanConfig` with layered loader (defaults → YAML → env → overrides). Key flags: `enhanced_discovery` (TCP+UDP multi-port ping, default True), `skip_passive_dns`, `scan_unresponsive`, `skip_msf_scan`, `skip_fingerprintx` |
| `src/wireghost/pipeline/orchestrator.py` | Async phase coordinator; call `run_pipeline()` |
| `src/wireghost/pipeline/discovery.py` | Phase 1 — nmap/fping/ARP/DNS sweep with per-subnet parallel tool execution, CIDR partitioning, fping ICMP Host Unreachable capture (firewalled hosts always scanned) |
| `src/wireghost/pipeline/portscan.py` | Phase 3 — port discovery fallback chain (nmap → naabu → masscan) + service analysis (nmap -sV -sC -O) + fingerprintx augmentation (second source of truth for unidentified ports) |
| `src/wireghost/pipeline/webdetect.py` | Phase 4 — verification-driven web probing: two-layer filter (service-name skip → HTTP HEAD verify). Service names come from portscan (nmap -sV + fingerprintx) |
| `src/wireghost/pipeline/service_enum.py` | Pure-Python enumeration of 18 services (SSH, FTP, Redis, MongoDB, MySQL, PostgreSQL, SMTP, VNC, RDP, LDAP, NTP, DNS, SIP, NNTP, Memcached, Elasticsearch, Docker, Telnet) — no brute force |
| `src/wireghost/pipeline/web_crawl.py` | katana spider — crawls web endpoints before vuln scan so nuclei scans discovered URLs |
| `src/wireghost/pipeline/webscreenshot.py` | gowitness screenshots of all web endpoints |
| `src/wireghost/pipeline/vulnscan.py` | nuclei + nmap vuln + searchsploit + getsploit + nikto (all concurrent per host) |
| `src/wireghost/pipeline/msf_scan.py` | Service-routed Metasploit auxiliary/scanner modules |
| `src/wireghost/parsers/getsploit.py` | Parses Vulners API JSON (getsploit output) into Finding objects |
| `src/wireghost/parsers/msf.py` | Parses MSF spool/console output into Finding objects |
| `src/wireghost/deploy/engine.py` | Cloud-native deployment engine (SAM, IaC generation) |
| `src/wireghost/reports/engine.py` | Single dispatcher: one `ScanReport` → N output files |
| `web_portal/scanner/tasks/__init__.py` | Celery bridge: ORM → `run_pipeline` → ORM; AD recon 8-phase task imported from `tasks/ad_recon.py` |
| `web_portal/scanner/models/__init__.py` | Django models — User, Scan, Host, Port, Finding, Asset, Permission, ScanPolicy, ScheduledScan, ApiToken, ReportConfig, SiteConfig, ExploitMatch, AuditLog, Screenshot; 11 encrypted AD recon models re-exported from `models/ad_recon.py` |
| `web_portal/scanner/views/__init__.py` | DRF ViewSets with RBAC; AD recon ViewSet in `views/ad_recon.py` |
| `web_portal/scanner/serializers/__init__.py` | DRF serializers; AD recon serializers in `serializers/ad_recon.py` |
| `web_portal/scanner/auth_views.py` | Auth endpoints — login/logout, setup wizard, MFA, API tokens, Telegram link codes, user management |
| `web_portal/scanner/bot/handlers.py` | Telegram bot command handlers — `/start`, `/menu`, `/status`, `/scans`, `/findings`, `/newscan`, etc. |
| `web_portal/scanner/bot/menus.py` | Telegram inline keyboard builders for all screens |
| `web_portal/scanner/notifications.py` | Notification dispatch — scan complete/fail/critical/report-ready events to Telegram |
| `web_portal/scanner/msf_matcher.py` | Post-scan Metasploit exploit matching against discovered services |
| `web_portal/scanner/support.py` | Support bundle generation (logs, system snapshot, redacted audit trail) |
| `web_portal/scanner/admin.py` | Django admin registrations for all models including AD recon |
| `web_portal/scanner/tools_health.py` | Tools health probe; dispatched to worker, falls back to `ok=False` stubs when Celery unavailable |
| `web_portal/wireghost_web/urls.py` | REST routes + auth endpoints; AD recon routes at `/api/ad-recon/` |
| `web/js/app/pages/ad-recon.js` | AD recon SPA frontend — three-panel cockpit, session polling, credential management |
| `docker-compose.yml` | 7 services: db, redis, api, worker, beat, bot, portal (+ wireghost tools profile) |
| `docker-compose.dev.yml` | Dev overlay — bind mounts `./src`, debug ports, HTTP mode |
| `nginx.conf` | Portal reverse proxy; CSP + `/admin` block |
| `.github/workflows/ci.yml` | CI — pytest + Django tests + frontend JS + installer tests; Trivy security scan |

## Conventions & Gotchas

- **Python 3.11+** (project), **Docker uses 3.12**. `pyproject.toml` pins `requires-python = ">=3.11"`.
- **Dependency pinning**: `typer[all]>=0.9,<0.24` and `rich>=13.0,<14.0` in `pyproject.toml` — Typer 0.23.0+ changed `Option()` signature and removed `CliRunner(mix_stderr=...)`. Test assertions checking CLI output in stdout may find text in stderr (Rich `Console(stderr=True)`).
- **`web_portal/requirements.txt`** must stay in sync with `pyproject.toml` pins — CI installs both. Notable: `cryptography>=44.0` (AD recon Fernet encryption), `django>=5.0,<7.0`, `celery[redis]>=5.4`.
- **UUIDv7 primary keys**: All models use `uuid_utils.uuid7()` via `generate_uuid7()` helper. Django's default UUID PKs are not used — always call `generate_uuid7()` for new models.
- Pytest: `asyncio_mode = "auto"` — async tests don't need `@pytest.mark.asyncio`. ~851 tests collected.
- XML parsing uses `defusedxml` — don't reach for `xml.etree` directly.
- Report templates: `src/wireghost/reports/templates/` (Jinja2) and `src/wireghost/reports/assets/`.
- Output tree normalization: `/` and `:` → `_` in target names. Structure: `<output_dir>/<target>/{all,ips/<ip>/{nmap_xml,web,vuln,service_enum,cms},reports}`.
- Nuclei external templates are batched (default 5000) to cap CPU/RAM on large template sets.
- **getsploit (Vulners API)**: Requires `VULNERS_API_KEY` env var (mapped via config layering). Queries Vulners across Exploit-DB, Metasploit, Packetstorm. Runs in parallel with other vuln scanners.
- **Tmux scan**: `wireghost scan` launches a detached tmux session by default. Session named `wg-<target>`. Re-attach with `wireghost scan --attach <target>` or `tmux attach -t wg-<target>`. Use `--no-tmux` for foreground runs.
- **CI**: Trivy scans at `HIGH,CRITICAL` with `exit-code: 0` and `.trivyignore`. Django scanner tests need `DJANGO_SECRET_KEY=ci-secret`. Tools health tests expect `ok=False` stubs when no Celery worker.
- **Dev compose** (`docker-compose.dev.yml`): bind-mounts `./src` read-only into api/worker containers, exposes Redis on `:6379`, Django on `:8000`, portal on `:9995`. Requires `.env` to exist first (run `scripts/install.sh` to generate it, or copy from `config/.env.example`).
- **Django management commands** always need `DJANGO_SECRET_KEY` set and `cd web_portal` first. The `telegrambot` command runs the bot in long-polling mode.
- **Branch**: `rewrite-v2` (default). GitHub: `Lw1nM1n4ung/demon-in-the-wire`. Docker Hub: `callmedemon/wireghost`.
- No `script/` directory — v1 bash orchestration has been fully replaced. Any docs referencing `script/main.sh` or `/root/output/` are stale.
- **fping ICMP Host Unreachable**: During discovery, fping stderr is parsed for `ICMP Host Unreachable from <gateway> for ICMP Echo sent to <target>` messages. These are hosts the gateway **confirms exist** but which drop ICMP (firewall/WAF). They are **always** added to scan targets regardless of `scan_unresponsive`. Results persisted to `fping_unreachable.txt`.
- **fingerprintx vs nmap naming conventions**: The two tools use different protocol names for some services — `dns` vs `domain`, `postgres` vs `postgresql`, `mssql` vs `ms-sql-s`, `rpc` vs `rpcbind`. The `_NON_WEB_PROTOCOLS` frozenset in `webdetect.py` includes both conventions. If adding a new service name check anywhere in the pipeline, ensure both naming conventions are handled. The `_CHECKS` dict in `service_enum.py` and `_SERVICE_MODULES` in `msf_scan.py` currently use nmap names — fingerprintx-augmented ports with alternate names may not route correctly.
- **masscan rate**: No `--rate` flag — uses masscan's default (100 pps). Previously was hardcoded to 5000.
