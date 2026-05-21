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

`orchestrator.run_pipeline(config, on_progress=None, on_discovery_complete=None, on_host_complete=None, on_host_phase=None)` is the single async entry point. The pipeline tracks 6 phases in `PHASE_ORDER`:

```python
PHASE_ORDER = ["discovery", "portscan", "webdetect", "webcrawl", "enumeration", "reports"]
```

**Per-host weighted progress**: Instead of a global bottleneck phase, each host independently advances through phases via `_advance_host_phase(ip, phase)`. Progress is a weighted average across all hosts using per-phase weights (`discovery=9, portscan=27, webdetect=46, webcrawl=58, enumeration=77, reports=94`). Fast hosts pull the bar forward — one slow host won't stall it.

**Callbacks** (from orchestrator to Celery bridge):
- `on_progress(phase_label, weighted_pct, hosts_fully_done)` — scan-level progress, called on every host phase change
- `on_discovery_complete(live_ips, mac_vendor_map)` — called after host discovery
- `on_host_complete(host, findings)` — called after a host finishes its FULL pipeline (ports, findings, screenshots populated)
- `on_host_phase(ip, phase)` — per-host phase change, writes `Host.current_phase` in the DB

**Important: `asyncio.gather` barrier** — `on_host_complete` fires for ALL hosts only after `asyncio.gather` returns, meaning port/finding/screenshot data only appears in the DB when the ENTIRE scan completes. During a running scan, only progress counters and per-host phases are visible.

The web portal's Celery task uses **daemon thread + queue** to write these fields to the DB in real time. The `on_progress` callback enqueues `(phase_label, pct, done)` tuples; a dedicated thread dequeues and writes via raw SQL (bypassing Django's `SynchronousOnlyOperation` in `asyncio.run()`).

All phases fan out per-host with `asyncio.Semaphore(config.parallelism)`:

1. Tool check
2. **Phase: discovery** — nmap `-sn` (enhanced: TCP SYN to 17 ports + UDP ping to 5 ports) + fping ICMP sweep + arp-scan/netdiscover L2 ARP + passive DNS sweep (`nmap -sL -R`). **Tools within each subnet run in parallel** (`asyncio.gather`). Large CIDRs (wider than /23) auto-partition into /24 subnets scanned concurrently. Also captures **fping ICMP Host Unreachable** responses from stderr — these are hosts the gateway confirms exist but which drop ICMP (firewall/WAF). They are always included in the scan regardless of `scan_unresponsive`. Results merge + dedupe into live IP set. Progress reports per-subnet: `(subnets_done, total_subnets)`.
3. Per-host pipeline (all hosts run in parallel, semaphore-bounded):
   - **Phase: portscan** — nmap → naabu → masscan **fallback chain** (if N finds 0 ports, try N+1), then targeted `nmap -sV -sC -O` on discovered ports, then **fingerprintx augmentation** (fills in service names where nmap was uncertain — benefits ALL downstream phases)
   - **Phase: webdetect** — **verification-driven, two-layer**: service-name filter (skip only confident non-web protocols from nmap/fingerprintx) → HTTP HEAD verification (HTTP then HTTPS on every candidate). httpx tech detect on confirmed endpoints
   - **Phase: webcrawl** — katana spider crawls web endpoints before vuln scan so nuclei scans discovered URLs
   - **Phase: enumeration** — all of the following run concurrently per host:
     - CMS scan — auto-triggers WPScan for WordPress
     - Service enumeration — 18 services, pure-Python, no brute force
     - SMB/NetExec/LDAP/SNMP/NFS enumeration
     - TLS/SSL audit
     - Vulnerability scan — nuclei + nmap `--script=vuln` + searchsploit + getsploit (Vulners API) + nikto (all concurrent per host)
     - MSF scan — service-routed Metasploit auxiliary/scanner modules (skips gracefully if msfconsole not installed)
     - Screenshots via gowitness
4. **Phase: reports** — `ReportEngine.generate()` dispatches to all configured formats

### Models → Parsers → Renderers

All parsers in `src/wireghost/parsers/` produce the same typed objects: `Host`, `Port`, `WebTech`, `Finding` (with forensic fields: `request`, `response`, `curl_command`, `cvss`, `cwe`, `cve`, `references`), `Severity` (enum with consistent RGB colors), and `ScanReport` (the aggregate).

`reports/engine.py` dispatches one `ScanReport` into HTML (dashboard), DOCX, XLSX. Adding a format = add a renderer + register it. Don't duplicate parsing.

### Web portal (`web_portal/`)

Celery bridges Django ORM ↔ pipeline: `scanner/tasks/__init__.py::run_scan` loads a `Scan` ORM row (UUIDv7 PKs), builds `ScanConfig`, starts a **daemon thread** for real-time progress DB writes (bypasses Django's `SynchronousOnlyOperation` in `asyncio.run()`), calls `asyncio.run(run_pipeline(config, on_progress=_on_progress))`, then writes dataclasses back to ORM via `_persist_results()`.

The `Scan` model carries three progress-tracking fields written by the daemon thread via raw SQL: `current_phase` (dominant active phase across hosts), `hosts_scanned` (pre-computed weighted progress percentage 0-99), and `hosts_total` (total live hosts). The API exposes these in scan serializers; the frontend `WG.phaseProgress()` reads `hosts_scanned` directly as the progress percentage.

Django REST routes in `web_portal/wireghost_web/urls.py`. Auth: session cookies + CSRF + API-key flow + first-launch setup wizard. Celery Beat drives scheduled scan dispatch.

Models, views, serializers, and tasks have each been split from single files into **packages**: `scanner/models/` (`__init__.py` + `ad_recon.py`), `scanner/views/`, `scanner/serializers/`, `scanner/tasks/`. The AD recon subsystem adds 11 encrypted models (Fernet AES-256-GCM), DRF ViewSets with RBAC, and an 8-phase Celery task (`ad_recon_task`, phase 0 connectivity gate + 7 tool phases).

**Telegram bot** (`scanner/bot/`) — full remote control via long-polling: 14 files including `handlers.py` (all `/command` handlers), `menus.py` (inline keyboard builders), `auth.py` (account linking, rate limiting, permission checks), and `callbacks/` (9 callback handler files for inline keyboard navigation). Role-gated with pagination, screenshot delivery, and report file delivery.

Frontend is vanilla JS in `web/`: hash-router in `web/js/app/router.js`, pages in `web/js/app/pages/` (including `ad-recon.js` — three-panel cockpit with session polling; and `scan-queue.js` — live queue with per-phase progress pills), `api.js` wraps fetch with CSRF. Stored XSS hardening applied — prefer `textContent` over `innerHTML` when injecting scan output into the DOM.

The shared components file (`web/js/app/components.js`) defines the single source of truth for scan progress display:
- **`WG.PHASE_ORDER`** — `['discovery', 'portscan', 'webdetect', 'webcrawl', 'enumeration', 'reports']`
- **`WG.PHASE_LABELS`** — human-readable labels for each phase
- **`WG.phaseProgress(s)`** — reads progress % directly from `hosts_scanned` (pre-computed by the orchestrator's weighted average; 0-99 for running, 100 for terminal states)
- **`WG.phaseLabel(phase)`** — returns human-readable phase name
- **`WG._startElapsedTicker()`** — live duration counter updating every second

Three pages consume these: `scans.js` (running scan cards), `scan-queue.js` (queue items), and `scan-detail.js` (detail view). All pages reference `WG.PHASE_ORDER` and `WG.PHASE_LABELS` — never hardcode phase lists in individual pages.

### Nginx (`nginx.conf`)

The portal container serves `/web` statically, proxies `/api/` to Django, blocks `/admin` and dotfiles with 404, and sets a strict CSP. The API service is not published outside the Docker network.

**nginx.conf is mounted as a volume** (`./nginx.conf:/etc/nginx/conf.d/default.conf:ro`). Changes take effect with `docker exec wireghost-portal-1 nginx -s reload` — no container recreate needed.

**The host IP is hardcoded in three places** in `nginx.conf`: `server_name`, `return 301` (HTTP→HTTPS), and `return 302` (auth gate → login). When the host IP changes (DHCP), all three must be updated AND nginx reloaded. Updating only `.env`/`DJANGO_ALLOWED_HOSTS` is not enough — nginx still binds to the old IP, producing 500 errors even though Django is correctly configured.

### IP reload (`ip-reload.py`)

One-command tool to update the host IP across all config files: `sudo python3 ip-reload.py <NEW_IP>`. Updates `.env` (`WIREGHOST_HOST`, `CSRF_TRUSTED_ORIGINS`), `docker-compose.yml` (`DJANGO_ALLOWED_HOSTS`), and `nginx.conf` (server_name + redirect targets), then recreates the API container and reloads nginx.

### Docker images

Two Dockerfiles in `web_portal/`:
- `Dockerfile` — worker image with all scan tools (nmap, nuclei, metasploit-framework, etc.). Pre-built: `callmedemon/wireghost`.
- `Dockerfile.web` — slim API/portal image (no scan tools, tools health dispatched to worker via Celery).

## Key Files

| File | Role |
|------|------|
| `src/wireghost/cli/dispatcher.py` | Typer CLI entry point; mounts all domain apps (auth, scan, scans, hosts, findings, exploits, policies, schedules, users, tokens, sessions, system, dashboard, reports, notifications, support) |
| `src/wireghost/cli/scan.py` | `scan` command — tmux session management (`--attach`, `--list`, `--kill`, `--no-tmux`) |
| `src/wireghost/cli/client.py` | `WireGhostClient` — HTTP API client with token-based auth caching for remote portal interaction |
| `src/wireghost/cli/auth.py` | CLI auth commands — `login`, `logout`, `whoami` against portal API |
| `src/wireghost/cli/output.py` | Shared output formatting — `echo_table()`, `echo_json()` for consistent CLI rendering |
| `src/wireghost/cli/deploy.py` | Cloud deployment CLI (`aws`, `aws-serverless`, `aws-sam`) |
| `src/wireghost/config.py` | `ScanConfig` with layered loader (defaults → YAML → env → overrides). Key flags: `enhanced_discovery` (TCP+UDP multi-port ping, default False — plain `nmap -sn`), `skip_passive_dns`, `scan_unresponsive`, `skip_msf_scan`, `skip_fingerprintx` |
| `src/wireghost/pipeline/orchestrator.py` | Async phase coordinator with `PHASE_ORDER` (6 phases) and per-host weighted progress via `_advance_host_phase()` + `_compute_progress()`; call `run_pipeline(config, on_progress=None, on_discovery_complete=None, on_host_complete=None, on_host_phase=None)` |
| `src/wireghost/pipeline/discovery.py` | Phase: discovery — nmap/fping/ARP/DNS sweep with per-subnet parallel tool execution, CIDR partitioning, fping ICMP Host Unreachable capture (firewalled hosts always scanned) |
| `src/wireghost/pipeline/portscan.py` | Phase: portscan — port discovery fallback chain (nmap → naabu → masscan) + service analysis (nmap -sV -sC -O) + fingerprintx augmentation (second source of truth for unidentified ports) |
| `src/wireghost/pipeline/webdetect.py` | Phase: webdetect — verification-driven web probing: two-layer filter (service-name skip → HTTP HEAD verify). Service names come from portscan (nmap -sV + fingerprintx) |
| `src/wireghost/pipeline/web_crawl.py` | Phase: webcrawl — katana spider; crawls web endpoints before vuln scan so nuclei scans discovered URLs |
| `src/wireghost/pipeline/vulnscan.py` | Phase: enumeration — nuclei + nmap vuln + searchsploit + getsploit + nikto (all concurrent per host) |
| `src/wireghost/pipeline/service_enum.py` | Phase: enumeration — Pure-Python enumeration of 18 services (SSH, FTP, Redis, MongoDB, MySQL, PostgreSQL, SMTP, VNC, RDP, LDAP, NTP, DNS, SIP, NNTP, Memcached, Elasticsearch, Docker, Telnet) — no brute force |
| `src/wireghost/pipeline/msf_scan.py` | Phase: enumeration — Service-routed Metasploit auxiliary/scanner modules (skips if msfconsole not installed) |
| `src/wireghost/pipeline/smb_enum.py` | Phase: enumeration — SMB enumeration via NetExec (shares, users, groups, password policy) |
| `src/wireghost/pipeline/netexec_enum.py` | Phase: enumeration — NetExec multi-protocol enumeration (SMB, SSH, FTP, RDP, LDAP, WinRM, MSSQL) |
| `src/wireghost/pipeline/ldap_enum.py` | Phase: enumeration — LDAP directory enumeration (naming contexts, domain info, users, computers, groups) |
| `src/wireghost/pipeline/snmp_enum.py` | Phase: enumeration — SNMP enumeration (system info, interfaces, users, processes) |
| `src/wireghost/pipeline/nfs_enum.py` | Phase: enumeration — NFS export enumeration (exports, permissions, mountable shares) |
| `src/wireghost/pipeline/tls_audit.py` | Phase: enumeration — TLS/SSL certificate audit (cipher suites, protocol versions, certificate details) |
| `src/wireghost/pipeline/cms_scan.py` | Phase: enumeration — CMS detection + WPScan trigger for WordPress |
| `src/wireghost/pipeline/webscreenshot.py` | Phase: enumeration — gowitness v3 screenshots of web endpoints (`--chrome-window-x/y` not `--resolution-x/y`; add `--screenshot-format png` since v3 defaults to JPEG) |
| `src/wireghost/pipeline/nikto_scan.py` | Phase: enumeration — nikto web server scanner subprocess |
| `src/wireghost/parsers/getsploit.py` | Parses Vulners API JSON (getsploit output) into Finding objects |
| `src/wireghost/parsers/msf.py` | Parses MSF spool/console output into Finding objects |
| `src/wireghost/deploy/engine.py` | Cloud-native deployment engine (SAM, IaC generation) |
| `src/wireghost/reports/engine.py` | Single dispatcher: one `ScanReport` → N output files |
| `web_portal/scanner/tasks/__init__.py` | Celery bridge: ORM → `run_pipeline` → ORM; AD recon 8-phase task imported from `tasks/ad_recon.py` |
| `web_portal/scanner/models/__init__.py` | Django models — User, Scan (with `current_phase`, `hosts_scanned`, `hosts_total` for real-time progress), Host (with `current_phase` for per-host phase tracking, migration 0031), Port, Finding, Asset, Permission, ScanPolicy, ScheduledScan, ApiToken, ReportConfig, SiteConfig, ExploitMatch, AuditLog, Screenshot; 11 encrypted AD recon models re-exported from `models/ad_recon.py` |
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
| `web_portal/scanner/docker_stats.py` | Docker container stats via proxy; `COMPOSE_PROJECT` env var MUST match the compose project name (directory basename) or label filter returns zero containers |
| `web/js/app/components.js` | Shared UI helpers — `WG.PHASE_ORDER` and `WG.PHASE_LABELS` (single source of truth for phases), `WG.phaseProgress(s)` for weighted progress bar, `WG.phaseLabel(phase)` for human-readable labels, `WG._startElapsedTicker()` for live duration counter |
| `web/js/app/pages/scan-queue.js` | Scan Queue page — live running/pending scan cards with per-phase progress pills; references `WG.PHASE_ORDER` + `WG.PHASE_LABELS`, bulk cancel/remove |
| `web/js/app/pages/scan-detail.js` | Scan detail page — uses `WG.phaseProgress()` and `WG.phaseLabel()` |
| `web_portal/wireghost_web/urls.py` | REST routes + auth endpoints; AD recon routes at `/api/ad-recon/` |
| `web/js/app/pages/ad-recon.js` | AD recon SPA frontend — three-panel cockpit, session polling, credential management |
| `docker-compose.yml` | 7 services: db, redis, api, worker, beat, bot, portal (+ wireghost tools profile) |
| `docker-compose.dev.yml` | Dev overlay — bind mounts `./src`, debug ports, HTTP mode |
| `nginx.conf` | Portal reverse proxy; CSP + `/admin` block; IP hardcoded in server_name + redirects |
| `ip-reload.py` | One-command IP update across `.env`, `docker-compose.yml`, `nginx.conf` + container reload |
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
- **masscan rate**: No `--rate` flag — uses masscan's default (100 pps). Previously was hardcoded to 5000. At 100 pps a full 65535-port scan takes ~11 minutes per host — a major bottleneck for large scans. Hosts with no open ports still pay this full cost due to the nmap → naabu → masscan fallback chain.
- **gowitness v3 breaking changes**: The worker image ships gowitness 3.1.1 (not v2). Flags `--resolution-x`/`--resolution-y` are renamed to `--chrome-window-x`/`--chrome-window-y`. Default screenshot format is JPEG (not PNG) — always pass `--screenshot-format png` for backward compatibility. Using the old v2 flags causes gowitness to error out; the exception is silently caught, resulting in zero screenshots.
- **Daemon thread sentinel ordering (CRITICAL)**: In the Celery bridge's `finally` block, the sentinel `_progress_queue.put(None)` MUST come BEFORE `_progress_stop.set()`. The daemon thread exits when `_progress_stop` is set, so stopping first discards all enqueued `host_result` items — meaning ports, findings, and screenshots are lost for the entire scan. Always: sentinel → `join(30s)` → force-stop only if stuck.
- **`asyncio.gather` persistence barrier**: `on_host_complete` fires only after ALL hosts finish their pipeline (gather returns all results at once). During a running scan, per-host ports/findings/screenshots exist on disk but are NOT yet in the DB. Only progress counters and `Host.current_phase` are visible mid-scan.
- **Worker source code paths**: Pipeline code lives at `/app/src/wireghost/pipeline/` (installed as a package). Django task code lives at `/app/scanner/tasks/`. When `docker cp`-ing fixes into the worker, use the correct path. The worker image (`callmedemon/wireghost`) is NOT read-only — `docker cp` + `docker restart` works.
- **UUID format for raw SQL**: `str(uuid)` produces dashed format (`019e4470-e6e2-7200-b202-9d97eb11a6c0`) but MySQL stores UUIDs without dashes as CHAR(32) (`019e4470e6e27200b2029d97eb11a6c0`). When using raw SQL (e.g., cursor.execute with `WHERE id=%s`), always do `str(uuid).replace("-", "")`. ORM queries handle this automatically — this only matters for raw SQL.
- **Threaded progress updater**: Django's `SynchronousOnlyOperation` blocks synchronous DB access inside `asyncio.run()`. The Celery task bridges this with a **daemon thread + queue** pattern. Queue items: `("progress", phase_label, pct, done)`, `("discovery", ips, mac_map)`, `("host_phase", ip, phase)`, `("host_result", host, findings)`. The `on_progress` callback runs inside the async event loop — never call the Django ORM directly from it; only enqueue tuples.
- **Celery worker bytecode caching**: The Celery prefork pool reuses child processes. After live-patching `.py` files in a running container, child processes may still run the old bytecode. Always `docker restart` the worker container after code changes — a `docker cp` or bind-mount edit is not enough.
- **API container read-only rootfs**: The API/portal image (`callmedemon/wireghost:web`) uses a read-only root filesystem. You cannot `docker cp` files into it or write to `/app/` at runtime. To change behavior, either set environment variables in the compose file and recreate the container, or rebuild the image.
- **nginx.conf hardcoded IP (CRITICAL)**: `nginx.conf` has the host IP hardcoded in three places: `server_name`, `return 301` (HTTP→HTTPS redirect), and `return 302` (auth gate → login redirect). When the host IP changes (DHCP lease), all three MUST be updated. `.env`/Django changes alone are not enough — nginx will still bind to the old IP. After editing `nginx.conf`, reload with `docker exec wireghost-portal-1 nginx -s reload` (no container recreate needed — it's a volume mount). Use `sudo python3 ip-reload.py <NEW_IP>` for a one-command fix.
- **Container Processes (docker-proxy)**: The `docker_stats.py` module queries a Docker socket proxy (`tecnativa/docker-socket-proxy`) to list containers. It filters by label `com.docker.compose.project=<COMPOSE_PROJECT>`. The compose file **explicitly sets** `COMPOSE_PROJECT` on the `api` service (which propagates to `worker`/`beat` via YAML anchor `*api-env`). The project name defaults to the directory basename (`demon-in-the-wire` for `demon-in-the-wire/`, NOT `wireghost`). If the env var is missing or mismatched, the `/api/system-processes/` endpoint returns zero containers.
