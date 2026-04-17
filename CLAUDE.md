# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Wire_Ghost (v2.0) is a security scanning toolkit that orchestrates multiple tools (nmap, nuclei, naabu, masscan, httpx, wpscan, searchsploit, scannerctl) through an async Python pipeline, persists results to typed models, and renders them into HTML / DOCX / XLSX / interactive dashboard reports. It ships in two modes:

- **Standalone CLI** — `wireghost scan <target>` (Typer-based, Python 3.11+)
- **Full web portal** — Django REST API + vanilla-JS SPA + Celery workers, orchestrated via Docker Compose (MySQL, Redis, Nginx)

Both paths call the same `wireghost.pipeline.orchestrator.run_pipeline()`. The portal wraps it with a Celery task that bridges Django ORM records to the pipeline's dataclasses.

## Common Commands

```bash
# Install in editable mode (with dev extras for tests)
pip install -e ".[dev]"

# Run a scan
wireghost scan 192.168.1.0/24
wireghost scan 10.0.0.1 --formats dashboard,docx --parallelism 20 --nuclei-templates /path/to/templates

# Re-render reports from existing scan output
wireghost report ./output/192.168.1.0_24 --formats dashboard,docx,xlsx

# Update tools / feeds / self
wireghost update --tools   # nuclei, naabu, httpx, apt packages
wireghost update --feeds   # nuclei templates, searchsploit DB, OpenVAS NASL
wireghost update --self    # git pull + pip install

# Config
wireghost config init      # copy wireghost.example.yml → wireghost.yml
wireghost config show      # print resolved config (after layering)

# Tests
python -m pytest tests/ -v
python -m pytest tests/test_parsers.py::test_parse_nuclei_json -v   # single test

# Full stack (portal at http://localhost:9995)
cp .env.example .env       # required: DJANGO_SECRET_KEY, MYSQL_PASSWORD, REDIS_PASSWORD
docker compose up -d

# Standalone scanner image (tools profile)
docker compose run --rm wireghost scan 10.0.0.0/24
```

`.env` is required for `docker compose up` — the compose file uses `:?` fail-on-unset for the three secrets above.

## Architecture

### Layered configuration (`src/wireghost/config.py`)

`ScanConfig.load()` resolves values in priority order: **explicit CLI/keyword overrides > `WIREGHOST_*` environment variables > `wireghost.yml` > dataclass defaults.** Any code that needs config should call `ScanConfig.load(...)` rather than reading env/yaml directly.

### Pipeline (`src/wireghost/pipeline/`)

`orchestrator.run_pipeline()` is the single async entry point. It sequences phases and runs a per-host fanout with `asyncio.Semaphore(config.parallelism)`:

1. Tool check (`utils/process.check_tools`)
2. `discovery.discover_hosts` — nmap `-sn` + fping, merge + dedupe
3. Per-host pipeline (parallel, bounded by semaphore):
   - `portscan.scan_host` — nmap → naabu → masscan **fallback chain** (if scanner N finds 0 ports, try N+1)
   - `webdetect.probe_host` — async HTTP/S probing + httpx tech detect
   - `cms_scan.scan_cms` — auto-triggers WPScan when WordPress fingerprinted
   - `service_enum.enumerate_services` — 18 services, pure-Python, no brute force
   - `vulnscan.scan_host_vulns` — nuclei + nmap `--script=vuln` + searchsploit (concurrent inside)
4. `_generate_reports` — calls `ReportEngine.generate()` if available

Nuclei external templates are batched (`nuclei_batch_size`, default 5000) to cap CPU/RAM on 37K+ template sets.

### Models → Parsers → Renderers (one-in, many-out)

All parsers in `src/wireghost/parsers/` (nmap, nuclei, naabu, masscan, openvas, searchsploit, wpscan) produce the same typed objects from `src/wireghost/models/`:

- `Host`, `Port`, `WebTech` (scan.py)
- `Finding` with full forensic fields: `request`, `response`, `curl_command`, `cvss`, `cwe`, `cve`, `references` (finding.py)
- `Severity` enum with consistent RGB colors used across every renderer
- `ScanReport` aggregates everything (report.py)

`reports/engine.py` dispatches one `ScanReport` into: `html_renderer`, `dashboard` (Jinja2 + Chart.js), `docx_renderer`, `xlsx_renderer`. Adding a format = add a renderer + register in the engine. Do not duplicate parsing.

### Web portal — Celery as the ORM↔pipeline bridge (`web_portal/`)

`web_portal/scanner/tasks.py::run_scan` is the critical integration point:

1. Loads a `Scan` ORM row (`web_portal/scanner/models.py` — custom `User` + `Scan`/`Host`/`Port`/`Finding`/`Report`/`ScanPolicy`/`ScheduledScan`, all with **UUIDv7** primary keys via `uuid_utils.uuid7`)
2. Builds a `ScanConfig` from the row's fields
3. `asyncio.run(run_pipeline(config))` — same pipeline as CLI
4. `_persist_results(scan, report)` writes dataclasses back to ORM
5. Invokes `ReportEngine` and records `Report` rows pointing at generated files

Django REST framework routes live in `web_portal/wireghost_web/urls.py`. Auth uses session cookies + CSRF (`scanner/authentication.py`, `scanner/auth_views.py`); there is also an API-key flow and a first-launch **setup wizard** (`setup-admin`, `site-setup-complete`). Singletons (`REPORT_CONFIG_UUID`, `SITE_CONFIG_UUID`) use fixed UUIDs.

Celery Beat drives `ScheduledScan` dispatch; worker consumes queues `scans,reports`.

### Frontend SPA (`web/`)

Vanilla JS, no framework. `web/js/router.js` is a hash router; pages live in `web/js/pages/` (dashboard, scans, findings, hosts, reports, topology, policies, scheduled, setup, etc.). `api.js` wraps fetch with CSRF handling. `mock.js` exists for offline frontend dev.

**Stored XSS hardening** has been applied across the JS layer (see commit `6ffa339`) — when touching any code that injects scan output into the DOM, prefer `textContent` over `innerHTML` and sanitize before rendering.

### Nginx (`nginx.conf`)

The portal container exposes only port 80 → `9995` on host. Nginx serves `/web` statically, proxies `/api/` to the Django `api` service, **blocks `/admin` and dotfiles with 404**, and sets a strict CSP. The API service is not published outside the Docker network.

### Docker image layout (`Dockerfile`)

Three-stage build: (1) pull latest nuclei/httpx/naabu release binaries, (2) compile `scannerctl` from OpenVAS Rust source, (3) assemble the `python:3.12-slim` runtime with nmap/fping/masscan/searchsploit + the wireghost package + pre-fetched nuclei templates and NASL feeds. `ENTRYPOINT ["wireghost"]`, so `docker run callmedemon/wireghost scan <target>` works directly.

External nuclei template archives (`templates/*.tar.gz`) are extracted at build **and** extracted by `web_portal/docker-entrypoint.sh` at container start, so dropping a new archive into `templates/` and restarting the stack is enough.

## Key Files

| File | Role |
|------|------|
| `src/wireghost/cli.py` | Typer entry: `scan`, `report`, `update`, `config` commands |
| `src/wireghost/config.py` | `ScanConfig` with layered loader (defaults → YAML → env → overrides) |
| `src/wireghost/pipeline/orchestrator.py` | Async phase coordinator; call site for the full pipeline |
| `src/wireghost/pipeline/portscan.py` | nmap → naabu → masscan fallback chain |
| `src/wireghost/pipeline/vulnscan.py` | nuclei + nmap vuln + searchsploit, with nuclei template batching |
| `src/wireghost/reports/engine.py` | Single dispatcher; one `ScanReport` in, N files out |
| `web_portal/scanner/tasks.py` | Celery bridge: ORM → `run_pipeline` → ORM |
| `web_portal/scanner/models.py` | Django models (UUIDv7 PKs, custom `User`, singleton config rows) |
| `web_portal/wireghost_web/urls.py` | REST routes + auth endpoints |
| `docker-compose.yml` | MySQL / Redis / api / worker / beat / portal / (tools profile) |
| `nginx.conf` | Portal reverse proxy; CSP + `/admin` block |

## Conventions & Gotchas

- **Python 3.11+** (project), **Docker image uses 3.12**. `pyproject.toml` pins `requires-python = ">=3.11"`.
- **No `script/` directory anymore.** The v1 bash orchestration (`main.sh`) has been fully replaced. Any docs referencing `script/main.sh`, `/root/output/`, or `script/docx/env/` are stale.
- Pytest is configured with `asyncio_mode = "auto"` — async tests don't need the `@pytest.mark.asyncio` decorator.
- XML parsing uses `defusedxml` (see dependency) — preserve this when adding parsers; don't reach for `xml.etree` directly.
- Report renderer template assets live in `src/wireghost/reports/templates/` (Jinja2) and `src/wireghost/reports/assets/`.
- Output tree (`utils/fs.build_output_tree`) produces `<output_dir>/<target_normalized>/{all,ips/<ip>/{nmap_xml,web,vuln,service_enum,cms},reports}`. Target normalization replaces `/` and `:` with `_`.
- Pre-built image on Docker Hub: `callmedemon/wireghost`. GitHub: `Lw1nM1n4ung/demon-in-the-wire`.
- Active branch: `rewrite-v2`. Main branch: `master`.
