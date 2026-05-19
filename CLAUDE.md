# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Wire_Ghost (v2.0) is a security scanning toolkit that orchestrates multiple tools (nmap, nuclei, nikto, naabu, masscan, httpx, wpscan, searchsploit, enum4linux, netexec, metasploit, impacket, kerbrute, bloodhound-python) through an async Python pipeline, persists results to typed models, and renders them into HTML / DOCX / XLSX / interactive dashboard reports. It ships in two modes:

- **Standalone CLI** — `wireghost scan <target>` (Typer-based, Python 3.11+)
- **Full web portal** — Django REST API + vanilla-JS SPA + Celery workers, orchestrated via Docker Compose (MySQL, Redis, Nginx)

Both paths call the same `wireghost.pipeline.orchestrator.run_pipeline()`. The portal wraps it with a Celery task that bridges Django ORM records to the pipeline's dataclasses. The portal also includes an **Active Directory reconnaissance tab** — credential management with Fernet encryption, 7-phase Celery task (LDAP → BloodHound → AS-REP roasting → Kerberoasting → RPC → ADCS → Responder), and DRF API with RBAC.

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

# Full stack (interactive installer generates .env, TLS certs, starts stack)
sudo bash scripts/install.sh

# Standalone scanner via Docker
docker compose run --rm wireghost scan 10.0.0.0/24
```

`.env` is required for `docker compose up` — the compose file uses `:?` fail-on-unset for required secrets.

## Architecture

### Layered configuration (`src/wireghost/config.py`)

`ScanConfig.load()` resolves values in priority order: **CLI overrides > `WIREGHOST_*` env vars > `wireghost.yml` > dataclass defaults.** Never read env/yaml directly — use the config object.

### Pipeline (`src/wireghost/pipeline/`)

`orchestrator.run_pipeline()` is the single async entry point. All phases fan out per-host with `asyncio.Semaphore(config.parallelism)`:

1. **Tool check** — verifies required tools (nmap, fping, nuclei) are installed; logs optional tool availability (naabu, masscan, msfconsole, etc.)

2. **Host discovery** — enhanced nmap `-sn` (TCP SYN to 17 ports + UDP ping to 5 ports) + fping ICMP sweep + arp-scan/netdiscover L2 ARP + passive DNS sweep (`nmap -sL -R`). **Tools within each subnet run in parallel** (`asyncio.gather`). **Passive DNS is interleaved with active scans** per /24 subnet — DNS coros are fanned out alongside scan coros so PTR lookups don't bottleneck. Large CIDRs (>/16) auto-partition into /24 subnets scanned concurrently. Results merge + dedupe into live IP set. `scan_unresponsive` flag forces port-scanning of ICMP-silent hosts.

3. **Per-host pipeline** (parallel, semaphore-bounded):
   - **3a. Port discovery** — nmap → naabu → masscan **symmetric fallback chain** (all three only do fast SYN scan, no service probing). If tool N finds 0 ports, try N+1. Symmetric because all three just find ports — no tool has an unfair advantage.
   - **3b. Service analysis** — **always runs** regardless of which tool won the chain. Runs `nmap -sV -sC [-O]` targeted at only discovered ports. Completes in seconds (vs 30-90 min for full -sV on 65535). Merges service/OS data back into the Host model.
   - **Web detection** — **verification-driven**: only skip ports where nmap confidently identifies a non-web protocol; probe everything else with HEAD requests. HTTP/HTTPS response IS the verification. + httpx tech detect
   - **Web crawl** — katana crawls discovered web endpoints (runs sequentially — nuclei needs the URLs for templated requests)
   - **11 parallel scanners** via `asyncio.gather`: CMS (WPScan), service_enum (18 services, pure-Python), SMB, netexec, TLS audit, SNMP, NFS, LDAP, vulnscan (nuclei + nmap-vuln + searchsploit + getsploit + nikto — all concurrent), screenshot (gowitness), MSF (service-routed auxiliary/scanner modules)
   - Cross-tool finding deduplication by CVE or normalized title prefix

4. **Report generation** — `ReportEngine.generate()` dispatches to all configured formats (HTML dashboard, DOCX, XLSX)

### Models → Parsers → Renderers

All parsers in `src/wireghost/parsers/` produce the same typed objects: `Host`, `Port`, `WebTech`, `Finding` (with forensic fields: `request`, `response`, `curl_command`, `cvss`, `cwe`, `cve`, `references`), `Severity` (enum with consistent RGB colors), and `ScanReport` (the aggregate).

`reports/engine.py` dispatches one `ScanReport` into HTML (dashboard), DOCX, XLSX. Adding a format = add a renderer + register it. Don't duplicate parsing.

### Web portal (`web_portal/`)

Celery bridges Django ORM ↔ pipeline: `scanner/tasks/__init__.py::run_scan` loads a `Scan` ORM row (UUIDv7 PKs), builds `ScanConfig`, calls `asyncio.run(run_pipeline(config))`, then writes dataclasses back to ORM via `_persist_results()`.

Django REST routes in `web_portal/wireghost_web/urls.py`. Auth: session cookies + CSRF + API-key flow + first-launch setup wizard. Celery Beat drives scheduled scan dispatch.

Models, views, serializers, and tasks have each been split from single files into **packages**: `scanner/models/` (`__init__.py` + `ad_recon.py`), `scanner/views/`, `scanner/serializers/`, `scanner/tasks/`. The AD recon subsystem adds 11 encrypted models (Fernet AES-256-GCM), DRF ViewSets with RBAC, and a 7-phase Celery task (`ad_recon_task`).

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
| `src/wireghost/config.py` | `ScanConfig` with layered loader (defaults → YAML → env → overrides). Key flags: `enhanced_discovery` (TCP 17 ports + UDP 5 ports, default True), `skip_passive_dns`, `scan_unresponsive`, `skip_msf_scan`, `msf_metadata_path`, `vulners_api_key` |
| `src/wireghost/pipeline/orchestrator.py` | Async phase coordinator; call `run_pipeline()` |
| `src/wireghost/pipeline/discovery.py` | Phase 2 — enhanced nmap/fping/ARP/DNS sweep; per-subnet parallel tool execution; passive DNS interleaved with active scans; CIDR partitioning |
| `src/wireghost/pipeline/portscan.py` | Phase 3a+3b — symmetric nmap→naabu→masscan port discovery + targeted `-sV -sC -O` service analysis |
| `src/wireghost/pipeline/webdetect.py` | Phase 4 — verification-driven web probing (negative nmap filter only, HTTP HEAD verification, httpx tech detect) |
| `src/wireghost/pipeline/web_crawl.py` | Phase 4a — katana web crawler (runs sequentially before vulnscan — nuclei needs crawled URLs) |
| `src/wireghost/pipeline/vulnscan.py` | nuclei + nmap vuln + searchsploit + getsploit + nikto (all concurrent per host) |
| `src/wireghost/pipeline/msf_scan.py` | Service-routed Metasploit auxiliary/scanner modules; static curated map + dynamic metadata lookup; RC script generation |
| `src/wireghost/parsers/getsploit.py` | Parses Vulners API JSON (getsploit output) into Finding objects |
| `src/wireghost/parsers/msf.py` | Parses MSF spool/console output into Finding objects |
| `src/wireghost/deploy/engine.py` | Cloud-native deployment engine (SAM, IaC generation) |
| `src/wireghost/reports/engine.py` | Single dispatcher: one `ScanReport` → N output files |
| `web_portal/scanner/tasks/__init__.py` | Celery bridge: ORM → `run_pipeline` → ORM; AD recon 7-phase task in `tasks/ad_recon.py` |
| `web_portal/scanner/models/__init__.py` | Django models (UUIDv7 PKs, custom User, singleton config rows); 11 encrypted AD recon models in `models/ad_recon.py` |
| `web_portal/scanner/views/__init__.py` | DRF ViewSets with RBAC; AD recon ViewSet in `views/ad_recon.py` |
| `web_portal/scanner/serializers/__init__.py` | DRF serializers; AD recon serializers in `serializers/ad_recon.py` |
| `web_portal/scanner/tools_health.py` | Tools health probe; dispatched to worker, falls back to `ok=False` stubs when Celery unavailable |
| `web_portal/wireghost_web/urls.py` | REST routes + auth endpoints; AD recon routes at `/api/ad-recon/` |
| `web/js/app/pages/ad-recon.js` | AD recon SPA frontend — three-panel cockpit, session polling, credential management |
| `docker-compose.yml` | MySQL / Redis / api / worker / beat / portal / wireghost (tools profile) |
| `nginx.conf` | Portal reverse proxy; CSP + `/admin` block |

## Conventions & Gotchas

- **Python 3.11+** (project), **Docker uses 3.12**. `pyproject.toml` pins `requires-python = ">=3.11"`.
- **Dependency pinning**: `typer[all]>=0.9,<0.24` and `rich>=13.0,<14.0` in `pyproject.toml` — Typer 0.23.0+ changed `Option()` signature and removed `CliRunner(mix_stderr=...)`. Test assertions checking CLI output in stdout may find text in stderr (Rich `Console(stderr=True)`).
- **`web_portal/requirements.txt`** must stay in sync with `pyproject.toml` pins — CI installs both.
- Pytest: `asyncio_mode = "auto"` — async tests don't need `@pytest.mark.asyncio`. ~851 tests collected.
- XML parsing uses `defusedxml` — don't reach for `xml.etree` directly.
- Report templates: `src/wireghost/reports/templates/` (Jinja2) and `src/wireghost/reports/assets/`.
- Output tree normalization: `/` and `:` → `_` in target names. Structure: `<output_dir>/<target>/{all,ips/<ip>/{nmap_xml,web,vuln,service_enum,cms},reports}`.
- Nuclei external templates are batched (default 5000) to cap CPU/RAM on large template sets.
- **getsploit (Vulners API)**: Requires `VULNERS_API_KEY` env var (mapped via config layering). Queries Vulners across Exploit-DB, Metasploit, Packetstorm. Runs in parallel with other vuln scanners.
- **Port scan is two-phase**: Phase 3a discovers ports (nmap `-p- --open -Pn`, SYN only, no service probing — all three scanners symmetric); Phase 3b runs targeted `nmap -sV -sC [-O]` on only the discovered ports. This keeps the fallback chain symmetric and makes service analysis independent of which tool won. Output: `portscan.xml` (discovery) and `service_analysis.xml` (targeted analysis).
- **Web detection is verification-driven**: Only nmap's confident non-web protocol labels are trusted to skip ports. Everything else gets probed with HTTP HEAD — the response IS the verification. No positive assumptions from port numbers.
- **Cross-tool finding dedup**: `_dedup_findings()` in orchestrator.py normalizes by CVE (when present) or title prefix (stripping `nmap:`, `msf:`, `nxc:` prefixes), deduplicating on `host:port:identity`.
- **Tmux scan**: `wireghost scan` launches a detached tmux session by default. Session named `wg-<target>`. Re-attach with `wireghost scan --attach <target>` or `tmux attach -t wg-<target>`. Use `--no-tmux` for foreground runs.
- **CI**: Trivy scans at `HIGH,CRITICAL` with `exit-code: 0` and `.trivyignore`. Django scanner tests need `DJANGO_SECRET_KEY=ci-secret`. Tools health tests expect `ok=False` stubs when no Celery worker.
- **Branch**: `rewrite-v2` (default). GitHub: `Lw1nM1n4ung/demon-in-the-wire`. Docker Hub: `callmedemon/wireghost`.
- No `script/` directory — v1 bash orchestration has been fully replaced. Any docs referencing `script/main.sh` or `/root/output/` are stale.
