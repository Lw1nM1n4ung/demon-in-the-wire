# Wire_Ghost — Copilot Instructions

## Common Commands

```bash
# Install in editable mode
pip install -e ".[dev]"

# Run a scan (CLI)
wireghost scan 192.168.1.0/24
wireghost scan 10.0.0.1 --formats dashboard,docx --parallelism 20

# Re-render reports from existing output
wireghost report ./output/192.168.1.0_24 --formats dashboard,docx,xlsx

# Config
wireghost config init      # copy wireghost.example.yml → wireghost.yml
wireghost config show      # print resolved config (after layering)
```

### Tests

```bash
# Python pipeline tests (~890 tests, asyncio_mode=auto)
python -m pytest tests/ -v
python -m pytest tests/test_parsers.py::test_parse_nuclei_json -v   # single test

# Django scanner tests (needs DJANGO_SECRET_KEY and cd web_portal)
cd web_portal && DJANGO_SECRET_KEY=ci-secret python manage.py test scanner --verbosity=1

# AD recon tests only
cd web_portal && DJANGO_SECRET_KEY=ci-secret python manage.py test \
  scanner.tests.test_ad_models scanner.tests.test_ad_tasks \
  scanner.tests.test_ad_views scanner.tests.test_ad_integration --verbosity=1

# Frontend JS unit tests (pure logic, no browser)
node tests/test_frontend_js.js
node tests/test_topology_js.js

# Installer shell tests
bash tests/test_installers.sh

# Full QA gate (disposable Docker stack, all suites)
bash scripts/run_qa.sh
bash scripts/run_qa.sh --fresh-clone   # clone from remote first
```

### Lint

```bash
ruff check --output-format=github
ruff format --check --diff
```

### Docker

```bash
# Full stack
sudo bash scripts/install.sh           # interactive: generates .env, TLS certs, starts stack

# Dev stack (bind mounts, debug ports, HTTP)
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# Standalone scanner via Docker
docker compose run --rm wireghost scan 10.0.0.0/24

# Apply migrations (api image is read-only — run on host, apply in container)
docker compose exec api python manage.py migrate

# Reload nginx after config changes
docker exec wireghost-portal-1 nginx -s reload
```

`.env` is required for `docker compose up` — the compose file uses `${VAR:?}` fail-on-unset.

## Architecture

### Two modes, one pipeline

- **Standalone CLI** — `wireghost scan <target>` (Typer, Python 3.11+)
- **Full web portal** — Django REST API + vanilla-JS SPA + Celery workers, Docker Compose (MySQL, Redis, Nginx)

Both call the same core: `wireghost.pipeline.orchestrator.run_pipeline()`. The portal wraps it with a Celery task that bridges Django ORM records to the pipeline's dataclasses.

### Pipeline (7 phases)

```
discovery → portscan → webdetect → webcrawl → vulnscan → enumeration → reports
```

`orchestrator.run_pipeline(config, on_progress=None, on_discovery_complete=None, on_host_complete=None, on_host_phase=None, on_subnet_complete=None)` — single async entry point. Per-host weighted progress via `_advance_host_phase()` — fast hosts pull the bar forward, one slow host won't stall it.

### Layered configuration

`ScanConfig.load()` resolves: **CLI overrides > `WIREGHOST_*` env vars > `wireghost.yml` > dataclass defaults.** Never read env/yaml directly — use the config object.

### Celery bridge pattern

Django's `SynchronousOnlyOperation` blocks sync DB access inside `asyncio.run()`. The Celery task bridges this with a **daemon thread + queue**: callbacks inside the async loop enqueue tuples like `("progress", phase_label, pct, done)`, `("host_result", host, findings)`, etc. A dedicated thread dequeues and writes via raw SQL.

**Critical sentinel ordering:** In the `finally` block, the sentinel `_progress_queue.put(None)` MUST come BEFORE `_progress_stop.set()`. The daemon thread exits when `_progress_stop` is set, so stopping first discards all enqueued `host_result` items — meaning ports, findings, and screenshots are lost.

### Models → Parsers → Renderers

All parsers in `src/wireghost/parsers/` produce the same typed objects: `Host`, `Port`, `WebTech`, `Finding` (with forensic fields: `request`, `response`, `curl_command`, `cvss`, `cwe`, `cve`, `references`), `Severity` (enum with consistent RGB colors), `ScanReport`.

`reports/engine.py` dispatches one `ScanReport` into HTML (dashboard), DOCX, XLSX. Adding a format = add a renderer + register it.

### Docker images

| Dockerfile | Image | Purpose |
|------------|-------|---------|
| `Dockerfile` (root) | `callmedemon/wireghost` | Standalone CLI scanner with all tools + Metasploit |
| `web_portal/Dockerfile` | `callmedemon/wireghost:worker` | Worker with all scan tools |
| `web_portal/Dockerfile.web` | `callmedemon/wireghost:web` | Slim API/portal (read-only rootfs, no tools) |
| `web_portal/Dockerfile.portal` | `callmedemon/wireghost:portal` | Nginx + static SPA assets baked in |

## Key Conventions

### Python

- **Python 3.11+** (project), **Docker uses 3.12**
- **UUIDv7 primary keys**: All models use `uuid_utils.uuid7()` via `generate_uuid7()` helper. Never use Django's default UUID PKs.
- **UUID format for raw SQL**: `str(uuid)` produces dashes (`019e4470-e6e2-7200-...`) but MySQL stores without dashes as CHAR(32). Always do `str(uuid).replace("-", "")` in raw SQL. ORM handles this automatically.
- **XML parsing**: Use `defusedxml` — never `xml.etree` directly.
- **Pytest**: `asyncio_mode = "auto"` — async tests don't need `@pytest.mark.asyncio`.
- **Output tree**: `/` and `:` → `_` in target names. Multi-target strings > 200 chars are truncated with 8-char SHA256 hash to avoid ENAMETOOLONG.
- Type hints everywhere. `pathlib` over `os.path`.

### Port scan is two-phase

Step 1 discovers ports (nmap `-p- --open -Pn`, SYN only — all three scanners symmetric). Step 2 runs targeted `nmap -sV -sC [-O]` on only discovered ports, then fingerprintx augments service names.

### fingerprintx vs nmap naming

The two tools use different protocol names: `dns` vs `domain`, `postgres` vs `postgresql`, `mssql` vs `ms-sql-s`, `rpc` vs `rpcbind`. When adding a new service name check, handle both conventions.

### Web detection is verification-driven

Only nmap's confident non-web protocol labels are trusted to skip ports. Everything else gets probed with HTTP HEAD — the response IS the verification. No positive assumptions from port numbers.

### masscan rate

Uses `--rate 5000` (~13s per host). Without `--rate`, masscan defaults to 100 pps (~11 min per host) causing event-loop deadlocks. Never remove the `--rate` flag.

### gowitness v3 breaking changes

Worker image ships gowitness 3.x (not v2). Flags `--resolution-x`/`--resolution-y` are renamed to `--chrome-window-x`/`--chrome-window-y`. Default format is JPEG — always pass `--screenshot-format png`. Using v2 flags causes silent failures and zero screenshots.

### Fernet encryption (AD recon)

Uses Django `SECRET_KEY` hashed with SHA256 → base64 → Fernet key. Applied to `CredentialProfile.password`, `CredentialFinding.password`, and other AD models. Always call model's `decrypt_password()` method — never access the raw field.

### AD recon credentials on command line

`ad_recon.py` passes decrypted credentials as CLI arguments to tools (ldapdomaindump, impacket, bloodhound-python). These appear in `/proc/*/cmdline` visible to any user. Do NOT add more tools that receive secrets via argv — prefer stdin, temp files with `chmod 600`, or environment variables.

### Frontend: phase progress

`web/js/app/components.js` defines the single source of truth:
- `WG.PHASE_ORDER` — `['discovery', 'portscan', 'webdetect', 'webcrawl', 'vulnscan', 'enumeration', 'reports']`
- `WG.PHASE_LABELS` — human-readable labels
- `WG.phaseProgress(s)` — reads from `hosts_scanned` (pre-computed weighted %)

All pages reference these — never hardcode phase lists in individual pages.

### nginx.conf: hardcoded IP

`nginx.conf` has the host IP hardcoded in `server_name` and both redirect targets (`return 301` for HTTP→HTTPS, `return 302` for auth gate). When the host IP changes, all three must be updated AND nginx reloaded. Use `sudo python3 ip-reload.py <NEW_IP>` for one-command fix.

### Django `makemigrations` on the HOST

The API image has a read-only rootfs. Run `makemigrations` on the host at `web_portal/scanner/migrations/`, apply with `docker compose exec api python manage.py migrate`.

### Docker DNS caches stale IPs

When an API container is recreated, nginx may cache the old IP for several minutes → 502 Bad Gateway. Fix: `docker compose restart portal` to force fresh DNS.

### Worker: bind mounts + container restart

Dev compose bind-mounts `./src` and `./web_portal/scanner` (read-only) into api/worker. Code changes take effect after container restart — no rebuild needed. Celery prefork pool reuses child processes — always `docker restart` the worker after code changes (bind-mount edit or `docker cp` is not enough).

### Discovery: high-concurrency semaphore

Discovery uses a dedicated semaphore `max(config.parallelism, 256)` — a /16 produces 256 /24 subnets scanned in a single wave. Worker container MUST have `nofile=65536` ulimit. Ulimit changes require container recreate (`docker compose up -d`), not just restart.

### ScanArtifact: raw tool output persistence

Raw tool output (nmap XML, nuclei JSON, enum4linux txt) is persisted to `ScanArtifact` rows via artifact queue in the Celery bridge's daemon thread. The serializer switches by action: `ScanArtifactListSerializer` (excludes `content`) for list, `ScanArtifactSerializer` (full detail) for retrieve. The frontend accordion viewer uses lazy loading from the detail endpoint.

### Tmux scan

`wireghost scan` launches a detached tmux session by default. Session named `wg-<target>`. Re-attach with `wireghost scan --attach <target>` or `tmux attach -t wg-<target>`. Use `--no-tmux` for foreground runs.

### COMPOSE_PROJECT

`docker_stats.py` filters containers by label `com.docker.compose.project=<PROJECT>`. The project name defaults to the directory basename. If `.env` sets `COMPOSE_PROJECT_NAME` to something mismatched, the `/api/system-processes/` endpoint returns zero containers.
