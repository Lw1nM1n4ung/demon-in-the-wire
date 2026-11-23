# AGENTS.md

Wire_Ghost — security scanning toolkit. Two delivery modes over one shared async pipeline:

- **Standalone CLI** — `src/wireghost/` (Typer), entry point `wireghost.cli:app`
- **Web portal** — `web_portal/` (Django REST + Celery + MySQL + Redis + nginx)

Both call the same core: `wireghost.pipeline.orchestrator.run_pipeline()`.
The frontend SPA is vanilla JS in `web/` (no build step, no bundler).

Long-form docs already exist: `README.md` (user/ops guide) and `API.md` (REST reference).
Read those before changing behavior; this file only records what is easy to get wrong.

## Setup

```bash
pip install -e ".[dev]"        # Python 3.11+; 'dev' adds pytest + pytest-asyncio
pip install -r web_portal/requirements.txt   # Django/DRF/Celery side (separate dep set)
npm ci                          # Playwright only (browser tests)
```

`web_portal/requirements.txt` must stay in sync with `pyproject.toml` pins — CI installs both.
A `wireghost.yml` config file is optional; `wireghost config init` copies the root
`wireghost.example.yml` (a shorter, different file than the annotated `config/wireghost.example.yml`).

## Commands

```bash
# Python pipeline tests (930 collected)
python -m pytest tests/ -q
python -m pytest tests/test_parsers.py::TestParseNucleiArray::test_parse_nuclei_array -q

# Django scanner tests — MUST cd into web_portal (settings use a relative sqlite fallback in test mode)
cd web_portal && DJANGO_SECRET_KEY=ci-secret python manage.py test scanner --verbosity=1
cd web_portal && DJANGO_SECRET_KEY=ci-secret python manage.py test scanner.tests.test_ad_models -v2

# Frontend JS unit tests (pure logic, no browser)
node tests/test_frontend_js.js
node tests/test_topology_js.js
bash tests/test_installers.sh

# Browser suites — need a running portal; WG_BASE defaults to https://localhost:18443
WG_BASE=https://localhost:18443 WG_FAIL_ON_SKIP=1 npm run test:browser

# Lint (ruff config lives in pyproject.toml; line-length 100, target py311)
ruff check --output-format=github
ruff format --check --diff

# Full disposable-stack QA gate (builds images, runs every suite, tears down)
bash scripts/run_qa.sh            # uses current working tree
bash scripts/run_qa.sh --fresh-clone
```

`scripts/run_qa.sh` is the only command that exercises the real Docker stack; everything else
is host-only.

Pytest needs the package importable — without `pip install -e .` (or `PYTHONPATH=src`)
`tests/test_wireghost_*.py` fail to import `wireghost.cli.*` and 28 modules error at collection.
`pytest-asyncio` must be installed or `asyncio_mode = "auto"` is ignored and 42 async tests
silently skip (pytest reports `Unknown config option: asyncio_mode`).

## CLI gotchas (Typer)

`wireghost scan` takes the target as an **option, not a positional arg**:

```bash
wireghost scan --target 192.168.1.0/24      # correct
wireghost scan 192.168.1.0/24               # ERROR: Missing option '--target'
```

This changed in commit `c97505e` (Typer 0.23+ parsing bug with `invoke_without_command=True`).
README.md still shows the old positional form — trust the code.

Other command facts:
- `wireghost scan` launches a **detached tmux session** named `wg-<target>` by default.
  Use `--no-tmux` for foreground, `--attach`/`--list`/`--kill` to manage sessions.
- `wireghost report` (top-level) is a deprecated stub. Real command is `wireghost report generate <dir>`,
  which shells out to `python -m wireghost report <dir>` — that inner path is currently broken
  (`No such command`), so CLI report regeneration does not work today.
- `wireghost update` is deprecated → `wireghost system update`. `wireghost auth login/logout/whoami`
  for portal auth; there is no top-level `wireghost login`.
- All CLI output goes to **stderr** (`Console(stderr=True)`), not stdout. Piping stdout yields nothing.

## Docker / compose

- `.env` is required: the compose file uses `${VAR:?}` fail-on-unset for `MYSQL_PASSWORD`,
  `MYSQL_ROOT_PASSWORD`, `DJANGO_SECRET_KEY`, `REDIS_PASSWORD`. `config/.env.example` is the template;
  `scripts/install.sh` generates a working one plus self-signed certs.
- Service list: `db redis docker-proxy api worker beat bot portal`. Extra tool images
  (`wireghost nmap nuclei httpx`) sit behind the `tools` profile — they are **not** started by default.
- Dev overlay: `docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d`
  bind-mounts `./src` and `./web_portal/scanner` read-only, sets `DJANGO_DEBUG=true` and
  `WIREGHOST_PROTO=http`, and adds published ports: Django `:8000`, Redis `:6379`,
  portal `:9995`→container 80 (plus the base `:2006`/`:2007`→443). Requires `.env` first.
- **Which nginx.conf is live?** `docker-compose.yml` mounts the *root* `nginx.conf`
  (gitignored, tracked anyway — `git ls-files` includes it). `config/nginx.conf` is what the
  portal image bakes in; `config/nginx.conf.tpl` is the template rendered by
  `offline-export.sh`/`offline-install.sh`/`run_qa.sh` into root `nginx.conf`.
  The three files have drifted — the root one is the one the running stack serves.
- Root `nginx.conf` redirects to `https://$host:2007/...` and uses `server_name _` (no hardcoded IP);
  the hardcoded `127.0.0.1:2006` still exists in `config/nginx.conf`.
- After editing root `nginx.conf`: `docker exec wireghost-portal-1 nginx -s reload` (volume mount, no recreate).
- Container name is `wireghost-portal-1` only when the project dir is named `demon-in-the-wire`
  (compose derives it from the directory basename). `COMPOSE_PROJECT` is hardcoded to
  `demon-in-the-wire` in `docker-compose.yml` while `docker_stats.py` defaults to `wireghost` —
  a mismatch makes `/api/system-processes/` return zero containers.
- API/beat/bot images are `read_only: true` — you cannot `docker cp` into them, and
  `makemigrations` must be run **on the host** (`web_portal/scanner/migrations/`) then applied with
  `docker compose exec api python manage.py migrate`. The `api` service command already runs
  `python manage.py migrate --noinput` on startup, so a restart applies new migrations.
- Worker source lives at `/app/src/wireghost/pipeline/`, Django task code at `/app/scanner/tasks/`.
- Celery prefork reuses children: `docker restart` the worker after code changes (`docker cp` is not enough).
- The worker needs `nofile=65536` (the container default is 1024). Discovery fans out with a
  dedicated semaphore of `max(parallelism, 256)`, so it spawns hundreds of nmap/fping subprocesses
  at once; at 1024 fds the affected subnets fail with `Errno 24 Too many open files` and are
  **silently dropped** from the results. `docker-compose.dev.yml` always set this; the production
  `docker-compose.yml` did not — it now does.
- `web_portal/scanner/` is bind-mounted read-only into api/worker, so Django-side code changes
  only need a `docker compose restart worker` — no image rebuild.

## Metasploit Framework in the worker image

- The worker image ships the framework, copied out of the official
  `metasploitframework/metasploit-framework:latest` image (Dockerfile build stage `msf`).
  The rubygems `metasploit-framework` gem is a **4 KB meta-gem** — no code, no `modules/`,
  no `msfconsole` binstub even with `CREATE_BINSTUBS=1`. Do not try to install it from rubygems.
- **That image is Alpine (musl); the worker is Debian (glibc).** The Ruby binary cannot be run
  in place. The musl loader and the Alpine shared libraries are copied to `/opt/msf/alpine`, the
  Ruby stdlib and `libruby.so` stay at `/usr/local/lib` (that path is compiled into the Ruby
  binary as RUNPATH), and `web_portal/msfconsole-wrapper.sh` — installed as
  `/usr/local/bin/msfconsole` — invokes the loader explicitly.
- The wrapper's env mirrors the official image's own: `GEM_HOME` points at the bundle and
  **`BUNDLE_PATH` must stay unset** — setting it makes Bundler look for a `ruby/3.3.0/`
  sub-layout that does not exist. `GEM_PATH` must stay unset too, or Ruby's bundled gems
  (`rexml` and friends) become invisible.
- Paths: framework `/opt/msf/framework`, module tree `/opt/msf/framework/modules`, metadata
  index `/opt/msf/framework/db/modules_metadata_base.json`, wordlists
  `/opt/msf/framework/data/wordlists/`. `MSF_BIN` / `MSF_MODULES_DIR` / `MSF_METADATA_PATH`
  override the lookups.
- `msfconsole -q -x '...'` output is a **column-aligned table**: the header row and the dashed
  separator are on *separate* lines, and the "Current Setting" column is often empty, which
  shifts every later column left if the row is split on whitespace. `_parse_option_table` takes
  the column boundaries from the header row instead.
- Each `msfconsole` process is ~150 MB RSS. `scan_msf` caps simultaneous consoles at
  `_MSF_MAX_CONCURRENCY = 3`; without that cap the per-host pipeline can start
  `config.parallelism` consoles at once and blow the worker's 2 GB memory limit.

## Pipeline facts that are easy to get wrong

- Phase list is fixed and mirrored in two places that must stay in sync:
  `PHASE_ORDER` in `src/wireghost/pipeline/orchestrator.py` and `WG.PHASE_ORDER` / `WG.PHASE_LABELS`
  in `web/js/app/components.js`. Pages must reference `WG.PHASE_ORDER`, never hardcode phases.
- Phase weights (`discovery=9, portscan=27, webdetect=46, webcrawl=58, vulnscan=67, enumeration=77, reports=94`)
  live in `_PHASE_WEIGHTS` in the orchestrator. Progress is a per-host weighted average, so a slow
  host does not stall the bar.
- Port scan is **two-phase**: a symmetric SYN-only fallback chain (nmap → naabu → masscan), then a
  targeted `nmap -sV -sC [-O]` over only the discovered ports, then fingerprintx augmentation.
  Steps 1 and 2 are separate; changing one does not change the other.
- masscan currently runs **without** `--rate` (reverted in `52102e1`). Do not re-add it
  without measuring.
- gowitness v3 renamed `--resolution-x/y` to `--chrome-window-x/y` and defaults to JPEG —
  the pipeline passes `--screenshot-format png` explicitly. v2 flags fail *silently* (caught exception → zero screenshots).
- fingerprintx and nmap use different protocol names (`dns`/`domain`, `postgres`/`postgresql`,
  `mssql`/`ms-sql-s`, `rpc`/`rpcbind`). Any new service-name check must handle both.
- Web detection is verification-driven: only confident non-web protocol labels are skipped; everything
  else gets an HTTP HEAD probe and the response *is* the verification.
- Discovery uses a dedicated semaphore `max(config.parallelism, 256)`; the worker needs
  `nofile=65536` (set only in `docker-compose.dev.yml`).
- **nmap's defaults make discovery crawl.** `nmap -sn` waits ~8 s per unresponsive host and keeps
  only a handful of hosts in flight, so a /24 where nothing answers cost ~19 min. The tuned flags
  live in `ScanConfig.discovery_nmap_args` (`--max-retries 0 --host-timeout 5s
  --min-parallelism 32 --max-parallelism 64 --initial-rtt-timeout 100ms --max-rtt-timeout 1500ms`)
  and bring it to ~15 s. Override them in `wireghost.yml` on a high-latency link.
- **Never parse nmap output with a bare IP regex.** nmap writes `Warning: <ip> giving up on port
  because retransmission cap hit (0).` to *stdout*, so `_IPV4_RE.findall(stdout)` turned a dead
  range into 256 phantom "live hosts". Use `_parse_nmap_hosts()` (report block + "Host is up")
  instead — `tests/test_nmap_host_parser.py` guards it.

## Django / Celery conventions

- All model PKs are UUIDv7 via `generate_uuid7()` (`web_portal/scanner/models/__init__.py`).
  Never use Django's default UUID field.
- Raw SQL against MySQL must use `str(uuid).replace("-", "")` — MySQL stores UUIDs as CHAR(32).
  The ORM handles this automatically; only raw SQL needs it.
- **Celery bridge sentinel ordering (critical):** in `web_portal/scanner/tasks/__init__.py`'s
  `finally` block, `_progress_queue.put(None)` MUST come before `_progress_stop.set()`.
  Stopping first discards queued `host_result` items — losing ports, findings, and screenshots.
- The bridge uses a daemon thread + `queue.Queue` because Django's `SynchronousOnlyOperation`
  blocks DB access inside `asyncio.run()`. Callbacks inside the async loop only enqueue tuples.
- Celery queue routing is limited to `scanner.tasks.run_scan` → `scans` and
  `scanner.tasks.generate_report` → `reports`; the worker consumes `celery,scans,reports`.
  A new task that must run on a separate queue needs a route added in `wireghost_web/celery.py`.
- AD recon passes decrypted credentials as CLI argv to external tools — visible in `/proc/*/cmdline`.
  Do not add more tools that take secrets via argv; prefer stdin / `chmod 600` temp files.
- Fernet key is derived from Django `SECRET_KEY`. Always call the model's `decrypt_password()`,
  never touch the raw field.

## Frontend conventions (`web/`)

- History API router (`web/js/app/router.js`), not hash routing. Route table is `WG._ROUTES`;
  each page module must be registered in `WG._ROUTES` **and** in the `pages` map in `WG.render`.
- Adding/removing a page touches three files: `web/app.html` (script tag + sidebar entry),
  `web/js/app/router.js` (route + render map), and the page module under `web/js/app/pages/`.
  The script tag carries a `?v=N` cache-buster — bump it when you change an existing file.
- `WG.api(path, method, body)` accepts a 3-arg form and auto-stringifies object bodies;
  a 2-arg `WG.api(path, {method, body})` form also works. CSRF token comes from the `csrftoken` cookie.
- Prefer `textContent` over `innerHTML` when injecting scan data (stored-XSS hardening;
  `tests/test_xss_regression.js` enforces this).
- Two-tier serving: `/js/public/*` is unauthenticated (login/setup), `/js/app/*` is behind the
  nginx `auth_request` gate. Public JS must not import app JS.
- `tests/test_frontend_js.js` loads a fixed file list via `vm.runInContext` — a page module that is
  deleted but still listed there breaks the whole suite with ENOENT (currently true for
  `pages/new-scan.js`). Keep that list and `web/app.html` in sync with what exists on disk.
- **`WG.getCached(key, apiPath)` never calls the API.** It is a synchronous in-memory lookup that
  returns `[]` when the cache is cold; `apiPath` is ignored. A page that only reads `getCached`
  therefore renders an empty list on a direct load. The fix is to pair it with
  `WG.refreshAndRerender(key, apiPath, renderFn, pageName)` (which does fetch + re-render) or to
  fetch directly. `live-discovery.js` and `reports.js` both needed this — the reports page silently
  fell back to **demo data** while real reports existed.
- `WG._ROUTES` and the `pages` map in `WG.render` must agree: a page present in only one of them is
  unreachable. `finding` was in the pages map but missing from `_ROUTES` (the `/findings/:id` detail
  page was supposed to be kept when `/findings` was removed).
- The API is throttled per user at **120 req/min** (`UserRateThrottle` in settings). Long browser
  test runs can trip it, and a 429 on `/api/auth/me/` stops the SPA from booting — clear the
  `throttle_*` cache keys or wait a minute before re-running the E2E suite.

## Repo state caveats (verify before trusting docs)

- `ruff check` currently reports **28 errors** and `ruff format --check` reports **30 Python + 9 Markdown
  files** needing reformat — the branch is not lint-clean. Ruff also formats Markdown code blocks,
  so scope `ruff format` to changed files.
- `API.md` says the API is unauthenticated; it is not — the portal uses session + CSRF + API keys +
  role gates (owner/engineer/viewer) with `HasPerm`/`HasMethodPerm` on the ViewSets.
- There is no `script/` directory; v1 bash orchestration was removed. References to
  `script/main.sh` or `/root/output/` are stale.
- `tests/test_full_qa.py` and `tests/test_portal_stable.py` hit a live portal at
  `https://localhost:18443` and self-skip when it is unreachable.
- `WIREGHOST_AUTO_INSTALL_TOOLS` defaults to `1`: the pipeline will try to apt/pip-install missing
  scan tools. Set it to `0` in CI or sandboxes (CI does this).
- `templates/*.tar.gz` (nuclei template archives) are extracted by `web_portal/docker-entrypoint.sh`
  at container start from `/opt/nuclei-template-archives` into `/opt/nuclei-external-templates`
  (the dir `config.nuclei_templates` points at). The dev overlay mounts the repo `templates/`
  over the archive dir, so archives dropped there are picked up on worker restart.

## Operations

- `scripts/wg-ctl` is the day-2 CLI: `status | start | stop | restart | backup | restore <file> --confirm |
  logs [service] | reset-password <user> | certs status|renew | update | shell | uninstall --confirm`.
- `scripts/update-wireghost.sh --full` does `compose down` + `--no-cache` rebuild + `--force-recreate`:
  running scans and in-flight Celery tasks are lost. Wait for active scans to finish.
- `scripts/install.sh` is interactive and needs root (generates `.env`, TLS certs, starts the stack).
  `scripts/install-wireghost.sh` is the one-line `curl | bash` remote installer.
- `uninstall.sh` and `scripts/remove-wireghost.sh` remove Docker resources; both accept
  `--keep-data` / `--keep-images` variants.
