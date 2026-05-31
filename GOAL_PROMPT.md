# /goal prompt for Wire_Ghost rewrite-v2

Copy the block below and use it with `/goal` at the start of a session:

---

```
Wire_Ghost v2.0 rewrite — rebuild a production-grade security scanning toolkit from scratch on the rewrite-v2 branch. All old source is deleted; you are building fresh. The project ships two modes (standalone CLI + Docker Compose web portal) that call the same async pipeline. Reference CLAUDE.md and README.md for the full architecture — those are source of truth, not suggestions.

**What we're rebuilding:**
- `src/wireghost/` — Python package: async pipeline (7-phase: discovery→portscan→webdetect→webcrawl→vulnscan→enumeration→reports), Typer CLI with 15+ domain apps, layered config, models, parsers, renderers (HTML/DOCX/XLSX/dashboard)
- `web_portal/` — Django REST API: RBAC (Owner/Engineer/Viewer, 17 permission codes), Celery bridge with daemon-thread+queue for real-time progress, UUIDv7 PKs, DRF ViewSets with HasPerm/HasMethodPerm, auth (session+token+setup wizard), Telegram bot (long-polling, 14 files, inline keyboards), notifications, AD recon engine (Fernet-encrypted creds, 8-phase Celery task), ScanArtifact persistence, 38+ migrations
- `web/` — vanilla JS SPA: History API hash-router, two-tier serving (public before auth, app behind auth_request), Chart.js+D3, real-time polling (2s for live discovery, 3s for scan progress), 22 page modules, XSS-hardened with textContent preference
- `scripts/` — bash: installer (interactive .env+TLS generation), wg-ctl management CLI, offline export/install, update-wireghost (full stack rebuild), verify-deploy, remove-wireghost
- Docker: 4 images (web ~180MB, worker ~700MB with all tools, portal ~50MB, CLI ~700MB with Metasploit), 8 compose services, dev overlay with bind mounts, ulimits for large scans

**How to work — process rules:**
- Read CLAUDE.md and README.md in full before writing any code — they encode months of debugging
- Follow the existing patterns exactly: UUIDv7 PKs, layered config (CLI>env>YAML>defaults), async Semaphore-bounded pipeline, daemon-thread+queue for ORM bridging, vanilla JS SPA with WG.* helpers, DRF serializers with method-switching
- Every model gets UUIDv7 primary keys via uuid_utils.uuid7() — never Django's default UUID
- Reuse the same architectural decisions: two-phase portscan (SYN discovery→targeted -sV), verification-driven web detection, cross-tool dedup by CVE or normalized title, two-pass NVD CVE search, weighted per-host progress
- Don't add abstractions the old codebase didn't have. Three similar lines beats a premature helper. No half-finished implementations
- No comments unless the WHY is non-obvious (hidden constraint, subtle invariant, workaround for known bug). Never document WHAT the code does
- For every new file, match the old naming convention. For every new function, match the old signature patterns. Consistency over cleverness

**Security non-negotiables (from the old codebase's hardening):**
- SSRF-safe target validation: block loopback/link-local/multicast/reserved/cloud-metadata IPs, detect hex/octal/short-form encoding, resolve hostnames via getaddrinfo against full blocklist
- Path traversal: all file-serving endpoints use Path.is_relative_to()
- XSS: prefer textContent over innerHTML when injecting scan output
- AD recon: Fernet AES-256-GCM encryption, never pass creds via argv (use stdin/tempfiles), no double-encryption guard
- CSP via nginx, Django admin blocked at nginx level, two-tier JS serving, HttpOnly+SameSite=Lax cookies
- API tokens: wg_ prefix, SHA-256 hashed, shown once, instant revoke

**Critical gotchas to never repeat:**
- Daemon thread sentinel ordering: sentinel BEFORE stop event, or all host results are lost
- Masscan needs --rate 5000 (100 pps default causes event-loop deadlocks)
- Gowitness v3: --chrome-window-x/y not --resolution-x/y, always --screenshot-format png
- fingerprintx vs nmap naming: dns≠domain, postgres≠postgresql, mssql≠ms-sql-s — maintain both conventions
- nginx.conf has host IP hardcoded in 3 places — when IP changes, all 3 must update
- Worker container needs nofile=65536 ulimit for discovery (256 concurrent nmap)
- makemigrations on host, not API container (read-only rootfs)
- UUID format for raw SQL: strip dashes (MySQL stores CHAR(32))
- Celery child processes cache bytecode — always docker restart after code changes
- Docker DNS caches stale container IPs — restart portal after API recreate

**Test infrastructure to rebuild:**
- pytest ~890 tests with asyncio_mode=auto
- Django scanner tests (DJANGO_SECRET_KEY=ci-secret, manage.py test scanner)
- Frontend JS unit tests (node tests/test_frontend_js.js, test_topology_js.js)
- Installer shell tests (bash tests/test_installers.sh)
- Playwright browser tests (npm run test:js-regression, test:xss-regression, test:portal-e2e)
- Full QA gate: bash scripts/run_qa.sh (disposable Docker stack, all suites)
- Every test must pass before claiming completion

**Quality bar:**
- ruff lint with pyflakes+pycodestyle+bugbear, line-length=100, no E402/E501/E731/B007/B008/B904/B905
- CI: GitHub Actions with pytest+Django+frontend+installer tests, Trivy security scan at HIGH/CRITICAL
- Docker compose config must validate (docker compose config --quiet)
- All installer scripts must pass shellcheck
- Pre-commit hooks exist and catch issues before commit
```

---

## Usage

```bash
/goal <paste the block above>
```

Or save as a snippet and paste. The goal persists for the session — Claude will treat this as its directive and work accordingly.

## Customization

Shorter version for focused sessions:

```
Work on Wire_Ghost rewrite-v2. Follow patterns in CLAUDE.md exactly. No new abstractions. Security hardening is non-negotiable. Tests must pass. Read CLAUDE.md before writing code.
```
