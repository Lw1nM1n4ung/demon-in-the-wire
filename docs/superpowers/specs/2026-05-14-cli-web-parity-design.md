# CLI/Web Parity — Design Spec

**Date:** 2026-05-14
**Status:** Draft
**Goal:** Full feature parity between the Wire_Ghost web portal and CLI. Every action possible in the web UI is available via `wireghost` (Python/typer) commands. The bash `wg-ctl` remains the infrastructure-ops tool.

---

## Architecture

Two CLIs with clear separation:

| CLI | Language | Scope |
|---|---|---|
| `wireghost` | Python / typer | Scan execution, scan management, findings triage, user/policy/schedule admin, reporting, auth |
| `wg-ctl` | Bash | Infrastructure operations: start/stop, backup/restore, certs, logs, update, uninstall |

`wireghost` is an API client — it talks to the portal's REST API over HTTPS. No direct database access. This keeps business logic in Django and makes the CLI work against remote portals too.

```
┌──────────────┐     HTTPS (self-signed OK)     ┌─────────────────┐
│  wireghost   │ ────────────────────────────── │  Wire_Ghost API  │
│  (typer CLI) │                                 │  (Django REST)   │
└──────────────┘                                 └─────────────────┘
       │                                                  │
       │ auth via login command                            │
       │ (session cookie + token)                          │
       │ or WIREGHOST_TOKEN env var                        │
```

---

## File Layout

```
src/wireghost/cli/
├── __init__.py
├── client.py            # WireGhostClient — HTTP, auth, session cache
├── auth.py              # wireghost {login,logout,whoami}
├── scans.py             # wireghost scans {list,show,create,cancel,clone,run,findings}
├── hosts.py             # wireghost hosts {list,show,topology}
├── findings.py          # wireghost findings {list,show,toggle}
├── policies.py          # wireghost policies {list,show,create,update,delete}
├── schedules.py         # wireghost schedules {list,show,create,update,delete,toggle}
├── exploits.py          # wireghost exploits {list,show}
├── users.py             # wireghost users {list,show,create,update,delete,reset-password}
├── tokens.py            # wireghost tokens {list,create,revoke}
├── sessions.py          # wireghost sessions {list,revoke}
├── system.py            # wireghost system {stats,processes,tools,audit,update,feeds}
├── reports.py           # wireghost report {generate,download,config,logo}
├── notifications.py     # wireghost notify {config,test}
├── dashboard.py         # wireghost dashboard {stats,screenshots}
├── support.py           # wireghost support-bundle
└── scan.py              # wireghost scan — local pipeline runner with tmux
```

`cli.py` (existing) becomes a thin dispatcher that imports and mounts each domain app:

```python
from wireghost.cli import (
    auth, scans, hosts, findings, policies, schedules, exploits,
    users, tokens, sessions, system, reports, notifications, dashboard, support,
)
app.add_typer(auth.app, name="auth", help="Authentication")
app.add_typer(scans.app, name="scans", help="Manage scans")
# ... etc
```

---

## API Client

### WireGhostClient (`cli/client.py`)

```python
class WireGhostClient:
    def __init__(self):
        # Resolves config: env vars → ~/.wireghost/config.yml → defaults
        self.base_url = os.environ.get("WIREGHOST_API_URL", "https://localhost:18443")
        self._verify = not self.base_url.startswith("https://localhost")
        self._session = httpx.Client(timeout=30, verify=self._verify)

    def request(self, method, path, **kw):
        url = f"{self.base_url.rstrip('/')}/api{path}"
        # Attach auth from cached token or session cookie
        self._attach_auth(kw)
        return self._session.request(method, url, **kw)

    def get(self, path, **kw): ...
    def post(self, path, **kw): ...
    def put(self, path, **kw): ...
    def delete(self, path, **kw): ...
    def upload(self, path, files, **kw): ...
```

Single global client instance via `get_client()` — reads config once, shared across commands.

### Auth storage

```
~/.wireghost/
├── config.yml      # portal_url, default output formats
├── session.json    # cookies dict + csrf_token + expiry timestamp
└── .token          # auto-generated personal API token (plaintext, chmod 600)
```

### Auth flow

1. First use: `wireghost login` → prompts for portal URL, username, password, MFA → exchanges for session cookie and auto-creates a personal API token → caches both
2. Subsequent commands: use cached token as `Authorization: Token wg_tok_xxx` header
3. Token expiry (401): client prints `Session expired — run 'wireghost login'` and exits
4. `wireghost logout`: deletes `~/.wireghost/session.json` and revokes the cached token via API
5. `wireghost whoami`: `GET /api/auth/me/` → prints username, role, session validity
6. `WIREGHOST_TOKEN` env var bypasses all cached auth (CI/automation fallback)

### Auth precedence

1. `--token` CLI flag (highest)
2. `WIREGHOST_TOKEN` env var
3. `~/.wireghost/.token` file
4. Cached session cookie (`session.json`)

### TLS behavior

- `https://localhost:*` → `verify=False` automatically (self-signed certs)
- `WIREGHOST_CA_PATH` env var → custom CA bundle path
- Remote hosts always verify unless `--insecure` flag is passed

---

## tmux Integration (`wireghost scan`)

The local scan pipeline (`wireghost scan <target>`) gains tmux session management. This is the ONLY command that uses tmux — all API-facing commands are simple request/response.

### Session naming

Target CIDR/hostname is slugified: `/` → `-`, whitespace stripped.
- `192.168.1.0/24` → `wg-192.168.1.0-24`
- `example.com` → `wg-example.com`
- `10.0.0.0/8` → `wg-10.0.0.0-8`

### Default behavior

```
$ wireghost scan 192.168.1.0/24 -o ./output -j 20
▸ Created tmux session: wg-192.168.1.0-24
  Reattach: wireghost scan --attach 192.168.1.0/24
  Watch progress: tmux attach -t wg-192.168.1.0-24
```

Creates a detached tmux session with two panes:
- **Top pane (80%):** live scan pipeline output (structured log stream)
- **Bottom pane (20%):** status bar refreshed every 2s — `Hosts: N/M | Ports: P | Findings: F | Elapsed: HH:MM:SS`

The command exits immediately after creating the session so the terminal is free.

### Subcommands

```
wireghost scan --list              # List all wg-* tmux sessions with status
wireghost scan --attach <target>   # Attach to a running scan (alias: tmux attach -t wg-<target>)
wireghost scan --kill <target>     # Kill a running scan (sends SIGTERM, kills tmux session)
wireghost scan --no-tmux <target>  # Run in foreground (no tmux)
```

### tmux not installed

Graceful fallback: prints `tmux not found — running in foreground` and executes the scan directly. No hard dependency.

### Multiple scans

Each scan gets its own tmux session. `wireghost scan --list` shows all `wg-*` sessions with their start time and whether the pipeline process is still alive.

---

## Complete Command Reference

Every command supports `--json` for machine-readable output (raw API response to stdout).

### auth

```
wireghost login
    Login to a Wire_Ghost portal (interactive).
    Prompts: portal URL, username, password, MFA code.
    Caches session and auto-creates personal API token.

wireghost logout
    Revoke cached token and delete session cache.

wireghost whoami
    Show current user, role, and session validity.
```

### scan (local pipeline)

```
wireghost scan <target> [--output DIR] [--parallelism N] [--timeout SEC]
              [--skip-nuclei] [--skip-vuln] [--skip-screenshots]
              [--skip-enum4linux] [--skip-nikto] [--skip-netexec]
              [--skip-msf]
              [--nuclei-templates PATH] [--no-nuclei-default-templates]
              [--formats html,docx,xlsx] [--title TEXT] [--verbose]
              [--config PATH]
              [--no-tmux] [--attach] [--list] [--kill TARGET]
    Run a full scan pipeline against a target.
    Default: launches in detached tmux session named after the target.
```

### scans (portal-managed)

**Naming note:** `wireghost scan` (singular) = local pipeline, runs offline with tmux. `wireghost scans` (plural) = portal-managed scans, requires auth. This maps to the web UI's "Scans" page.

```
wireghost scans list [--limit N] [--status running|completed|cancelled|queued]
wireghost scans show <id>
wireghost scans create <target> [--policy NAME] [--title TEXT]
wireghost scans cancel <id>
wireghost scans clone <id> [--target NEW-TARGET]
wireghost scans run <id>
wireghost scans findings <id> [--severity critical|high|medium|low|info] [--source nuclei|nmap_vuln|...]
wireghost scans hosts <id>
wireghost scans topology <id>
```

`wireghost scans findings <id>` and `wireghost findings list --scan <id>` are equivalent — both paths work. Use whichever is more natural.

### hosts

```
wireghost hosts list [--scan <id>] [--limit N]
wireghost hosts show <ip> [--scan <id>]
wireghost hosts topology <scan-id>
```

### findings

```
wireghost findings list [--scan <id>] [--severity critical|high|medium|low|info]
                        [--source nuclei|nmap_vuln|msf_scan|...] [--search TERM]
                        [--limit N]
wireghost findings show <id>
wireghost findings toggle <id>
```

### policies

```
wireghost policies list
wireghost policies show <id>
wireghost policies create --name NAME --type external|internal|full [--description TEXT]
                          [--skip-nuclei] [--skip-vuln] [--skip-screenshots]
                          [--nuclei-templates PATH] [--parallelism N] [--timeout SEC]
wireghost policies update <id> [same flags as create]
wireghost policies delete <id>
wireghost policies clone <id> [--name NEW-NAME]
```

### schedules

```
wireghost schedules list
wireghost schedules show <id>
wireghost schedules create --name NAME --target TARGET --cron "0 2 * * *"
                           [--policy NAME] [--title TEXT]
wireghost schedules update <id> [same flags as create]
wireghost schedules delete <id>
wireghost schedules toggle <id>
```

### exploits

```
wireghost exploits list [--scan <id>] [--limit N]
wireghost exploits show <id>
```

### users

```
wireghost users list
wireghost users show <id>
wireghost users create --username NAME [--password PASS | --password-prompt]
                        --role owner|engineer|viewer [--email ADDR]
wireghost users update <id> [--username NAME] [--role ROLE] [--email ADDR]
wireghost users delete <id>
wireghost users reset-password <username>
```

Password can be passed via `--password` (warns about shell history) or `--password-prompt` (interactive, no echo). If neither is given, `--password-prompt` is the default.

### tokens

```
wireghost tokens list
wireghost tokens create --name "description"
wireghost tokens revoke <id>
```

### sessions

```
wireghost sessions list
wireghost sessions revoke <session-key>
wireghost sessions revoke-all
```

### system

```
wireghost system stats
wireghost system processes
wireghost system tools
wireghost system audit [--limit N]
wireghost system update [--tools] [--feeds]
wireghost system feeds
```

### report

```
wireghost report generate <scan-dir> [--output DIR] [--formats html,docx,xlsx] [--title TEXT]
wireghost report download <scan-id> [--format docx|html|xlsx] [--output DIR]
wireghost report config
wireghost report logo <image-path>
```

### notify

```
wireghost notify config
wireghost notify test [--channel telegram|email]
```

### dashboard

```
wireghost dashboard stats
wireghost dashboard screenshots [--scan <id>] [--limit N]
```

### support

```
wireghost support-bundle [--output PATH]
```

### config

```
wireghost config show
wireghost config init
```

---

## Output Formats

### Default (human-readable)

`list` commands use Rich tables:

```
$ wireghost scans list
┌──────────────────────────────────────┬───────────────┬──────────┬──────────┬─────────────────────┐
│ ID                                   │ Target        │ Status   │ Findings │ Created             │
├──────────────────────────────────────┼───────────────┼──────────┼──────────┼─────────────────────┤
│ a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d │ 10.0.1.0/24   │ running  │ 47       │ 2026-05-14 09:23    │
│ e5f6a7b8-c9d0-4e1f-2a3b-4c5d6e7f8a9b │ example.com   │ completed│ 312      │ 2026-05-13 14:11    │
└──────────────────────────────────────┴───────────────┴──────────┴──────────┴─────────────────────┘
```

`show` commands use key-value:

```
$ wireghost users show admin
Username:   admin
Role:       owner
Email:      admin@example.com
Created:    2026-04-15 08:30
Last login: 2026-05-14 11:02
```

### Machine-readable (`--json`)

Every command accepts `--json`. Outputs raw API response as JSON to stdout. All errors, warnings, and prompts go to stderr. Compatible with `jq`:

```
$ wireghost scans list --json | jq '.[] | select(.status == "running") | .id'
```

### Verbose (`--verbose`)

Adds request/response metadata to stderr: HTTP method, URL, status code, duration.

---

## Error Handling

| Scenario | Exit code | Output (stderr) |
|---|---|---|
| Portal unreachable | 2 | `Error: Cannot reach https://host:port — connection refused` |
| Not authenticated | 1 | `Error: Not authenticated — run 'wireghost login'` |
| Session expired | 1 | `Error: Session expired — run 'wireghost login'` |
| Permission denied (403) | 1 | `Error: Forbidden — you don't have required permission (code: scans:write)` |
| Resource not found (404) | 1 | `Error: Scan 'deadbeef-...' not found` |
| Validation error (400) | 1 | `Error: Invalid input — name is required` (field-level errors listed) |
| Server error (500) | 2 | `Error: Server error — check portal logs` |
| MFA required during login | 0 | Interactive prompt for code |

All API errors include the HTTP status and a human-readable message. The raw response body is available with `--verbose`.

---

## Migration from Old Commands

| Old | New | Notes |
|---|---|---|
| `wireghost scan <t>` | Same (`wireghost scan <t>`) | Enhanced with tmux |
| `wireghost report <d>` | `wireghost report generate <d>` | Old command prints deprecation notice |
| `wireghost update` | `wireghost system update` | Old command prints deprecation notice |
| `wireghost config show` | Unchanged | |
| `wireghost config init` | Unchanged | |
| `wg-ctl reset-password` | `wireghost users reset-password` | wg-ctl keeps it as alias |

Deprecation stubs remain for one release cycle before removal. The stub prints the new command and exits with code 0.

All `wg-ctl` commands remain unchanged — `status`, `backup`, `restore`, `update`, `logs`, `certs`, `start`, `stop`, `restart`, `shell`, `uninstall`.

---

## Dependencies

Zero new Python dependencies. All required packages are already in `web_portal/requirements.txt`:

| Package | Used for | Present? |
|---|---|---|
| `httpx` | API client HTTP | Already in reqs (nuclei downloader) |
| `rich` | Terminal tables, formatting | Already in reqs |
| `typer` | CLI framework | Already in reqs |
| `pyyaml` | Config file parsing | Already in reqs (Django YAML serializer) |

`tmux` is an optional runtime dependency — checked via `shutil.which('tmux')`, graceful fallback.

---

## Edge Cases & Constraints

1. **No portal running:** `wireghost scan` (local pipeline) still works offline. All API commands show connection error.
2. **Multiple portals:** `wireghost login` can be re-run to switch portals. `--portal` flag on any command overrides cached URL for that invocation.
3. **Piped output:** When stdout is not a TTY, `--json` is implied (tables/key-value suppressed). No ANSI codes written to pipes.
4. **Concurrent scans:** tmux sessions are independent. No limit on concurrent `wireghost scan` invocations beyond system resources.
5. **Large result sets:** `list` commands default to 20 items with `--limit` for more. Pagination via `--page` and `--limit` for very large sets.
6. **Password in shell history:** `wireghost users create --password` warns: `Warning: passing passwords on the command line may expose them in shell history. Use --password-prompt for interactive input.`
