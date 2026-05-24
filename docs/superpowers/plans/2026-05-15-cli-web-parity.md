# CLI/Web Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build every web portal action as a `wireghost` CLI command — 15 domain-grouped typer apps backed by an httpx API client.

**Architecture:** A single `WireGhostClient` class handles HTTPS, auth caching, and token refresh. Each domain (scans, hosts, findings, etc.) lives in its own file under `src/wireghost/cli/` and mounts into the main typer app via `app.add_typer()`. The existing `cli.py` becomes a thin dispatcher.

**Tech Stack:** Python 3.12+, typer, httpx, rich, pyyaml — all already installed. Zero new dependencies.

---

## File Map

```
src/wireghost/cli/
├── __init__.py         (empty)
├── client.py           WireGhostClient — NEW
├── auth.py             login, logout, whoami — NEW
├── scans.py            scans {list,show,create,cancel,clone,run,findings,hosts,topology} — NEW
├── hosts.py            hosts {list,show,topology} — NEW
├── findings.py         findings {list,show,toggle} — NEW
├── policies.py         policies {list,show,create,update,delete,clone} — NEW
├── schedules.py        schedules {list,show,create,update,delete,toggle} — NEW
├── exploits.py         exploits {list,show} — NEW
├── users.py            users {list,show,create,update,delete,reset-password} — NEW
├── tokens.py           tokens {list,create,revoke} — NEW
├── sessions.py         sessions {list,revoke,revoke-all} — NEW
├── system.py           system {stats,processes,tools,audit,update,feeds} — NEW
├── reports.py          report {generate,download,config,logo} — NEW
├── notifications.py    notify {config,test} — NEW
├── dashboard.py        dashboard {stats,screenshots} — NEW
├── support.py          support-bundle — NEW
src/wireghost/cli.py    → refactored into thin dispatcher
web_portal/requirements.txt → add httpx, typer
```

---

### Task 1: Add httpx + typer to requirements.txt

**Files:**
- Modify: `web_portal/requirements.txt`

- [ ] **Step 1: Add httpx and typer to requirements**

```diff
 rich>=13.0
 aiohttp>=3.9
 defusedxml>=0.7
+# CLI (wireghost API client)
+httpx>=0.27
+typer>=0.12
 # Real-time System Monitor page (cgroup-scoped CPU/mem/disk/net)
 psutil>=6.0
```

- [ ] **Step 2: Install and verify**

Run: `pip install httpx typer`
Expected: both already installed (should show "Requirement already satisfied")

- [ ] **Step 3: Commit**

```bash
git add web_portal/requirements.txt
git commit -m "deps: add httpx and typer for CLI API client"
```

---

### Task 2: WireGhostClient — API client with auth caching

**Files:**
- Create: `src/wireghost/cli/__init__.py`
- Create: `src/wireghost/cli/client.py`
- Test: `tests/test_wireghost_client.py`

- [ ] **Step 1: Create cli package init**

```python
# src/wireghost/cli/__init__.py
```

- [ ] **Step 2: Write the client class**

```python
# src/wireghost/cli/client.py
"""WireGhostClient — HTTP API client with auth caching."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx


def _config_dir() -> Path:
    return Path(os.environ.get("WIREGHOST_CONFIG_DIR", Path.home() / ".wireghost"))


def _ensure_config_dir() -> Path:
    d = _config_dir()
    d.mkdir(mode=0o700, exist_ok=True)
    return d


class WireGhostClient:
    """Thin HTTPS client for the Wire_Ghost portal REST API."""

    def __init__(
        self,
        base_url: str | None = None,
        token: str | None = None,
        insecure: bool = False,
    ):
        self.base_url = (
            base_url
            or os.environ.get("WIREGHOST_API_URL", "https://localhost:18443")
        ).rstrip("/")
        self._verify = not insecure and not self.base_url.startswith("https://localhost")
        self._session = httpx.Client(timeout=30, verify=self._verify)

        # Auth precedence: --token flag → WIREGHOST_TOKEN env → cached .token → session cookie
        self._token = token or os.environ.get("WIREGHOST_TOKEN")
        if not self._token:
            self._token = self._read_cached_token()
        self._cookies: dict[str, str] = self._read_cached_session()

    # ── token cache ──────────────────────────────────────────────

    def _token_path(self) -> Path:
        return _config_dir() / ".token"

    def _read_cached_token(self) -> str | None:
        p = self._token_path()
        if p.exists():
            try:
                return p.read_text().strip() or None
            except OSError:
                return None
        return None

    def _write_cached_token(self, token: str) -> None:
        p = self._token_path()
        p.write_text(token)
        p.chmod(0o600)

    def _clear_cached_token(self) -> None:
        p = self._token_path()
        if p.exists():
            p.unlink()

    # ── session cache ────────────────────────────────────────────

    def _session_path(self) -> Path:
        return _config_dir() / "session.json"

    def _read_cached_session(self) -> dict[str, str]:
        p = self._session_path()
        if p.exists():
            try:
                data = json.loads(p.read_text())
                # Check expiry
                import time
                if data.get("expires_at", 0) > time.time():
                    return data.get("cookies", {})
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _write_cached_session(self, cookies: dict[str, str], expires_at: float) -> None:
        p = self._session_path()
        p.write_text(json.dumps({"cookies": cookies, "expires_at": expires_at}))
        p.chmod(0o600)

    def _clear_cached_session(self) -> None:
        p = self._session_path()
        if p.exists():
            p.unlink()

    # ── auth attachment ──────────────────────────────────────────

    def _attach_auth(self, kwargs: dict) -> None:
        """Attach token or session cookie to request kwargs."""
        if self._token:
            kwargs.setdefault("headers", {})["Authorization"] = f"Token {self._token}"
        elif self._cookies:
            kwargs.setdefault("cookies", self._cookies)

    # ── HTTP methods ─────────────────────────────────────────────

    def request(self, method: str, path: str, **kw: Any) -> httpx.Response:
        url = f"{self.base_url}/api{path}"
        self._attach_auth(kw)
        resp = self._session.request(method, url, **kw)
        return resp

    def get(self, path: str, **kw: Any) -> httpx.Response:
        return self.request("GET", path, **kw)

    def post(self, path: str, **kw: Any) -> httpx.Response:
        return self.request("POST", path, **kw)

    def put(self, path: str, **kw: Any) -> httpx.Response:
        return self.request("PUT", path, **kw)

    def patch(self, path: str, **kw: Any) -> httpx.Response:
        return self.request("PATCH", path, **kw)

    def delete(self, path: str, **kw: Any) -> httpx.Response:
        return self.request("DELETE", path, **kw)

    # ── high-level auth ──────────────────────────────────────────

    def login(self, username: str, password: str, mfa_code: str | None = None) -> dict:
        """Interactive login — exchange credentials for session + auto-create API token."""
        # Step 1: get CSRF token
        csrf_resp = self._session.get(f"{self.base_url}/api/auth/csrf/")
        csrf_resp.raise_for_status()
        csrf_token = csrf_resp.json().get("csrfToken", "")
        cookies = dict(csrf_resp.cookies)

        # Step 2: login
        data: dict[str, str] = {"username": username, "password": password}
        if mfa_code:
            data["mfa_code"] = mfa_code
        login_resp = self._session.post(
            f"{self.base_url}/api/auth/login/",
            json=data,
            headers={"X-CSRFToken": csrf_token},
            cookies=cookies,
        )
        login_resp.raise_for_status()
        result = login_resp.json()

        # Cache session cookies
        import time
        session_cookies = dict(login_resp.cookies)
        self._write_cached_session(
            session_cookies,
            time.time() + 86400 * 7,  # 7-day estimate
        )
        self._cookies = session_cookies

        # Step 3: auto-create a personal API token
        token_resp = self._session.post(
            f"{self.base_url}/api/auth/tokens/",
            json={"name": "wireghost CLI"},
            cookies=session_cookies,
        )
        if token_resp.status_code == 201:
            token_data = token_resp.json()
            token = token_data.get("token") or token_data.get("key", "")
            if token:
                self._token = token
                self._write_cached_token(token)

        return result

    def logout(self) -> None:
        """Revoke token and clear cached session."""
        if self._token:
            try:
                self._session.post(
                    f"{self.base_url}/api/auth/tokens/current/revoke/",
                    headers={"Authorization": f"Token {self._token}"},
                )
            except Exception:
                pass
        self._clear_cached_token()
        self._clear_cached_session()
        self._token = None
        self._cookies = {}

    def whoami(self) -> dict:
        resp = self.get("/auth/me/")
        resp.raise_for_status()
        return resp.json()


# Singleton
_client: WireGhostClient | None = None


def get_client() -> WireGhostClient:
    global _client
    if _client is None:
        _client = WireGhostClient()
    return _client
```

- [ ] **Step 3: Write the unit test**

```python
# tests/test_wireghost_client.py
"""Tests for WireGhostClient."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from wireghost.cli.client import WireGhostClient, _config_dir, get_client


class TestConfigDir:
    def test_default_is_home_wireghost(self):
        with patch.dict(os.environ, {}, clear=True):
            d = _config_dir()
            assert d == Path.home() / ".wireghost"

    def test_env_override(self):
        with patch.dict(os.environ, {"WIREGHOST_CONFIG_DIR": "/tmp/wgtest"}):
            d = _config_dir()
            assert d == Path("/tmp/wgtest")


class TestTokenCache:
    def test_read_token_from_file(self):
        with tempfile.TemporaryDirectory() as td:
            token_file = Path(td) / ".token"
            token_file.write_text("wg_tok_test123")
            token_file.chmod(0o600)
            with patch.dict(os.environ, {"WIREGHOST_CONFIG_DIR": td}):
                client = WireGhostClient()
                assert client._token == "wg_tok_test123"

    def test_token_env_overrides_file(self):
        with tempfile.TemporaryDirectory() as td:
            token_file = Path(td) / ".token"
            token_file.write_text("wg_tok_file")
            with patch.dict(
                os.environ,
                {"WIREGHOST_CONFIG_DIR": td, "WIREGHOST_TOKEN": "wg_tok_env"},
            ):
                client = WireGhostClient()
                assert client._token == "wg_tok_env"


class TestAuthPrecedence:
    def test_constructor_token_highest(self):
        client = WireGhostClient(token="wg_tok_flag")
        assert client._token == "wg_tok_flag"

    def test_env_token_over_cached(self):
        with tempfile.TemporaryDirectory() as td:
            token_file = Path(td) / ".token"
            token_file.write_text("wg_tok_file")
            with patch.dict(
                os.environ,
                {"WIREGHOST_CONFIG_DIR": td, "WIREGHOST_TOKEN": "wg_tok_env"},
            ):
                client = WireGhostClient()
                assert client._token == "wg_tok_env"


class TestTLSBehavior:
    def test_localhost_skips_verify(self):
        client = WireGhostClient(base_url="https://localhost:18443")
        assert client._verify is False

    def test_remote_verifies(self):
        client = WireGhostClient(base_url="https://portal.example.com")
        assert client._verify is True

    def test_insecure_flag(self):
        client = WireGhostClient(base_url="https://portal.example.com", insecure=True)
        assert client._verify is False


class TestAttachAuth:
    def test_token_auth_header(self):
        client = WireGhostClient(token="wg_tok_abc")
        kwargs: dict = {}
        client._attach_auth(kwargs)
        assert kwargs["headers"]["Authorization"] == "Token wg_tok_abc"

    def test_session_cookie_fallback(self):
        client = WireGhostClient()
        client._cookies = {"sessionid": "abc123"}
        kwargs: dict = {}
        client._attach_auth(kwargs)
        assert kwargs["cookies"] == {"sessionid": "abc123"}
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_wireghost_client.py -v`
Expected: 9 tests pass

- [ ] **Step 5: Commit**

```bash
git add src/wireghost/cli/__init__.py src/wireghost/cli/client.py tests/test_wireghost_client.py
git commit -m "feat: add WireGhostClient with auth caching and token precedence"
```

---

### Task 3: Auth commands — login, logout, whoami

**Files:**
- Create: `src/wireghost/cli/auth.py`
- Test: `tests/test_wireghost_auth.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_wireghost_auth.py
"""Tests for wireghost auth commands."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from wireghost.cli.auth import app

runner = CliRunner()


class TestWhoami:
    def test_whoami_shows_user(self):
        mock_client = MagicMock()
        mock_client.whoami.return_value = {
            "username": "admin",
            "role": "owner",
            "email": "admin@example.com",
        }
        with patch(
            "wireghost.cli.auth.get_client", return_value=mock_client
        ):
            result = runner.invoke(app, ["whoami"])
            assert result.exit_code == 0
            assert "admin" in result.stdout
            assert "owner" in result.stdout

    def test_whoami_unauthorized(self):
        mock_client = MagicMock()
        mock_client.whoami.side_effect = RuntimeError("401")
        with patch(
            "wireghost.cli.auth.get_client", return_value=mock_client
        ):
            result = runner.invoke(app, ["whoami"])
            assert result.exit_code == 1


class TestLogout:
    def test_logout_clears_session(self):
        mock_client = MagicMock()
        with patch(
            "wireghost.cli.auth.get_client", return_value=mock_client
        ):
            result = runner.invoke(app, ["logout"])
            assert result.exit_code == 0
            mock_client.logout.assert_called_once()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_wireghost_auth.py -v`
Expected: FAIL — "ModuleNotFoundError: No module named 'wireghost.cli.auth'"

- [ ] **Step 3: Implement auth commands**

```python
# src/wireghost/cli/auth.py
"""wireghost auth — login, logout, whoami."""
from __future__ import annotations

import sys

import typer
from rich.console import Console

from wireghost.cli.client import get_client

app = typer.Typer(name="auth", help="Authentication")
console = Console(stderr=True)


@app.command()
def login(
    portal_url: str = typer.Option(
        "", "--portal", "-p", help="Portal URL (default: prompts)"
    ),
    username: str = typer.Option("", "--username", "-u", help="Username"),
    password: str = typer.Option("", "--password", "-P", help="Password (warning: shell history)"),
    mfa_code: str = typer.Option("", "--mfa", help="MFA code if required"),
) -> None:
    """Login to a Wire_Ghost portal (interactive)."""
    client = get_client()

    # Prompt for missing values
    if not portal_url:
        portal_url = typer.prompt("Portal URL", default="https://localhost:18443")
        client.base_url = portal_url.rstrip("/")
    if not username:
        username = typer.prompt("Username")
    if not password:
        import getpass
        password = getpass.getpass("Password: ")

    try:
        result = client.login(username, password, mfa_code or None)
        user = result.get("user", result)
        console.print(f"[bold green]Logged in as[/] {user.get('username', username)} ({user.get('role', '?')})")
        console.print(f"Portal: {client.base_url}")
    except Exception as e:
        console.print(f"[bold red]Login failed:[/] {e}")
        raise typer.Exit(code=1)


@app.command()
def logout() -> None:
    """Revoke cached token and delete session cache."""
    client = get_client()
    try:
        client.logout()
        console.print("[bold green]Logged out.[/]")
    except Exception as e:
        console.print(f"[bold yellow]Warning:[/] {e}")
    console.print("Run [bold]wireghost login[/] to authenticate again.")


@app.command()
def whoami() -> None:
    """Show current user, role, and session validity."""
    client = get_client()
    try:
        info = client.whoami()
        console.print(f"Username:   [bold]{info.get('username', '?')}[/]")
        console.print(f"Role:       {info.get('role', '?')}")
        console.print(f"Email:      {info.get('email', '—')}")
        console.print(f"Portal:     {client.base_url}")
    except Exception as e:
        console.print(f"[bold red]Not authenticated:[/] {e}")
        console.print("Run [bold]wireghost login[/] to authenticate.")
        raise typer.Exit(code=1)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_wireghost_auth.py -v`
Expected: 3 tests pass

- [ ] **Step 5: Commit**

```bash
git add src/wireghost/cli/auth.py tests/test_wireghost_auth.py
git commit -m "feat: add wireghost auth (login, logout, whoami)"
```

---

### Task 4: Refactor cli.py into thin dispatcher

**Files:**
- Modify: `src/wireghost/cli.py` (major rewrite)
- Modify: `src/wireghost/__init__.py` (bump version)

- [ ] **Step 1: Rewrite cli.py as dispatcher**

```python
# src/wireghost/cli.py
"""Wire_Ghost CLI — thin dispatcher that mounts domain apps."""
from __future__ import annotations

import typer

from wireghost import __version__

app = typer.Typer(
    name="wireghost",
    help="Wire_Ghost security scanning toolkit",
    no_args_is_help=True,
)


@app.callback(invoke_without_command=True)
def main(
    version: bool = typer.Option(
        False, "--version", "-V", help="Show version and exit"
    ),
) -> None:
    """Wire_Ghost — automated security scanning toolkit."""
    if version:
        typer.echo(f"wireghost {__version__}")
        raise typer.Exit()


# Mount domain apps
from wireghost.cli.auth import app as auth_app
app.add_typer(auth_app, name="auth", help="Authentication")

from wireghost.cli.scans import app as scans_app
app.add_typer(scans_app, name="scans", help="Manage portal scans")

from wireghost.cli.hosts import app as hosts_app
app.add_typer(hosts_app, name="hosts", help="Host information")

from wireghost.cli.findings import app as findings_app
app.add_typer(findings_app, name="findings", help="View and triage findings")

from wireghost.cli.policies import app as policies_app
app.add_typer(policies_app, name="policies", help="Manage scan policies")

from wireghost.cli.schedules import app as schedules_app
app.add_typer(schedules_app, name="schedules", help="Manage scan schedules")

from wireghost.cli.exploits import app as exploits_app
app.add_typer(exploits_app, name="exploits", help="View exploit matches")

from wireghost.cli.users import app as users_app
app.add_typer(users_app, name="users", help="User management")

from wireghost.cli.tokens import app as tokens_app
app.add_typer(tokens_app, name="tokens", help="API token management")

from wireghost.cli.sessions import app as sessions_app
app.add_typer(sessions_app, name="sessions", help="Session management")

from wireghost.cli.system import app as system_app
app.add_typer(system_app, name="system", help="System operations")

from wireghost.cli.reports import app as reports_app
app.add_typer(reports_app, name="report", help="Report generation and download")

from wireghost.cli.notifications import app as notifications_app
app.add_typer(notifications_app, name="notify", help="Notification configuration")

from wireghost.cli.dashboard import app as dashboard_app
app.add_typer(dashboard_app, name="dashboard", help="Dashboard stats and screenshots")

from wireghost.cli.support import app as support_app
app.add_typer(support_app, name="support-bundle", help="Generate support diagnostic bundle")
```

- [ ] **Step 2: Verify cli.py imports don't crash**

Run: `python -c "from wireghost.cli import app; print('OK')"`
Expected: `OK` (all imported domain apps must exist — they will since we create them in subsequent tasks, but for now we need stubs)

- [ ] **Step 3: Commit**

```bash
git add src/wireghost/cli.py
git commit -m "refactor: cli.py becomes thin dispatcher mounting domain apps"
```

---

### Task 5: Read-only commands — scans list/show, hosts, findings, exploits

**Files:**
- Create: `src/wireghost/cli/scans.py`
- Create: `src/wireghost/cli/hosts.py`
- Create: `src/wireghost/cli/findings.py`
- Create: `src/wireghost/cli/exploits.py`
- Create: `src/wireghost/cli/output.py` (shared Rich output helpers)
- Test: `tests/test_wireghost_readonly.py`

- [ ] **Step 1: Create shared output helpers**

```python
# src/wireghost/cli/output.py
"""Shared output formatting helpers."""
from __future__ import annotations

import json as _json
import sys
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

console = Console(stderr=True)


def echo_json(data: Any) -> None:
    """Print data as JSON to stdout."""
    typer.echo(_json.dumps(data, default=str, indent=2))


def echo_table(
    title: str,
    columns: list[tuple[str, str]],  # (key, header)
    rows: list[dict],
) -> None:
    """Print a Rich table from a list of dicts."""
    if not sys.stdout.isatty():
        echo_json(rows)
        return

    table = Table(title=title, show_header=True, title_style="bold")
    for key, header in columns:
        table.add_column(header)
    for row in rows:
        table.add_row(*[str(row.get(k, "")) for k, _ in columns])
    console.print(table)


def echo_keyvalue(pairs: list[tuple[str, Any]]) -> None:
    """Print key-value pairs."""
    if not sys.stdout.isatty():
        echo_json(dict(pairs))
        return

    max_key = max(len(k) for k, _ in pairs) if pairs else 0
    for key, val in pairs:
        console.print(f"{key:<{max_key + 2}}{val}")


def check_json_flag() -> bool:
    """Check if --json was passed by inspecting sys.argv."""
    return "--json" in sys.argv
```

- [ ] **Step 2: Create scans.py (read-only commands first)**

```python
# src/wireghost/cli/scans.py
"""wireghost scans — portal-managed scan operations."""
from __future__ import annotations

import sys
from uuid import UUID

import typer

from wireghost.cli.client import get_client
from wireghost.cli.output import (
    check_json_flag,
    console,
    echo_json,
    echo_keyvalue,
    echo_table,
)

app = typer.Typer(name="scans", help="Manage portal scans")


@app.callback()
def scans_callback(
    json: bool = typer.Option(
        False, "--json", help="Machine-readable JSON output"
    ),
) -> None:
    pass


@app.command("list")
def list_scans(
    limit: int = typer.Option(20, "--limit", "-n", help="Max results"),
    status: str = typer.Option(
        "", "--status", help="Filter: running, completed, cancelled, queued"
    ),
) -> None:
    """List portal scans."""
    client = get_client()
    params: dict = {"limit": limit}
    if status:
        params["status"] = status

    try:
        resp = client.get("/scans/", params=params)
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("results", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            "Portal Scans",
            [("id", "ID"), ("target", "Target"), ("status", "Status"),
             ("finding_count", "Findings"), ("created_at", "Created")],
            results,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("show")
def show_scan(
    scan_id: str = typer.Argument(..., help="Scan UUID"),
) -> None:
    """Show scan details."""
    client = get_client()
    try:
        resp = client.get(f"/scans/{scan_id}/")
        resp.raise_for_status()
        data = resp.json()
        if check_json_flag():
            echo_json(data)
            return
        echo_keyvalue([
            ("ID:", data.get("id")),
            ("Target:", data.get("target")),
            ("Status:", data.get("status")),
            ("Title:", data.get("title", "—")),
            ("Policy:", data.get("policy", "—")),
            ("Findings:", str(data.get("finding_count", 0))),
            ("Hosts:", str(data.get("host_count", 0))),
            ("Created:", data.get("created_at", "—")),
            ("Started:", data.get("started_at", "—")),
            ("Completed:", data.get("completed_at", "—")),
        ])
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("findings")
def scan_findings(
    scan_id: str = typer.Argument(..., help="Scan UUID"),
    severity: str = typer.Option(
        "", "--severity", help="Filter: critical, high, medium, low, info"
    ),
    source: str = typer.Option(
        "", "--source", help="Filter: nuclei, nmap_vuln, msf_scan, ..."
    ),
) -> None:
    """List findings for a scan."""
    client = get_client()
    params: dict = {}
    if severity:
        params["severity"] = severity
    if source:
        params["source"] = source
    try:
        resp = client.get(f"/scans/{scan_id}/findings/", params=params)
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("results", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            f"Findings for {scan_id[:8]}...",
            [("id", "ID"), ("severity", "Severity"), ("source", "Source"),
             ("title", "Title"), ("host", "Host"), ("port", "Port")],
            results,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("hosts")
def scan_hosts(
    scan_id: str = typer.Argument(..., help="Scan UUID"),
) -> None:
    """List hosts for a scan."""
    client = get_client()
    try:
        resp = client.get(f"/scans/{scan_id}/hosts/")
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("results", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            f"Hosts for {scan_id[:8]}...",
            [("ip", "IP"), ("hostname", "Hostname"), ("os", "OS"),
             ("open_ports", "Open Ports"), ("status", "Status")],
            results,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("topology")
def scan_topology(
    scan_id: str = typer.Argument(..., help="Scan UUID"),
) -> None:
    """Show network topology for a scan."""
    client = get_client()
    try:
        resp = client.get(f"/scans/{scan_id}/topology/")
        resp.raise_for_status()
        data = resp.json()
        if check_json_flag():
            echo_json(data)
            return
        console.print(f"[bold]Topology for {scan_id[:8]}...[/]")
        nodes = data.get("nodes", [])
        edges = data.get("edges", [])
        console.print(f"  Nodes: {len(nodes)}")
        console.print(f"  Edges: {len(edges)}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
```

- [ ] **Step 3: Create hosts.py**

```python
# src/wireghost/cli/hosts.py
"""wireghost hosts — host information."""
from __future__ import annotations

import typer

from wireghost.cli.client import get_client
from wireghost.cli.output import (
    check_json_flag,
    console,
    echo_json,
    echo_keyvalue,
    echo_table,
)

app = typer.Typer(name="hosts", help="Host information")


@app.command("list")
def list_hosts(
    scan_id: str = typer.Option("", "--scan", help="Filter by scan ID"),
    limit: int = typer.Option(20, "--limit", "-n", help="Max results"),
) -> None:
    """List hosts."""
    client = get_client()
    params: dict = {"limit": limit}
    if scan_id:
        params["scan"] = scan_id
    try:
        resp = client.get("/hosts/", params=params)
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("results", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            "Hosts",
            [("ip", "IP"), ("hostname", "Hostname"), ("os", "OS"),
             ("open_ports", "Ports"), ("status", "Status")],
            results,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("show")
def show_host(
    ip: str = typer.Argument(..., help="Host IP address"),
    scan_id: str = typer.Option("", "--scan", help="Scan ID context"),
) -> None:
    """Show host details."""
    client = get_client()
    params: dict = {}
    if scan_id:
        params["scan"] = scan_id
    try:
        resp = client.get(f"/hosts/{ip}/", params=params)
        resp.raise_for_status()
        data = resp.json()
        if check_json_flag():
            echo_json(data)
            return
        echo_keyvalue([
            ("IP:", data.get("ip")),
            ("Hostname:", data.get("hostname", "—")),
            ("OS:", data.get("os", "—")),
            ("Status:", data.get("status", "—")),
            ("Open Ports:", str(data.get("open_ports", 0))),
            ("MAC:", data.get("mac", "—")),
        ])
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("topology")
def host_topology(
    scan_id: str = typer.Argument(..., help="Scan ID"),
) -> None:
    """Show network topology for a scan."""
    client = get_client()
    try:
        resp = client.get(f"/scans/{scan_id}/topology/")
        resp.raise_for_status()
        data = resp.json()
        if check_json_flag():
            echo_json(data)
            return
        console.print(f"[bold]Topology for {scan_id[:8]}...[/]")
        console.print(f"  Nodes: {len(data.get('nodes', []))}")
        console.print(f"  Edges: {len(data.get('edges', []))}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
```

- [ ] **Step 4: Create findings.py**

```python
# src/wireghost/cli/findings.py
"""wireghost findings — view and triage findings."""
from __future__ import annotations

import typer

from wireghost.cli.client import get_client
from wireghost.cli.output import (
    check_json_flag,
    console,
    echo_json,
    echo_keyvalue,
    echo_table,
)

app = typer.Typer(name="findings", help="View and triage findings")


@app.command("list")
def list_findings(
    scan_id: str = typer.Option("", "--scan", help="Filter by scan ID"),
    severity: str = typer.Option(
        "", "--severity", help="Filter: critical, high, medium, low, info"
    ),
    source: str = typer.Option(
        "", "--source", help="Filter: nuclei, nmap_vuln, msf_scan, ..."
    ),
    search: str = typer.Option("", "--search", help="Full-text search"),
    limit: int = typer.Option(20, "--limit", "-n", help="Max results"),
) -> None:
    """List findings."""
    client = get_client()
    params: dict = {"limit": limit}
    if scan_id:
        params["scan"] = scan_id
    if severity:
        params["severity"] = severity
    if source:
        params["source"] = source
    if search:
        params["search"] = search
    try:
        resp = client.get("/findings/", params=params)
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("results", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            "Findings",
            [("id", "ID"), ("severity", "Severity"), ("source", "Source"),
             ("title", "Title"), ("host", "Host"), ("port", "Port")],
            results,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("show")
def show_finding(
    finding_id: str = typer.Argument(..., help="Finding UUID"),
) -> None:
    """Show finding details."""
    client = get_client()
    try:
        resp = client.get(f"/findings/{finding_id}/")
        resp.raise_for_status()
        data = resp.json()
        if check_json_flag():
            echo_json(data)
            return
        echo_keyvalue([
            ("ID:", data.get("id")),
            ("Title:", data.get("title", "—")),
            ("Severity:", str(data.get("severity", "—"))),
            ("Source:", data.get("source", "—")),
            ("Host:", data.get("host", "—")),
            ("Port:", str(data.get("port", ""))),
            ("CVE:", data.get("cve", "—")),
            ("Description:", data.get("description", "—")),
            ("Template:", data.get("template_id", "—")),
            ("False Positive:", str(data.get("false_positive", False))),
        ])
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("toggle")
def toggle_finding(
    finding_id: str = typer.Argument(..., help="Finding UUID"),
) -> None:
    """Toggle finding false-positive status."""
    client = get_client()
    try:
        resp = client.patch(f"/findings/{finding_id}/", json={"toggle_fp": True})
        resp.raise_for_status()
        data = resp.json()
        status = "flagged as false positive" if data.get("false_positive") else "unflagged"
        console.print(f"[bold green]Finding {finding_id[:8]}... {status}[/]")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
```

- [ ] **Step 5: Create exploits.py**

```python
# src/wireghost/cli/exploits.py
"""wireghost exploits — exploit matches."""
from __future__ import annotations

import typer

from wireghost.cli.client import get_client
from wireghost.cli.output import (
    check_json_flag,
    console,
    echo_json,
    echo_keyvalue,
    echo_table,
)

app = typer.Typer(name="exploits", help="View exploit matches")


@app.command("list")
def list_exploits(
    scan_id: str = typer.Option("", "--scan", help="Filter by scan ID"),
    limit: int = typer.Option(20, "--limit", "-n", help="Max results"),
) -> None:
    """List exploit matches."""
    client = get_client()
    params: dict = {"limit": limit}
    if scan_id:
        params["scan"] = scan_id
    try:
        resp = client.get("/exploits/", params=params)
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("results", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            "Exploit Matches",
            [("id", "ID"), ("name", "Name"), ("service", "Service"),
             ("host", "Host"), ("port", "Port"), ("severity", "Severity")],
            results,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("show")
def show_exploit(
    exploit_id: str = typer.Argument(..., help="Exploit match UUID"),
) -> None:
    """Show exploit match details."""
    client = get_client()
    try:
        resp = client.get(f"/exploits/{exploit_id}/")
        resp.raise_for_status()
        data = resp.json()
        if check_json_flag():
            echo_json(data)
            return
        echo_keyvalue([
            ("ID:", data.get("id")),
            ("Name:", data.get("name", "—")),
            ("Description:", data.get("description", "—")),
            ("Service:", data.get("service", "—")),
            ("Host:", data.get("host", "—")),
            ("Port:", str(data.get("port", ""))),
            ("Severity:", str(data.get("severity", "—"))),
        ])
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
```

- [ ] **Step 6: Write minimal test that exercises the import chain**

```python
# tests/test_wireghost_readonly.py
"""Smoke tests for read-only CLI commands."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest
from typer.testing import CliRunner

from wireghost.cli.scans import app as scans_app
from wireghost.cli.hosts import app as hosts_app
from wireghost.cli.findings import app as findings_app
from wireghost.cli.exploits import app as exploits_app

runner = CliRunner()


class TestScansList:
    def test_list_empty(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = []
        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp
        with patch("wireghost.cli.scans.get_client", return_value=mock_client):
            result = runner.invoke(scans_app, ["list"])
            assert result.exit_code == 0


class TestHostsList:
    def test_list_empty(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = []
        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp
        with patch("wireghost.cli.hosts.get_client", return_value=mock_client):
            result = runner.invoke(hosts_app, ["list"])
            assert result.exit_code == 0


class TestFindingsList:
    def test_list_empty(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = []
        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp
        with patch("wireghost.cli.findings.get_client", return_value=mock_client):
            result = runner.invoke(findings_app, ["list"])
            assert result.exit_code == 0


class TestExploitsList:
    def test_list_empty(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = []
        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp
        with patch("wireghost.cli.exploits.get_client", return_value=mock_client):
            result = runner.invoke(exploits_app, ["list"])
            assert result.exit_code == 0
```

- [ ] **Step 7: Run tests**

Run: `pytest tests/test_wireghost_readonly.py -v`
Expected: 4 tests pass

- [ ] **Step 8: Commit**

```bash
git add src/wireghost/cli/scans.py src/wireghost/cli/hosts.py src/wireghost/cli/findings.py src/wireghost/cli/exploits.py src/wireghost/cli/output.py tests/test_wireghost_readonly.py
git commit -m "feat: add read-only CLI commands (scans, hosts, findings, exploits)"
```

---

### Task 6: Dashboard + System commands

**Files:**
- Create: `src/wireghost/cli/dashboard.py`
- Create: `src/wireghost/cli/system.py`
- Test: `tests/test_wireghost_dashboard_system.py`

- [ ] **Step 1: Create dashboard.py**

```python
# src/wireghost/cli/dashboard.py
"""wireghost dashboard — stats and screenshots."""
from __future__ import annotations

import typer

from wireghost.cli.client import get_client
from wireghost.cli.output import (
    check_json_flag,
    console,
    echo_json,
    echo_keyvalue,
    echo_table,
)

app = typer.Typer(name="dashboard", help="Dashboard stats and screenshots")


@app.command("stats")
def dashboard_stats() -> None:
    """Show dashboard statistics."""
    client = get_client()
    try:
        resp = client.get("/dashboard/")
        resp.raise_for_status()
        data = resp.json()
        if check_json_flag():
            echo_json(data)
            return
        echo_keyvalue([
            ("Total scans:", str(data.get("total_scans", 0))),
            ("Running scans:", str(data.get("running_scans", 0))),
            ("Total hosts:", str(data.get("total_hosts", 0))),
            ("Total findings:", str(data.get("total_findings", 0))),
            ("Critical:", str(data.get("critical_findings", 0))),
            ("High:", str(data.get("high_findings", 0))),
            ("Medium:", str(data.get("medium_findings", 0))),
            ("Low:", str(data.get("low_findings", 0))),
        ])
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("screenshots")
def dashboard_screenshots(
    scan_id: str = typer.Option("", "--scan", help="Filter by scan ID"),
    limit: int = typer.Option(20, "--limit", "-n", help="Max results"),
) -> None:
    """List dashboard screenshots."""
    client = get_client()
    params: dict = {"limit": limit}
    if scan_id:
        params["scan"] = scan_id
    try:
        resp = client.get("/dashboard/screenshots/", params=params)
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("results", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            "Screenshots",
            [("id", "ID"), ("url", "URL"), ("host", "Host"),
             ("port", "Port"), ("title", "Title")],
            results,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
```

- [ ] **Step 2: Create system.py**

```python
# src/wireghost/cli/system.py
"""wireghost system — system operations."""
from __future__ import annotations

import typer

from wireghost.cli.client import get_client
from wireghost.cli.output import (
    check_json_flag,
    console,
    echo_json,
    echo_keyvalue,
    echo_table,
)

app = typer.Typer(name="system", help="System operations")


@app.command("stats")
def system_stats() -> None:
    """Show real-time system resource usage."""
    client = get_client()
    try:
        resp = client.get("/system-stats/")
        resp.raise_for_status()
        data = resp.json()
        if check_json_flag():
            echo_json(data)
            return
        echo_keyvalue([
            ("CPU %:", str(data.get("cpu_percent", "—"))),
            ("Memory:", data.get("memory", "—")),
            ("Disk:", data.get("disk", "—")),
            ("Uptime:", data.get("uptime", "—")),
        ])
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("processes")
def system_processes() -> None:
    """Show container processes."""
    client = get_client()
    try:
        resp = client.get("/system-processes/")
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("results", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            "Container Processes",
            [("name", "Name"), ("pid", "PID"), ("cpu", "CPU%"),
             ("mem", "Mem%"), ("status", "Status")],
            results,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("tools")
def system_tools() -> None:
    """Show installed tool versions."""
    client = get_client()
    try:
        resp = client.get("/tools-health/")
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("tools", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            "Security Tools",
            [("name", "Tool"), ("version", "Version"), ("status", "Status")],
            results if isinstance(results, list) else list(results.items()),
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("audit")
def system_audit(
    limit: int = typer.Option(50, "--limit", "-n", help="Max results"),
) -> None:
    """Show audit log."""
    client = get_client()
    try:
        resp = client.get("/audit-log/", params={"limit": limit})
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("results", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            "Audit Log",
            [("timestamp", "Time"), ("user", "User"), ("action", "Action"),
             ("detail", "Detail")],
            results,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("update")
def system_update(
    tools: bool = typer.Option(False, "--tools", help="Update security tools"),
    feeds: bool = typer.Option(False, "--feeds", help="Update vulnerability feeds"),
) -> None:
    """Check for or apply updates."""
    client = get_client()
    try:
        # Default: check for updates
        if not tools and not feeds:
            resp = client.get("/update-check/")
            resp.raise_for_status()
            data = resp.json()
            if check_json_flag():
                echo_json(data)
                return
            echo_keyvalue([
                ("Current version:", data.get("current", "—")),
                ("Latest version:", data.get("latest", "—")),
                ("Update available:", str(data.get("update_available", False))),
            ])
        else:
            if tools:
                resp = client.post("/update/apply/", json={"type": "tools"})
                resp.raise_for_status()
                console.print("[bold green]Tools update triggered[/]")
            if feeds:
                resp = client.post("/update/feeds/")
                resp.raise_for_status()
                console.print("[bold green]Feeds update triggered[/]")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("feeds")
def system_feeds() -> None:
    """Show vulnerability feed status."""
    client = get_client()
    try:
        resp = client.get("/update/feeds/")
        resp.raise_for_status()
        data = resp.json()
        if check_json_flag():
            echo_json(data)
            return
        echo_keyvalue([
            ("Nuclei templates:", data.get("nuclei_templates", "—")),
            ("SearchSploit:", data.get("searchsploit_db", "—")),
            ("MSF metadata:", data.get("msf_metadata", "—")),
        ])
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
```

- [ ] **Step 3: Write smoke tests**

```python
# tests/test_wireghost_dashboard_system.py
"""Smoke tests for dashboard and system commands."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
from typer.testing import CliRunner

from wireghost.cli.dashboard import app as dashboard_app
from wireghost.cli.system import app as system_app

runner = CliRunner()


class TestDashboard:
    def test_stats(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"total_scans": 5}
        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp
        with patch("wireghost.cli.dashboard.get_client", return_value=mock_client):
            result = runner.invoke(dashboard_app, ["stats"])
            assert result.exit_code == 0


class TestSystem:
    def test_stats(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"cpu_percent": 12.5}
        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp
        with patch("wireghost.cli.system.get_client", return_value=mock_client):
            result = runner.invoke(system_app, ["stats"])
            assert result.exit_code == 0

    def test_tools(self):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"name": "nmap", "version": "7.95"}]
        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp
        with patch("wireghost.cli.system.get_client", return_value=mock_client):
            result = runner.invoke(system_app, ["tools"])
            assert result.exit_code == 0
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_wireghost_dashboard_system.py -v`
Expected: 3 tests pass

- [ ] **Step 5: Commit**

```bash
git add src/wireghost/cli/dashboard.py src/wireghost/cli/system.py tests/test_wireghost_dashboard_system.py
git commit -m "feat: add dashboard and system CLI commands"
```

---

### Task 7: Write commands — policies, schedules, users, tokens, sessions

**Files:**
- Create: `src/wireghost/cli/policies.py`
- Create: `src/wireghost/cli/schedules.py`
- Create: `src/wireghost/cli/users.py`
- Create: `src/wireghost/cli/tokens.py`
- Create: `src/wireghost/cli/sessions.py`
- Test: `tests/test_wireghost_write.py`

- [ ] **Step 1: Create policies.py**

```python
# src/wireghost/cli/policies.py
"""wireghost policies — CRUD for scan policies."""
from __future__ import annotations

import typer

from wireghost.cli.client import get_client
from wireghost.cli.output import (
    check_json_flag,
    console,
    echo_json,
    echo_keyvalue,
    echo_table,
)

app = typer.Typer(name="policies", help="Manage scan policies")


@app.command("list")
def list_policies() -> None:
    """List scan policies."""
    client = get_client()
    try:
        resp = client.get("/policies/")
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("results", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            "Scan Policies",
            [("id", "ID"), ("name", "Name"), ("type", "Type"),
             ("parallelism", "Parallelism"), ("created_at", "Created")],
            results,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("show")
def show_policy(
    policy_id: str = typer.Argument(..., help="Policy UUID"),
) -> None:
    """Show policy details."""
    client = get_client()
    try:
        resp = client.get(f"/policies/{policy_id}/")
        resp.raise_for_status()
        data = resp.json()
        if check_json_flag():
            echo_json(data)
            return
        echo_keyvalue([
            ("ID:", data.get("id")),
            ("Name:", data.get("name", "—")),
            ("Type:", data.get("type", "—")),
            ("Description:", data.get("description", "—")),
            ("Parallelism:", str(data.get("parallelism", 10))),
            ("Timeout:", str(data.get("timeout", 3600))),
            ("Skip Nuclei:", str(data.get("skip_nuclei", False))),
            ("Skip Vuln:", str(data.get("skip_vuln", False))),
            ("Skip Screenshots:", str(data.get("skip_screenshots", False))),
        ])
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("create")
def create_policy(
    name: str = typer.Option(..., "--name", help="Policy name"),
    type: str = typer.Option("external", "--type", help="external, internal, or full"),
    description: str = typer.Option("", "--description", help="Description"),
    skip_nuclei: bool = typer.Option(False, "--skip-nuclei"),
    skip_vuln: bool = typer.Option(False, "--skip-vuln"),
    skip_screenshots: bool = typer.Option(False, "--skip-screenshots"),
    parallelism: int = typer.Option(10, "--parallelism", "-j"),
    timeout: int = typer.Option(3600, "--timeout", "-t"),
) -> None:
    """Create a new scan policy."""
    client = get_client()
    try:
        resp = client.post("/policies/", json={
            "name": name, "type": type, "description": description,
            "skip_nuclei": skip_nuclei, "skip_vuln": skip_vuln,
            "skip_screenshots": skip_screenshots,
            "parallelism": parallelism, "timeout": timeout,
        })
        resp.raise_for_status()
        data = resp.json()
        console.print(f"[bold green]Policy created:[/] {data.get('id', '?')}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("update")
def update_policy(
    policy_id: str = typer.Argument(..., help="Policy UUID"),
    name: str = typer.Option("", "--name", help="New name"),
    description: str = typer.Option("", "--description", help="New description"),
    parallelism: int = typer.Option(0, "--parallelism", "-j", help="New parallelism"),
    timeout: int = typer.Option(0, "--timeout", "-t", help="New timeout"),
) -> None:
    """Update a scan policy."""
    client = get_client()
    body: dict = {}
    if name:
        body["name"] = name
    if description:
        body["description"] = description
    if parallelism:
        body["parallelism"] = parallelism
    if timeout:
        body["timeout"] = timeout
    try:
        resp = client.patch(f"/policies/{policy_id}/", json=body)
        resp.raise_for_status()
        console.print(f"[bold green]Policy updated:[/] {policy_id[:8]}...")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("delete")
def delete_policy(
    policy_id: str = typer.Argument(..., help="Policy UUID"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
) -> None:
    """Delete a scan policy."""
    if not force:
        confirm = typer.confirm(f"Delete policy {policy_id}?")
        if not confirm:
            raise typer.Exit()
    client = get_client()
    try:
        resp = client.delete(f"/policies/{policy_id}/")
        resp.raise_for_status()
        console.print(f"[bold green]Policy deleted:[/] {policy_id[:8]}...")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("clone")
def clone_policy(
    policy_id: str = typer.Argument(..., help="Policy UUID to clone"),
    name: str = typer.Option("", "--name", help="New policy name"),
) -> None:
    """Clone a scan policy."""
    client = get_client()
    try:
        resp = client.post(f"/policies/{policy_id}/clone/", json={"name": name} if name else {})
        resp.raise_for_status()
        data = resp.json()
        console.print(f"[bold green]Policy cloned:[/] {data.get('id', '?')}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
```

- [ ] **Step 2: Create schedules.py**

```python
# src/wireghost/cli/schedules.py
"""wireghost schedules — CRUD for scheduled scans."""
from __future__ import annotations

import typer

from wireghost.cli.client import get_client
from wireghost.cli.output import (
    check_json_flag,
    console,
    echo_json,
    echo_keyvalue,
    echo_table,
)

app = typer.Typer(name="schedules", help="Manage scan schedules")


@app.command("list")
def list_schedules() -> None:
    """List scheduled scans."""
    client = get_client()
    try:
        resp = client.get("/schedules/")
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("results", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            "Scheduled Scans",
            [("id", "ID"), ("name", "Name"), ("target", "Target"),
             ("cron", "Cron"), ("enabled", "Enabled"), ("next_run", "Next Run")],
            results,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("show")
def show_schedule(
    schedule_id: str = typer.Argument(..., help="Schedule UUID"),
) -> None:
    """Show schedule details."""
    client = get_client()
    try:
        resp = client.get(f"/schedules/{schedule_id}/")
        resp.raise_for_status()
        data = resp.json()
        if check_json_flag():
            echo_json(data)
            return
        echo_keyvalue([
            ("ID:", data.get("id")),
            ("Name:", data.get("name", "—")),
            ("Target:", data.get("target", "—")),
            ("Cron:", data.get("cron", "—")),
            ("Policy:", data.get("policy", "—")),
            ("Enabled:", str(data.get("enabled", False))),
            ("Next run:", data.get("next_run", "—")),
            ("Last run:", data.get("last_run", "—")),
        ])
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("create")
def create_schedule(
    name: str = typer.Option(..., "--name", help="Schedule name"),
    target: str = typer.Option(..., "--target", help="Scan target"),
    cron: str = typer.Option(..., "--cron", help="Cron expression (e.g. '0 2 * * *')"),
    policy: str = typer.Option("", "--policy", help="Policy name"),
    title: str = typer.Option("", "--title", help="Scan title"),
) -> None:
    """Create a new scheduled scan."""
    client = get_client()
    body: dict = {"name": name, "target": target, "cron": cron}
    if policy:
        body["policy"] = policy
    if title:
        body["title"] = title
    try:
        resp = client.post("/schedules/", json=body)
        resp.raise_for_status()
        data = resp.json()
        console.print(f"[bold green]Schedule created:[/] {data.get('id', '?')}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("update")
def update_schedule(
    schedule_id: str = typer.Argument(..., help="Schedule UUID"),
    name: str = typer.Option("", "--name", help="New name"),
    target: str = typer.Option("", "--target", help="New target"),
    cron: str = typer.Option("", "--cron", help="New cron expression"),
) -> None:
    """Update a scheduled scan."""
    client = get_client()
    body: dict = {}
    if name:
        body["name"] = name
    if target:
        body["target"] = target
    if cron:
        body["cron"] = cron
    try:
        resp = client.patch(f"/schedules/{schedule_id}/", json=body)
        resp.raise_for_status()
        console.print(f"[bold green]Schedule updated:[/] {schedule_id[:8]}...")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("delete")
def delete_schedule(
    schedule_id: str = typer.Argument(..., help="Schedule UUID"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
) -> None:
    """Delete a scheduled scan."""
    if not force:
        confirm = typer.confirm(f"Delete schedule {schedule_id}?")
        if not confirm:
            raise typer.Exit()
    client = get_client()
    try:
        resp = client.delete(f"/schedules/{schedule_id}/")
        resp.raise_for_status()
        console.print(f"[bold green]Schedule deleted:[/] {schedule_id[:8]}...")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("toggle")
def toggle_schedule(
    schedule_id: str = typer.Argument(..., help="Schedule UUID"),
) -> None:
    """Toggle a schedule on/off."""
    client = get_client()
    try:
        resp = client.post(f"/schedules/{schedule_id}/toggle/")
        resp.raise_for_status()
        data = resp.json()
        state = "enabled" if data.get("enabled") else "disabled"
        console.print(f"[bold green]Schedule {schedule_id[:8]}... {state}[/]")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
```

- [ ] **Step 3: Create users.py**

```python
# src/wireghost/cli/users.py
"""wireghost users — user management."""
from __future__ import annotations

import sys

import typer

from wireghost.cli.client import get_client
from wireghost.cli.output import (
    check_json_flag,
    console,
    echo_json,
    echo_keyvalue,
    echo_table,
)

app = typer.Typer(name="users", help="User management")


@app.command("list")
def list_users() -> None:
    """List users."""
    client = get_client()
    try:
        resp = client.get("/auth/users/")
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("results", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            "Users",
            [("id", "ID"), ("username", "Username"), ("role", "Role"),
             ("email", "Email"), ("status", "Status"), ("last_login", "Last Login")],
            results,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("show")
def show_user(
    user_id: str = typer.Argument(..., help="User UUID or username"),
) -> None:
    """Show user details."""
    client = get_client()
    try:
        resp = client.get(f"/auth/users/{user_id}/")
        resp.raise_for_status()
        data = resp.json()
        if check_json_flag():
            echo_json(data)
            return
        echo_keyvalue([
            ("ID:", data.get("id")),
            ("Username:", data.get("username", "—")),
            ("Name:", data.get("name", "—")),
            ("Role:", data.get("role", "—")),
            ("Email:", data.get("email", "—")),
            ("Status:", data.get("status", "—")),
            ("Last login:", data.get("last_login", "—")),
            ("Created:", data.get("created_at", "—")),
        ])
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("create")
def create_user(
    username: str = typer.Option(..., "--username", help="Username"),
    role: str = typer.Option(..., "--role", help="owner, engineer, or viewer"),
    email: str = typer.Option("", "--email", help="Email address"),
    password: str = typer.Option("", "--password", help="Password (warning: shell history)"),
    password_prompt: bool = typer.Option(
        False, "--password-prompt", help="Interactive password input"
    ),
) -> None:
    """Create a new user."""
    client = get_client()

    if password_prompt or (not password):
        import getpass
        password = getpass.getpass("Password: ")
    elif password:
        console.print(
            "[bold yellow]Warning:[/] passing passwords on the command line may "
            "expose them in shell history. Use --password-prompt for interactive input.",
            file=sys.stderr,
        )

    try:
        resp = client.post("/auth/users/create/", json={
            "username": username, "role": role, "email": email, "password": password,
        })
        resp.raise_for_status()
        data = resp.json()
        console.print(f"[bold green]User created:[/] {data.get('username', '?')}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("update")
def update_user(
    user_id: str = typer.Argument(..., help="User UUID"),
    username: str = typer.Option("", "--username", help="New username"),
    role: str = typer.Option("", "--role", help="New role"),
    email: str = typer.Option("", "--email", help="New email"),
) -> None:
    """Update a user."""
    client = get_client()
    body: dict = {}
    if username:
        body["username"] = username
    if role:
        body["role"] = role
    if email:
        body["email"] = email
    try:
        resp = client.put(f"/auth/users/{user_id}/", json=body)
        resp.raise_for_status()
        console.print(f"[bold green]User updated:[/] {user_id[:8]}...")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("delete")
def delete_user(
    user_id: str = typer.Argument(..., help="User UUID"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
) -> None:
    """Delete a user."""
    if not force:
        confirm = typer.confirm(f"Delete user {user_id}?")
        if not confirm:
            raise typer.Exit()
    client = get_client()
    try:
        resp = client.delete(f"/auth/users/{user_id}/delete/")
        resp.raise_for_status()
        console.print(f"[bold green]User deleted:[/] {user_id[:8]}...")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("reset-password")
def reset_password(
    username: str = typer.Argument(..., help="Username to reset password for"),
) -> None:
    """Reset a user's password (interactive)."""
    import getpass

    new_password = getpass.getpass(f"New password for {username}: ")
    confirm = getpass.getpass("Confirm password: ")
    if new_password != confirm:
        console.print("[bold red]Passwords do not match[/]")
        raise typer.Exit(code=1)

    client = get_client()
    try:
        # Try the API endpoint; fall back to telling user to use wg-ctl
        resp = client.post(f"/auth/users/{username}/reset-password/", json={
            "password": new_password,
        })
        if resp.status_code == 404:
            console.print(
                "[bold yellow]API endpoint not available.[/] "
                "Use [bold]wg-ctl reset-password <username>[/] from the server."
            )
            raise typer.Exit(code=1)
        resp.raise_for_status()
        console.print(f"[bold green]Password reset for {username}[/]")
    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
```

- [ ] **Step 4: Create tokens.py**

```python
# src/wireghost/cli/tokens.py
"""wireghost tokens — API token management."""
from __future__ import annotations

import typer

from wireghost.cli.client import get_client
from wireghost.cli.output import (
    check_json_flag,
    console,
    echo_json,
    echo_table,
)

app = typer.Typer(name="tokens", help="API token management")


@app.command("list")
def list_tokens() -> None:
    """List personal API tokens."""
    client = get_client()
    try:
        resp = client.get("/auth/tokens/")
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("results", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            "API Tokens",
            [("id", "ID"), ("name", "Name"), ("last_used", "Last Used"),
             ("created_at", "Created")],
            results,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("create")
def create_token(
    name: str = typer.Option(..., "--name", help="Token description"),
) -> None:
    """Create a new personal API token."""
    client = get_client()
    try:
        resp = client.post("/auth/tokens/", json={"name": name})
        resp.raise_for_status()
        data = resp.json()
        token = data.get("token") or data.get("key", "")
        console.print(f"[bold green]Token created:[/] {data.get('name', name)}")
        if token:
            console.print(f"[bold]Token value (save this — it won't be shown again):[/]")
            console.print(token)
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("revoke")
def revoke_token(
    token_id: str = typer.Argument(..., help="Token UUID"),
) -> None:
    """Revoke a personal API token."""
    client = get_client()
    try:
        resp = client.post(f"/auth/tokens/{token_id}/revoke/")
        resp.raise_for_status()
        console.print(f"[bold green]Token revoked:[/] {token_id[:8]}...")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
```

- [ ] **Step 5: Create sessions.py**

```python
# src/wireghost/cli/sessions.py
"""wireghost sessions — session management."""
from __future__ import annotations

import typer

from wireghost.cli.client import get_client
from wireghost.cli.output import (
    check_json_flag,
    console,
    echo_json,
    echo_table,
)

app = typer.Typer(name="sessions", help="Session management")


@app.command("list")
def list_sessions() -> None:
    """List active sessions."""
    client = get_client()
    try:
        resp = client.get("/sessions/")
        resp.raise_for_status()
        data = resp.json()
        results = data if isinstance(data, list) else data.get("results", data)
        if check_json_flag():
            echo_json(results)
            return
        echo_table(
            "Active Sessions",
            [("session_key", "Key"), ("user", "User"), ("ip", "IP"),
             ("last_activity", "Last Activity")],
            results,
        )
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("revoke")
def revoke_session(
    session_key: str = typer.Argument(..., help="Session key"),
) -> None:
    """Revoke a specific session."""
    client = get_client()
    try:
        resp = client.post("/sessions/revoke/", json={"session_key": session_key})
        resp.raise_for_status()
        console.print(f"[bold green]Session revoked:[/] {session_key[:16]}...")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("revoke-all")
def revoke_all_sessions(
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
) -> None:
    """Revoke all sessions except current."""
    if not force:
        confirm = typer.confirm("Revoke all other sessions?")
        if not confirm:
            raise typer.Exit()
    client = get_client()
    try:
        resp = client.post("/sessions/revoke-all/")
        resp.raise_for_status()
        console.print("[bold green]All other sessions revoked[/]")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
```

- [ ] **Step 6: Run tests**

```python
# tests/test_wireghost_write.py
"""Smoke tests for write commands."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
from typer.testing import CliRunner

from wireghost.cli.policies import app as policies_app
from wireghost.cli.schedules import app as schedules_app
from wireghost.cli.users import app as users_app
from wireghost.cli.tokens import app as tokens_app
from wireghost.cli.sessions import app as sessions_app

runner = CliRunner()


def _mock_200(data=None):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = 200
    resp.json.return_value = data or []
    return resp


def _mock_client(mod):
    mock_client = MagicMock()
    mock_client.get.return_value = _mock_200()
    mock_client.post.return_value = _mock_200({"id": "fake-uuid"})
    return patch(mod, return_value=mock_client)


class TestPolicies:
    def test_list(self):
        with _mock_client("wireghost.cli.policies.get_client"):
            result = runner.invoke(policies_app, ["list"])
            assert result.exit_code == 0


class TestSchedules:
    def test_list(self):
        with _mock_client("wireghost.cli.schedules.get_client"):
            result = runner.invoke(schedules_app, ["list"])
            assert result.exit_code == 0


class TestUsers:
    def test_list(self):
        with _mock_client("wireghost.cli.users.get_client"):
            result = runner.invoke(users_app, ["list"])
            assert result.exit_code == 0


class TestTokens:
    def test_list(self):
        with _mock_client("wireghost.cli.tokens.get_client"):
            result = runner.invoke(tokens_app, ["list"])
            assert result.exit_code == 0


class TestSessions:
    def test_list(self):
        with _mock_client("wireghost.cli.sessions.get_client"):
            result = runner.invoke(sessions_app, ["list"])
            assert result.exit_code == 0
```

Run: `pytest tests/test_wireghost_write.py -v`
Expected: 5 tests pass

- [ ] **Step 7: Commit**

```bash
git add src/wireghost/cli/policies.py src/wireghost/cli/schedules.py src/wireghost/cli/users.py src/wireghost/cli/tokens.py src/wireghost/cli/sessions.py tests/test_wireghost_write.py
git commit -m "feat: add write commands (policies, schedules, users, tokens, sessions)"
```

---

### Task 8: Scan management — create, cancel, clone, run

**Files:**
- Modify: `src/wireghost/cli/scans.py` (add create/cancel/clone/run commands)

- [ ] **Step 1: Append write commands to scans.py**

Add these commands to the existing `src/wireghost/cli/scans.py` (after the `findings`, `hosts`, `topology` commands):

```python
@app.command("create")
def create_scan(
    target: str = typer.Argument(..., help="Target IP, CIDR, or hostname"),
    policy: str = typer.Option("", "--policy", help="Policy name"),
    title: str = typer.Option("", "--title", help="Scan title"),
) -> None:
    """Create and queue a new portal-managed scan."""
    client = get_client()
    body: dict = {"target": target}
    if policy:
        body["policy"] = policy
    if title:
        body["title"] = title
    try:
        resp = client.post("/scans/", json=body)
        resp.raise_for_status()
        data = resp.json()
        console.print(f"[bold green]Scan created:[/] {data.get('id', '?')}")
        console.print(f"  Target: {target}")
        console.print(f"  Status: {data.get('status', '?')}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("cancel")
def cancel_scan(
    scan_id: str = typer.Argument(..., help="Scan UUID"),
) -> None:
    """Cancel a running or queued scan."""
    client = get_client()
    try:
        resp = client.post(f"/scans/{scan_id}/cancel/")
        resp.raise_for_status()
        console.print(f"[bold green]Scan cancelled:[/] {scan_id[:8]}...")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("clone")
def clone_scan(
    scan_id: str = typer.Argument(..., help="Scan UUID to clone"),
    target: str = typer.Option("", "--target", help="New target"),
) -> None:
    """Clone a scan (optionally with a new target)."""
    client = get_client()
    body: dict = {}
    if target:
        body["target"] = target
    try:
        resp = client.post(f"/scans/{scan_id}/clone/", json=body)
        resp.raise_for_status()
        data = resp.json()
        console.print(f"[bold green]Scan cloned:[/] {data.get('id', '?')}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("run")
def run_scan(
    scan_id: str = typer.Argument(..., help="Scan UUID"),
) -> None:
    """Run a queued scan immediately."""
    client = get_client()
    try:
        resp = client.post(f"/scans/{scan_id}/run/")
        resp.raise_for_status()
        console.print(f"[bold green]Scan started:[/] {scan_id[:8]}...")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
```

- [ ] **Step 2: Run smoke tests**

Run: `pytest tests/test_wireghost_readonly.py -v`
Expected: 4 tests pass (existing tests still work)

- [ ] **Step 3: Commit**

```bash
git add src/wireghost/cli/scans.py
git commit -m "feat: add scan management commands (create, cancel, clone, run)"
```

---

### Task 9: tmux integration for wireghost scan

**Files:**
- Create: `src/wireghost/cli/scan.py` (local pipeline + tmux)
- Modify: `src/wireghost/cli.py` (mount scan app)

- [ ] **Step 1: Create scan.py with tmux support**

```python
# src/wireghost/cli/scan.py
"""wireghost scan — local pipeline runner with tmux integration."""
from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from wireghost import __version__

app = typer.Typer(name="scan", help="Run a local security scan")
console = Console(stderr=True)


def _slugify_target(target: str) -> str:
    """Slugify target for tmux session name: 192.168.1.0/24 → wg-192.168.1.0-24."""
    import re
    slug = re.sub(r"[^a-zA-Z0-9./-]", "", target)
    slug = slug.replace("/", "-")
    return f"wg-{slug}"


def _has_tmux() -> bool:
    return shutil.which("tmux") is not None


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target IP, CIDR range, or hostname"),
    output_dir: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output directory (default: ./output)"
    ),
    parallelism: int = typer.Option(
        10, "--parallelism", "-j", help="Max concurrent host scans"
    ),
    skip_nuclei: bool = typer.Option(False, "--skip-nuclei"),
    skip_vuln: bool = typer.Option(False, "--skip-vuln"),
    skip_screenshots: bool = typer.Option(False, "--skip-screenshots"),
    skip_enum4linux: bool = typer.Option(False, "--skip-enum4linux"),
    skip_nikto: bool = typer.Option(False, "--skip-nikto"),
    skip_netexec: bool = typer.Option(False, "--skip-netexec"),
    skip_msf: bool = typer.Option(False, "--skip-msf"),
    timeout: float = typer.Option(3600.0, "--timeout", "-t", help="Per-tool timeout"),
    report_formats: Optional[str] = typer.Option(
        None, "--formats", "-f", help="Comma-separated report formats"
    ),
    title: Optional[str] = typer.Option(None, "--title", help="Report title"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    nuclei_templates: Optional[str] = typer.Option(
        None, "--nuclei-templates", help="External nuclei template directory"
    ),
    nuclei_default_templates: bool = typer.Option(
        True, "--nuclei-default-templates/--no-nuclei-default-templates"
    ),
    config_file: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to wireghost.yml config"
    ),
    no_tmux: bool = typer.Option(False, "--no-tmux", help="Run in foreground (no tmux)"),
    attach: bool = typer.Option(
        False, "--attach", help="Attach to a running scan"
    ),
    list_sessions: bool = typer.Option(
        False, "--list", help="List running wg-* tmux sessions"
    ),
    kill_target: Optional[str] = typer.Option(
        None, "--kill", help="Kill a running scan by target"
    ),
) -> None:
    """Run a full security scan pipeline against a target.

    Default: launches in a detached tmux session named after the target.
    Use --no-tmux to run in the foreground without tmux.
    """
    # ── management commands ──────────────────────────────────────
    if list_sessions:
        _list_sessions()
        return

    if kill_target:
        _kill_session(kill_target)
        return

    if attach:
        _attach(target)
        return

    # ── import pipeline ──────────────────────────────────────────
    from wireghost.config import ScanConfig
    from wireghost.pipeline.orchestrator import run_pipeline

    overrides: dict = {
        "output_dir": output_dir,
        "parallelism": parallelism,
        "skip_nuclei": skip_nuclei,
        "skip_vuln": skip_vuln,
        "skip_screenshots": skip_screenshots,
        "skip_enum4linux": skip_enum4linux,
        "skip_nikto": skip_nikto,
        "skip_netexec": skip_netexec,
        "skip_msf_scan": skip_msf,
        "tool_timeout": timeout,
        "verbose": verbose,
        "nuclei_templates": nuclei_templates,
        "nuclei_default_templates": nuclei_default_templates,
    }
    if report_formats:
        overrides["report_formats"] = [
            f.strip() for f in report_formats.split(",") if f.strip()
        ]
    if title:
        overrides["report_title"] = title

    cfg = ScanConfig.load(target=target, config_path=config_file, **overrides)
    cfg.output_dir = cfg.output_dir.resolve()

    # ── tmux path ────────────────────────────────────────────────
    session_name = _slugify_target(target)

    if not no_tmux and _has_tmux():
        _launch_tmux(session_name, target, cfg)
    else:
        if not no_tmux:
            console.print("[bold yellow]tmux not found — running in foreground[/]")
        _run_foreground(cfg)


def _launch_tmux(session_name: str, target: str, cfg) -> None:
    """Launch a detached tmux session with scan pipeline."""
    # Build the command that tmux will run
    python = sys.executable
    cmd_parts = [
        python, "-m", "wireghost", "scan", target,
        "--no-tmux",
        "-o", str(cfg.output_dir),
        "-j", str(cfg.parallelism),
    ]
    if cfg.skip_nuclei:
        cmd_parts.append("--skip-nuclei")
    if cfg.skip_vuln:
        cmd_parts.append("--skip-vuln")
    if cfg.verbose:
        cmd_parts.append("--verbose")

    scan_cmd = " ".join(f"'{p}'" if " " in str(p) else str(p) for p in cmd_parts)

    # Kill existing session if present
    try:
        subprocess.run(
            ["tmux", "kill-session", "-t", session_name],
            capture_output=True, timeout=5,
        )
    except Exception:
        pass

    # Create new detached session
    subprocess.run(
        ["tmux", "new-session", "-d", "-s", session_name, "-n", "scan"],
        check=True, timeout=10,
    )

    # Top pane (80%): scan output
    subprocess.run(
        ["tmux", "send-keys", "-t", f"{session_name}:scan.0",
         scan_cmd, "Enter"],
        check=True, timeout=5,
    )

    # Create bottom pane (20%): status bar
    subprocess.run(
        ["tmux", "split-window", "-d", "-t", f"{session_name}:scan.0",
         "-l", "8"],
        check=True, timeout=5,
    )
    status_cmd = (
        f"while true; do "
        f" echo 'Target: {target} | Elapsed: $(date +%H:%M:%S) | "
        f"Press Ctrl-B d to detach'; "
        f" sleep 5; "
        f"done"
    )
    subprocess.run(
        ["tmux", "send-keys", "-t", f"{session_name}:scan.1",
         f"echo 'Wire_Ghost scan: {target}'; {status_cmd}", "Enter"],
        check=True, timeout=5,
    )

    # Select top pane
    subprocess.run(
        ["tmux", "select-pane", "-t", f"{session_name}:scan.0"],
        check=True, timeout=5,
    )

    console.print(f"[bold green]Created tmux session: {session_name}[/]")
    console.print(f"  Reattach: [bold]wireghost scan --attach {target}[/]")
    console.print(f"  Watch:    [bold]tmux attach -t {session_name}[/]")


def _run_foreground(cfg) -> None:
    """Run the scan pipeline in the foreground."""
    from wireghost.pipeline.orchestrator import run_pipeline

    console.print(f"[bold green]Wire_Ghost v{__version__}[/]")
    console.print(f"Target: [bold]{cfg.target}[/]")
    console.print(f"Output: {cfg.output_dir}")

    report = asyncio.run(run_pipeline(cfg))

    console.print()
    console.print("[bold green]Scan complete![/]")
    console.print(f"  Hosts:    {len(report.hosts)}")
    console.print(f"  Ports:    {report.total_open_ports}")
    console.print(f"  Findings: {len(report.findings)}")


def _attach(target: str) -> None:
    """Attach to a running scan tmux session."""
    session_name = _slugify_target(target)
    if not _has_tmux():
        console.print("[bold red]tmux not installed[/]")
        raise typer.Exit(code=1)

    # Check if session exists
    result = subprocess.run(
        ["tmux", "has-session", "-t", session_name],
        capture_output=True, timeout=5,
    )
    if result.returncode != 0:
        console.print(f"[bold red]Session not found:[/] {session_name}")
        console.print("Running sessions:")
        _list_sessions()
        raise typer.Exit(code=1)

    os.execvp("tmux", ["tmux", "attach-session", "-t", session_name])


def _kill_session(target: str) -> None:
    """Kill a running scan tmux session."""
    session_name = _slugify_target(target)
    try:
        subprocess.run(
            ["tmux", "kill-session", "-t", session_name],
            check=True, timeout=5,
        )
        console.print(f"[bold green]Killed session:[/] {session_name}")
    except subprocess.CalledProcessError:
        console.print(f"[bold yellow]Session not running:[/] {session_name}")
        raise typer.Exit(code=1)


def _list_sessions() -> None:
    """List all wg-* tmux sessions."""
    if not _has_tmux():
        console.print("[bold yellow]tmux not installed[/]")
        return

    result = subprocess.run(
        ["tmux", "list-sessions", "-F", "#{session_name} #{session_created}"],
        capture_output=True, text=True, timeout=5,
    )
    sessions = [
        line.split(" ", 1)
        for line in result.stdout.strip().split("\n")
        if line.startswith("wg-")
    ]
    if not sessions:
        console.print("[dim]No active wg-* scan sessions[/]")
        return

    from wireghost.cli.output import echo_table
    echo_table(
        "Active Scan Sessions",
        [("name", "Session"), ("created", "Started")],
        [{"name": s[0], "created": s[1] if len(s) > 1 else "—"} for s in sessions],
    )
```

- [ ] **Step 2: Add scan app mount to cli.py**

Add these lines to `src/wireghost/cli.py` after the auth mount and before the scans mount:

```python
from wireghost.cli.scan import app as scan_app
app.add_typer(scan_app, name="scan", help="Run a local scan pipeline")
```

- [ ] **Step 3: Verify import**

Run: `python -c "from wireghost.cli import app; print('OK')"`
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add src/wireghost/cli/scan.py src/wireghost/cli.py
git commit -m "feat: add tmux-integrated wireghost scan command"
```

---

### Task 10: Report, notifications, support-bundle commands

**Files:**
- Create: `src/wireghost/cli/reports.py`
- Create: `src/wireghost/cli/notifications.py`
- Create: `src/wireghost/cli/support.py`
- Create: `tests/test_wireghost_remaining.py`

- [ ] **Step 1: Create reports.py**

```python
# src/wireghost/cli/reports.py
"""wireghost report — report generation and download."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Optional

import typer

from wireghost.cli.client import get_client
from wireghost.cli.output import console, echo_json

app = typer.Typer(name="report", help="Report generation and download")


@app.command("generate")
def generate_report(
    scan_dir: Path = typer.Argument(..., help="Path to scan output directory"),
    output_dir: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output directory"
    ),
    formats: str = typer.Option(
        "html,docx,xlsx", "--formats", "-f", help="Comma-separated formats"
    ),
    title: str = typer.Option(
        "Security Assessment Summary Report", "--title", help="Report title"
    ),
) -> None:
    """Generate reports from a local scan directory."""
    # Build args for old `wireghost report` command (runs the report engine)
    cmd = [sys.executable, "-m", "wireghost", "report", str(scan_dir)]
    if output_dir:
        cmd.extend(["-o", str(output_dir)])
    cmd.extend(["-f", formats])
    cmd.extend(["--title", title])

    console.print(f"[dim]Running: {' '.join(cmd)}[/]")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        console.print("[bold red]Report generation failed[/]")
        raise typer.Exit(code=1)


@app.command("download")
def download_report(
    scan_id: str = typer.Argument(..., help="Portal scan UUID"),
    format: str = typer.Option("docx", "--format", help="docx, html, or xlsx"),
    output_dir: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output directory"
    ),
) -> None:
    """Download a report from a portal-managed scan."""
    client = get_client()
    try:
        resp = client.get(f"/reports/{scan_id}/download/", params={"format": format})
        resp.raise_for_status()
        ext = {"docx": "docx", "html": "html", "xlsx": "xlsx"}.get(format, format)
        out = output_dir or Path(".")
        out.mkdir(parents=True, exist_ok=True)
        outfile = out / f"report_{scan_id[:8]}.{ext}"
        outfile.write_bytes(resp.content)
        console.print(f"[bold green]Report saved:[/] {outfile}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("config")
def report_config() -> None:
    """Show report configuration."""
    client = get_client()
    try:
        resp = client.get("/report-config/")
        resp.raise_for_status()
        data = resp.json()
        echo_json(data) if "--json" in sys.argv else None
        console.print(f"Company: {data.get('company', '—')}")
        console.print(f"Logo:    {data.get('logo_url', '—')}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("logo")
def report_logo(
    image_path: Path = typer.Argument(..., help="Path to logo image file"),
) -> None:
    """Upload a report logo."""
    client = get_client()
    try:
        with open(image_path, "rb") as f:
            resp = client.post(
                "/report-config/logo/",
                files={"logo": (image_path.name, f, "image/png")},
            )
        resp.raise_for_status()
        console.print(f"[bold green]Logo uploaded:[/] {image_path}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
```

- [ ] **Step 2: Create notifications.py**

```python
# src/wireghost/cli/notifications.py
"""wireghost notify — notification configuration."""
from __future__ import annotations

import typer

from wireghost.cli.client import get_client
from wireghost.cli.output import check_json_flag, console, echo_json, echo_keyvalue

app = typer.Typer(name="notify", help="Notification configuration")


@app.command("config")
def notify_config() -> None:
    """Show notification configuration."""
    client = get_client()
    try:
        resp = client.get("/notifications/config/")
        resp.raise_for_status()
        data = resp.json()
        if check_json_flag():
            echo_json(data)
            return
        echo_keyvalue([
            ("Telegram bot:", data.get("telegram_bot_token", "—")[:20] + "..." if data.get("telegram_bot_token") else "—"),
            ("Enabled:", str(data.get("enabled", False))),
            ("On findings:", str(data.get("on_finding", False))),
            ("On scan complete:", str(data.get("on_scan_complete", False))),
        ])
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)


@app.command("test")
def notify_test(
    channel: str = typer.Option(
        "telegram", "--channel", help="telegram or email"
    ),
) -> None:
    """Send a test notification."""
    client = get_client()
    try:
        resp = client.post("/notifications/test/", json={"channel": channel})
        resp.raise_for_status()
        console.print(f"[bold green]Test notification sent via {channel}[/]")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
```

- [ ] **Step 3: Create support.py**

```python
# src/wireghost/cli/support.py
"""wireghost support-bundle — diagnostic bundle generation."""
from __future__ import annotations

import typer

from wireghost.cli.client import get_client
from wireghost.cli.output import console

app = typer.Typer(name="support-bundle", help="Generate support diagnostic bundle")


@app.callback(invoke_without_command=True)
def support_bundle(
    output: str = typer.Option(
        "", "--output", "-o", help="Output path for bundle"
    ),
) -> None:
    """Generate a support diagnostic bundle (Owner only)."""
    client = get_client()
    try:
        console.print("[dim]Generating support bundle...[/]")
        resp = client.post("/support-bundle/")
        resp.raise_for_status()
        data = resp.json()
        bundle_path = data.get("path", "support_bundle.tar.gz")
        console.print(f"[bold green]Support bundle ready:[/] {bundle_path}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        raise typer.Exit(code=1)
```

- [ ] **Step 4: Run tests**

```python
# tests/test_wireghost_remaining.py
"""Smoke tests for remaining CLI commands."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
from typer.testing import CliRunner

from wireghost.cli.notifications import app as notify_app
from wireghost.cli.support import app as support_app

runner = CliRunner()


def _mock_200(data=None):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = 200
    resp.json.return_value = data or {}
    return resp


class TestNotify:
    def test_config(self):
        mock_client = MagicMock()
        mock_client.get.return_value = _mock_200()
        with patch("wireghost.cli.notifications.get_client", return_value=mock_client):
            result = runner.invoke(notify_app, ["config"])
            assert result.exit_code == 0


class TestSupport:
    def test_bundle(self):
        mock_client = MagicMock()
        mock_client.post.return_value = _mock_200({"path": "bundle.tar.gz"})
        with patch("wireghost.cli.support.get_client", return_value=mock_client):
            result = runner.invoke(support_app, [])
            assert result.exit_code == 0
```

Run: `pytest tests/test_wireghost_remaining.py -v`
Expected: 2 tests pass

- [ ] **Step 5: Commit**

```bash
git add src/wireghost/cli/reports.py src/wireghost/cli/notifications.py src/wireghost/cli/support.py tests/test_wireghost_remaining.py
git commit -m "feat: add report, notify, and support-bundle commands"
```

---

### Task 11: Deprecation stubs + final wiring

**Files:**
- Modify: `src/wireghost/cli.py` (add deprecation stubs for `report` and `update`)

- [ ] **Step 1: Add deprecation stubs to cli.py**

Add these functions to `src/wireghost/cli.py` before the domain app mounts:

```python
# ── Deprecation stubs (old commands, now under domain apps) ──────

@app.command("report", hidden=True)
def report_deprecated(
    scan_dir: str = typer.Argument(..., help="Scan directory"),
) -> None:
    """[DEPRECATED] Use 'wireghost report generate' instead."""
    console = Console(stderr=True)
    console.print(
        "[bold yellow]Deprecated:[/] 'wireghost report' → use "
        "'wireghost report generate <scan-dir>'"
    )
    # Forward to new command
    from wireghost.cli.reports import generate_report
    import subprocess, sys
    cmd = [sys.executable, "-m", "wireghost", "report", "generate", scan_dir]
    subprocess.run(cmd)


@app.command("update", hidden=True)
def update_deprecated() -> None:
    """[DEPRECATED] Use 'wireghost system update' instead."""
    console = Console(stderr=True)
    console.print(
        "[bold yellow]Deprecated:[/] 'wireghost update' → use "
        "'wireghost system update'"
    )
```

- [ ] **Step 2: Full integration test — verify all commands exist**

Run: `python -m wireghost --help`
Expected: lists all command groups: auth, scan, scans, hosts, findings, policies, schedules, exploits, users, tokens, sessions, system, report, notify, dashboard, support-bundle

- [ ] **Step 3: Run all new tests**

Run: `pytest tests/test_wireghost_*.py -v`
Expected: all tests pass (~25+ tests)

- [ ] **Step 4: Commit**

```bash
git add src/wireghost/cli.py
git commit -m "feat: add deprecation stubs and final wiring"
```

---

### Task 12: Final integration — run all tests, verify help output

- [ ] **Step 1: Full test run**

Run: `pytest tests/test_wireghost_*.py -v --tb=short`
Expected: all tests pass

- [ ] **Step 2: Verify complete help tree**

Run:
```
python -m wireghost --help
python -m wireghost scans --help
python -m wireghost auth --help
python -m wireghost scan --help
```
Expected: each command group shows its subcommands with help text

- [ ] **Step 3: Verify --json and --help on every subcommand**

Run: `python -m wireghost scans list --help 2>&1 | grep -q "\-\-json" && echo "PASS" || echo "FAIL"`
Expected: PASS for all list commands

- [ ] **Step 4: Verify import doesn't require network**

Run: `python -c "from wireghost.cli import app; print('OK')"`
Expected: OK (no connection attempts)

- [ ] **Step 5: Commit**

```bash
git add .
git commit -m "chore: final integration verification for CLI/web parity"
```

---

## Verification Checklist

- [ ] `wireghost --help` shows all 15+ command groups
- [ ] `wireghost auth login --help` shows all options
- [ ] `wireghost scan --help` shows tmux flags
- [ ] `wireghost scans list --help` shows --json, --limit, --status
- [ ] `wireghost policies create --help` shows --name, --type, etc.
- [ ] `wireghost users create --help` shows --password-prompt
- [ ] `wireghost --version` shows version
- [ ] All command modules imported without network access
- [ ] `--json` flag present on all list/show commands
- [ ] All test files pass: `pytest tests/test_wireghost_*.py -v`
