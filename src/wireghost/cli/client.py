# src/wireghost/cli/client.py
"""WireGhostClient — HTTP API client with auth caching."""

from __future__ import annotations

import json
import os
import time
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
            base_url or os.environ.get("WIREGHOST_API_URL", "https://localhost:18443")
        ).rstrip("/")
        self._verify = not insecure and not self.base_url.startswith("https://localhost")
        self._session = httpx.Client(timeout=30, verify=self._verify)

        # Auth precedence: --token flag → WIREGHOST_TOKEN env → cached .token → session cookie
        self._token = token or os.environ.get("WIREGHOST_TOKEN")
        if not self._token:
            self._token = self._read_cached_token()
        _ensure_config_dir()
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
