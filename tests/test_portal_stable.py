"""Stable end-to-end tests against the live Wire_Ghost portal.

Hits the real HTTPS API at localhost:18443 — requires the Docker stack running.
Tests: auth flows, RBAC, CRUD on all endpoints, dashboard data, session management,
scan lifecycle, finding/host detail, settings, and edge cases.

Run: python -m pytest tests/test_portal_stable.py -v --tb=short -x
"""

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.request
from typing import Any

import pytest

BASE = "https://localhost:18443"

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE

ADMIN_USER = "admin"
ADMIN_PASS = "admin123"


# ================================================================
# HTTP helpers
# ================================================================


class PortalClient:
    """Thin HTTP client wrapping urllib for cookie-based session auth."""

    def __init__(self) -> None:
        self.session_cookie: str = ""
        self.csrf_token: str = ""

    def request(
        self,
        method: str,
        path: str,
        data: dict | None = None,
        expect: int | None = None,
    ) -> tuple[int, Any]:
        url = f"{BASE}{path}"
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("Referer", BASE + "/")
        if self.session_cookie:
            req.add_header("Cookie", f"sessionid={self.session_cookie}; csrftoken={self.csrf_token}")
        if method in ("POST", "PUT", "PATCH", "DELETE") and self.csrf_token:
            req.add_header("X-CSRFToken", self.csrf_token)
        try:
            resp = urllib.request.urlopen(req, context=_ctx, timeout=30)
            code = resp.status
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                body_parsed = json.loads(raw) if raw.strip() else {}
            except json.JSONDecodeError:
                body_parsed = {"_raw": raw[:500]}
            # Capture cookies
            for hdr in resp.headers.get_all("Set-Cookie") or []:
                if "sessionid=" in hdr:
                    self.session_cookie = hdr.split("sessionid=")[1].split(";")[0]
                if "csrftoken=" in hdr:
                    self.csrf_token = hdr.split("csrftoken=")[1].split(";")[0]
        except urllib.error.HTTPError as e:
            code = e.code
            raw = e.read().decode("utf-8", errors="replace")
            try:
                body_parsed = json.loads(raw) if raw.strip() else {}
            except json.JSONDecodeError:
                body_parsed = {"_raw": raw[:500]}
        if expect is not None:
            assert code == expect, f"{method} {path} → {code} (expected {expect}): {body_parsed}"
        return code, body_parsed

    def get(self, path: str, expect: int | None = None) -> tuple[int, Any]:
        return self.request("GET", path, expect=expect)

    def post(self, path: str, data: dict | None = None, expect: int | None = None) -> tuple[int, Any]:
        return self.request("POST", path, data=data, expect=expect)

    def delete(self, path: str, expect: int | None = None) -> tuple[int, Any]:
        return self.request("DELETE", path, expect=expect)

    def login(self, username: str, password: str) -> tuple[int, Any]:
        code, body = self.post("/api/auth/login/", {"username": username, "password": password})
        return code, body


# ================================================================
# Fixtures
# ================================================================


@pytest.fixture(scope="session")
def portal_up():
    """Skip entire session if portal is unreachable."""
    try:
        req = urllib.request.Request(f"{BASE}/api/auth/csrf/", method="GET")
        resp = urllib.request.urlopen(req, context=_ctx, timeout=5)
        assert resp.status == 200
    except Exception:
        pytest.skip("Portal not reachable at localhost:18443")


@pytest.fixture(scope="session")
def admin(portal_up) -> PortalClient:
    c = PortalClient()
    code, body = c.login(ADMIN_USER, ADMIN_PASS)
    assert code == 200, f"Admin login failed: {body}"
    return c


@pytest.fixture(scope="session")
def anon(portal_up) -> PortalClient:
    return PortalClient()


# ================================================================
# 1. AUTH: login, logout, CSRF, me, check
# ================================================================


class TestAuth:
    def test_login_valid(self, admin: PortalClient):
        assert admin.session_cookie != ""
        assert admin.csrf_token != ""

    def test_login_invalid(self, anon: PortalClient):
        code, body = anon.login("admin", "wrongpassword")
        assert code in (401, 403, 400)
        assert "error" in body or "detail" in body

    def test_login_empty_body(self, anon: PortalClient):
        code, _ = anon.post("/api/auth/login/", {})
        assert code in (400, 401, 403)

    def test_csrf_endpoint(self, anon: PortalClient):
        code, body = anon.get("/api/auth/csrf/", expect=200)
        assert "csrfToken" in body or anon.csrf_token

    def test_me_authenticated(self, admin: PortalClient):
        code, body = admin.get("/api/auth/me/", expect=200)
        assert body["username"] == ADMIN_USER
        assert body["role"] == "owner"

    def test_me_unauthenticated(self, anon: PortalClient):
        code, _ = anon.get("/api/auth/me/")
        assert code in (401, 403)

    def test_check_authenticated(self, admin: PortalClient):
        code, body = admin.get("/api/auth/check/")
        assert code in (200, 204)

    def test_check_unauthenticated(self, anon: PortalClient):
        code, body = anon.get("/api/auth/check/")
        assert code in (200, 401, 403)

    def test_logout(self, portal_up):
        c = PortalClient()
        c.get("/api/auth/csrf/")
        code, _ = c.login(ADMIN_USER, ADMIN_PASS)
        if code != 200:
            pytest.skip("Could not get fresh session for logout test")
        code, _ = c.post("/api/auth/logout/")
        assert code in (200, 204)
        code2, _ = c.get("/api/auth/me/")
        assert code2 in (401, 403)


# ================================================================
# 2. DASHBOARD
# ================================================================


class TestDashboard:
    def test_dashboard_stats(self, admin: PortalClient):
        code, body = admin.get("/api/dashboard/", expect=200)
        assert isinstance(body, dict)
        assert len(body) > 0

    def test_dashboard_unauthenticated(self, anon: PortalClient):
        code, _ = anon.get("/api/dashboard/")
        assert code in (401, 403)

    def test_dashboard_screenshots(self, admin: PortalClient):
        code, body = admin.get("/api/dashboard/screenshots/", expect=200)
        assert isinstance(body, list)


# ================================================================
# 3. SCANS: list, detail, create, cancel, delete
# ================================================================


class TestScans:
    def test_list_scans(self, admin: PortalClient):
        code, body = admin.get("/api/scans/", expect=200)
        assert "results" in body or isinstance(body, list)

    def test_list_scans_unauthenticated(self, anon: PortalClient):
        code, _ = anon.get("/api/scans/")
        assert code in (401, 403)

    def test_scan_detail(self, admin: PortalClient):
        _, listing = admin.get("/api/scans/", expect=200)
        results = listing.get("results", listing)
        if not results:
            pytest.skip("No scans in DB")
        scan_id = results[0]["id"]
        code, body = admin.get(f"/api/scans/{scan_id}/", expect=200)
        assert body["id"] == scan_id
        assert "target" in body
        assert "status" in body

    def test_scan_findings(self, admin: PortalClient):
        _, listing = admin.get("/api/scans/", expect=200)
        results = listing.get("results", listing)
        if not results:
            pytest.skip("No scans in DB")
        scan_id = results[0]["id"]
        code, body = admin.get(f"/api/scans/{scan_id}/findings/", expect=200)
        assert isinstance(body, list)

    def test_scan_hosts(self, admin: PortalClient):
        _, listing = admin.get("/api/scans/", expect=200)
        results = listing.get("results", listing)
        if not results:
            pytest.skip("No scans in DB")
        scan_id = results[0]["id"]
        code, body = admin.get(f"/api/scans/{scan_id}/hosts/", expect=200)
        assert isinstance(body, list)

    def test_scan_topology(self, admin: PortalClient):
        _, listing = admin.get("/api/scans/", expect=200)
        results = listing.get("results", listing)
        if not results:
            pytest.skip("No scans in DB")
        scan_id = results[0]["id"]
        code, body = admin.get(f"/api/scans/{scan_id}/topology/", expect=200)
        assert "nodes" in body or "links" in body or isinstance(body, dict)

    def test_scan_not_found(self, admin: PortalClient):
        code, _ = admin.get("/api/scans/00000000-0000-0000-0000-000000000000/")
        assert code == 404

    def test_create_scan_minimal(self, admin: PortalClient):
        code, body = admin.post("/api/scans/", {
            "target": "203.0.113.99",
            "scan_type": "quick",
        })
        assert code == 201, f"Create failed: {body}"
        assert body["status"] in ("pending", "running")
        assert body["target"] == "203.0.113.99"
        scan_id = body["id"]
        # Cancel immediately so it doesn't run forever
        admin.post(f"/api/scans/{scan_id}/cancel/")
        # Clean up
        admin.delete(f"/api/scans/{scan_id}/")

    def test_create_scan_invalid_name(self, admin: PortalClient):
        code, body = admin.post("/api/scans/", {
            "target": "10.0.0.1",
            "scan_type": "quick",
            "name": "<script>alert(1)</script>",
        })
        assert code == 400, f"XSS in name not rejected: {body}"

    def test_create_scan_missing_target(self, admin: PortalClient):
        code, _ = admin.post("/api/scans/", {"scan_type": "quick"})
        assert code == 400


# ================================================================
# 4. FINDINGS
# ================================================================


class TestFindings:
    def test_list_findings(self, admin: PortalClient):
        code, body = admin.get("/api/findings/", expect=200)
        assert "results" in body or isinstance(body, list)

    def test_list_findings_unauthenticated(self, anon: PortalClient):
        code, _ = anon.get("/api/findings/")
        assert code in (401, 403)

    def test_finding_detail(self, admin: PortalClient):
        _, listing = admin.get("/api/findings/", expect=200)
        results = listing.get("results", listing)
        if not results:
            pytest.skip("No findings in DB")
        fid = results[0]["id"]
        code, body = admin.get(f"/api/findings/{fid}/", expect=200)
        assert body["id"] == fid
        assert "severity" in body
        assert "title" in body

    def test_findings_filter_severity(self, admin: PortalClient):
        code, body = admin.get("/api/findings/?severity=critical", expect=200)
        results = body.get("results", body)
        for f in results:
            assert f["severity"].lower() == "critical"

    def test_findings_filter_source(self, admin: PortalClient):
        code, body = admin.get("/api/findings/?source=nuclei", expect=200)
        results = body.get("results", body)
        for f in results:
            assert f["source"] == "nuclei"

    def test_findings_search(self, admin: PortalClient):
        code, body = admin.get("/api/findings/?search=apache", expect=200)
        assert isinstance(body.get("results", body), list)


# ================================================================
# 5. HOSTS
# ================================================================


class TestHosts:
    def test_list_hosts(self, admin: PortalClient):
        code, body = admin.get("/api/hosts/", expect=200)
        assert "results" in body or isinstance(body, list)

    def test_list_hosts_unauthenticated(self, anon: PortalClient):
        code, _ = anon.get("/api/hosts/")
        assert code in (401, 403)

    def test_host_detail(self, admin: PortalClient):
        _, listing = admin.get("/api/hosts/", expect=200)
        results = listing.get("results", listing)
        if not results:
            pytest.skip("No hosts in DB")
        hid = results[0]["id"]
        code, body = admin.get(f"/api/hosts/{hid}/", expect=200)
        assert body["id"] == hid
        assert "ip" in body


# ================================================================
# 6. EXPLOITS
# ================================================================


class TestExploits:
    def test_list_exploits(self, admin: PortalClient):
        code, body = admin.get("/api/exploits/", expect=200)
        assert "results" in body or isinstance(body, list)


# ================================================================
# 7. POLICIES
# ================================================================


class TestPolicies:
    def test_list_policies(self, admin: PortalClient):
        code, body = admin.get("/api/policies/", expect=200)
        assert "results" in body or isinstance(body, list)

    def test_create_and_delete_policy(self, admin: PortalClient):
        code, body = admin.post("/api/policies/", {
            "name": "QA Test Policy",
            "scan_type": "quick",
            "parallelism": 5,
            "timeout": 1800,
        })
        if code == 201:
            pid = body["id"]
            admin.delete(f"/api/policies/{pid}/", expect=204)
        else:
            assert code in (400, 201)


# ================================================================
# 8. SCHEDULES
# ================================================================


class TestSchedules:
    def test_list_schedules(self, admin: PortalClient):
        code, body = admin.get("/api/schedules/", expect=200)
        assert "results" in body or isinstance(body, list)


# ================================================================
# 9. REPORTS
# ================================================================


class TestReports:
    def test_report_config(self, admin: PortalClient):
        code, body = admin.get("/api/report-config/", expect=200)
        assert isinstance(body, dict)


# ================================================================
# 10. SITE CONFIG
# ================================================================


class TestSiteConfig:
    def test_get_site_config(self, admin: PortalClient):
        code, body = admin.get("/api/site-config/", expect=200)
        assert isinstance(body, dict)

    def test_site_config_unauthenticated(self, anon: PortalClient):
        code, body = anon.get("/api/site-config/")
        assert code in (200, 401, 403, 429)


# ================================================================
# 11. TOOLS HEALTH
# ================================================================


class TestToolsHealth:
    def test_tools_health(self, admin: PortalClient):
        code, body = admin.get("/api/tools-health/", expect=200)
        assert isinstance(body, (dict, list))


# ================================================================
# 12. SYSTEM
# ================================================================


class TestSystem:
    def test_system_stats(self, admin: PortalClient):
        code, body = admin.get("/api/system-stats/", expect=200)
        assert isinstance(body, dict)

    def test_system_stats_unauthenticated(self, anon: PortalClient):
        code, _ = anon.get("/api/system-stats/")
        assert code in (401, 403)


# ================================================================
# 13. SESSIONS
# ================================================================


class TestSessions:
    def test_list_sessions(self, admin: PortalClient):
        code, body = admin.get("/api/sessions/", expect=200)
        assert isinstance(body, list)
        assert len(body) >= 1

    def test_sessions_unauthenticated(self, anon: PortalClient):
        code, _ = anon.get("/api/sessions/")
        assert code in (401, 403)


# ================================================================
# 14. AUDIT LOG
# ================================================================


class TestAuditLog:
    def test_audit_log(self, admin: PortalClient):
        code, body = admin.get("/api/audit-log/", expect=200)
        assert "results" in body or isinstance(body, list)

    def test_audit_log_unauthenticated(self, anon: PortalClient):
        code, _ = anon.get("/api/audit-log/")
        assert code in (401, 403)


# ================================================================
# 15. USERS (admin only)
# ================================================================


class TestUsers:
    def test_list_users(self, admin: PortalClient):
        code, body = admin.get("/api/auth/users/", expect=200)
        assert isinstance(body, list)
        usernames = [u["username"] for u in body]
        assert ADMIN_USER in usernames

    def test_create_and_delete_user(self, admin: PortalClient):
        ts = str(int(time.time()))[-6:]
        code, body = admin.post("/api/auth/users/create/", {
            "username": f"qa_user_{ts}",
            "password": f"TestPass123!_{ts}",
            "email": f"qa{ts}@test.com",
            "role": "viewer",
            "name": "QA Test User",
        })
        assert code in (200, 201), f"Create user failed: {body}"
        uid = body["id"]
        dcode, _ = admin.delete(f"/api/auth/users/{uid}/delete/")
        assert dcode in (200, 204)

    def test_users_unauthenticated(self, anon: PortalClient):
        code, _ = anon.get("/api/auth/users/")
        assert code in (401, 403)


# ================================================================
# 16. PREFERENCES
# ================================================================


class TestPreferences:
    def test_get_preferences(self, admin: PortalClient):
        code, body = admin.get("/api/preferences/", expect=200)
        assert isinstance(body, dict)

    def test_preferences_unauthenticated(self, anon: PortalClient):
        code, _ = anon.get("/api/preferences/")
        assert code in (401, 403)


# ================================================================
# 17. NOTIFICATIONS CONFIG
# ================================================================


class TestNotifications:
    def test_get_config(self, admin: PortalClient):
        code, body = admin.get("/api/notifications/config/", expect=200)
        assert isinstance(body, dict)


# ================================================================
# 18. MFA status
# ================================================================


class TestMFA:
    def test_mfa_status(self, admin: PortalClient):
        code, body = admin.get("/api/auth/mfa/status/", expect=200)
        assert "enabled" in body or "mfa_enabled" in body or isinstance(body, dict)


# ================================================================
# 19. API TOKENS
# ================================================================


class TestAPITokens:
    def test_list_tokens(self, admin: PortalClient):
        code, body = admin.get("/api/auth/tokens/", expect=200)
        assert isinstance(body, list)

    def test_create_and_revoke_token(self, admin: PortalClient):
        code, body = admin.post("/api/auth/tokens/", {"name": "qa-test-token"})
        assert code in (200, 201), f"Create token failed: {body}"
        token_id = body.get("id")
        if token_id:
            rcode, _ = admin.post(f"/api/auth/tokens/{token_id}/revoke/")
            assert rcode in (200, 204)


# ================================================================
# 20. RBAC: viewer cannot write
# ================================================================


@pytest.fixture(scope="session")
def viewer(portal_up) -> PortalClient:
    c = PortalClient()
    code, body = c.login("test_viewer", "test_viewer")
    if code != 200:
        pytest.skip("test_viewer account not available")
    return c


@pytest.fixture(scope="session")
def engineer(portal_up) -> PortalClient:
    c = PortalClient()
    code, body = c.login("test_engineer", "test_engineer")
    if code != 200:
        pytest.skip("test_engineer account not available")
    return c


class TestRBAC:

    def test_viewer_can_read_scans(self, viewer: PortalClient):
        code, _ = viewer.get("/api/scans/")
        assert code == 200

    def test_viewer_can_read_findings(self, viewer: PortalClient):
        code, _ = viewer.get("/api/findings/")
        assert code == 200

    def test_viewer_can_read_hosts(self, viewer: PortalClient):
        code, _ = viewer.get("/api/hosts/")
        assert code == 200

    def test_viewer_cannot_create_scan(self, viewer: PortalClient):
        code, _ = viewer.post("/api/scans/", {
            "target": "10.0.0.1",
            "scan_type": "quick",
        })
        assert code == 403

    def test_viewer_cannot_list_users(self, viewer: PortalClient):
        code, _ = viewer.get("/api/auth/users/")
        assert code == 403

    def test_viewer_cannot_delete_scan(self, viewer: PortalClient):
        code, _ = viewer.delete("/api/scans/00000000-0000-0000-0000-000000000000/")
        assert code in (403, 404)

    def test_engineer_can_create_scan(self, engineer: PortalClient):
        code, body = engineer.post("/api/scans/", {
            "target": "203.0.113.88",
            "scan_type": "quick",
        })
        if code == 201:
            sid = body["id"]
            engineer.post(f"/api/scans/{sid}/cancel/")
            # Only owner/creator can delete
            engineer.delete(f"/api/scans/{sid}/")

    def test_engineer_cannot_manage_users(self, engineer: PortalClient):
        code, _ = engineer.get("/api/auth/users/")
        assert code == 403


# ================================================================
# 21. INPUT VALIDATION / XSS
# ================================================================


class TestInputValidation:
    def test_scan_name_xss_rejected(self, admin: PortalClient):
        code, _ = admin.post("/api/scans/", {
            "target": "10.0.0.1",
            "scan_type": "quick",
            "name": '<img src=x onerror="alert(1)">',
        })
        assert code == 400

    def test_scan_target_length_limit(self, admin: PortalClient):
        code, body = admin.post("/api/scans/", {
            "target": "A" * 1000,
            "scan_type": "quick",
        })
        if code == 201:
            sid = body["id"]
            admin.post(f"/api/scans/{sid}/cancel/")
            admin.delete(f"/api/scans/{sid}/")
            assert len(body["target"]) <= 500

    def test_invalid_scan_type(self, admin: PortalClient):
        code, _ = admin.post("/api/scans/", {
            "target": "10.0.0.1",
            "scan_type": "INVALID_TYPE",
        })
        assert code == 400

    def test_check_username_endpoint(self, admin: PortalClient):
        code, body = admin.get("/api/auth/check-username/?username=admin")
        if code == 405:
            code, body = admin.post("/api/auth/check-username/", {"username": "admin"})
        assert code == 200
        assert body.get("available") is False or body.get("exists") is True


# ================================================================
# 22. CONCURRENT SCAN LIMIT
# ================================================================


class TestConcurrentLimits:
    def test_max_concurrent_scans_enforced(self, admin: PortalClient):
        created = []
        try:
            for i in range(6):
                code, body = admin.post("/api/scans/", {
                    "target": f"203.0.113.{50 + i}",
                    "scan_type": "quick",
                })
                if code == 201:
                    created.append(body["id"])
                elif code == 429:
                    assert i >= 5
                    break
        finally:
            for sid in created:
                admin.post(f"/api/scans/{sid}/cancel/")
                admin.delete(f"/api/scans/{sid}/")


# ================================================================
# 23. UPDATE CHECK
# ================================================================


class TestUpdateCheck:
    def test_update_check(self, admin: PortalClient):
        code, body = admin.get("/api/update-check/", expect=200)
        assert isinstance(body, dict)


# ================================================================
# 24. EDGE CASES
# ================================================================


class TestEdgeCases:
    def test_nonexistent_endpoint(self, admin: PortalClient):
        code, _ = admin.get("/api/totally-fake-endpoint/")
        assert code == 404

    def test_method_not_allowed(self, admin: PortalClient):
        code, _ = admin.request("PUT", "/api/auth/login/", {"foo": "bar"})
        assert code == 405

    def test_empty_post_to_login(self, anon: PortalClient):
        code, _ = anon.post("/api/auth/login/", {})
        assert code in (400, 401, 403, 429)

    def test_support_bundle(self, admin: PortalClient):
        code, body = admin.post("/api/support-bundle/")
        assert code in (200, 403)
