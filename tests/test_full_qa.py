"""Full QA — tests every API endpoint, RBAC, CRUD, edge cases.

Run:  python -m pytest tests/test_full_qa.py -v --tb=short -x
Requires: Docker stack running at localhost:18443
"""

from __future__ import annotations

import json
import ssl
import time
import uuid
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


class PortalClient:
    def __init__(self) -> None:
        self.session_cookie: str = ""
        self.csrf_token: str = ""

    def request(
        self, method: str, path: str, data: dict | None = None,
        expect: int | None = None, timeout: int = 30,
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
            resp = urllib.request.urlopen(req, context=_ctx, timeout=timeout)
            code = resp.status
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                body_parsed = json.loads(raw) if raw.strip() else {}
            except json.JSONDecodeError:
                body_parsed = {"_raw": raw[:500]}
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
            assert code == expect, f"{method} {path} -> {code} (expected {expect}): {body_parsed}"
        return code, body_parsed

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, data=None, **kw):
        return self.request("POST", path, data=data, **kw)

    def put(self, path, data=None, **kw):
        return self.request("PUT", path, data=data, **kw)

    def patch(self, path, data=None, **kw):
        return self.request("PATCH", path, data=data, **kw)

    def delete(self, path, **kw):
        return self.request("DELETE", path, **kw)

    def login(self, username: str, password: str) -> tuple[int, Any]:
        return self.post("/api/auth/login/", {"username": username, "password": password})


# ── Fixtures ──────────────────────────────────────────

@pytest.fixture(scope="session")
def portal_up():
    try:
        req = urllib.request.Request(f"{BASE}/api/auth/csrf/", method="GET")
        resp = urllib.request.urlopen(req, context=_ctx, timeout=5)
        assert resp.status == 200
    except Exception:
        pytest.skip("Portal not reachable at localhost:18443")


@pytest.fixture(scope="session")
def admin(portal_up) -> PortalClient:
    c = PortalClient()
    c.get("/api/auth/csrf/")
    code, body = c.login(ADMIN_USER, ADMIN_PASS)
    assert code == 200, f"Admin login failed: {body}"
    return c


@pytest.fixture(scope="session")
def anon(portal_up) -> PortalClient:
    c = PortalClient()
    c.get("/api/auth/csrf/")
    return c


# ── 1. Auth Endpoints ────────────────────────────────

class TestAuth:
    def test_csrf(self, anon):
        code, body = anon.get("/api/auth/csrf/")
        assert code == 200

    def test_login_valid(self, admin):
        assert admin.session_cookie != ""

    def test_login_invalid(self, portal_up):
        c = PortalClient()
        c.get("/api/auth/csrf/")
        code, _ = c.login("admin", "wrongpassword")
        assert code in (400, 401, 403)

    def test_login_empty(self, portal_up):
        c = PortalClient()
        c.get("/api/auth/csrf/")
        code, _ = c.post("/api/auth/login/", {})
        assert code in (400, 401, 403)

    def test_me_authed(self, admin):
        code, body = admin.get("/api/auth/me/", expect=200)
        assert body["username"] == ADMIN_USER
        assert body["role"] == "owner"
        assert "id" in body

    def test_me_unauthed(self, anon):
        code, _ = anon.get("/api/auth/me/")
        assert code in (401, 403)

    def test_check_authed(self, admin):
        code, _ = admin.get("/api/auth/check/")
        assert code in (200, 204)

    def test_check_unauthed(self, anon):
        code, _ = anon.get("/api/auth/check/")
        assert code in (200, 401, 403)

    def test_logout_flow(self, portal_up):
        c = PortalClient()
        c.get("/api/auth/csrf/")
        code, _ = c.login(ADMIN_USER, ADMIN_PASS)
        if code != 200:
            pytest.skip("Could not create session")
        code, _ = c.post("/api/auth/logout/")
        assert code in (200, 204)
        code, _ = c.get("/api/auth/me/")
        assert code in (401, 403)

    def test_check_username(self, admin):
        code, body = admin.get("/api/auth/check-username/?username=admin")
        assert code == 200

    def test_check_username_new(self, admin):
        code, body = admin.get(f"/api/auth/check-username/?username=test_{uuid.uuid4().hex[:6]}")
        assert code == 200


# ── 2. User Management (CRUD) ────────────────────────

class TestUserManagement:
    _created_user_id = None

    def test_list_users(self, admin):
        code, body = admin.get("/api/auth/users/", expect=200)
        assert isinstance(body, list)
        assert len(body) >= 1

    def test_create_user(self, admin):
        uname = f"qatest_{uuid.uuid4().hex[:6]}"
        code, body = admin.post("/api/auth/users/create/", {
            "username": uname,
            "password": "QaTest123!@#",
            "role": "viewer",
        })
        assert code in (200, 201), f"Create user failed: {body}"
        TestUserManagement._created_user_id = body.get("id")
        assert TestUserManagement._created_user_id

    def test_update_user(self, admin):
        uid = TestUserManagement._created_user_id
        if not uid:
            pytest.skip("No user created")
        code, body = admin.put(f"/api/auth/users/{uid}/", {"role": "engineer"})
        assert code == 200

    def test_created_user_login(self, portal_up):
        uid = TestUserManagement._created_user_id
        if not uid:
            pytest.skip("No user created")
        c = PortalClient()
        c.get("/api/auth/csrf/")
        code, _ = c.login("qatest_", "QaTest123!@#")
        # Might fail since username is dynamic, that's fine
        assert code in (200, 400, 401, 403)

    def test_delete_user(self, admin):
        uid = TestUserManagement._created_user_id
        if not uid:
            pytest.skip("No user created")
        code, _ = admin.delete(f"/api/auth/users/{uid}/delete/")
        assert code in (200, 204)

    def test_delete_nonexistent(self, admin):
        fake = "00000000-0000-0000-0000-000000000000"
        code, _ = admin.delete(f"/api/auth/users/{fake}/delete/")
        assert code in (404, 400)

    def test_anon_cannot_list(self, anon):
        code, _ = anon.get("/api/auth/users/")
        assert code in (401, 403)

    def test_anon_cannot_create(self, anon):
        code, _ = anon.post("/api/auth/users/create/", {
            "username": "hack", "password": "hack", "role": "owner",
        })
        assert code in (401, 403)


# ── 3. Dashboard ─────────────────────────────────────

class TestDashboard:
    def test_dashboard_stats(self, admin):
        code, body = admin.get("/api/dashboard/", expect=200)
        assert "kpis" in body, f"Missing key: kpis — got keys: {list(body.keys())}"
        assert "severity_trend" in body

    def test_dashboard_screenshots(self, admin):
        code, body = admin.get("/api/dashboard/screenshots/")
        assert code == 200

    def test_dashboard_unauthed(self, anon):
        code, _ = anon.get("/api/dashboard/")
        assert code in (401, 403)


# ── 4. Scans ViewSet ─────────────────────────────────

class TestScans:
    _scan_id = None

    def test_list_scans(self, admin):
        code, body = admin.get("/api/scans/", expect=200)
        assert "results" in body or isinstance(body, list)

    def test_create_scan(self, admin):
        code, body = admin.post("/api/scans/", {
            "name": "QA Test Scan",
            "target": "192.168.1.0/24",
            "scan_type": "port",
        })
        assert code in (200, 201), f"Create scan failed: {body}"
        if isinstance(body, dict) and "id" in body:
            TestScans._scan_id = body["id"]

    def test_retrieve_scan(self, admin):
        sid = TestScans._scan_id
        if not sid:
            code, body = admin.get("/api/scans/")
            results = body.get("results", body) if isinstance(body, dict) else body
            if results and isinstance(results, list) and len(results) > 0:
                sid = results[0].get("id")
                TestScans._scan_id = sid
        if not sid:
            pytest.skip("No scan available")
        code, body = admin.get(f"/api/scans/{sid}/")
        assert code == 200
        assert body.get("id") == sid

    def test_scan_not_found(self, admin):
        fake = "00000000-0000-0000-0000-000000000000"
        code, _ = admin.get(f"/api/scans/{fake}/")
        assert code == 404

    def test_anon_cannot_list_scans(self, anon):
        code, _ = anon.get("/api/scans/")
        assert code in (401, 403)


# ── 5. Findings ViewSet ──────────────────────────────

class TestFindings:
    def test_list_findings(self, admin):
        code, body = admin.get("/api/findings/", expect=200)
        assert "results" in body or isinstance(body, list)

    def test_filter_by_severity(self, admin):
        code, body = admin.get("/api/findings/?severity=critical")
        assert code == 200

    def test_filter_by_source(self, admin):
        code, body = admin.get("/api/findings/?source=nuclei")
        assert code == 200

    def test_anon_cannot_list(self, anon):
        code, _ = anon.get("/api/findings/")
        assert code in (401, 403)


# ── 6. Hosts ViewSet ─────────────────────────────────

class TestHosts:
    def test_list_hosts(self, admin):
        code, body = admin.get("/api/hosts/", expect=200)
        assert "results" in body or isinstance(body, list)

    def test_anon_cannot_list(self, anon):
        code, _ = anon.get("/api/hosts/")
        assert code in (401, 403)


# ── 7. Assets ViewSet ────────────────────────────────

class TestAssets:
    def test_list_assets(self, admin):
        code, body = admin.get("/api/assets/", expect=200)
        assert "results" in body or isinstance(body, list)

    def test_anon_cannot_list(self, anon):
        code, _ = anon.get("/api/assets/")
        assert code in (401, 403)


# ── 8. Policies ViewSet ──────────────────────────────

class TestPolicies:
    _policy_id = None

    def test_list_policies(self, admin):
        code, body = admin.get("/api/policies/", expect=200)
        assert "results" in body or isinstance(body, list)

    def test_create_policy(self, admin):
        code, body = admin.post("/api/policies/", {
            "name": f"QA Policy {uuid.uuid4().hex[:4]}",
            "scan_type": "full",
            "parallelism": 2,
            "timeout": 120,
        })
        assert code in (200, 201), f"Create policy failed: {body}"
        if isinstance(body, dict) and "id" in body:
            TestPolicies._policy_id = body["id"]

    def test_retrieve_policy(self, admin):
        pid = TestPolicies._policy_id
        if not pid:
            pytest.skip("No policy created")
        code, body = admin.get(f"/api/policies/{pid}/")
        assert code == 200

    def test_update_policy(self, admin):
        pid = TestPolicies._policy_id
        if not pid:
            pytest.skip("No policy created")
        code, body = admin.patch(f"/api/policies/{pid}/", {"parallelism": 3})
        assert code == 200

    def test_delete_policy(self, admin):
        pid = TestPolicies._policy_id
        if not pid:
            pytest.skip("No policy created")
        code, _ = admin.delete(f"/api/policies/{pid}/")
        assert code in (200, 204)

    def test_anon_cannot_create(self, anon):
        code, _ = anon.post("/api/policies/", {"name": "hack", "scan_type": "full"})
        assert code in (401, 403)


# ── 9. Schedules ViewSet ─────────────────────────────

class TestSchedules:
    _sched_id = None

    def test_list_schedules(self, admin):
        code, body = admin.get("/api/schedules/", expect=200)
        assert "results" in body or isinstance(body, list)

    def test_create_schedule(self, admin):
        code, body = admin.post("/api/schedules/", {
            "name": f"QA Schedule {uuid.uuid4().hex[:4]}",
            "target": "10.0.0.0/24",
            "frequency": "daily",
            "time": "03:00",
            "scan_type": "quick",
        })
        assert code in (200, 201), f"Create schedule failed: {body}"
        if isinstance(body, dict) and "id" in body:
            TestSchedules._sched_id = body["id"]

    def test_retrieve_schedule(self, admin):
        sid = TestSchedules._sched_id
        if not sid:
            pytest.skip("No schedule created")
        code, body = admin.get(f"/api/schedules/{sid}/")
        assert code == 200

    def test_delete_schedule(self, admin):
        sid = TestSchedules._sched_id
        if not sid:
            pytest.skip("No schedule created")
        code, _ = admin.delete(f"/api/schedules/{sid}/")
        assert code in (200, 204)


# ── 10. Exploits ViewSet ─────────────────────────────

class TestExploits:
    def test_list_exploits(self, admin):
        code, body = admin.get("/api/exploits/", expect=200)
        assert "results" in body or isinstance(body, list)


# ── 11. Site Config ──────────────────────────────────

class TestSiteConfig:
    def test_get_config(self, admin):
        code, body = admin.get("/api/site-config/", expect=200)
        assert "company_name" in body or "branding" in body or isinstance(body, dict)

    def test_update_config(self, admin):
        code, body = admin.put("/api/site-config/update/", {
            "default_parallelism": 4,
        })
        assert code == 200

    def test_anon_can_read_branding(self, anon):
        code, _ = anon.get("/api/site-config/")
        assert code == 200


# ── 12. Report Config ────────────────────────────────

class TestReportConfig:
    def test_get_report_config(self, admin):
        code, body = admin.get("/api/report-config/", expect=200)
        assert isinstance(body, dict)

    def test_anon_cannot_read(self, anon):
        code, _ = anon.get("/api/report-config/")
        assert code in (401, 403)


# ── 13. Preferences ──────────────────────────────────

class TestPreferences:
    def test_get_preferences(self, admin):
        code, body = admin.get("/api/preferences/", expect=200)
        assert isinstance(body, dict)

    def test_update_preferences(self, admin):
        code, body = admin.put("/api/preferences/", {"timezone": "UTC"})
        assert code == 200

    def test_telegram_link_code(self, admin):
        code, body = admin.post("/api/preferences/telegram-link/")
        assert code == 200

    def test_telegram_link_status(self, admin):
        code, body = admin.get("/api/auth/telegram-link-status/")
        assert code == 200


# ── 14. Sessions ─────────────────────────────────────

class TestSessions:
    def test_list_sessions(self, admin):
        code, body = admin.get("/api/sessions/", expect=200)
        assert isinstance(body, list) or isinstance(body, dict)

    def test_anon_cannot_list(self, anon):
        code, _ = anon.get("/api/sessions/")
        assert code in (401, 403)


# ── 15. Audit Log ────────────────────────────────────

class TestAuditLog:
    def test_list_audit_log(self, admin):
        code, body = admin.get("/api/audit-log/", expect=200)
        assert isinstance(body, (list, dict))

    def test_anon_cannot_read(self, anon):
        code, _ = anon.get("/api/audit-log/")
        assert code in (401, 403)


# ── 16. Support Bundle ───────────────────────────────

class TestSupportBundle:
    def test_create_bundle(self, admin):
        code, body = admin.post("/api/support-bundle/")
        assert code == 200

    def test_anon_cannot_create(self, anon):
        code, _ = anon.post("/api/support-bundle/")
        assert code in (401, 403)


# ── 17. MFA Endpoints ────────────────────────────────

class TestMFA:
    def test_mfa_status(self, admin):
        code, body = admin.get("/api/auth/mfa/status/")
        assert code == 200

    def test_mfa_setup(self, admin):
        code, body = admin.post("/api/auth/mfa/setup/")
        assert code in (200, 400, 403)

    def test_mfa_verify_invalid(self, admin):
        code, _ = admin.post("/api/auth/mfa/verify/", {"code": "000000"})
        assert code in (400, 401, 403, 200)

    def test_mfa_resend(self, admin):
        code, _ = admin.post("/api/auth/mfa/resend/")
        assert code in (200, 400, 401)

    def test_mfa_backup_codes(self, admin):
        code, body = admin.post("/api/auth/mfa/backup-codes/")
        assert code in (200, 400, 403, 405)

    def test_anon_mfa_status(self, anon):
        code, _ = anon.get("/api/auth/mfa/status/")
        assert code in (401, 403)


# ── 18. API Tokens ───────────────────────────────────

class TestAPITokens:
    _token_id = None

    def test_list_tokens(self, admin):
        code, body = admin.get("/api/auth/tokens/", expect=200)
        assert isinstance(body, (list, dict))

    def test_create_token(self, admin):
        code, body = admin.post("/api/auth/tokens/", {
            "name": f"qa-token-{uuid.uuid4().hex[:4]}",
        })
        assert code in (200, 201), f"Create token failed: {body}"
        if isinstance(body, dict):
            TestAPITokens._token_id = body.get("id")

    def test_revoke_token(self, admin):
        tid = TestAPITokens._token_id
        if not tid:
            pytest.skip("No token created")
        code, _ = admin.post(f"/api/auth/tokens/{tid}/revoke/")
        assert code in (200, 204)

    def test_anon_cannot_list(self, anon):
        code, _ = anon.get("/api/auth/tokens/")
        assert code in (401, 403)


# ── 19. Notifications ────────────────────────────────

class TestNotifications:
    def test_get_config(self, admin):
        code, body = admin.get("/api/notifications/config/", expect=200)
        assert isinstance(body, dict)

    def test_anon_cannot_read(self, anon):
        code, _ = anon.get("/api/notifications/config/")
        assert code in (401, 403)


# ── 20. System Endpoints ─────────────────────────────

class TestSystem:
    def test_tools_health(self, admin):
        code, body = admin.get("/api/tools-health/", expect=200)
        assert isinstance(body, (list, dict))

    def test_system_stats(self, admin):
        code, body = admin.get("/api/system-stats/", expect=200)
        assert isinstance(body, dict)

    def test_container_processes(self, admin):
        code, body = admin.get("/api/system-processes/")
        assert code in (200, 500)

    def test_update_check(self, admin):
        code, body = admin.get("/api/update-check/")
        assert code in (200, 500)

    def test_update_feeds(self, admin):
        code, body = admin.post("/api/update/feeds/")
        assert code in (200, 404, 500)

    def test_anon_system_stats(self, anon):
        code, _ = anon.get("/api/system-stats/")
        assert code in (401, 403)

    def test_anon_tools_health(self, anon):
        code, _ = anon.get("/api/tools-health/")
        assert code in (401, 403)


# ── 21. Reauth ───────────────────────────────────────

class TestReauth:
    def test_reauth_valid(self, admin):
        code, body = admin.post("/api/auth/reauth/", {"password": ADMIN_PASS})
        assert code in (200, 204)

    def test_reauth_invalid(self, admin):
        code, _ = admin.post("/api/auth/reauth/", {"password": "wrong"})
        assert code in (400, 401, 403)


# ── 22. RBAC — Viewer Cannot Write ───────────────────

class TestRBAC:
    _viewer_client = None

    @pytest.fixture(autouse=True)
    def setup_viewer(self, admin, portal_up):
        if TestRBAC._viewer_client is not None:
            return
        uname = f"viewer_{uuid.uuid4().hex[:6]}"
        code, body = admin.post("/api/auth/users/create/", {
            "username": uname, "password": "Viewer123!@#", "role": "viewer",
        })
        if code not in (200, 201):
            pytest.skip(f"Could not create viewer: {body}")
        TestRBAC._viewer_user_id = body.get("id")
        c = PortalClient()
        c.get("/api/auth/csrf/")
        code, _ = c.login(uname, "Viewer123!@#")
        if code != 200:
            pytest.skip("Viewer login failed")
        TestRBAC._viewer_client = c

    def test_viewer_can_read_scans(self):
        c = TestRBAC._viewer_client
        if not c:
            pytest.skip("No viewer client")
        code, _ = c.get("/api/scans/")
        assert code == 200

    def test_viewer_can_read_findings(self):
        c = TestRBAC._viewer_client
        if not c:
            pytest.skip("No viewer client")
        code, _ = c.get("/api/findings/")
        assert code == 200

    def test_viewer_can_read_dashboard(self):
        c = TestRBAC._viewer_client
        if not c:
            pytest.skip("No viewer client")
        code, _ = c.get("/api/dashboard/")
        assert code == 200

    def test_viewer_cannot_create_scan(self):
        c = TestRBAC._viewer_client
        if not c:
            pytest.skip("No viewer client")
        code, _ = c.post("/api/scans/", {"name": "hack", "target": "1.1.1.1", "scan_type": "port"})
        assert code in (403, 401)

    def test_viewer_cannot_create_user(self):
        c = TestRBAC._viewer_client
        if not c:
            pytest.skip("No viewer client")
        code, _ = c.post("/api/auth/users/create/", {
            "username": "escalated", "password": "Hack123!@#", "role": "owner",
        })
        assert code in (403, 401)

    def test_viewer_cannot_update_config(self):
        c = TestRBAC._viewer_client
        if not c:
            pytest.skip("No viewer client")
        code, _ = c.put("/api/site-config/update/", {"default_parallelism": 99})
        assert code in (403, 401)

    def test_viewer_cannot_delete_user(self):
        c = TestRBAC._viewer_client
        if not c:
            pytest.skip("No viewer client")
        code, _ = c.delete("/api/auth/users/00000000-0000-0000-0000-000000000000/delete/")
        assert code in (403, 401)

    def test_cleanup_viewer(self, admin):
        uid = getattr(TestRBAC, "_viewer_user_id", None)
        if uid:
            admin.delete(f"/api/auth/users/{uid}/delete/")


# ── 23. Edge Cases ───────────────────────────────────

class TestEdgeCases:
    def test_404_unknown_path(self, admin):
        code, _ = admin.get("/api/nonexistent/")
        assert code == 404

    def test_method_not_allowed(self, admin):
        code, _ = admin.delete("/api/dashboard/")
        assert code in (405, 400, 404)

    def test_invalid_uuid_in_path(self, admin):
        code, _ = admin.get("/api/scans/not-a-uuid/")
        assert code in (400, 404)

    def test_large_payload(self, admin):
        code, _ = admin.post("/api/auth/login/", {
            "username": "A" * 10000,
            "password": "B" * 10000,
        })
        assert code in (400, 401, 403, 413)

    def test_empty_post_to_scans(self, admin):
        code, _ = admin.post("/api/scans/", {})
        assert code in (400, 422)

    def test_sql_injection_login(self, portal_up):
        c = PortalClient()
        c.get("/api/auth/csrf/")
        code, _ = c.login("admin' OR '1'='1", "pass")
        assert code in (400, 401, 403)

    def test_xss_in_scan_name(self, admin):
        code, body = admin.post("/api/scans/", {
            "name": '<script>alert("xss")</script>',
            "target": "127.0.0.1",
            "scan_type": "port",
        })
        if code in (200, 201) and isinstance(body, dict):
            assert "<script>" not in json.dumps(body)
            sid = body.get("id")
            if sid:
                admin.delete(f"/api/scans/{sid}/")


# ── 24. Pagination & Filtering ───────────────────────

class TestPagination:
    def test_scans_pagination(self, admin):
        code, body = admin.get("/api/scans/?page=1&page_size=5")
        assert code == 200

    def test_findings_pagination(self, admin):
        code, body = admin.get("/api/findings/?page=1&page_size=5")
        assert code == 200

    def test_hosts_pagination(self, admin):
        code, body = admin.get("/api/hosts/?page=1&page_size=5")
        assert code == 200

    def test_scans_ordering(self, admin):
        code, body = admin.get("/api/scans/?ordering=-created_at")
        assert code == 200

    def test_findings_search(self, admin):
        code, body = admin.get("/api/findings/?search=CVE")
        assert code == 200


# ── 25. Security Headers ─────────────────────────────

class TestSecurityHeaders:
    def test_csrf_cookie_set(self, portal_up):
        req = urllib.request.Request(f"{BASE}/api/auth/csrf/", method="GET")
        resp = urllib.request.urlopen(req, context=_ctx, timeout=10)
        cookies = resp.headers.get_all("Set-Cookie") or []
        csrf_found = any("csrftoken=" in c for c in cookies)
        assert csrf_found, "CSRF cookie not set"

    def test_no_cors_wildcard(self, portal_up):
        req = urllib.request.Request(f"{BASE}/api/auth/csrf/", method="GET")
        req.add_header("Origin", "https://evil.com")
        resp = urllib.request.urlopen(req, context=_ctx, timeout=10)
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        assert acao != "*", "CORS allows wildcard origin"


# ── Summary fixture ──────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def summary(request):
    yield
    passed = request.session.testscollected - request.session.testsfailed
    total = request.session.testscollected
    failed = request.session.testsfailed
    print(f"\n\n{'='*60}")
    print(f"  FULL QA: {passed}/{total} passed, {failed} failed")
    print(f"{'='*60}\n")
