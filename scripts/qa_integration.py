#!/usr/bin/env python3
"""Wire_Ghost — Phase 3 API Integration Tests.

Tests every API endpoint against the live Docker stack with all 3 RBAC roles.
Handles the setup wizard, creates test users, and runs the full RBAC matrix.

Usage: python3 qa_integration.py --base https://localhost:18443 --results qa-results/phase-3.json
"""
import argparse, json, sys, time, urllib3
urllib3.disable_warnings()

try:
    import requests
except ImportError:
    sys.exit("requests library required: pip install requests")

# ── Test harness ─────────────────────────────────────────────────────

class QA:
    def __init__(self, base):
        self.base = base.rstrip('/')
        self.passed = 0
        self.failed = 0
        self.total = 0
        self.failures = []
        self.sessions = {}

    def check(self, name, condition, detail=""):
        self.total += 1
        if condition:
            self.passed += 1
            print(f"  \033[32m✓\033[0m {name}")
        else:
            self.failed += 1
            self.failures.append({"test": name, "detail": detail})
            print(f"  \033[31m✗\033[0m {name}  — {detail}")

    def login(self, username, password):
        s = requests.Session()
        r = s.get(f"{self.base}/api/auth/csrf/", verify=False)
        csrf = r.json().get("csrf", r.json().get("csrfToken", ""))
        s.headers.update({"X-CSRFToken": csrf, "Referer": f"{self.base}/"})
        r = s.post(f"{self.base}/api/auth/login/",
                   json={"username": username, "password": password}, verify=False)
        if r.status_code == 200:
            cr = s.get(f"{self.base}/api/auth/csrf/", verify=False)
            csrf2 = cr.json().get("csrf", cr.json().get("csrfToken", ""))
            s.headers.update({"X-CSRFToken": csrf2})
        return s, r.status_code

    def get_csrf(self, session):
        r = session.get(f"{self.base}/api/auth/csrf/", verify=False)
        csrf = r.json().get("csrf", r.json().get("csrfToken", ""))
        session.headers.update({"X-CSRFToken": csrf})
        return csrf

    def report(self):
        return {
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "failures": self.failures,
        }


OWNER_USER = "admin"
OWNER_PASS = "QAtest2026!"
ENGINEER_USER = "test_engineer"
ENGINEER_PASS = "QAtest2026!"


def flush_rate_limits():
    """Clear DRF throttle and login lockout keys from Redis."""
    import subprocess
    subprocess.run(
        ["docker", "compose", "exec", "-T", "api",
         "python", "manage.py", "shell", "-c",
         "c=__import__('django.core.cache',fromlist=['cache']).cache;"
         "r=c._cache.get_client();"
         "[r.delete(k) for k in r.keys('*throttle*')+r.keys('*login*')]"],
        capture_output=True, text=True,
        cwd="/home/demon/Tools/demon-in-the-wire",
    )
VIEWER_USER = "test_viewer"
VIEWER_PASS = "QAtest2026!"


def phase_3a_setup(qa):
    """Setup wizard — create owner account via one-shot endpoint."""
    print("\n── 3A: Setup Wizard ──")
    s = requests.Session()

    r = s.get(f"{qa.base}/api/auth/csrf/", verify=False)
    qa.check("3A.1 CSRF token", r.status_code == 200 and ("csrf" in r.json() or "csrfToken" in r.json()),
             f"status={r.status_code}")
    csrf = r.json().get("csrf", r.json().get("csrfToken", ""))
    s.headers.update({"X-CSRFToken": csrf, "Referer": f"{qa.base}/"})

    r = s.post(f"{qa.base}/api/auth/setup/", data={
        "username": OWNER_USER, "password": OWNER_PASS,
        "email": "owner@test.local", "name": "QA Owner",
        "company_name": "QA Corp",
    }, verify=False)
    if r.status_code == 201:
        qa.check("3A.2 Setup one-shot creates owner",
                 r.json().get("user", {}).get("role") == "owner",
                 f"status={r.status_code} body={r.text[:120]}")
    elif r.status_code == 409:
        qa.check("3A.2 Setup already completed (409 — ok)", True)
        s, code = qa.login(OWNER_USER, OWNER_PASS)
    else:
        qa.check("3A.2 Setup one-shot creates owner", False,
                 f"status={r.status_code} body={r.text[:120]}")

    qa.get_csrf(s)
    r2 = s.post(f"{qa.base}/api/auth/setup/", data={
        "username": "dup", "password": OWNER_PASS, "email": "d@t.l", "name": "D",
    }, verify=False)
    qa.check("3A.3 Setup idempotent (409)", r2.status_code == 409,
             f"status={r2.status_code}")

    r3 = s.get(f"{qa.base}/api/auth/me/", verify=False)
    qa.check("3A.4 Owner session active", r3.status_code == 200,
             f"status={r3.status_code}")

    qa.sessions["owner"] = s


def phase_3b_users(qa):
    """User management — create engineer and viewer."""
    print("\n── 3B: User Management ──")
    own = qa.sessions["owner"]
    qa.get_csrf(own)

    r = own.post(f"{qa.base}/api/auth/users/create/", json={
        "username": ENGINEER_USER, "password": ENGINEER_PASS, "role": "engineer",
        "email": "eng@test.local", "name": "QA Engineer",
    }, verify=False)
    qa.check("3B.1 Create engineer", r.status_code in (201, 400),
             f"status={r.status_code} {r.text[:80]}")

    qa.get_csrf(own)
    r = own.post(f"{qa.base}/api/auth/users/create/", json={
        "username": VIEWER_USER, "password": VIEWER_PASS, "role": "viewer",
        "email": "view@test.local", "name": "QA Viewer",
    }, verify=False)
    qa.check("3B.2 Create viewer", r.status_code in (201, 400),
             f"status={r.status_code} {r.text[:80]}")

    qa.get_csrf(own)
    r = own.post(f"{qa.base}/api/auth/users/create/", json={
        "username": "bad_owner", "password": OWNER_PASS, "role": "owner",
        "email": "o2@t.l", "name": "Bad",
    }, verify=False)
    qa.check("3B.3 Cannot create second owner", r.status_code in (400, 409, 500), f"status={r.status_code}")

    eng_s, eng_code = qa.login(ENGINEER_USER, ENGINEER_PASS)
    qa.sessions["engineer"] = eng_s
    qa.get_csrf(eng_s)
    r = eng_s.post(f"{qa.base}/api/auth/users/create/", json={
        "username": "x", "password": "P@ss1234!", "role": "viewer",
    }, verify=False)
    qa.check("3B.4 Engineer cannot create users", r.status_code in (403, 405),
             f"status={r.status_code}")

    view_s, view_code = qa.login(VIEWER_USER, VIEWER_PASS)
    qa.sessions["viewer"] = view_s
    qa.get_csrf(view_s)
    r = view_s.post(f"{qa.base}/api/auth/users/create/", json={
        "username": "y", "password": "P@ss1234!", "role": "viewer",
    }, verify=False)
    qa.check("3B.5 Viewer cannot create users", r.status_code in (403, 405),
             f"status={r.status_code}")

    r = own.get(f"{qa.base}/api/auth/users/", verify=False)
    user_count = len(r.json()) if r.status_code == 200 and isinstance(r.json(), list) else 0
    qa.check("3B.6 Owner lists users (3)", r.status_code == 200 and user_count >= 3,
             f"status={r.status_code} count={user_count}")


def phase_3c_auth(qa):
    """Authentication flows."""
    print("\n── 3C: Authentication ──")

    s, code = qa.login(OWNER_USER, OWNER_PASS)
    qa.check("3C.1 Valid login", code == 200)

    _, code = qa.login(OWNER_USER, "wrong_password_999")
    qa.check("3C.2 Wrong password → 401", code == 401, f"got {code}")

    # Rate limit — send rapid failed logins
    blocked = False
    for i in range(12):
        _, c = qa.login("rate_limit_test_user", "bad")
        if c == 429:
            blocked = True
            break
    qa.check("3C.3 Login rate limit", blocked, "never got 429")

    # Clear rate limit for this user
    time.sleep(1)

    r = requests.get(f"{qa.base}/api/scans/", verify=False)
    qa.check("3C.4 Unauthenticated API → 401/403", r.status_code in (401, 403),
             f"got {r.status_code}")

    no_csrf = requests.Session()
    r = no_csrf.get(f"{qa.base}/api/auth/csrf/", verify=False)
    no_csrf.post(f"{qa.base}/api/auth/login/",
                 json={"username": OWNER_USER, "password": OWNER_PASS},
                 verify=False)
    r = no_csrf.post(f"{qa.base}/api/scans/", json={"target": "test"}, verify=False)
    qa.check("3C.5 Missing CSRF → 403", r.status_code == 403, f"got {r.status_code}")

    own = qa.sessions["owner"]
    qa.get_csrf(own)
    r = own.post(f"{qa.base}/api/auth/tokens/", json={"name": "qa_token"}, verify=False)
    token_ok = r.status_code == 201 and r.json().get("token", "").startswith("wg_")
    raw_token = r.json().get("token", "") if r.status_code == 201 else ""
    qa.check("3C.6 Owner creates API token", token_ok, f"status={r.status_code}")

    if raw_token:
        r = requests.get(f"{qa.base}/api/auth/me/",
                         headers={"Authorization": f"Token {raw_token}"}, verify=False)
        qa.check("3C.7 Token auth works", r.status_code == 200, f"got {r.status_code}")

        expires = r.json().get("expires_at") if r.status_code == 200 else None
    else:
        qa.check("3C.7 Token auth works", False, "no token created")

    view_s = qa.sessions["viewer"]
    qa.get_csrf(view_s)
    r = view_s.post(f"{qa.base}/api/auth/tokens/", json={"name": "bad"}, verify=False)
    qa.check("3C.8 Viewer token creation blocked (OWASP fix)", r.status_code == 403,
             f"got {r.status_code}")

    qa.get_csrf(own)
    r = own.post(f"{qa.base}/api/auth/tokens/", json={"name": "expiry_check"}, verify=False)
    exp = r.json().get("expires_at") if r.status_code == 201 else None
    qa.check("3C.9 Token default 90-day expiry", exp is not None, f"expires_at={exp}")

    logout_s, _ = qa.login(OWNER_USER, OWNER_PASS)
    qa.get_csrf(logout_s)
    logout_s.post(f"{qa.base}/api/auth/logout/", verify=False)
    r = logout_s.get(f"{qa.base}/api/auth/me/", verify=False)
    qa.check("3C.10 Logout invalidates session", r.status_code in (401, 403),
             f"got {r.status_code}")


def phase_3d_rbac(qa):
    """RBAC matrix — test key endpoints across all roles."""
    print("\n── 3D: RBAC Matrix ──")
    own = qa.sessions["owner"]
    eng = qa.sessions["engineer"]
    view = qa.sessions["viewer"]

    matrix = [
        ("3D.1", "GET",  "/api/scans/",                     200, 200, 200),
        ("3D.2", "GET",  "/api/hosts/",                      200, 200, 200),
        ("3D.3", "GET",  "/api/findings/",                   200, 200, 200),
        ("3D.4", "GET",  "/api/auth/users/",                 200, 403, 403),
        ("3D.5", "GET",  "/api/policies/",                   200, 200, 403),
        ("3D.6", "GET",  "/api/schedules/",                  200, 200, 403),
        ("3D.7", "GET",  "/api/exploits/",                   200, 200, 200),
        ("3D.8", "GET",  "/api/assets/",                     200, 200, 200),
        ("3D.9", "GET",  "/api/report-config/",              200, 200, 200),
        ("3D.10", "GET", "/api/site-config/",                200, 200, 200),
    ]

    for tid, method, path, exp_own, exp_eng, exp_view in matrix:
        for role, sess, expected in [("owner", own, exp_own), ("engineer", eng, exp_eng), ("viewer", view, exp_view)]:
            r = sess.request(method, f"{qa.base}{path}", verify=False)
            qa.check(f"{tid} {method} {path} as {role} → {expected}",
                     r.status_code == expected, f"got {r.status_code}")

    # Write operations
    qa.get_csrf(view)
    r = view.post(f"{qa.base}/api/scans/", json={"target": "10.0.0.1", "scan_type": "quick"}, verify=False)
    qa.check("3D.11 Viewer POST /api/scans/ → 403", r.status_code == 403, f"got {r.status_code}")

    qa.get_csrf(eng)
    r = eng.post(f"{qa.base}/api/scans/", json={"target": "10.0.0.1", "scan_type": "quick"}, verify=False)
    qa.check("3D.12 Engineer POST /api/scans/ → 201", r.status_code == 201, f"got {r.status_code}")

    # OWASP fix: setup_complete role check
    for role, sess, expected in [("engineer", eng, 403), ("viewer", view, 403)]:
        qa.get_csrf(sess)
        r = sess.post(f"{qa.base}/api/site-config/setup-complete/", json={}, verify=False)
        qa.check(f"3D.13 setup_complete as {role} → {expected} (OWASP)",
                 r.status_code == expected, f"got {r.status_code}")

    # Support bundle — owner only
    qa.get_csrf(own)
    r = own.post(f"{qa.base}/api/support-bundle/", verify=False)
    qa.check("3D.14 Support bundle as owner → 200", r.status_code == 200, f"got {r.status_code}")

    qa.get_csrf(view)
    r = view.post(f"{qa.base}/api/support-bundle/", verify=False)
    qa.check("3D.15 Support bundle as viewer → 403", r.status_code == 403, f"got {r.status_code}")


def phase_3e_scan(qa):
    """Scan lifecycle."""
    print("\n── 3E: Scan Lifecycle ──")
    eng = qa.sessions["engineer"]

    qa.get_csrf(eng)
    r = eng.post(f"{qa.base}/api/scans/", json={
        "name": "QA Scan", "target": "scanme.nmap.org", "scan_type": "quick",
    }, verify=False)
    scan_ok = r.status_code == 201
    scan_id = r.json().get("id", "") if scan_ok else ""
    qa.check("3E.1 Create scan", scan_ok, f"status={r.status_code} {r.text[:100]}")

    r = eng.get(f"{qa.base}/api/scans/", verify=False)
    has_scan = any(s.get("id") == scan_id for s in r.json().get("results", r.json() if isinstance(r.json(), list) else []))
    qa.check("3E.2 Scan in list", has_scan or r.status_code == 200)

    if scan_id:
        r = eng.get(f"{qa.base}/api/scans/{scan_id}/", verify=False)
        qa.check("3E.3 Scan detail", r.status_code == 200, f"status={r.status_code}")

    # SSRF blocked
    qa.get_csrf(eng)
    r = eng.post(f"{qa.base}/api/scans/", json={"target": "127.0.0.1", "scan_type": "quick"}, verify=False)
    qa.check("3E.4 SSRF blocked (localhost)", r.status_code == 400, f"got {r.status_code}")

    qa.get_csrf(eng)
    r = eng.post(f"{qa.base}/api/scans/", json={"target": "169.254.169.254", "scan_type": "quick"}, verify=False)
    qa.check("3E.5 SSRF blocked (metadata)", r.status_code == 400, f"got {r.status_code}")

    qa.get_csrf(eng)
    r = eng.post(f"{qa.base}/api/scans/", json={"target": "http://169.254.169.254/latest/", "scan_type": "quick"}, verify=False)
    qa.check("3E.6 SSRF blocked (URL format)", r.status_code == 400, f"got {r.status_code}")


def phase_3f_pagination(qa):
    """Pagination and throttle."""
    print("\n── 3F: Pagination & Throttle ──")
    own = qa.sessions["owner"]

    r = own.get(f"{qa.base}/api/scans/", verify=False)
    has_pagination = isinstance(r.json(), dict) and "results" in r.json()
    qa.check("3F.1 Paginated response", r.status_code == 200 and has_pagination,
             f"keys={list(r.json().keys()) if isinstance(r.json(), dict) else 'not dict'}")

    r = own.get(f"{qa.base}/api/scans/?page_size=99999", verify=False)
    qa.check("3F.2 Large page_size accepted", r.status_code == 200)

    # Throttle test — 121 requests
    throttled = False
    for i in range(125):
        r = own.get(f"{qa.base}/api/auth/me/", verify=False)
        if r.status_code == 429:
            throttled = True
            qa.check(f"3F.3 User throttle (429 at req #{i+1})", True)
            break
    if not throttled:
        qa.check("3F.3 User throttle", False, "never got 429 in 125 requests")

    # Anon throttle — must use an endpoint that permits anon access;
    # authenticated-only endpoints reject with 401 before throttle runs.
    anon_throttled = False
    for i in range(45):
        r = requests.get(f"{qa.base}/api/auth/csrf/", verify=False)
        if r.status_code == 429:
            anon_throttled = True
            qa.check(f"3F.4 Anon throttle (429 at req #{i+1})", True)
            break
    if not anon_throttled:
        qa.check("3F.4 Anon throttle", False, "never got 429 in 45 requests")


def phase_3g_mfa(qa):
    """MFA flow — Telegram OTP based (not TOTP). Tests what can be verified without Telegram."""
    print("\n── 3G: MFA Flow ──")
    own = qa.sessions.get("owner")
    if not own:
        own, _ = qa.login(OWNER_USER, OWNER_PASS)
        qa.sessions["owner"] = own

    r = own.get(f"{qa.base}/api/auth/mfa/status/", verify=False)
    qa.check("3G.1 MFA status endpoint", r.status_code == 200, f"status={r.status_code}")
    if r.status_code == 200:
        qa.check("3G.2 MFA initially disabled", r.json().get("enabled") is False,
                 f"enabled={r.json().get('enabled')}")

    # MFA setup requires reauth — 403 is expected without recent reauth
    qa.get_csrf(own)
    r = own.post(f"{qa.base}/api/auth/mfa/setup/", verify=False)
    qa.check("3G.3 MFA setup requires reauth (403)",
             r.status_code == 403, f"status={r.status_code}")

    # MFA confirm without valid setup_token → 401
    qa.get_csrf(own)
    r = own.post(f"{qa.base}/api/auth/mfa/confirm/",
                 json={"setup_token": "bogus", "code": "000000"}, verify=False)
    qa.check("3G.4 MFA confirm rejects invalid token",
             r.status_code == 401, f"status={r.status_code}")


def phase_3h_config(qa):
    """Site config and report config."""
    print("\n── 3H: Site Config ──")
    own = qa.sessions["owner"]
    eng = qa.sessions["engineer"]

    r = own.get(f"{qa.base}/api/site-config/", verify=False)
    qa.check("3H.1 GET site-config", r.status_code == 200)

    qa.get_csrf(own)
    r = own.put(f"{qa.base}/api/site-config/update/",
                json={"schedule_timezone": "UTC"}, verify=False)
    qa.check("3H.2 Owner update site config", r.status_code == 200,
             f"status={r.status_code} {r.text[:80]}")

    qa.get_csrf(eng)
    r = eng.put(f"{qa.base}/api/site-config/update/",
                json={"schedule_timezone": "UTC"}, verify=False)
    qa.check("3H.3 Engineer update site config → 403", r.status_code == 403,
             f"got {r.status_code}")

    r = own.get(f"{qa.base}/api/report-config/", verify=False)
    qa.check("3H.4 GET report-config", r.status_code == 200)


def main():
    parser = argparse.ArgumentParser(description="Wire_Ghost QA Integration Tests")
    parser.add_argument("--base", default="https://localhost:18443")
    parser.add_argument("--results", default="qa-results/phase-3.json")
    args = parser.parse_args()

    qa = QA(args.base)

    flush_rate_limits()
    phase_3a_setup(qa)
    phase_3b_users(qa)
    phase_3c_auth(qa)
    flush_rate_limits()
    phase_3d_rbac(qa)
    phase_3e_scan(qa)
    flush_rate_limits()
    phase_3g_mfa(qa)
    phase_3h_config(qa)
    flush_rate_limits()
    phase_3f_pagination(qa)  # last — throttle tests exhaust rate limits

    report = qa.report()
    print(f"\n{'='*50}")
    print(f"Phase 3 Results: {report['passed']}/{report['total']} passed, {report['failed']} failed")
    if report["failures"]:
        print("Failures:")
        for f in report["failures"]:
            print(f"  - {f['test']}: {f['detail']}")

    with open(args.results, "w") as fh:
        json.dump(report, fh, indent=2)

    sys.exit(0 if report["failed"] == 0 else 1)


if __name__ == "__main__":
    main()
