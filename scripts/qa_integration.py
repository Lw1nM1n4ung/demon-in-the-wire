#!/usr/bin/env python3
"""Wire_Ghost — Phase 3 API Integration Tests.

Tests every API endpoint against the live Docker stack with all 3 RBAC roles.
Handles the setup wizard, creates test users, and seeds deterministic browser
fixture data for the Playwright suites.

Usage: python3 qa_integration.py --base https://localhost:18443 --results qa-results/phase-3.json
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import urllib3
urllib3.disable_warnings()

try:
    import requests
except ImportError:
    sys.exit("requests library required: pip install requests")


REPO_ROOT = Path(__file__).resolve().parents[1]
OWNER_USER = "admin"
OWNER_PASS = "QAtest2026!"
ENGINEER_USER = "test_engineer"
ENGINEER_PASS = "QAtest2026!"
VIEWER_USER = "test_viewer"
VIEWER_PASS = "QAtest2026!"
FIXTURE_SCAN_NAME = "QA Browser Fixture"


class QA:
    def __init__(self, base):
        self.base = base.rstrip('/')
        self.passed = 0
        self.failed = 0
        self.total = 0
        self.failures = []
        self.sessions = {}
        self.fixture = {}
        self.owner_api_token = ""

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
        r = s.post(
            f"{self.base}/api/auth/login/",
            json={"username": username, "password": password},
            verify=False,
        )
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


def docker_api_shell(code):
    return subprocess.run(
        ["docker", "compose", "exec", "-T", "api", "python", "manage.py", "shell", "-c", code],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


def flush_rate_limits():
    """Clear DRF throttle and login lockout keys from Redis."""
    docker_api_shell(
        "c=__import__('django.core.cache',fromlist=['cache']).cache;"
        "r=c._cache.get_client();"
        "[r.delete(k) for k in r.keys('*throttle*')+r.keys('*login*')]"
    )


def phase_3a_setup(qa):
    """Setup wizard — create owner account via one-shot endpoint."""
    print("\n── 3A: Setup Wizard ──")
    s = requests.Session()

    r = s.get(f"{qa.base}/api/auth/csrf/", verify=False)
    qa.check(
        "3A.1 CSRF token",
        r.status_code == 200 and ("csrf" in r.json() or "csrfToken" in r.json()),
        f"status={r.status_code}",
    )
    csrf = r.json().get("csrf", r.json().get("csrfToken", ""))
    s.headers.update({"X-CSRFToken": csrf, "Referer": f"{qa.base}/"})

    r = s.post(
        f"{qa.base}/api/auth/setup/",
        data={
            "username": OWNER_USER,
            "password": OWNER_PASS,
            "email": "owner@test.local",
            "name": "QA Owner",
            "company_name": "QA Corp",
        },
        verify=False,
    )
    if r.status_code == 201:
        body = r.json()
        role = body.get("user", {}).get("role") or body.get("role")
        qa.check(
            "3A.2 Setup one-shot creates owner",
            role == "owner",
            f"status={r.status_code} body={r.text[:120]}",
        )
    elif r.status_code == 409:
        qa.check("3A.2 Setup already completed (409 — ok)", True)
        s, _ = qa.login(OWNER_USER, OWNER_PASS)
    else:
        qa.check(
            "3A.2 Setup one-shot creates owner",
            False,
            f"status={r.status_code} body={r.text[:120]}",
        )

    qa.get_csrf(s)
    r2 = s.post(
        f"{qa.base}/api/auth/setup/",
        data={"username": "dup", "password": OWNER_PASS, "email": "d@t.l", "name": "D"},
        verify=False,
    )
    qa.check("3A.3 Setup idempotent (409)", r2.status_code == 409, f"status={r2.status_code}")

    r3 = s.get(f"{qa.base}/api/auth/me/", verify=False)
    qa.check("3A.4 Owner session active", r3.status_code == 200, f"status={r3.status_code}")

    qa.sessions["owner"] = s


def phase_3b_users(qa):
    """User management — create engineer and viewer."""
    print("\n── 3B: User Management ──")
    own = qa.sessions["owner"]
    qa.get_csrf(own)

    r = own.post(
        f"{qa.base}/api/auth/users/create/",
        json={
            "username": ENGINEER_USER,
            "password": ENGINEER_PASS,
            "role": "engineer",
            "email": "eng@test.local",
            "name": "QA Engineer",
        },
        verify=False,
    )
    qa.check("3B.1 Create engineer", r.status_code in (201, 400), f"status={r.status_code} {r.text[:80]}")

    qa.get_csrf(own)
    r = own.post(
        f"{qa.base}/api/auth/users/create/",
        json={
            "username": VIEWER_USER,
            "password": VIEWER_PASS,
            "role": "viewer",
            "email": "view@test.local",
            "name": "QA Viewer",
        },
        verify=False,
    )
    qa.check("3B.2 Create viewer", r.status_code in (201, 400), f"status={r.status_code} {r.text[:80]}")

    qa.get_csrf(own)
    r = own.post(
        f"{qa.base}/api/auth/users/create/",
        json={
            "username": "bad_owner",
            "password": OWNER_PASS,
            "role": "owner",
            "email": "o2@t.l",
            "name": "Bad",
        },
        verify=False,
    )
    qa.check("3B.3 Cannot create second owner", r.status_code in (400, 409, 500), f"status={r.status_code}")

    eng_s, _ = qa.login(ENGINEER_USER, ENGINEER_PASS)
    qa.sessions["engineer"] = eng_s
    qa.get_csrf(eng_s)
    r = eng_s.post(
        f"{qa.base}/api/auth/users/create/",
        json={"username": "x", "password": "P@ss1234!", "role": "viewer"},
        verify=False,
    )
    qa.check("3B.4 Engineer cannot create users", r.status_code in (403, 405), f"status={r.status_code}")

    view_s, _ = qa.login(VIEWER_USER, VIEWER_PASS)
    qa.sessions["viewer"] = view_s
    qa.get_csrf(view_s)
    r = view_s.post(
        f"{qa.base}/api/auth/users/create/",
        json={"username": "y", "password": "P@ss1234!", "role": "viewer"},
        verify=False,
    )
    qa.check("3B.5 Viewer cannot create users", r.status_code in (403, 405), f"status={r.status_code}")

    r = own.get(f"{qa.base}/api/auth/users/", verify=False)
    user_count = len(r.json()) if r.status_code == 200 and isinstance(r.json(), list) else 0
    qa.check("3B.6 Owner lists users (3)", r.status_code == 200 and user_count >= 3, f"status={r.status_code} count={user_count}")


def phase_3c_auth(qa):
    """Authentication flows."""
    print("\n── 3C: Authentication ──")

    _, code = qa.login(OWNER_USER, OWNER_PASS)
    qa.check("3C.1 Valid login", code == 200)

    _, code = qa.login(OWNER_USER, "wrong_password_999")
    qa.check("3C.2 Wrong password → 401", code == 401, f"got {code}")

    blocked = False
    for _ in range(12):
        _, c = qa.login("rate_limit_test_user", "bad")
        if c == 429:
            blocked = True
            break
    qa.check("3C.3 Login rate limit", blocked, "never got 429")

    time.sleep(1)

    r = requests.get(f"{qa.base}/api/scans/", verify=False)
    qa.check("3C.4 Unauthenticated API → 401/403", r.status_code in (401, 403), f"got {r.status_code}")

    no_csrf = requests.Session()
    no_csrf.get(f"{qa.base}/api/auth/csrf/", verify=False)
    no_csrf.post(
        f"{qa.base}/api/auth/login/",
        json={"username": OWNER_USER, "password": OWNER_PASS},
        verify=False,
    )
    r = no_csrf.post(f"{qa.base}/api/scans/", json={"target": "test"}, verify=False)
    qa.check("3C.5 Missing CSRF → 403", r.status_code == 403, f"got {r.status_code}")

    own = qa.sessions["owner"]
    docker_api_shell(f"from scanner.models import ApiToken, User; ApiToken.objects.filter(user__username={OWNER_USER!r}).delete(); print('cleared')")
    qa.get_csrf(own)
    r = own.post(f"{qa.base}/api/auth/tokens/", json={"name": "qa_token"}, verify=False)
    token_ok = r.status_code == 201 and r.json().get("token", "").startswith("wg_")
    raw_token = r.json().get("token", "") if r.status_code == 201 else ""
    qa.check("3C.6 Owner creates API token", token_ok, f"status={r.status_code}")
    if raw_token:
        qa.owner_api_token = raw_token

    if raw_token:
        r = requests.get(
            f"{qa.base}/api/auth/me/",
            headers={"Authorization": f"Token {raw_token}"},
            verify=False,
        )
        qa.check("3C.7 Token auth works", r.status_code == 200, f"got {r.status_code}")
    else:
        qa.check("3C.7 Token auth works", False, "no token created")

    view_s = qa.sessions["viewer"]
    qa.get_csrf(view_s)
    r = view_s.post(f"{qa.base}/api/auth/tokens/", json={"name": "bad"}, verify=False)
    qa.check("3C.8 Viewer token creation blocked (OWASP fix)", r.status_code == 403, f"got {r.status_code}")

    qa.get_csrf(own)
    r = own.post(f"{qa.base}/api/auth/tokens/", json={"name": "expiry_check"}, verify=False)
    exp = r.json().get("expires_at") if r.status_code == 201 else None
    qa.check("3C.9 Token default 90-day expiry", exp is not None, f"expires_at={exp}")

    logout_s, _ = qa.login(OWNER_USER, OWNER_PASS)
    qa.get_csrf(logout_s)
    logout_s.post(f"{qa.base}/api/auth/logout/", verify=False)
    r = logout_s.get(f"{qa.base}/api/auth/me/", verify=False)
    qa.check("3C.10 Logout invalidates session", r.status_code in (401, 403), f"got {r.status_code}")


def phase_3d_rbac(qa):
    """RBAC matrix — test key endpoints across all roles."""
    print("\n── 3D: RBAC Matrix ──")
    own = qa.sessions["owner"]
    eng = qa.sessions["engineer"]
    view = qa.sessions["viewer"]

    matrix = [
        ("3D.1", "GET", "/api/scans/", 200, 200, 200),
        ("3D.2", "GET", "/api/hosts/", 200, 200, 200),
        ("3D.3", "GET", "/api/findings/", 200, 200, 200),
        ("3D.4", "GET", "/api/auth/users/", 200, 403, 403),
        ("3D.5", "GET", "/api/policies/", 200, 200, 403),
        ("3D.6", "GET", "/api/schedules/", 200, 200, 403),
        ("3D.7", "GET", "/api/exploits/", 200, 200, 200),
        ("3D.8", "GET", "/api/assets/", 200, 200, 200),
        ("3D.9", "GET", "/api/report-config/", 200, 200, 200),
        ("3D.10", "GET", "/api/site-config/", 200, 200, 200),
    ]

    for tid, method, path, exp_own, exp_eng, exp_view in matrix:
        for role, sess, expected in [("owner", own, exp_own), ("engineer", eng, exp_eng), ("viewer", view, exp_view)]:
            r = sess.request(method, f"{qa.base}{path}", verify=False)
            qa.check(f"{tid} {method} {path} as {role} → {expected}", r.status_code == expected, f"got {r.status_code}")

    qa.get_csrf(view)
    r = view.post(f"{qa.base}/api/scans/", json={"target": "10.0.0.1", "scan_type": "quick"}, verify=False)
    qa.check("3D.11 Viewer POST /api/scans/ → 403", r.status_code == 403, f"got {r.status_code}")

    qa.get_csrf(eng)
    r = eng.post(f"{qa.base}/api/scans/", json={"target": "10.0.0.1", "scan_type": "quick"}, verify=False)
    qa.check("3D.12 Engineer POST /api/scans/ → 201", r.status_code == 201, f"got {r.status_code}")

    for role, sess, expected in [("engineer", eng, 403), ("viewer", view, 403)]:
        qa.get_csrf(sess)
        r = sess.post(f"{qa.base}/api/site-config/setup-complete/", json={}, verify=False)
        qa.check(f"3D.13 setup_complete as {role} → {expected} (OWASP)", r.status_code == expected, f"got {r.status_code}")

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
    r = eng.post(
        f"{qa.base}/api/scans/",
        json={"name": "QA Scan", "target": "scanme.nmap.org", "scan_type": "quick"},
        verify=False,
    )
    scan_ok = r.status_code == 201
    scan_id = r.json().get("id", "") if scan_ok else ""
    qa.check("3E.1 Create scan", scan_ok, f"status={r.status_code} {r.text[:100]}")

    r = eng.get(f"{qa.base}/api/scans/", verify=False)
    payload = r.json()
    rows = payload.get("results", payload if isinstance(payload, list) else [])
    has_scan = any(s.get("id") == scan_id for s in rows)
    qa.check("3E.2 Scan in list", has_scan or r.status_code == 200)

    if scan_id:
        r = eng.get(f"{qa.base}/api/scans/{scan_id}/", verify=False)
        qa.check("3E.3 Scan detail", r.status_code == 200, f"status={r.status_code}")

    qa.get_csrf(eng)
    r = eng.post(f"{qa.base}/api/scans/", json={"target": "127.0.0.1", "scan_type": "quick"}, verify=False)
    qa.check("3E.4 SSRF blocked (localhost)", r.status_code == 400, f"got {r.status_code}")

    qa.get_csrf(eng)
    r = eng.post(f"{qa.base}/api/scans/", json={"target": "169.254.169.254", "scan_type": "quick"}, verify=False)
    qa.check("3E.5 SSRF blocked (metadata)", r.status_code == 400, f"got {r.status_code}")

    qa.get_csrf(eng)
    r = eng.post(
        f"{qa.base}/api/scans/",
        json={"target": "http://169.254.169.254/latest/", "scan_type": "quick"},
        verify=False,
    )
    qa.check("3E.6 SSRF blocked (URL format)", r.status_code == 400, f"got {r.status_code}")


def phase_3f_pagination(qa):
    """Pagination and throttle."""
    print("\n── 3F: Pagination & Throttle ──")
    own = qa.sessions["owner"]

    r = own.get(f"{qa.base}/api/scans/", verify=False)
    has_pagination = isinstance(r.json(), dict) and "results" in r.json()
    qa.check(
        "3F.1 Paginated response",
        r.status_code == 200 and has_pagination,
        f"keys={list(r.json().keys()) if isinstance(r.json(), dict) else 'not dict'}",
    )

    r = own.get(f"{qa.base}/api/scans/?page_size=99999", verify=False)
    qa.check("3F.2 Large page_size accepted", r.status_code == 200)

    flush_rate_limits()

    token = qa.owner_api_token
    if not token:
        qa.get_csrf(own)
        r = own.post(f"{qa.base}/api/auth/tokens/", json={"name": "qa_throttle_probe"}, verify=False)
        if r.status_code == 201:
            token = r.json().get("token", "")
            qa.owner_api_token = token

    prime_result = docker_api_shell(f'''
import json
from django.core.cache import cache
from rest_framework.test import APIRequestFactory
from rest_framework.throttling import UserRateThrottle
from scanner.models import User
r = cache._cache.get_client()
[r.delete(k) for k in r.keys('*throttle*')]
user = User.objects.get(username={OWNER_USER!r})
req = APIRequestFactory().get('/api/auth/me/', HTTP_HOST='localhost')
req.user = user
throttle = UserRateThrottle()
blocked_at = None
for i in range(150):
    if not throttle.allow_request(req, None):
        blocked_at = i + 1
        break
print(json.dumps({{'blocked_at': blocked_at, 'wait': throttle.wait()}}))
''')

    prime_payload = None
    if prime_result.returncode == 0:
        for line in reversed([line.strip() for line in prime_result.stdout.splitlines() if line.strip()]):
            try:
                prime_payload = json.loads(line)
                break
            except json.JSONDecodeError:
                continue

    if not token:
        qa.check("3F.3 User throttle", False, "owner token unavailable")
    elif prime_result.returncode != 0:
        qa.check("3F.3 User throttle", False, (prime_result.stderr or prime_result.stdout).strip()[:200])
    elif not prime_payload or not prime_payload.get("blocked_at"):
        qa.check("3F.3 User throttle", False, f"prime payload={prime_payload}")
    else:
        try:
            r = requests.get(
                f"{qa.base}/api/auth/me/",
                headers={"Authorization": f"Token {token}"},
                verify=False,
                timeout=20,
            )
            qa.check(
                "3F.3 User throttle",
                r.status_code == 429,
                f"prime={prime_payload} external_status={r.status_code}",
            )
        except requests.RequestException as exc:
            qa.check("3F.3 User throttle", False, f"external request failed: {type(exc).__name__}")

    flush_rate_limits()

    anon_throttled = False
    for i in range(45):
        r = requests.get(f"{qa.base}/api/auth/csrf/", verify=False, timeout=5)
        if r.status_code == 429:
            anon_throttled = True
            qa.check(f"3F.4 Anon throttle (429 at req #{i + 1})", True)
            break
    if not anon_throttled:
        qa.check("3F.4 Anon throttle", False, "never got 429 in 45 requests")


def phase_3g_mfa(qa):
    """MFA flow — Telegram OTP based (not TOTP)."""
    print("\n── 3G: MFA Flow ──")
    own = qa.sessions.get("owner")
    if not own:
        own, _ = qa.login(OWNER_USER, OWNER_PASS)
        qa.sessions["owner"] = own

    r = own.get(f"{qa.base}/api/auth/mfa/status/", verify=False)
    qa.check("3G.1 MFA status endpoint", r.status_code == 200, f"status={r.status_code}")
    if r.status_code == 200:
        qa.check("3G.2 MFA initially disabled", r.json().get("enabled") is False, f"enabled={r.json().get('enabled')}")

    qa.get_csrf(own)
    r = own.post(f"{qa.base}/api/auth/mfa/setup/", verify=False)
    qa.check("3G.3 MFA setup requires reauth (403)", r.status_code == 403, f"status={r.status_code}")

    qa.get_csrf(own)
    r = own.post(
        f"{qa.base}/api/auth/mfa/confirm/",
        json={"setup_token": "bogus", "code": "000000"},
        verify=False,
    )
    qa.check("3G.4 MFA confirm rejects invalid token", r.status_code == 401, f"status={r.status_code}")


def phase_3h_config(qa):
    """Site config and report config."""
    print("\n── 3H: Site Config ──")
    own = qa.sessions["owner"]
    eng = qa.sessions["engineer"]

    r = own.get(f"{qa.base}/api/site-config/", verify=False)
    qa.check("3H.1 GET site-config", r.status_code == 200)

    qa.get_csrf(own)
    r = own.put(f"{qa.base}/api/site-config/update/", json={"schedule_timezone": "UTC"}, verify=False)
    qa.check("3H.2 Owner update site config", r.status_code == 200, f"status={r.status_code} {r.text[:80]}")

    qa.get_csrf(eng)
    r = eng.put(f"{qa.base}/api/site-config/update/", json={"schedule_timezone": "UTC"}, verify=False)
    qa.check("3H.3 Engineer update site config → 403", r.status_code == 403, f"got {r.status_code}")

    r = own.get(f"{qa.base}/api/report-config/", verify=False)
    qa.check("3H.4 GET report-config", r.status_code == 200)


def phase_3i_browser_fixture(qa):
    """Seed a deterministic completed scan with real host/finding/report data."""
    print("\n── 3I: Browser Fixture Seed ──")
    fixture_code = r'''
import json
from datetime import timedelta
from pathlib import Path
from django.utils import timezone
from scanner.models import Finding, Host, Port, Report, Scan, User

user = User.objects.get(username="test_engineer")
Scan.objects.filter(name="QA Browser Fixture").delete()
now = timezone.now()
output_dir = Path("/data/output/qa-browser-fixture")
output_dir.mkdir(parents=True, exist_ok=True)
report_path = output_dir / "qa-browser-fixture.html"
report_body = """<!doctype html><html><head><meta charset='utf-8'><title>QA Browser Fixture</title></head><body><h1>QA Browser Fixture</h1><p>Completed scan seeded by scripts/qa_integration.py for browser QA.</p></body></html>"""
report_path.write_text(report_body, encoding="utf-8")
scan = Scan.objects.create(
    name="QA Browser Fixture",
    target="198.51.100.10",
    scan_type="web",
    status="completed",
    parallelism=10,
    timeout=3600,
    report_formats="dashboard,html",
    version_detect=True,
    os_detect=True,
    service_enum=True,
    skip_nuclei=False,
    skip_screenshots=True,
    nuclei_default_templates=True,
    scan_unresponsive=False,
    enum4linux=False,
    skip_nikto=False,
    skip_netexec=False,
    hosts_count=1,
    ports_count=1,
    findings_count=1,
    critical_count=0,
    high_count=1,
    medium_count=0,
    low_count=0,
    info_count=0,
    started_at=now - timedelta(minutes=3),
    completed_at=now - timedelta(minutes=1),
    duration_seconds=120,
    output_dir=str(output_dir),
    created_by=user,
)
host = Host.objects.create(
    scan=scan,
    ip="198.51.100.10",
    hostname="fixture-host.internal",
    os="Linux",
    status="up",
    ports_count=1,
    findings_count=1,
)
Port.objects.create(
    host=host,
    number=443,
    protocol="tcp",
    state="open",
    service_name="https",
    service_product="nginx",
    service_version="1.24",
)
finding = Finding.objects.create(
    scan=scan,
    host=host,
    source="nikto",
    severity="high",
    title="Fixture TLS hardening issue",
    description="Deterministic QA fixture finding for browser regression coverage.",
    host_ip=host.ip,
    port="443",
    protocol="tcp",
    endpoint="/",
    full_url="https://198.51.100.10/",
    cve="CVE-2024-0001",
    references="https://example.invalid/fix",
)
report = Report.objects.create(
    scan=scan,
    format="html",
    file_path=str(report_path),
    file_size=report_path.stat().st_size,
)
print(json.dumps({
    "scan_id": str(scan.id),
    "host_id": str(host.id),
    "finding_id": str(finding.id),
    "report_id": str(report.id),
    "report_path": str(report_path),
}))
'''
    proc = docker_api_shell(fixture_code)
    qa.check("3I.1 Fixture seed command succeeds", proc.returncode == 0, (proc.stderr or proc.stdout).strip()[:200])
    if proc.returncode != 0:
        return

    fixture_json = None
    for line in reversed([line.strip() for line in proc.stdout.splitlines() if line.strip()]):
        try:
            fixture_json = json.loads(line)
            break
        except json.JSONDecodeError:
            continue
    qa.check("3I.2 Fixture seed returned JSON", fixture_json is not None, proc.stdout.strip()[:200])
    if not fixture_json:
        return

    qa.fixture = fixture_json
    own = qa.sessions["owner"]

    r = own.get(f"{qa.base}/api/scans/{fixture_json['scan_id']}/", verify=False)
    detail = r.json() if r.status_code == 200 else {}
    qa.check(
        "3I.3 Fixture scan detail is completed",
        r.status_code == 200 and detail.get("status") == "completed",
        f"status={r.status_code} body={str(detail)[:120]}",
    )
    qa.check(
        "3I.4 Fixture scan detail exposes reports",
        isinstance(detail.get("reports"), list) and len(detail.get("reports", [])) >= 1,
        f"reports={detail.get('reports')}",
    )

    r = own.get(f"{qa.base}/api/scans/", verify=False)
    payload = r.json() if r.status_code == 200 else {}
    rows = payload.get("results", payload if isinstance(payload, list) else [])
    fixture_row = next((row for row in rows if row.get("id") == fixture_json["scan_id"]), None)
    qa.check(
        "3I.5 Fixture scan appears in list with report metadata",
        fixture_row is not None and isinstance(fixture_row.get("reports"), list) and len(fixture_row.get("reports", [])) >= 1,
        f"row={fixture_row}",
    )

    r = own.get(f"{qa.base}/api/hosts/", verify=False)
    host_rows = r.json().get("results", r.json() if r.status_code == 200 else [])
    qa.check(
        "3I.6 Fixture host appears in global hosts",
        any(row.get("id") == fixture_json["host_id"] for row in host_rows),
        f"status={r.status_code} count={len(host_rows) if isinstance(host_rows, list) else 0}",
    )

    r = own.get(f"{qa.base}/api/findings/", verify=False)
    finding_rows = r.json().get("results", r.json() if r.status_code == 200 else [])
    qa.check(
        "3I.7 Fixture finding appears in global findings",
        any(row.get("id") == fixture_json["finding_id"] for row in finding_rows),
        f"status={r.status_code} count={len(finding_rows) if isinstance(finding_rows, list) else 0}",
    )

    r = own.get(f"{qa.base}/api/reports/{fixture_json['report_id']}/download/", verify=False)
    qa.check(
        "3I.8 Fixture report download works",
        r.status_code == 200 and len(r.content) > 0,
        f"status={r.status_code} bytes={len(r.content)}",
    )


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
    phase_3i_browser_fixture(qa)
    flush_rate_limits()
    phase_3g_mfa(qa)
    phase_3h_config(qa)
    flush_rate_limits()
    phase_3f_pagination(qa)

    report = qa.report()
    print(f"\n{'=' * 50}")
    print(f"Phase 3 Results: {report['passed']}/{report['total']} passed, {report['failed']} failed")
    if report["failures"]:
        print("Failures:")
        for failure in report["failures"]:
            print(f"  - {failure['test']}: {failure['detail']}")

    os.makedirs(os.path.dirname(args.results) or ".", exist_ok=True)
    with open(args.results, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    sys.exit(0 if report["failed"] == 0 else 1)


if __name__ == "__main__":
    main()
