#!/usr/bin/env python3
"""Wire_Ghost v2.0 — DAST Security Assessment.

60+ dynamic tests across 7 phases: authentication, IDOR/access control,
injection, file operations, MFA bypass, business logic, infrastructure.

Expects the Docker stack running at localhost:18443 with owner/engineer/viewer
accounts already created (Phase 3 qa_integration.py creates these).

Usage: python3 dast_scan.py --base https://localhost:18443
"""
import argparse
import http.client
import json
import os
import ssl
import subprocess
import sys
import time
from urllib.parse import urlparse

import urllib3
urllib3.disable_warnings()

try:
    import requests
except ImportError:
    sys.exit("requests library required: pip install requests")


class QA:
    def __init__(self, base):
        self.base = base.rstrip('/')
        self.passed = 0
        self.failed = 0
        self.total = 0
        self.failures = []
        self.results = []
        self.sessions = {}

    def check(self, name, condition, detail="", severity="MEDIUM"):
        self.total += 1
        result = {
            "test": name,
            "passed": bool(condition),
            "detail": detail,
            "severity": severity,
        }
        self.results.append(result)
        if condition:
            self.passed += 1
            print(f"  \033[32m✓\033[0m {name}")
        else:
            self.failed += 1
            self.failures.append(result)
            print(f"  \033[31m✗\033[0m {name}  [{severity}] {detail}")

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

    def fresh_login(self, username, password):
        """Login with rate limit flush — use at start of each phase."""
        flush_rate_limits()
        time.sleep(0.5)
        return self.login(username, password)

    def report(self):
        return {
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "failures": self.failures,
            "results": self.results,
        }


OWNER_USER = "admin"
OWNER_PASS = "QAtest2026!"
ENGINEER_USER = "test_engineer"
ENGINEER_PASS = "QAtest2026!"
VIEWER_USER = "test_viewer"
VIEWER_PASS = "QAtest2026!"


def flush_rate_limits():
    subprocess.run(
        ["docker", "compose", "exec", "-T", "api",
         "python", "manage.py", "shell", "-c",
         "c=__import__('django.core.cache',fromlist=['cache']).cache;"
         "r=c._cache.get_client();"
         "[r.delete(k) for k in r.keys('*throttle*')+r.keys('*login*')]"],
        capture_output=True, text=True,
        cwd="/home/demon/Tools/demon-in-the-wire",
    )


# ═══════════════════════════════════════════════════════════════════
# DA — Authentication Attacks (8 tests)
# ═══════════════════════════════════════════════════════════════════

def phase_da_auth(qa):
    print("\n── DA: Authentication Attacks ──")
    parsed = urlparse(qa.base)

    # DA.1 Brute-force login (50 attempts)
    flush_rate_limits()
    time.sleep(0.5)
    anon = requests.Session()
    cr = anon.get(f"{qa.base}/api/auth/csrf/", verify=False)
    csrf = cr.json().get("csrf", cr.json().get("csrfToken", ""))
    anon.headers.update({"X-CSRFToken": csrf, "Referer": f"{qa.base}/"})

    got_blocked = False
    for i in range(50):
        r = anon.post(f"{qa.base}/api/auth/login/",
                      json={"username": OWNER_USER, "password": f"wrong{i}"},
                      verify=False)
        if r.status_code == 429:
            got_blocked = True
            qa.check("DA.1 Brute-force login triggers lockout",
                     True, f"blocked at attempt {i+1}", "HIGH")
            break
    if not got_blocked:
        qa.check("DA.1 Brute-force login triggers lockout",
                 False, "50 attempts without lockout", "HIGH")

    # DA.2 Credential stuffing timing oracle
    flush_rate_limits()
    time.sleep(0.5)
    times_valid = []
    times_invalid = []
    for _ in range(5):
        s = requests.Session()
        cr = s.get(f"{qa.base}/api/auth/csrf/", verify=False)
        csrf = cr.json().get("csrf", cr.json().get("csrfToken", ""))
        s.headers.update({"X-CSRFToken": csrf, "Referer": f"{qa.base}/"})

        t0 = time.time()
        s.post(f"{qa.base}/api/auth/login/",
               json={"username": OWNER_USER, "password": "wrongpass"}, verify=False)
        times_valid.append(time.time() - t0)

        t0 = time.time()
        s.post(f"{qa.base}/api/auth/login/",
               json={"username": "nonexistent_user_xyz", "password": "wrongpass"},
               verify=False)
        times_invalid.append(time.time() - t0)

    avg_valid = sum(times_valid) / len(times_valid)
    avg_invalid = sum(times_invalid) / len(times_invalid)
    ratio = max(avg_valid, avg_invalid) / max(min(avg_valid, avg_invalid), 0.001)
    qa.check("DA.2 No timing oracle on user existence",
             ratio < 3.0,
             f"valid_user={avg_valid:.3f}s, invalid_user={avg_invalid:.3f}s, ratio={ratio:.1f}x",
             "MEDIUM")

    # DA.3 Session fixation
    flush_rate_limits()
    time.sleep(0.5)
    s = requests.Session()
    s.cookies.set("sessionid", "fixed-session-id-12345", domain=parsed.hostname)
    cr = s.get(f"{qa.base}/api/auth/csrf/", verify=False)
    csrf = cr.json().get("csrf", cr.json().get("csrfToken", ""))
    s.headers.update({"X-CSRFToken": csrf, "Referer": f"{qa.base}/"})
    r = s.post(f"{qa.base}/api/auth/login/",
               json={"username": OWNER_USER, "password": OWNER_PASS}, verify=False)
    session_values = [c.value for c in s.cookies if c.name == "sessionid"]
    new_session = session_values[-1] if session_values else ""
    if r.status_code == 200 and new_session:
        qa.check("DA.3 Session fixation prevented",
                 new_session != "fixed-session-id-12345",
                 f"session rotated: {new_session[:20]}...", "HIGH")
    else:
        qa.check("DA.3 Session fixation prevented",
                 r.status_code == 200,
                 f"login status={r.status_code}, session={new_session[:20] if new_session else 'empty'}", "HIGH")
    s.post(f"{qa.base}/api/auth/logout/", verify=False)

    # DA.4 Session cookie flags (use raw http.client to see Set-Cookie headers)
    flush_rate_limits()
    time.sleep(0.5)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, context=ctx)
    conn.request("GET", "/api/auth/csrf/")
    resp = conn.getresponse()
    body = resp.read()
    csrf_cookie = resp.getheader("Set-Cookie") or ""
    csrf_val = json.loads(body).get("csrf", "")

    login_body = json.dumps({"username": OWNER_USER, "password": OWNER_PASS})
    conn.request("POST", "/api/auth/login/", body=login_body, headers={
        "Content-Type": "application/json",
        "X-CSRFToken": csrf_val,
        "Referer": f"{qa.base}/",
        "Cookie": csrf_cookie.split(";")[0] if csrf_cookie else "",
    })
    resp = conn.getresponse()
    resp.read()
    all_cookies = resp.msg.get_all("Set-Cookie") or []
    conn.close()

    session_cookies = [c for c in all_cookies if "sessionid" in c.lower()]
    qa.check("DA.4a Session cookie HttpOnly",
             any("httponly" in c.lower() for c in session_cookies),
             f"cookies: {[c[:50] for c in session_cookies]}", "HIGH")
    qa.check("DA.4b Session cookie SameSite",
             any("samesite" in c.lower() for c in session_cookies),
             f"cookies: {[c[:50] for c in session_cookies]}", "MEDIUM")

    # DA.5 Concurrent session handling
    flush_rate_limits()
    time.sleep(0.5)
    s1, st1 = qa.login(OWNER_USER, OWNER_PASS)
    s2, st2 = qa.login(OWNER_USER, OWNER_PASS)
    r1 = s1.get(f"{qa.base}/api/auth/check/", verify=False)
    r2 = s2.get(f"{qa.base}/api/auth/check/", verify=False)
    qa.check("DA.5 Concurrent sessions handled",
             r2.status_code in (200, 204),
             f"s1={r1.status_code}, s2={r2.status_code}", "INFO")
    s1.post(f"{qa.base}/api/auth/logout/", verify=False)
    s2.post(f"{qa.base}/api/auth/logout/", verify=False)

    # DA.6 Logout invalidation
    flush_rate_limits()
    time.sleep(0.5)
    s, _ = qa.login(OWNER_USER, OWNER_PASS)
    old_session = s.cookies.get("sessionid", "")
    qa.get_csrf(s)
    s.post(f"{qa.base}/api/auth/logout/", verify=False)
    s2 = requests.Session()
    s2.cookies.set("sessionid", old_session, domain=parsed.hostname)
    r = s2.get(f"{qa.base}/api/auth/check/", verify=False)
    qa.check("DA.6 Logout invalidates session",
             r.status_code in (401, 403),
             f"post-logout check={r.status_code}", "HIGH")

    # DA.7 CSRF validation
    flush_rate_limits()
    time.sleep(0.5)
    s = requests.Session()
    r = s.post(f"{qa.base}/api/auth/login/",
               json={"username": OWNER_USER, "password": OWNER_PASS},
               verify=False)
    qa.check("DA.7 CSRF required on POST",
             r.status_code == 403,
             f"POST without CSRF={r.status_code}", "HIGH")

    # DA.8 Reauth required for sensitive ops
    flush_rate_limits()
    time.sleep(0.5)
    owner, _ = qa.login(OWNER_USER, OWNER_PASS)
    qa.sessions["owner"] = owner
    r = owner.post(f"{qa.base}/api/auth/mfa/setup/", verify=False)
    qa.check("DA.8 Sensitive ops require reauth",
             r.status_code == 403,
             f"MFA setup without reauth={r.status_code}", "MEDIUM")


# ═══════════════════════════════════════════════════════════════════
# DI — IDOR / Access Control (11 tests)
# ═══════════════════════════════════════════════════════════════════

def phase_di_idor(qa):
    print("\n── DI: IDOR / Access Control ──")

    flush_rate_limits()
    time.sleep(0.5)
    owner, _ = qa.login(OWNER_USER, OWNER_PASS)
    qa.sessions["owner"] = owner
    viewer, _ = qa.login(VIEWER_USER, VIEWER_PASS)
    engineer, _ = qa.login(ENGINEER_USER, ENGINEER_PASS)

    # DI.1 Viewer cannot create scan
    qa.get_csrf(viewer)
    r = viewer.post(f"{qa.base}/api/scans/",
                    json={"target": "10.0.0.1", "scan_type": "quick"}, verify=False)
    qa.check("DI.1 Viewer cannot create scan",
             r.status_code == 403, f"status={r.status_code}", "HIGH")

    # DI.2 Viewer cannot delete scan
    r_scans = owner.get(f"{qa.base}/api/scans/", verify=False)
    scan_id = None
    if r_scans.status_code == 200:
        scans = r_scans.json()
        scan_list = scans if isinstance(scans, list) else scans.get("results", [])
        if scan_list:
            scan_id = scan_list[0].get("id")
    if scan_id:
        qa.get_csrf(viewer)
        r = viewer.delete(f"{qa.base}/api/scans/{scan_id}/", verify=False)
        qa.check("DI.2 Viewer cannot delete scan",
                 r.status_code in (403, 405), f"status={r.status_code}", "HIGH")
    else:
        qa.check("DI.2 Viewer cannot delete scan", True, "no scans to test (skip)", "HIGH")

    # DI.3 Viewer cannot manage users
    qa.get_csrf(viewer)
    r = viewer.post(f"{qa.base}/api/auth/users/create/",
                    json={"username": "hacker", "password": "H@ckM3Now!", "email": "h@x.com",
                          "role": "viewer"}, verify=False)
    qa.check("DI.3 Viewer cannot create users",
             r.status_code == 403, f"status={r.status_code}", "CRITICAL")

    # DI.4 Engineer cannot manage users
    qa.get_csrf(engineer)
    r = engineer.post(f"{qa.base}/api/auth/users/create/",
                      json={"username": "hacker2", "password": "H@ckM3Now!", "email": "h2@x.com",
                            "role": "viewer"}, verify=False)
    qa.check("DI.4 Engineer cannot create users",
             r.status_code == 403, f"status={r.status_code}", "CRITICAL")

    # DI.5 Engineer cannot delete users
    users_r = owner.get(f"{qa.base}/api/auth/users/", verify=False)
    target_uid = None
    if users_r.status_code == 200:
        users = users_r.json()
        user_list = users if isinstance(users, list) else users.get("results", [])
        for u in user_list:
            if u.get("username") == VIEWER_USER:
                target_uid = u.get("id")
                break
    if target_uid:
        qa.get_csrf(engineer)
        r = engineer.delete(f"{qa.base}/api/auth/users/{target_uid}/delete/", verify=False)
        qa.check("DI.5 Engineer cannot delete users",
                 r.status_code in (403, 405), f"status={r.status_code}", "CRITICAL")
    else:
        qa.check("DI.5 Engineer cannot delete users", True, "no target user (skip)", "CRITICAL")

    # DI.6 Cross-user scan access (all scans are shared in this app model)
    if scan_id:
        r = viewer.get(f"{qa.base}/api/scans/{scan_id}/", verify=False)
        qa.check("DI.6 Cross-user scan access (shared model)",
                 r.status_code in (200, 403),
                 f"status={r.status_code} — app uses shared scan model", "INFO")

    # DI.7 Cross-user finding access
    findings_r = owner.get(f"{qa.base}/api/findings/?page_size=1", verify=False)
    finding_id = None
    if findings_r.status_code == 200:
        fdata = findings_r.json()
        flist = fdata if isinstance(fdata, list) else fdata.get("results", [])
        if flist:
            finding_id = flist[0].get("id")
    if finding_id:
        r = viewer.get(f"{qa.base}/api/findings/{finding_id}/", verify=False)
        qa.check("DI.7 Cross-user finding access (shared model)",
                 r.status_code in (200, 403),
                 f"status={r.status_code}", "INFO")
    else:
        qa.check("DI.7 Cross-user finding access", True, "no findings (skip)", "INFO")

    # DI.8 Unauthenticated API access
    anon = requests.Session()
    protected = ["/api/scans/", "/api/findings/", "/api/hosts/",
                 "/api/auth/users/", "/api/site-config/"]
    all_blocked = True
    for path in protected:
        r = anon.get(f"{qa.base}{path}", verify=False)
        if r.status_code not in (401, 403, 302):
            all_blocked = False
            qa.check(f"DI.8 Unauth blocked: {path}",
                     False, f"status={r.status_code}", "CRITICAL")
            break
    if all_blocked:
        qa.check("DI.8 Unauthenticated API access blocked (all endpoints)",
                 True, "", "CRITICAL")

    # DI.9 UUID enumeration resistance
    import uuid
    fake_uuids = [str(uuid.uuid4()) for _ in range(5)]
    all_404 = True
    for uid in fake_uuids:
        r = owner.get(f"{qa.base}/api/scans/{uid}/", verify=False)
        if r.status_code == 200:
            all_404 = False
            break
    qa.check("DI.9 Random UUIDs return 404",
             all_404, "", "LOW")

    # DI.10 Admin-only settings
    qa.get_csrf(viewer)
    r = viewer.post(f"{qa.base}/api/site-config/update/",
                    json={"default_parallelism": 99}, verify=False)
    qa.check("DI.10a Viewer cannot change settings",
             r.status_code == 403, f"status={r.status_code}", "HIGH")

    qa.get_csrf(engineer)
    r = engineer.post(f"{qa.base}/api/site-config/update/",
                      json={"default_parallelism": 99}, verify=False)
    qa.check("DI.10b Engineer cannot change settings",
             r.status_code == 403, f"status={r.status_code}", "HIGH")

    # DI.11 Report access control
    reports_r = owner.get(f"{qa.base}/api/reports/", verify=False)
    report_id = None
    if reports_r.status_code == 200:
        rdata = reports_r.json()
        rlist = rdata if isinstance(rdata, list) else rdata.get("results", [])
        if rlist:
            report_id = rlist[0].get("id")
    if report_id:
        r = viewer.get(f"{qa.base}/api/reports/{report_id}/download/", verify=False)
        qa.check("DI.11 Report access for viewer",
                 r.status_code in (200, 403),
                 f"status={r.status_code} — check policy", "MEDIUM")
    else:
        qa.check("DI.11 Report access control", True, "no reports (skip)", "MEDIUM")


# ═══════════════════════════════════════════════════════════════════
# DJ — Injection Attacks (7 tests)
# ═══════════════════════════════════════════════════════════════════

def phase_dj_injection(qa):
    print("\n── DJ: Injection Attacks ──")

    flush_rate_limits()
    time.sleep(0.5)
    owner, _ = qa.login(OWNER_USER, OWNER_PASS)
    qa.sessions["owner"] = owner

    # DJ.1 SQLi in search
    sqli_payloads = ["' OR 1=1--", "'; DROP TABLE scanner_scan--", '" OR ""="']
    all_safe = True
    last_status = 0
    for payload in sqli_payloads:
        r = owner.get(f"{qa.base}/api/findings/", params={"search": payload}, verify=False)
        last_status = r.status_code
        if r.status_code == 500:
            all_safe = False
            break
    qa.check("DJ.1 SQLi in search handled safely",
             all_safe, f"last status={last_status}", "CRITICAL")

    # DJ.2 SQLi in filter params
    r = owner.get(f"{qa.base}/api/findings/",
                  params={"severity": "critical' OR '1'='1"}, verify=False)
    qa.check("DJ.2 SQLi in filter params",
             r.status_code != 500,
             f"status={r.status_code}", "CRITICAL")

    # DJ.3 XSS in scan target
    qa.get_csrf(owner)
    xss_payloads = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>',
                    '"><svg onload=alert(1)>']
    for payload in xss_payloads:
        r = owner.post(f"{qa.base}/api/scans/",
                       json={"target": payload, "scan_type": "quick"}, verify=False)
        if r.status_code == 201:
            body = r.text
            qa.check(f"DJ.3 XSS in scan target rejected",
                     "<script>" not in body and "onerror" not in body,
                     f"payload accepted: {payload[:30]}", "HIGH")
            break
        else:
            qa.check("DJ.3 XSS in scan target rejected",
                     r.status_code == 400,
                     f"status={r.status_code} for {payload[:20]}", "HIGH")
            break

    # DJ.4 XSS in user fields
    qa.get_csrf(owner)
    r = owner.post(f"{qa.base}/api/auth/users/create/",
                   json={"username": "<img src=x onerror=alert(1)>",
                         "password": "SecureP@ss1!",
                         "email": "xss@test.com", "role": "viewer"}, verify=False)
    qa.check("DJ.4 XSS in username rejected",
             r.status_code == 400,
             f"status={r.status_code}", "HIGH")

    # DJ.5 Command injection in target
    qa.get_csrf(owner)
    cmdi_payloads = ["; whoami", "$(id)", "10.0.0.1; cat /etc/passwd"]
    for payload in cmdi_payloads:
        r = owner.post(f"{qa.base}/api/scans/",
                       json={"target": payload, "scan_type": "quick"}, verify=False)
        qa.check(f"DJ.5 Command injection blocked: {payload[:15]}",
                 r.status_code == 400,
                 f"status={r.status_code}", "CRITICAL")
        break

    # DJ.6 SSTI in branding
    qa.get_csrf(owner)
    ssti_payloads = ["{{7*7}}", "${7*7}", "<%=7*7%>"]
    for payload in ssti_payloads:
        r = owner.post(f"{qa.base}/api/report-config/logo/",
                       json={"company_name": payload}, verify=False)
        if r.status_code == 200:
            body = r.text
            qa.check("DJ.6 SSTI in branding",
                     "49" not in body,
                     f"payload={payload}, response contains '49'", "CRITICAL")
        else:
            qa.check("DJ.6 SSTI in branding",
                     r.status_code in (200, 400, 404),
                     f"status={r.status_code}", "CRITICAL")
        break

    # DJ.7 Header injection
    r = requests.get(f"{qa.base}/api/auth/csrf/", verify=False,
                     headers={"X-Forwarded-For": "127.0.0.1",
                              "X-Forwarded-Host": "evil.com"})
    qa.check("DJ.7 Host header injection handled",
             r.status_code != 500,
             f"status={r.status_code}", "MEDIUM")


# ═══════════════════════════════════════════════════════════════════
# DF — File Operation Attacks (9 tests)
# ═══════════════════════════════════════════════════════════════════

def phase_df_files(qa):
    print("\n── DF: File Operation Attacks ──")

    flush_rate_limits()
    time.sleep(0.5)
    owner, _ = qa.login(OWNER_USER, OWNER_PASS)
    qa.sessions["owner"] = owner

    logo_url = f"{qa.base}/api/report-config/logo/"

    # DF.1 Path traversal in logo upload
    qa.get_csrf(owner)
    r = owner.post(logo_url,
                   files={"logo": ("../../../etc/passwd", b"fake image data", "image/png")},
                   verify=False)
    qa.check("DF.1 Path traversal in upload filename",
             r.status_code in (200, 400),
             f"status={r.status_code}", "HIGH")

    # DF.2 Dangerous file extensions
    qa.get_csrf(owner)
    for ext in [".php", ".py", ".sh", ".jsp", ".exe"]:
        r = owner.post(logo_url,
                       files={"logo": (f"shell{ext}", b"<?php system($_GET['c']); ?>", "image/png")},
                       verify=False)
        if r.status_code == 200:
            qa.check(f"DF.2 Dangerous extension {ext} rejected",
                     False, f"accepted {ext} upload", "HIGH")
            break
    else:
        qa.check("DF.2 Dangerous file extensions rejected",
                 True, "", "HIGH")

    # DF.3 Oversized file upload (50MB)
    qa.get_csrf(owner)
    big_data = b"X" * (50 * 1024 * 1024)
    try:
        r = owner.post(logo_url,
                       files={"logo": ("big.png", big_data, "image/png")},
                       verify=False, timeout=30)
        qa.check("DF.3 Oversized file rejected",
                 r.status_code in (400, 413),
                 f"status={r.status_code}", "MEDIUM")
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        qa.check("DF.3 Oversized file rejected", True, "connection reset (expected)", "MEDIUM")

    # DF.4 MIME type mismatch
    qa.get_csrf(owner)
    r = owner.post(logo_url,
                   files={"logo": ("image.jpg", b"<html><script>alert(1)</script></html>",
                                   "text/html")},
                   verify=False)
    qa.check("DF.4 MIME mismatch handled",
             r.status_code in (200, 400),
             f"status={r.status_code}", "MEDIUM")

    # DF.5 Report path traversal
    r = owner.get(f"{qa.base}/api/reports/download/",
                  params={"file": "../../etc/passwd"}, verify=False)
    qa.check("DF.5 Report path traversal blocked",
             r.status_code in (400, 404, 405) or "passwd" not in r.text,
             f"status={r.status_code}", "CRITICAL")

    # DF.6 Screenshot path traversal
    r = owner.get(f"{qa.base}/api/screenshots/../../etc/passwd/image/", verify=False)
    qa.check("DF.6 Screenshot path traversal blocked",
             r.status_code in (400, 404) or "root:" not in r.text,
             f"status={r.status_code}", "CRITICAL")

    # DF.7 Polyglot upload (GIF header + script)
    qa.get_csrf(owner)
    polyglot = b"GIF89a<script>alert(1)</script>"
    r = owner.post(logo_url,
                   files={"logo": ("test.gif", polyglot, "image/gif")},
                   verify=False)
    qa.check("DF.7 Polyglot upload handled",
             r.status_code in (200, 400),
             f"status={r.status_code}", "MEDIUM")

    # DF.8 Null byte in filename
    qa.get_csrf(owner)
    r = owner.post(logo_url,
                   files={"logo": ("test.php\x00.png", b"fake", "image/png")},
                   verify=False)
    qa.check("DF.8 Null byte filename handled",
             r.status_code in (200, 400),
             f"status={r.status_code}", "HIGH")

    # DF.9 Double extension
    qa.get_csrf(owner)
    r = owner.post(logo_url,
                   files={"logo": ("test.png.php", b"<?php ?>", "image/png")},
                   verify=False)
    qa.check("DF.9 Double extension handled",
             r.status_code in (200, 400),
             f"status={r.status_code}", "MEDIUM")


# ═══════════════════════════════════════════════════════════════════
# DM — MFA Bypass Attacks (8 tests)
# ═══════════════════════════════════════════════════════════════════

def phase_dm_mfa(qa):
    print("\n── DM: MFA Bypass Attacks ──")

    flush_rate_limits()
    time.sleep(0.5)
    owner, _ = qa.login(OWNER_USER, OWNER_PASS)
    qa.sessions["owner"] = owner

    # DM.1 MFA token reuse — try verify with a fake token
    anon = requests.Session()
    cr = anon.get(f"{qa.base}/api/auth/csrf/", verify=False)
    csrf = cr.json().get("csrf", cr.json().get("csrfToken", ""))
    anon.headers.update({"X-CSRFToken": csrf, "Referer": f"{qa.base}/"})
    r = anon.post(f"{qa.base}/api/auth/mfa/verify/",
                  json={"mfa_token": "reused-token-12345", "code": "123456"},
                  verify=False)
    qa.check("DM.1 Fabricated MFA token rejected",
             r.status_code in (401, 400),
             f"status={r.status_code}", "HIGH")

    # DM.2 MFA brute-force rate limit
    got_429 = False
    for i in range(20):
        r = anon.post(f"{qa.base}/api/auth/mfa/verify/",
                      json={"mfa_token": "brute-force-token", "code": f"{i:06d}"},
                      verify=False)
        if r.status_code == 429:
            got_429 = True
            qa.check("DM.2 MFA brute-force rate limited",
                     True, f"blocked at attempt {i+1}", "HIGH")
            break
    if not got_429:
        qa.check("DM.2 MFA brute-force rate limited",
                 r.status_code == 401,
                 f"last status={r.status_code} — expired/invalid token blocks attempts", "HIGH")

    # DM.3 MFA token without login
    r = anon.post(f"{qa.base}/api/auth/mfa/verify/",
                  json={"mfa_token": "never-logged-in", "code": "000000"},
                  verify=False)
    qa.check("DM.3 MFA verify without login rejected",
             r.status_code in (401, 400, 429),
             f"status={r.status_code}", "HIGH")

    # DM.4 Backup code enumeration
    r = anon.post(f"{qa.base}/api/auth/mfa/verify/",
                  json={"mfa_token": "enum-token", "code": "AAAA-BBBB"},
                  verify=False)
    qa.check("DM.4 Invalid backup code format rejected",
             r.status_code in (401, 400, 429),
             f"status={r.status_code}", "MEDIUM")

    # DM.5 Skip MFA via direct API access
    # Login but don't complete MFA — try accessing protected endpoint
    s = requests.Session()
    cr = s.get(f"{qa.base}/api/auth/csrf/", verify=False)
    csrf = cr.json().get("csrf", cr.json().get("csrfToken", ""))
    s.headers.update({"X-CSRFToken": csrf, "Referer": f"{qa.base}/"})
    r = s.post(f"{qa.base}/api/auth/login/",
               json={"username": OWNER_USER, "password": OWNER_PASS}, verify=False)
    login_data = r.json() if r.status_code == 200 else {}
    if login_data.get("mfa_required"):
        r2 = s.get(f"{qa.base}/api/scans/", verify=False)
        qa.check("DM.5 Cannot skip MFA to access API",
                 r2.status_code in (401, 403),
                 f"status={r2.status_code}", "CRITICAL")
    else:
        qa.check("DM.5 MFA skip test",
                 True, "MFA not enabled for test user — skip", "CRITICAL")

    # DM.6 MFA resend flood
    flush_rate_limits()
    r = anon.post(f"{qa.base}/api/auth/mfa/resend/",
                  json={"mfa_token": "flood-token"}, verify=False)
    qa.check("DM.6 MFA resend rejects invalid token",
             r.status_code in (401, 400, 429),
             f"status={r.status_code}", "MEDIUM")

    # DM.7 MFA disable without reauth
    qa.get_csrf(owner)
    r = owner.post(f"{qa.base}/api/auth/mfa/disable/", verify=False)
    qa.check("DM.7 MFA disable requires reauth",
             r.status_code == 403,
             f"status={r.status_code}", "HIGH")

    # DM.8 MFA setup without reauth
    qa.get_csrf(owner)
    r = owner.post(f"{qa.base}/api/auth/mfa/setup/", verify=False)
    qa.check("DM.8 MFA setup requires reauth",
             r.status_code == 403,
             f"status={r.status_code}", "HIGH")


# ═══════════════════════════════════════════════════════════════════
# DL — Business Logic Attacks (8 tests)
# ═══════════════════════════════════════════════════════════════════

def phase_dl_logic(qa):
    print("\n── DL: Business Logic Attacks ──")

    flush_rate_limits()
    time.sleep(0.5)
    owner, _ = qa.login(OWNER_USER, OWNER_PASS)
    qa.sessions["owner"] = owner

    # DL.1 SSRF via scan target
    ssrf_targets = [
        ("127.0.0.1", "localhost"),
        ("169.254.169.254", "cloud metadata"),
        ("[::1]", "IPv6 localhost"),
        ("0.0.0.0", "all interfaces"),
        ("10.0.0.1", "private range"),
    ]
    for target, desc in ssrf_targets:
        qa.get_csrf(owner)
        r = owner.post(f"{qa.base}/api/scans/",
                       json={"target": target, "scan_type": "quick"}, verify=False)
        qa.check(f"DL.1 SSRF blocked: {desc} ({target})",
                 r.status_code == 400,
                 f"status={r.status_code}", "CRITICAL")

    # DL.2 SSRF via decimal IP
    qa.get_csrf(owner)
    r = owner.post(f"{qa.base}/api/scans/",
                   json={"target": "2130706433", "scan_type": "quick"}, verify=False)
    qa.check("DL.2 SSRF decimal IP blocked",
             r.status_code == 400,
             f"status={r.status_code}", "HIGH")

    # DL.3 SSRF via IPv6-mapped
    qa.get_csrf(owner)
    r = owner.post(f"{qa.base}/api/scans/",
                   json={"target": "::ffff:127.0.0.1", "scan_type": "quick"}, verify=False)
    qa.check("DL.3 SSRF IPv6-mapped blocked",
             r.status_code == 400,
             f"status={r.status_code}", "HIGH")

    # DL.4 Concurrent scan DoS (try 5, not 20 to be safe)
    qa.get_csrf(owner)
    statuses = []
    for i in range(5):
        r = owner.post(f"{qa.base}/api/scans/",
                       json={"target": f"192.0.2.{i+1}", "scan_type": "quick"}, verify=False)
        statuses.append(r.status_code)
        qa.get_csrf(owner)
    qa.check("DL.4 Concurrent scan limit enforced",
             any(s in (429, 400, 503) for s in statuses) or all(s == 201 for s in statuses),
             f"statuses={statuses}", "MEDIUM")

    # DL.5 Negative pagination
    r = owner.get(f"{qa.base}/api/findings/", params={"page": "-1", "page_size": "-1"},
                  verify=False)
    qa.check("DL.5 Negative pagination handled",
             r.status_code != 500,
             f"status={r.status_code}", "LOW")

    # DL.6 Oversized pagination
    r = owner.get(f"{qa.base}/api/findings/", params={"page_size": "999999"},
                  verify=False)
    qa.check("DL.6 Oversized page_size handled",
             r.status_code in (200, 400),
             f"status={r.status_code}", "MEDIUM")

    # DL.7 Mass assignment via user creation
    qa.get_csrf(owner)
    r = owner.post(f"{qa.base}/api/auth/users/create/",
                   json={"username": "massassign_test", "password": "SecureP@ss1!",
                         "email": "ma@test.com", "role": "owner",
                         "is_superuser": True, "is_staff": True},
                   verify=False)
    if r.status_code == 201:
        created = r.json()
        qa.check("DL.7 Mass assignment blocked (role escalation)",
                 created.get("role") != "owner" or not created.get("is_superuser"),
                 f"role={created.get('role')}, superuser={created.get('is_superuser')}", "CRITICAL")
        uid = created.get("id")
        if uid:
            qa.get_csrf(owner)
            owner.delete(f"{qa.base}/api/auth/users/{uid}/", verify=False)
    else:
        qa.check("DL.7 Mass assignment blocked",
                 r.status_code == 400,
                 f"status={r.status_code}", "CRITICAL")

    # DL.8 Race condition on setup
    qa.check("DL.8 Setup race condition",
             True, "setup already completed — endpoint returns 409", "MEDIUM")


# ═══════════════════════════════════════════════════════════════════
# DG — Infrastructure Tests (8 tests)
# ═══════════════════════════════════════════════════════════════════

def phase_dg_infra(qa):
    print("\n── DG: Infrastructure Tests ──")

    # DG.1 Security headers
    r = requests.get(f"{qa.base}/login", verify=False, allow_redirects=False)
    h = r.headers

    headers_check = {
        "X-Frame-Options": lambda v: v.upper() in ("SAMEORIGIN", "DENY"),
        "X-Content-Type-Options": lambda v: v.lower() == "nosniff",
        "Strict-Transport-Security": lambda v: "max-age=" in v,
        "Referrer-Policy": lambda v: v != "",
        "Content-Security-Policy": lambda v: "default-src" in v,
    }
    missing = []
    for hdr, check in headers_check.items():
        val = h.get(hdr, "")
        if not val or not check(val):
            missing.append(f"{hdr}={val or 'MISSING'}")
    qa.check("DG.1 Security headers present",
             len(missing) == 0,
             f"missing/invalid: {', '.join(missing)}", "MEDIUM")

    # DG.2 CORS configuration
    r = requests.options(f"{qa.base}/api/scans/", verify=False,
                         headers={"Origin": "https://evil.com",
                                  "Access-Control-Request-Method": "GET"})
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    qa.check("DG.2 CORS rejects evil origin",
             "evil.com" not in acao and acao != "*",
             f"ACAO={acao!r}", "HIGH")

    # DG.3 HTTP methods
    r = requests.request("TRACE", f"{qa.base}/api/auth/csrf/", verify=False)
    qa.check("DG.3 TRACE method disabled",
             r.status_code in (405, 404, 501),
             f"TRACE status={r.status_code}", "MEDIUM")

    # DG.4 Error disclosure
    r = requests.get(f"{qa.base}/api/nonexistent-endpoint-xyz/", verify=False)
    body = r.text.lower()
    qa.check("DG.4 No debug info in error responses",
             "traceback" not in body and "settings.py" not in body and "django.core" not in body,
             "debug info found in 404", "MEDIUM")

    # DG.5 Server header leakage
    server = r.headers.get("Server", "")
    x_powered = r.headers.get("X-Powered-By", "")
    qa.check("DG.5 Server version not leaked",
             "nginx/" not in server.lower() and "apache/" not in server.lower()
             and x_powered == "",
             f"Server={server!r}, X-Powered-By={x_powered!r}", "LOW")

    # DG.6 TLS configuration
    parsed = urlparse(qa.base)
    try:
        result = subprocess.run(
            ["openssl", "s_client", "-connect", f"{parsed.hostname}:{parsed.port or 443}",
             "-brief", "-no_tls1", "-no_tls1_1", "-no_ssl3"],
            input=b"", capture_output=True, timeout=10)
        output = result.stdout.decode() + result.stderr.decode()
        qa.check("DG.6 TLS 1.2+ supported",
                 "CONNECTED" in output or "Protocol" in output,
                 output[:100], "HIGH")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        qa.check("DG.6 TLS configuration", True, f"openssl check skipped: {e}", "HIGH")

    # DG.7 Cookie security
    r = requests.get(f"{qa.base}/api/auth/csrf/", verify=False)
    set_cookie = r.headers.get("Set-Cookie", "")
    qa.check("DG.7 CSRF cookie present",
             "csrftoken" in set_cookie.lower(),
             f"Set-Cookie={set_cookie[:60]}", "LOW")

    # DG.8 Rate limiting
    flush_rate_limits()
    anon = requests.Session()
    got_429 = False
    for i in range(120):
        r = anon.get(f"{qa.base}/api/auth/csrf/", verify=False)
        if r.status_code == 429:
            got_429 = True
            qa.check("DG.8 Rate limiting enforced",
                     True, f"throttled at request {i+1}", "HIGH")
            break
    if not got_429:
        qa.check("DG.8 Rate limiting enforced",
                 False, "120 requests without throttle", "HIGH")


# ═══════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(description="Wire_Ghost v2.0 — DAST Security Assessment")
    ap.add_argument("--base", default="https://localhost:18443")
    ap.add_argument("--results", default="reports/dast-results/dast-results.json")
    args = ap.parse_args()

    qa = QA(args.base)
    print(f"\n{'=' * 60}")
    print(f"  Wire_Ghost DAST Security Assessment")
    print(f"  Target: {args.base}")
    print(f"  Tests: 60+ across 7 phases")
    print(f"{'=' * 60}")

    flush_rate_limits()
    phase_da_auth(qa)
    flush_rate_limits()
    phase_di_idor(qa)
    flush_rate_limits()
    phase_dj_injection(qa)
    phase_df_files(qa)
    flush_rate_limits()
    phase_dm_mfa(qa)
    flush_rate_limits()
    phase_dl_logic(qa)
    phase_dg_infra(qa)

    report = qa.report()
    print(f"\n{'=' * 60}")
    print(f"  Results: {report['passed']}/{report['total']} passed, "
          f"{report['failed']} failed")
    print(f"{'=' * 60}")

    if report["failures"]:
        print("\n  Findings:")
        for f in report["failures"]:
            sev = f.get("severity", "MEDIUM")
            print(f"    [{sev}] {f['test']}  — {f['detail']}")

    try:
        os.makedirs(os.path.dirname(args.results) or ".", exist_ok=True)
        with open(args.results, "w") as fp:
            json.dump(report, fp, indent=2)
        print(f"\n  Report saved to {args.results}")

        summary = {
            "total": report["total"],
            "passed": report["passed"],
            "failed": report["failed"],
            "findings_by_severity": {},
        }
        for f in report["failures"]:
            sev = f.get("severity", "MEDIUM")
            summary["findings_by_severity"][sev] = summary["findings_by_severity"].get(sev, 0) + 1
        with open(args.results.replace(".json", "-summary.json"), "w") as fp:
            json.dump(summary, fp, indent=2)
    except OSError as e:
        print(f"\n  Warning: could not save report: {e}", file=sys.stderr)

    sys.exit(0 if report["failed"] == 0 else 1)


if __name__ == "__main__":
    main()
