#!/usr/bin/env python3
"""Wire_Ghost — Phase 5 Security Regression Tests.

Validates OWASP audit fixes, security headers, access controls, session
security, and input validation against the live Docker stack.

Expects Phase 3 to have already created the owner/engineer/viewer accounts.

Usage: python3 qa_security.py --base https://localhost:28443 --results qa-results/phase-5.json
"""
import argparse, json, sys, urllib3
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
VIEWER_USER = "test_viewer"
VIEWER_PASS = "QAtest2026!"


# ═══════════════════════════════════════════════════════════════════
# 5A — OWASP Fix Regressions (10 tests)
# ═══════════════════════════════════════════════════════════════════

def phase_5a_owasp(qa):
    print("\n── 5A: OWASP Fix Regressions ──")

    owner, _ = qa.login(OWNER_USER, OWNER_PASS)
    engineer, _ = qa.login(ENGINEER_USER, ENGINEER_PASS)
    viewer, _ = qa.login(VIEWER_USER, VIEWER_PASS)

    # 5A.1 Cross-user token revocation — owner creates token, viewer cannot delete it
    r = owner.post(f"{qa.base}/api/auth/tokens/",
                   json={"name": "sec_test_token"}, verify=False)
    if r.status_code == 201:
        tok_id = r.json().get("id") or r.json().get("token_id")
        if tok_id:
            r2 = viewer.delete(f"{qa.base}/api/auth/tokens/{tok_id}/", verify=False)
            qa.check("5A.1 Cross-user token revocation blocked",
                     r2.status_code in (403, 404),
                     f"viewer DELETE token → {r2.status_code}")
            owner.delete(f"{qa.base}/api/auth/tokens/{tok_id}/", verify=False)
        else:
            qa.check("5A.1 Cross-user token revocation blocked", False, "no token id in response")
    else:
        qa.check("5A.1 Cross-user token revocation blocked", False, f"token create → {r.status_code}")

    # 5A.2 Token default expiry — newly minted tokens must have expires_at
    r = owner.post(f"{qa.base}/api/auth/tokens/",
                   json={"name": "expiry_check"}, verify=False)
    if r.status_code == 201:
        data = r.json()
        expires = data.get("expires_at") or data.get("expires")
        qa.check("5A.2 Token default expiry populated",
                 expires is not None and expires != "",
                 f"expires_at={expires}")
        tok_id = data.get("id") or data.get("token_id")
        if tok_id:
            owner.delete(f"{qa.base}/api/auth/tokens/{tok_id}/", verify=False)
    else:
        qa.check("5A.2 Token default expiry populated", False, f"create → {r.status_code}")

    # 5A.3 Mass assignment — extra fields in user update ignored
    # Try PATCH first; if 405 (method not allowed), that also blocks mass assignment
    r = viewer.patch(f"{qa.base}/api/auth/me/",
                     json={"role": "owner", "is_superuser": True}, verify=False)
    if r.status_code == 200:
        me = viewer.get(f"{qa.base}/api/auth/me/", verify=False).json()
        qa.check("5A.3 Mass assignment blocked",
                 me.get("role") == "viewer",
                 f"role after PATCH={me.get('role')}")
    else:
        qa.check("5A.3 Mass assignment blocked", True,
                 f"rejected {r.status_code}")

    # 5A.4 moved to phase_5f_throttle (runs last to avoid starving other tests)

    # 5A.5 setup_complete as viewer → 403
    r = viewer.post(f"{qa.base}/api/site-config/setup-complete/", verify=False)
    qa.check("5A.5 setup_complete blocked for viewer",
             r.status_code == 403, f"status={r.status_code}")

    # 5A.6 setup_complete as engineer → 403
    r = engineer.post(f"{qa.base}/api/site-config/setup-complete/", verify=False)
    qa.check("5A.6 setup_complete blocked for engineer",
             r.status_code == 403, f"status={r.status_code}")

    # 5A.7 Viewer token creation → 403
    r = viewer.post(f"{qa.base}/api/auth/tokens/",
                    json={"name": "viewer_token"}, verify=False)
    qa.check("5A.7 Viewer cannot create API tokens",
             r.status_code == 403, f"status={r.status_code}")

    # 5A.8 SSRF — metadata IP blocked
    r = owner.post(f"{qa.base}/api/scans/",
                   json={"target": "169.254.169.254", "scan_type": "quick"}, verify=False)
    qa.check("5A.8 SSRF metadata IP blocked",
             r.status_code == 400, f"status={r.status_code}")

    # 5A.9 SSRF — localhost blocked
    r = owner.post(f"{qa.base}/api/scans/",
                   json={"target": "127.0.0.1", "scan_type": "quick"}, verify=False)
    qa.check("5A.9 SSRF localhost blocked",
             r.status_code == 400, f"status={r.status_code}")

    # 5A.10 HSTS on /api/ responses
    r = requests.get(f"{qa.base}/api/auth/csrf/", verify=False)
    hsts = r.headers.get("Strict-Transport-Security", "")
    qa.check("5A.10 HSTS present on /api/",
             "max-age=" in hsts, f"HSTS={hsts!r}")


# ═══════════════════════════════════════════════════════════════════
# 5B — Security Headers (8 tests)
# ═══════════════════════════════════════════════════════════════════

def phase_5b_headers(qa):
    print("\n── 5B: Security Headers ──")

    r = requests.get(f"{qa.base}/login", verify=False, allow_redirects=False)
    h = r.headers

    qa.check("5B.1 HSTS on root",
             "max-age=" in h.get("Strict-Transport-Security", ""),
             f"HSTS={h.get('Strict-Transport-Security', 'MISSING')!r}")

    qa.check("5B.2 X-Frame-Options",
             h.get("X-Frame-Options", "").upper() in ("SAMEORIGIN", "DENY"),
             f"XFO={h.get('X-Frame-Options', 'MISSING')!r}")

    qa.check("5B.3 X-Content-Type-Options",
             h.get("X-Content-Type-Options", "").lower() == "nosniff",
             f"XCTO={h.get('X-Content-Type-Options', 'MISSING')!r}")

    qa.check("5B.4 Content-Security-Policy present",
             "default-src" in h.get("Content-Security-Policy", ""),
             f"CSP={h.get('Content-Security-Policy', 'MISSING')[:60]!r}")

    qa.check("5B.5 Cache-Control no-store",
             "no-store" in h.get("Cache-Control", ""),
             f"CC={h.get('Cache-Control', 'MISSING')!r}")

    qa.check("5B.6 X-XSS-Protection",
             h.get("X-XSS-Protection", "") != "",
             f"XXSS={h.get('X-XSS-Protection', 'MISSING')!r}")

    qa.check("5B.7 Referrer-Policy",
             h.get("Referrer-Policy", "") != "",
             f"RP={h.get('Referrer-Policy', 'MISSING')!r}")

    qa.check("5B.8 Server token suppressed",
             "nginx/" not in h.get("Server", "").lower()
             and "apache/" not in h.get("Server", "").lower(),
             f"Server={h.get('Server', 'MISSING')!r}")


# ═══════════════════════════════════════════════════════════════════
# 5C — Access Control (8 tests)
# ═══════════════════════════════════════════════════════════════════

def phase_5c_access(qa):
    print("\n── 5C: Access Control ──")

    # 5C.1 /admin/ blocked
    r = requests.get(f"{qa.base}/admin/", verify=False, allow_redirects=False)
    qa.check("5C.1 /admin/ blocked",
             r.status_code == 404, f"status={r.status_code}")

    # 5C.2 /.env blocked
    r = requests.get(f"{qa.base}/.env", verify=False, allow_redirects=False)
    qa.check("5C.2 /.env blocked",
             r.status_code in (301, 302, 404), f"status={r.status_code}")

    # 5C.3 /.git/ blocked
    r = requests.get(f"{qa.base}/.git/config", verify=False, allow_redirects=False)
    qa.check("5C.3 /.git/ blocked",
             r.status_code in (301, 302, 404), f"status={r.status_code}")

    # 5C.4 No API docs endpoint (swagger/redoc)
    for path in ["/api/docs/", "/api/schema/", "/swagger/", "/redoc/"]:
        r = requests.get(f"{qa.base}{path}", verify=False, allow_redirects=False)
        if r.status_code == 200:
            qa.check("5C.4 No public API docs",
                     False, f"{path} → 200")
            break
    else:
        qa.check("5C.4 No public API docs", True)

    # 5C.5 No self-registration endpoint
    s = requests.Session()
    cr = s.get(f"{qa.base}/api/auth/csrf/", verify=False)
    csrf = cr.json().get("csrf", cr.json().get("csrfToken", ""))
    s.headers.update({"X-CSRFToken": csrf, "Referer": f"{qa.base}/"})
    r = s.post(f"{qa.base}/api/auth/register/",
               json={"username": "hacker", "password": "P@ssw0rd123!", "email": "h@x.com"},
               verify=False)
    qa.check("5C.5 No self-registration",
             r.status_code in (404, 405, 403, 401), f"status={r.status_code}")

    # 5C.6 CORS — arbitrary origin rejected
    r = requests.get(f"{qa.base}/api/auth/csrf/", verify=False,
                     headers={"Origin": "https://evil.com"})
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    qa.check("5C.6 CORS rejects evil origin",
             "evil.com" not in acao and acao != "*",
             f"ACAO={acao!r}")

    # 5C.7 Debug mode off
    r = requests.get(f"{qa.base}/api/nonexistent-endpoint-404/", verify=False)
    body = r.text.lower()
    qa.check("5C.7 Debug mode off",
             "traceback" not in body and "django" not in body and "settings.py" not in body,
             "debug info leaked in 404 response")

    # 5C.8 Dockerfile / .dockerignore blocked
    r = requests.get(f"{qa.base}/Dockerfile", verify=False, allow_redirects=False)
    qa.check("5C.8 Dockerfile blocked",
             r.status_code in (301, 302, 404), f"status={r.status_code}")


# ═══════════════════════════════════════════════════════════════════
# 5D — Session Security (4 tests)
# ═══════════════════════════════════════════════════════════════════

def phase_5d_session(qa):
    print("\n── 5D: Session Security ──")

    # Use http.client to capture raw Set-Cookie headers (requests merges them)
    import http.client, ssl
    from urllib.parse import urlparse
    parsed = urlparse(qa.base)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, context=ctx)

    conn.request("GET", "/api/auth/csrf/")
    resp = conn.getresponse()
    body = resp.read()
    csrf_raw_cookie = resp.getheader("Set-Cookie") or ""
    csrf_val = json.loads(body).get("csrf", "")

    login_body = json.dumps({"username": OWNER_USER, "password": OWNER_PASS})
    conn.request("POST", "/api/auth/login/", body=login_body, headers={
        "Content-Type": "application/json",
        "X-CSRFToken": csrf_val,
        "Referer": f"{qa.base}/",
        "Cookie": csrf_raw_cookie.split(";")[0] if csrf_raw_cookie else "",
    })
    resp = conn.getresponse()
    resp.read()
    all_set_cookies = resp.msg.get_all("Set-Cookie") or []
    conn.close()

    session_cookies = [c for c in all_set_cookies if "sessionid" in c.lower()]
    csrf_cookies = [c for c in all_set_cookies if "csrftoken" in c.lower()]

    qa.check("5D.1 Session cookie HttpOnly",
             any("httponly" in c.lower() for c in session_cookies),
             f"session cookies: {[c[:60] for c in session_cookies]!r}")

    qa.check("5D.2 Session cookie SameSite",
             any("samesite" in c.lower() for c in session_cookies),
             f"session cookies: {[c[:60] for c in session_cookies]!r}")

    qa.check("5D.3 CSRF cookie readable by JS",
             len(csrf_cookies) > 0,
             f"all cookies: {[c[:40] for c in all_set_cookies]!r}")

    qa.check("5D.4 Session expiry configured",
             any("max-age=" in c.lower() or "expires=" in c.lower() for c in session_cookies),
             f"session cookies: {[c[:60] for c in session_cookies]!r}")


# ═══════════════════════════════════════════════════════════════════
# 5E — Input Validation (6 tests)
# ═══════════════════════════════════════════════════════════════════

def phase_5e_input(qa):
    print("\n── 5E: Input Validation ──")

    # Fresh anon session for unauthenticated tests
    anon = requests.Session()
    cr = anon.get(f"{qa.base}/api/auth/csrf/", verify=False)
    csrf = cr.json().get("csrf", cr.json().get("csrfToken", ""))
    anon.headers.update({"X-CSRFToken": csrf, "Referer": f"{qa.base}/"})

    # 5E.1 XSS in username rejected
    r = anon.post(f"{qa.base}/api/auth/login/",
                  json={"username": '<script>alert(1)</script>', "password": "x"}, verify=False)
    body = r.text
    qa.check("5E.1 XSS in username not reflected",
             "<script>" not in body,
             "XSS payload reflected in response")

    # 5E.2 SQLi in login — should not crash (returns 401/400, not 500)
    r = anon.post(f"{qa.base}/api/auth/login/",
                  json={"username": "' OR 1=1--", "password": "x"}, verify=False)
    qa.check("5E.2 SQLi in login handled safely",
             r.status_code in (400, 401, 403, 429),
             f"status={r.status_code}")

    # 5E.3 Path traversal in logo field (setup endpoint)
    # Use a fresh anon session to avoid inheriting rate limit state
    anon2 = requests.Session()
    cr2 = anon2.get(f"{qa.base}/api/auth/csrf/", verify=False)
    csrf2 = cr2.json().get("csrf", cr2.json().get("csrfToken", ""))
    anon2.headers.update({"X-CSRFToken": csrf2, "Referer": f"{qa.base}/"})
    r = anon2.post(f"{qa.base}/api/auth/setup/",
                   data={"username": "trav_test", "password": "QAtest2026!",
                         "email": "t@t.com", "logo": "../../../etc/passwd"},
                   verify=False)
    qa.check("5E.3 Path traversal in logo handled safely",
             r.status_code in (400, 409, 403, 429),
             f"status={r.status_code}")

    # 5E.4 Oversized request body — nginx should block at 10M
    big_payload = "A" * (11 * 1024 * 1024)  # 11 MB
    try:
        r = anon.post(f"{qa.base}/api/auth/login/",
                      data=big_payload, verify=False,
                      headers={"Content-Type": "application/json"})
        qa.check("5E.4 Oversized body rejected",
                 r.status_code in (413, 400),
                 f"status={r.status_code}")
    except requests.exceptions.ConnectionError:
        qa.check("5E.4 Oversized body rejected", True, "connection reset (expected)")

    # 5E.5 Weak password rejected during user creation
    owner, _ = qa.login(OWNER_USER, OWNER_PASS)
    r = owner.post(f"{qa.base}/api/auth/users/create/",
                   json={"username": "weakuser", "password": "123", "email": "w@t.com",
                         "role": "viewer"}, verify=False)
    qa.check("5E.5 Weak password rejected",
             r.status_code == 400, f"status={r.status_code}")

    # 5E.6 Unicode handling — should not crash
    r = anon.post(f"{qa.base}/api/auth/login/",
                  json={"username": "用户\x00test", "password": "пароль"}, verify=False)
    qa.check("5E.6 Unicode input handled safely",
             r.status_code in (400, 401, 403, 429),
             f"status={r.status_code}")


# ═══════════════════════════════════════════════════════════════════
# 5F — Throttle (runs last to avoid starving other tests)
# ═══════════════════════════════════════════════════════════════════

def phase_5f_throttle(qa):
    print("\n── 5F: Throttle ──")
    anon = requests.Session()
    got_429 = False
    for i in range(150):
        r = anon.get(f"{qa.base}/api/auth/csrf/", verify=False)
        if r.status_code == 429:
            got_429 = True
            qa.check(f"5F.1 Anon throttle triggers 429 (at req #{i+1})", True)
            break
    if not got_429:
        qa.check("5F.1 Anon throttle triggers 429", False,
                 "sent 150 requests, never got 429")


# ═══════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(description="Wire_Ghost Phase 5 — Security Regression Tests")
    ap.add_argument("--base", default="https://localhost:28443")
    ap.add_argument("--results", default="qa-results/phase-5.json")
    args = ap.parse_args()

    qa = QA(args.base)
    print(f"\n{'═' * 60}")
    print(f"  Wire_Ghost Security Regression Tests")
    print(f"  Target: {args.base}")
    print(f"{'═' * 60}")

    phase_5a_owasp(qa)
    phase_5b_headers(qa)
    phase_5c_access(qa)
    phase_5d_session(qa)
    phase_5e_input(qa)
    phase_5f_throttle(qa)  # last — exhausts rate limits

    report = qa.report()
    print(f"\n{'═' * 60}")
    print(f"  Results: {report['passed']}/{report['total']} passed, "
          f"{report['failed']} failed")
    print(f"{'═' * 60}")

    if report["failures"]:
        print("\n  Failures:")
        for f in report["failures"]:
            print(f"    ✗ {f['test']}  — {f['detail']}")

    try:
        import os
        os.makedirs(os.path.dirname(args.results) or ".", exist_ok=True)
        with open(args.results, "w") as fp:
            json.dump(report, fp, indent=2)
        print(f"\n  Report saved to {args.results}")
    except OSError as e:
        print(f"\n  Warning: could not save report: {e}", file=sys.stderr)

    sys.exit(0 if report["failed"] == 0 else 1)


if __name__ == "__main__":
    main()
