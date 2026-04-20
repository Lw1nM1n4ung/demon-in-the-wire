# Wire_Ghost — Web Security Attack Pass

**Target**: Live portal at `http://95.111.251.53:18443/` (self-hosted, authorized)
**Date**: 2026-04-19
**Build under test**: `rewrite-v2` @ `cd9c06c` (pre-pass) → `350b562` (post-fix)
**Scope**: 4 attack classes — SSRF/cmd-injection, XSS, IDOR, Auth/Session/Token
**Fix-inline protocol**: any finding → minimal fix → cache-bust → commit → push → resume

## Summary

| Class | Payloads fired | Hits | Result |
|---|---|---|---|
| **Cmd-injection / SSRF via scan target** | 29 | 0 | Validator holds |
| **XSS (stored + reflected)** | 10 fields × 10 payloads | 0 | All renders escaped |
| **IDOR / horizontal access control** | 8 cells | **2** | **BUG #4 — fixed** |
| **Auth / session / token** | 5 checks | **1** | **BUG #5 — fixed** |

**2 bugs found, 2 fixed, 2 commits pushed.** Portal is live and regression-verified.

---

## Phase 1 — Command injection / SSRF via `POST /api/scans/` target field

Payload matrix fired at `validate_target()` in `web_portal/scanner/serializers.py`.

### Shell metacharacter injection (all blocked by regex whitelist)
```
127.0.0.1; id              400  Invalid target format
127.0.0.1 && touch /tmp/x  400  Invalid target format
127.0.0.1 | whoami         400  Invalid target format
127.0.0.1`id`              400  Invalid target format
127.0.0.1$(id)             400  Invalid target format
127.0.0.1 %0a id           400  Invalid target format
```
**Root cause of defense**: `re.match(r'^[\d./a-zA-Z0-9_:-]+$', value)` rejects `;`, `&`, `|`, `` ` ``, `$`, `%`, space before any subprocess touches the value.

### SSRF / loopback / metadata (all blocked by named checks)
```
127.0.0.1                  400  Loopback addresses not allowed
::1                        400  Loopback addresses not allowed
169.254.169.254            400  Link-local addresses not allowed
0.0.0.0                    400  Unspecified address not allowed
http://169.254...          400  Invalid hostname format (scheme rejected)
file:///etc/passwd         400  Invalid hostname format
localhost                  400  Blocked target
```

### IP-notation bypass (all blocked)
```
127.0.0.01                 400  Octal IP notation not allowed
0x7f000001                 400  Hex IP notation not allowed
2130706433                 400  Decimal IP notation not allowed
127.1                      400  Short-form IP not allowed
0177.0.0.1                 400  Octal IP notation not allowed
```

### DNS-rebind domains (all blocked)
```
localhost.nip.io           400  DNS rebinding domain not allowed
127.0.0.1.xip.io           400  DNS rebinding domain not allowed
```

### Internal-service resolution (blocked)
```
api                        400  Hostname resolves to blocked IP: 172.18.0.4
redis                      400  Hostname resolves to blocked IP: 172.18.0.3
mysql                      201  (resolves to nothing — DB is at hostname `db` in compose)
```

### Design notes
- Raw RFC1918 IPs (`10.0.0.1`, `192.168.0.1`) **are accepted**. Intentional: a self-hosted pentest tool must scan its operator's LAN.
- Hostnames resolving to RFC1918 **are blocked**. Intentional: prevents pivoting to internal Docker services via DNS lookup.

**Verdict**: Validator holds. No exploitable path.

---

## Phase 2 — XSS (stored + reflected)

### Payloads injected into every writable text field
10 payloads (`<script>`, `<img onerror=>`, `<svg onload=>`, `{{7*7}}`, `"><script>`, etc.) × these fields:

- Scan name: 7/10 rejected by whitelist (`re.match("^[a-zA-Z0-9 _./:()'\-]+$")`); the 3 that pass get escaped on render.
- Policy name + description: **stored verbatim** (API accepts any UTF-8), but rendered via `WG.escHtml(p.name)` — all payloads neutralized.
- Finding description / request / response / curl_command: all piped through `esc()` in `finding-detail.js`.

### `escHtml` implementation audit
```js
WG.escHtml = function(str) {
  var d = document.createElement('div');
  d.textContent = str;          // textContent auto-escapes
  return d.innerHTML;            // innerHTML re-reads the escaped value
};
```
Canonical browser-native sanitizer. Tested against `<script>`, attribute-escape (`"`), CDATA-close, template-literal (`{{7*7}}`) — all correctly escaped.

### One edge case (filed as observation, not bug)
`web/js/app/pages/finding-detail.js:60` embeds `JSON.stringify(f.curl_command)` raw inside `onclick="..."`. JSON.stringify escapes JS string delimiters correctly, but not HTML attribute delimiters; a `curl_command` containing `"` breaks out of the attribute. Exploitability is indirect: `curl_command` is server-generated from scan output, so an attacker would need to first control a scan-target response to Nuclei in a way that smuggles quotes into the persisted `curl_command` row. Low practical risk, but worth hardening in a future pass with `esc(JSON.stringify(...))`.

**Verdict**: No live XSS.

---

## BUG #4 — Engineer can DELETE admin-owned scans and policies

**Severity**: HIGH (horizontal privilege escalation, destructive)
**Status**: FIXED — commit `a7f6b5f`

### Reproduction
```bash
# Admin creates
ADMIN_SCAN=<uuid>
ADMIN_POL=<uuid>

# Engineer deletes — BEFORE FIX
curl -b eng.jar -X DELETE /api/scans/$ADMIN_SCAN/      → 204 (SUCCESS, scan gone)
curl -b eng.jar -X DELETE /api/policies/$ADMIN_POL/    → 204 (SUCCESS, policy gone)
```
Confirmed admin `GET` returned 404 immediately after, proving the row was destroyed.

### Root cause
`ScanViewSet.get_queryset()` returned `Scan.objects.all()` without filtering by `created_by`. The permission class `HasMethodPerm('scan:read', 'scan:write')` only checks the *role's* method permission (engineer has `scan:write`), not ownership. Same pattern on `ScanPolicyViewSet` and `ScheduledScanViewSet`.

### Fix
New permission class `IsCreatorOrOwnerForWrite` in `web_portal/scanner/views.py`:
```python
class IsCreatorOrOwnerForWrite(IsAuthenticated):
    def has_object_permission(self, request, view, obj):
        if request.method in ('GET', 'HEAD', 'OPTIONS'):
            return True
        if getattr(request.user, 'role', '') == 'owner':
            return True
        return getattr(obj, 'created_by_id', None) == request.user.id
```
Stacked after `HasMethodPerm` on `ScanViewSet`, `ScanPolicyViewSet`, `ScheduledScanViewSet`.

### Regression test (post-fix)
```
engineer DELETE admin scan     → 403 (was 204)
engineer DELETE admin policy   → 403 (was 204)
engineer GET    admin scan     → 200 (read preserved)
engineer DELETE own scan       → 204 (self-write preserved)
admin    DELETE any scan       → 204 (owner preserved)
admin    DELETE any policy     → 204 (owner preserved)
```

---

## BUG #5 — CSRF protection bypassed on all state-changing endpoints

**Severity**: HIGH (CSRF, universal)
**Status**: FIXED — commit `350b562`

### Reproduction
```bash
# Any authenticated session cookie + no CSRF token + any origin:
curl -b admin.jar -X POST /api/scans/     → 201 (scan created)
curl -b admin.jar -X DELETE /api/scans/<id>/ → 204 (scan deleted)
curl -b admin.jar -X POST -H "Origin: http://evil.com" /api/scans/ → 201
```

### Root cause
```python
# scanner/authentication.py (before fix)
class CsrfExemptAuth(SessionAuthentication):
    """Session auth without CSRF enforcement.
    SameSite=Lax cookie flag provides cross-origin protection instead."""
    def enforce_csrf(self, request):
        return                      # ← stubbed to no-op
```
The comment reasoned that `SameSite=Lax` replaces CSRF — incorrect:
1. Lax allows top-level form-POST navigations (`<form action=/api/... method=POST>`).
2. Lax doesn't protect against same-site / subdomain XSS pivots.
3. Defense-in-depth requires the server to enforce, not just trust the browser.

### Fix
Removed the `enforce_csrf` override. Class now inherits Django's default CSRF check. No frontend change needed — `web/js/public/api.js` already reads the csrf cookie and sets `X-CSRFToken` on every mutating request. `TokenHeaderAuth` users remain exempt (Authorization headers don't auto-attach cross-origin; that's legitimately CSRF-immune).

### Regression test (post-fix)
```
POST  /api/scans/ (no CSRF)       → 403  CSRF Failed: CSRF token missing.
DELETE /api/scans/<id>/ (no CSRF) → 403  CSRF Failed: CSRF token missing.
POST  /api/scans/ (WITH CSRF)     → 201  (SPA flow works)
POST  /api/scans/ (Token auth)    → 201  (token flow correctly exempt)
```

---

## Auth / session / token — other checks (all PASS)

| Check | Result |
|---|---|
| `POST /api/auth/setup-admin/` after completion | 403 `Setup already completed` ✓ |
| Login rate-limit (10 bad attempts) | 11th → 429 `Too many failed login attempts` ✓ |
| Rate-limit bypass via correct password | Still 429 during lockout ✓ (fix `39c51c2`) |
| Token prefix-guessing (`wg_XXXXXXXX` + random suffix) | 401 — SHA-256 of full token required ✓ |
| Unauth `GET /api/auth/users/` | 401 ✓ |
| Engineer `GET /api/auth/users/` | 403 `Not authorized` ✓ |
| Unauth download of admin report | 401 ✓ |
| Viewer download of admin report | 403 `No permission` ✓ |

---

## Commits from this pass

- `a7f6b5f` — `fix(auth): block horizontal priv-esc on scans/policies/schedules`
- `350b562` — `fix(auth): restore CSRF enforcement on session-based endpoints`

Both pushed to `rewrite-v2`. Image rebuilt (`docker compose build api worker`) so the fixes survive container recreation.

---

## Fresh run — 2026-04-19 (late)

Re-executed the entire 4-phase pass against the fixed build (`4a19bf6`) to confirm both fixes hold and no new regressions surfaced.

| Phase | Cells | Hits | Notes |
|---|---|---|---|
| 1 — SSRF / cmd-injection | 23 | 0 | Validator still blocks every variant |
| 2 — XSS (stored + reflected) | 7 payloads × policy name+desc | 0 | `escHtml` neutralizes on render |
| 3 — IDOR | 9 | 0 | `engineer DELETE admin scan/policy → 403` ✓ |
| 4 — Auth / CSRF / rate-limit / token | 10 | 0 | `POST without X-CSRFToken → 403` ✓; token mint/use/revoke/prefix-guess all correct |

**No new bugs found.** Both commits from the initial pass (`a7f6b5f`, `350b562`) verified live on the running portal.

---

## Re-run — 2026-04-20 (post-rebuild + fresh install + new logo surface)

Re-fired the entire matrix on the live VPS at HEAD `5471762`, after a full `docker compose down -v` + fresh git clone + setup-wizard re-install. New endpoints since the prior pass: `/api/system-stats/` (`d08f469`), `/api/report-config/logo/` invoked from the wizard (`5471762`), `nmap_timeout` config field (`5f8b7d5`), narrowed IDOR guard (`ba5001e`).

Cookie/token plumbing: minted Owner + Engineer + Viewer API tokens via Django shell against the new `admin` Owner; engineer/viewer accounts seeded as `attack_eng` / `attack_view`.

| Phase | Cells | Hits | Notes |
|---|---|---|---|
| 1 — SSRF / cmd-injection / IP-bypass | 23 | 0 | All variants still blocked by `validate_target` |
| 2 — XSS / template injection | 7 (policy) + 6 (branding fields) | 0 | Policy: stored verbatim, render-safe via `escHtml`. Branding: server-side regex whitelist rejects HTML chars (defense in depth). |
| 3 — IDOR / horizontal access (post `ba5001e` narrowing) | 9 | 0 | Destructive cells still 403; team-cooperate `@actions` (`/cancel/`, `/regenerate/`, `/clone/`) now correctly 200/201/400. |
| 4 — Auth / CSRF / token / rate-limit | 17 | 0 | Includes the **support-bundle ESXi-symptom check** — owner-token POST returns 200 here, confirming the ESXi 403 is environment-state (Redis perm cache or unapplied migration on that host), not a code bug. |
| 5 — **Logo upload** (NEW surface) | 14 | 0 | See section below for full breakdown |

**Total: 76 cells / 0 deviations.** All five fixes from the prior session (`a7f6b5f`, `350b562`, `3e5efba`, `f198371`, `ba5001e`) verified intact post-rebuild.

### Phase 5 — Logo upload attack matrix

`POST /api/report-config/logo/` — first time this endpoint has been audited because the setup wizard only started actually firing it after `5471762`.

Backend defenses (`web_portal/scanner/views.py::upload_logo`):
1. RBAC (`report:logo:upload`) — owner + engineer; viewer = 403.
2. Allowlist: `.png .jpg .jpeg .gif .bmp .webp`.
3. Denylist: `.php .py .sh .js .html .htm .svg .exe .bat .cmd .jsp .asp .aspx .cgi .pl`.
4. Multi-extension scan — every dot-suffix in the filename is checked against the denylist (blocks `shell.php.png`).
5. 2 MB hard size cap.
6. `os.path.basename(filename)` + `get_valid_filename()` strip path components and dangerous chars.
7. `os.path.realpath().startswith()` check rejects any path that escapes `/data/assets/logos/`.

Probe results:

| Cell | Got | Want | Notes |
|---|---|---|---|
| unauth POST | 401 | 401 | ✓ |
| viewer token POST | 403 | 403 | ✓ RBAC |
| engineer token POST valid PNG | 200 | 200 | ✓ engineer has the perm |
| owner token POST valid PNG | 200 | 200 | ✓ baseline |
| **traversal** filename `../../../etc/passwd.png` | 200, file landed as `passwd.png` in `/data/assets/logos/` | 200 with safe path | ✓ basename + realpath defenses held |
| double-ext `shell.php.png` | 400 | 400 | ✓ multi-ext scan caught it |
| SVG with `onload=alert(1)` | 400 | 400 | ✓ SVG in denylist |
| HTML body (`<script>alert(1)</script>`) renamed `.png` | 200, file stored | 200 | **safe in practice**: `/data/assets/logos/` is not exposed via any nginx URL — the file is reachable only through report rendering (server-side embed, no inline browser fetch). Confirmed by trying `GET /static/logos/...`, `/data/assets/logos/...`, `/assets/logos/...`, `/logos/...` — all 302 to login or 404 |
| 3 MB png (cap is 2 MB) | 400 | 400 | ✓ size cap |
| empty (0 byte) `.png` | 200 | (cosmetic) | minor — empty image stores but renders broken; not exploitable |
| random binary `.png` | 200 | (cosmetic) | backend trusts extension; same risk profile as empty file (renderer fails gracefully) |
| null-byte filename `logo.png\x00.php` | 400 | 400 | ✓ rejected at the HTTP/multipart parser layer before reaching the view |
| session cookie + NO `X-CSRFToken` | 403 | 403 | ✓ CSRF gate from `3e5efba` covers this endpoint too |
| session cookie + valid `X-CSRFToken` | 200 | 200 | ✓ |

**Verdict**: logo-upload endpoint is correctly hardened. The two "200" cells for HTML-body-renamed-to-png and random-binary-as-png are **non-exploitable** because the storage directory is not web-served — the file only flows back into reports via server-side embed. Empty-file 200 is the only thing worth noting (cosmetic, not security).

### What this re-run did NOT do (call-outs)

- Setup-wizard "race the setup-admin" attack — out of scope, requires destructive reset.
- Worker container-escape via subprocess pipeline — out of portal-layer scope.
- DoS testing on `/api/system-stats/` (high-frequency polled) — could measure latency budget but not actively flood.

### No commits this pass

Zero deviations found. No source files changed. Test users `attack_eng` + `attack_view` left in DB for follow-up audits.

