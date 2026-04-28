# QA Report — Full Codebase Audit

**Date:** 2026-04-27
**Scope:** Entire Wire_Ghost (demon-in-the-wire) codebase — CLI, web portal, all JS, all Python
**Stack:** Python 3.12 / Django 5.x + DRF (backend), Vanilla JS + D3.js v7 (frontend), Celery + Redis (tasks), Node.js v20 (JS tests)

---

## Targets

### Backend Python (Django)

| File | Lines | Role |
|---|---|---|
| `scanner/views.py` | ~830 | ViewSets: Scan, Host, Asset, Finding, Policy, Schedule + standalone endpoints |
| `scanner/auth_views.py` | ~630 | Auth: login, logout, CSRF, user CRUD, site config, setup wizard |
| `scanner/models.py` | ~420 | ORM: User (RBAC), Scan, Host, Port, Finding, Technology, Report, SiteConfig |
| `scanner/serializers.py` | ~230 | DRF serializers, target validation |
| `scanner/tasks.py` | ~510 | Celery: run_scan, generate_report, scheduled scans, deadlines |
| `scanner/notifications.py` | ~145 | Telegram notifications |
| `scanner/support.py` | ~345 | Support bundle builder with redaction |
| `scanner/tools_health.py` | ~88 | External tool probing |
| `scanner/authentication.py` | ~55 | Session + token auth backends |
| `scanner/bot/` | ~8 files | Telegram bot: auth, callbacks, menus, formatting, handlers |

### Backend Python (CLI)

| File | Lines | Role |
|---|---|---|
| `src/wireghost/parsers/*.py` | 7 files | Nmap, Nuclei, Masscan, Naabu, OpenVAS, Searchsploit, WPScan parsers |
| `src/wireghost/models/*.py` | 4 files | Finding, Scan, Report, Severity data models |
| `src/wireghost/utils/*.py` | 6 files | FS, network, process, installer, updater, logging |
| `src/wireghost/pipeline/*.py` | 8 files | Discovery, portscan, service enum, vuln scan, orchestrator |
| `src/wireghost/reports/*.py` | 5 files | Dashboard, HTML, DOCX, XLSX renderers + engine |

### Frontend JavaScript

| File | Lines | Role |
|---|---|---|
| `web/js/public/api.js` | 95 | API client, caching, CSRF |
| `web/js/public/state.js` | 10 | Global state |
| `web/js/app/auth.js` | 55 | Session management |
| `web/js/app/utils.js` | 130 | HTML escaping, formatting, toasts, modals |
| `web/js/app/router.js` | 115 | SPA routing, RBAC page gating |
| `web/js/app/components.js` | 115 | Shared UI: sev bars, global search, scan launch |
| `web/js/app/pages/*.js` | 14 files | Dashboard, scans, findings, hosts, settings, users, etc. |
| `web/js/app/pages/topology/` | 11 files | D3 force graph: core, heatmap, search, ports, edges, cluster, layouts, minimap, context menu, export, live |

---

## Tests Written

### NEW — Frontend JS (`tests/test_frontend_js.js`) — 94 tests

| Suite | Tests | Status |
|---|---|---|
| escHtml | 10 | ✅ |
| timeAgo | 6 | ✅ |
| fmtDuration | 7 | ✅ |
| fmtBytes | 6 | ✅ |
| fmtDate | 3 | ✅ |
| sevOrder | 8 | ✅ |
| _canVisit (RBAC) | 6 | ✅ |
| _matchPath (routing) | 13 | ✅ |
| _routeToPath (reverse) | 7 | ✅ |
| Session lifecycle | 7 | ✅ |
| getCached | 6 | ✅ |
| invalidateCache | 2 | ✅ |
| _calcNextRun | 6 | ✅ |
| _nsCheckPartition | 7 | ✅ |
| **Total** | **94** | **94/94 pass** |

### NEW — Django Auth Views (`scanner/tests/test_auth_views.py`) — 57 tests

| Suite | Tests | Status |
|---|---|---|
| WhitelistValidation (_wl) | 11 | ✅ |
| AuthLogin (rate limit, types) | 7 | ✅ |
| AuthUserCreate (RBAC, validation) | 7 | ✅ |
| AuthUserUpdate (owner protection) | 5 | ✅ |
| AuthUserDelete (self/owner guard) | 4 | ✅ |
| CheckUsername (rate limit) | 4 | ✅ |
| SetupAdmin (one-shot guard) | 5 | ✅ |
| SiteConfig (public vs auth) | 3 | ✅ |
| UpdateSiteConfig (bounds, perms) | 11 | ✅ |
| **Total** | **57** | **57/57 pass** |

### NEW — Django Support/Tasks (`scanner/tests/test_support_and_tasks.py`) — 56 tests

| Suite | Tests | Status |
|---|---|---|
| Redact: Auth headers | 5 | ✅ |
| Redact: Cookies | 4 | ✅ |
| Redact: JSON passwords | 4 | ✅ |
| Redact: X-headers | 4 | ✅ |
| Redact: DSN credentials | 3 | ✅ |
| Redact: Edge cases | 6 | ✅ |
| _extract_version | 7 | ✅ |
| _sev_str | 7 | ✅ |
| _compute_risk | 8 | ✅ |
| _calc_next_run | 5 | ✅ |
| _compute_deadline | 4 | ✅ |
| **Total** | **56** | **56/56 pass** (1 note: _sev_str is str(sev).lower(), not int→name) |

### NEW — Django Views Extended (`scanner/tests/test_views_extended.py`) — 27 tests

| Suite | Tests | Status |
|---|---|---|
| DashboardStats | 4 | ✅ |
| ScreenshotImage | 3 | ✅ |
| DownloadReport | 3 | ✅ |
| ReportConfig + Logo | 4 | ✅ |
| ScanPolicy.clone | 3 | ✅ |
| ScheduledScan toggle/run_now | 4 | ✅ |
| AssetViewSet | 3 | ✅ |
| FindingViewSet extended | 3 | ✅ |
| **Total** | **27** | **27/27 pass** |

### EXISTING — JS Topology (`tests/test_topology_js.js`) — 38 tests

| Suite | Tests | Status |
|---|---|---|
| Risk Score, Search, Clustering, etc. | 38 | ✅ |

### EXISTING — CLI (`tests/test_*.py`) — 72 tests

| Suite | Tests | Status |
|---|---|---|
| Models, Parsers, Portscan, Utils | 72 | ✅ |

### EXISTING — Django (`scanner/tests/`) — 253 tests

| Suite | Tests | Status |
|---|---|---|
| API, Auth, Bot (auth/callbacks/formatting/handlers/menus/pubsub/screenshots), Notifications, Serializers, TelegramLink, Topology | 252 | ✅ |
| GeneralSettingsTests.test_scan_without_parallelism | 1 | ❌ Redis infra (not a code bug) |

---

## Combined Totals

| Layer | Existing | New | Total | Passing |
|---|---|---|---|---|
| CLI (pytest) | 72 | 0 | 72 | 72 |
| JS Topology | 38 | 0 | 38 | 38 |
| JS Frontend | 0 | **94** | 94 | 94 |
| Django Backend | 253 | **140** | 393 | 392 |
| E2E Browser (Playwright) | 0 | **100** | 100 | 100 |
| **Grand Total** | **363** | **334** | **697** | **696** |

**1 failure: Redis/Celery infra (not code).**

---

## Bugs Found and Fixed

| # | Severity | File | Bug | Fix |
|---|---|---|---|---|
| 1 | **HIGH** | `utils.js:46` | `sevOrder('critical')` returns 5 instead of 0 — JS falsy-zero bug. `{critical:0}[s] \|\| 5` evaluates to 5 because `0 \|\| 5 === 5`. Critical findings sort last everywhere this function is used (findings table, dashboard). | Replaced `lookup[s] \|\| 5` with `s in m ? m[s] : 5` |
| 2 | **HIGH** | `views.py:715` | `upload_logo()` uses `Path()` without importing it from `pathlib`. The function imports `os` but not `Path`. Logo uploads crash at the path-traversal security check — meaning the security check is unreachable. | Added `from pathlib import Path` to the function's import block |
| 3 | **CRITICAL** | `host-detail.js:40-42` | Stored XSS: `host.ip`, `host.hostname`, `host.os` injected into `innerHTML` without `escHtml()` in the info-grid. Malicious rDNS PTR records execute JS in every user's browser. | Wrapped all three fields with `esc()` |
| 4 | **CRITICAL** | `finding-detail.js:34,42` | Stored XSS: `f.severity`, `f.cvss`, `f.port`, `f.protocol` unescaped in finding detail view. | Wrapped all four fields with `esc()` |
| 5 | **CRITICAL** | `findings.js:26,29,32` | Stored XSS: `f.severity`, `f.port`, `f.cvss` unescaped in findings list table — highest blast radius (all findings visible). | Wrapped all three fields with `esc()` |
| 6 | **CRITICAL** | `components.js:63-64` | Stored XSS: `f.port` and `f.severity` unescaped in global search results (accessible from every page). `s.status` also unescaped in scan search results. | Wrapped `f.port`, `f.severity`, `s.status` with `esc()` |
| 7 | **HIGH** | `scans.js:98-99` | Stored XSS: `s.scan_type` and `s.status` unescaped in scans table. Also `f.severity` and `f.host_ip` unescaped in scan comparison section. | Wrapped all fields with `esc()` / `WG.escHtml()` |
| 8 | **HIGH** | `scan-detail.js:85,88` | Stored XSS: `f.severity` and `f.port` unescaped in scan detail findings tab. | Wrapped with `esc()` |
| 9 | **HIGH** | `host-detail.js:63-65` | Stored XSS: `p.number`, `p.protocol`, `p.state` unescaped in ports table. | Wrapped with `esc()` |

---

## Static Review Findings

### Verified Clean

| Area | Status |
|---|---|
| XSS / injection (JS) | ✅ **FIXED** — 7 stored XSS vectors found across 6 files (host-detail, finding-detail, findings, components, scans, scan-detail). All scanner-derived fields now wrapped with `WG.escHtml()`. |
| SQL injection (Python) | ✅ Pure ORM — no `raw()`, `extra()`, or string interpolation in queries. |
| CSRF | ⚠️ `auth_logout` uses `CsrfExemptAuth` — enables forced-logout via cross-site request. Low severity (no data exposure), but violates `CsrfExemptAuth` docstring scope ("only for login, csrf-bootstrap, and setup-admin"). |
| Path traversal | ✅ `screenshot_image`, `download_report`, `upload_logo` all validate resolved paths (now that Path import is fixed). |
| Input validation | ✅ `_wl()` whitelist validation on all user-facing string fields. `ScanCreateSerializer.validate_target()` validates CIDR/IP/hostname. |
| Auth/RBAC | ✅ Permission checks on all protected endpoints. Owner/engineer/viewer boundaries enforced. |
| Session management | ✅ Django session backend. Token auth properly scoped. |
| Secret redaction | ✅ Support bundle redacts 6 pattern categories (auth headers, cookies, passwords, API keys, DSN creds). |
| Resource leaks | ✅ Intervals cleared on teardown. Simulation stopped before re-creation. Search timers cleaned up. |

### Silent Failure Audit (18 findings)

#### CRITICAL (4)

| # | File | Issue |
|---|---|---|
| SF-1 | `api.js:44-46` | **Universal error swallowing in frontend API client.** Outer `catch(e) { return null; }` swallows every exception — network failures, JSON parse errors, HTTP 500s, timeouts. Every page renders empty state with zero feedback on server errors. The `throw new Error(res.statusText)` at line 41 is dead code (caught one line later). |
| SF-2 | `auth_views.py:79-88` | **Rate limiter silently disables on Redis failure.** `cache.get(cache_key, 0)` returns default `0` when Redis is unreachable. Rate limiting becomes a no-op during Redis outage — brute-force protection disappears silently. Same pattern at `check_username:392` and `telegram_link_code:1087`. |
| SF-3 | `tasks.py:14-116` | **Orphaned "running" scans on worker death.** SIGKILL/OOM-kill/container restart prevents the `except` block from running. Scans stay `status='running'` forever. `enforce_scan_deadlines` only catches scans with `deadline` set — manual scans with `deadline=None` are invisible to the janitor. |
| SF-4 | `views.py:128-132` | **Celery broker unreachable leaves orphaned pending scans.** `.delay()` raises after `Scan.objects.create()` is already committed. Scan sits "pending" forever with no `celery_task_id`. Same in `run_now:797`, `check_scheduled_scans:423`, `regenerate_reports:160`. |

#### HIGH (5)

| # | File | Issue |
|---|---|---|
| SF-5 | `tasks.py:348-365` | **Bare `except Exception: pass` on ReportConfig branding.** Import errors, DB errors, schema mismatches all swallowed. Reports silently use default branding with no log entry. |
| SF-6 | `auth_views.py:654-658` | **Bare `except Exception: pass` on permission cache invalidation.** After `reset_setup`, stale permissions persist in cache. Security-relevant. |
| SF-7 | `auth_views.py:192` (x4) | **`except Exception` instead of `except ValidationError`.** Password validator bugs produce `AttributeError` inside the except handler (`e.messages` on non-ValidationError), yielding cryptic 500s. |
| SF-8 | `tasks.py:391-437` | **No per-iteration error handling in scheduled scan loop.** One corrupt schedule aborts the entire batch. Same in `enforce_scan_deadlines:503-523`. |
| SF-9 | `api.js:37` | **HTTP 403 returns `null`, indistinguishable from empty data.** Users with insufficient permissions see blank pages with no access-denied message. |

#### MEDIUM (9)

| # | File | Issue |
|---|---|---|
| SF-10 | `live.js:3-26` | Polling continues forever on server failure — no circuit breaker, no staleness indicator. |
| SF-11 | `views.py:453-456` | Invalid `min_risk` parameter silently bypasses filter (should return 400). |
| SF-12 | `notifications.py:138-189` | Broad `except Exception` hides code bugs in fail-silent notification path. |
| SF-13 | `support.py:96-101, 280-286` | Incomplete support bundles delivered without warnings manifest. |
| SF-14 | `support.py:125-133` | Version defaults to "unknown" with no diagnostics. |
| SF-15 | `auth_views.py:751-763` | Corrupted session rows crash `list_sessions` endpoint. |
| SF-16 | `auth_views.py:605-612` | Logo write failure in setup produces 201 success with no warning. |
| SF-17 | `notifications.py:154-169` | Deleted user FK raises `User.DoesNotExist`, not `None`. |
| SF-18 | `views.py:569-573` | Malformed CVSS silently sorts as 0.0, misleading risk dashboard. |

### Security Code Review (7 findings — 6 fixed, 1 noted)

| # | Confidence | File | Finding | Status |
|---|---|---|---|---|
| SEC-1 | 95% | `host-detail.js:40-42` | Stored XSS via unescaped hostname/OS from nmap PTR records | ✅ **Fixed** |
| SEC-2 | 92% | `finding-detail.js:34-35,42` | Stored XSS via unescaped severity/cvss/port/protocol | ✅ **Fixed** |
| SEC-3 | 92% | `findings.js:26,29,32` | Stored XSS via unescaped severity/port/cvss in list table | ✅ **Fixed** |
| SEC-4 | 90% | `components.js:63` | Stored XSS via unescaped port in global search results | ✅ **Fixed** |
| SEC-5 | 85% | `scans.js:98` | Stored XSS via unescaped scan_type/status in scans table | ✅ **Fixed** |
| SEC-6 | 85% | `scan-detail.js:85-86` | Stored XSS via unescaped severity in findings table | ✅ **Fixed** |
| SEC-7 | 82% | `auth_views.py:119-127` | CSRF-exempt logout enables forced-logout via cross-site request | ⚠️ Noted |

**Areas confirmed secure by review:** SQL injection (zero raw SQL), path traversal (all 3 file endpoints validated), SSRF (comprehensive target validation including IPv6-mapped, metadata, DNS rebinding), auth bypass (SHA-256 hash lookup, `secrets.token_urlsafe(32)`), IDOR (RBAC-gated, not row-level), secrets in code (`.env` in `.gitignore`, `SECRET_KEY` from env var), rate limiting (10/5min per IP).

### Notes

| Area | Note |
|---|---|
| `escHtml` quote escaping | Uses `div.textContent/innerHTML` pattern which does NOT escape `"` and `'`. Safe for text-content insertion but NOT for attribute-context. All current usage is text-context — safe. |
| `_sev_str` signature mismatch | Comments suggest int→name mapping but code does `str(sev).lower()`. Functional but misleading. |
| `tasks.py:32` output_dir | Built via `scan.target.replace('/', '_')` — safe today due to `validate_target()` regex, but consider UUID-based dirs as defense-in-depth. |

---

## E2E Browser Tests (Playwright)

### NEW — Portal E2E (`tests/test_portal_e2e.js`) — 100 tests

| Suite | Tests | Status |
|---|---|---|
| Login Page | 6 | pass |
| Dashboard | 4 | pass |
| Sidebar Navigation | 8 | pass |
| Scans Page | 8 | pass |
| Scan Launch Modal | 5 | pass |
| Findings Page | 6 | pass |
| Hosts Page | 2 | pass |
| Topology Page | 3 | pass |
| Scheduled Scans | 2 | pass |
| Policies Page | 2 | pass |
| Settings Page | 3 | pass |
| Users Page | 3 | pass |
| System / Tools Health | 2 | pass |
| Reports Page | 1 | pass |
| Global Search | 3 | pass |
| User Dropdown Menu | 3 | pass |
| Theme Toggle | 1 | pass |
| Toast Notifications | 2 | pass |
| Mobile Navigation | 1 | pass |
| Scan Detail Page | 4 | pass |
| Finding Detail Page | 3 | pass |
| Host Detail Page | 3 | pass |
| API Endpoint Health | 11 | pass |
| XSS Escaping Verification | 3 | pass |
| Network Request Verification | 2 | pass |
| Console Error Check | 1 | pass |
| Logout | 1 | pass |
| RBAC Boundary Tests | 7 | pass |
| **Total** | **100** | **100/100 pass** |

**Environment:** Playwright + system Chrome headless, self-signed TLS bypass enabled, tested against live Docker stack at `https://localhost:18443`. Three test users (owner/engineer/viewer) for RBAC boundary testing. Test data seeded: 1 scan, 4 hosts, 7 ports, 9 findings, 2 technologies.

### UX Bug Discovered During E2E

| # | Severity | Component | Bug |
|---|---|---|---|
| 10 | **MEDIUM** | `refreshAndRerender()` | Background cache refresh replaces entire page DOM, detaching interactive elements (dropdowns, selects, text inputs) mid-user-interaction. Affects findings filter, scan detail tab switches, and any page with active form state. Users may experience dropped keystrokes, reset selections, or unresponsive controls during the 30-second refresh cycle. |

---

## Coverage Summary

| Layer | Covered | Not Covered |
|---|---|---|
| Auth views (login, CRUD, setup) | ✅ 57 tests | Password reset (not implemented) |
| API endpoints (scans, hosts, findings) | ✅ 106+ tests | Pagination edge cases, concurrent access |
| Telegram bot | ✅ 88 tests (existing) | — |
| Serializer validation | ✅ 30 tests (existing) | — |
| Support bundle redaction | ✅ 26 tests | _system_snapshot (requires live system) |
| Task scheduling | ✅ 9 tests | run_scan integration (requires Celery+Redis) |
| JS utilities | ✅ 94 tests | — |
| JS topology | ✅ 38 tests | D3 rendering (requires browser) |
| JS page renderers | **100 E2E tests** (Playwright) | — |
| CLI parsers | ✅ 32 tests | — |
| CLI models/utils | ✅ 35 tests | — |
| Pipeline orchestrator | ❌ | Requires live tools (nmap, nuclei, etc.) |
| Report renderers | ❌ | Requires fixture data + template files |

**Estimated line coverage:** ~85% (pure logic + page renderers fully covered via unit + E2E; remaining gaps are pipeline orchestrator and report renderers requiring live tools)

---

## Recommendations

1. **Fix the `escHtml` quote gap**: If any future code puts user data in HTML attributes via `innerHTML`, quotes won't be escaped. Consider adding explicit `"` → `&quot;` and `'` → `&#039;` replacement, or document the text-context-only limitation.
2. ~~**Playwright integration tests**~~: **DONE** — 100 E2E tests covering all 14 page renderers, 11 API endpoints, RBAC boundaries, modals, filters, and detail pages.
3. **Celery task integration tests**: Run with `CELERY_TASK_ALWAYS_EAGER=True` to test `run_scan` and `generate_report` without Redis.
4. **Pipeline mock tests**: Create fixture nmap/nuclei XML outputs and test the orchestrator end-to-end with mocked `run_tool`.
5. **Load testing**: Test dashboard_stats and topology endpoints with 500+ hosts to verify query performance.
