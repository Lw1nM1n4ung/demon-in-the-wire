# Wire_Ghost v2.0 — Manual Test Matrix

16 scenarios requiring a human tester with the Docker stack running at `https://localhost:18443`.

## Prerequisites

- Docker stack running: `docker compose up -d`
- Admin account: `admin` / `QAtest2026!`
- Browser: Chrome or Firefox with HTTPS exception accepted

---

## Test Matrix

| # | Scenario | Steps | Expected Result | Pass? |
|---|----------|-------|-----------------|-------|
| M1 | First-launch setup | 1. `docker compose down -v && docker compose up -d` 2. Navigate to `https://localhost:18443` 3. Complete setup wizard (username, password, email) | Admin created, redirected to dashboard, all sidebar links work | [ ] |
| M2 | Scan a real target | 1. Click "New Scan" 2. Enter `scanme.nmap.org` 3. Select "Quick" scan type 4. Click "Start Scan" | Scan appears in list with "running" status, findings appear within 5 minutes | [ ] |
| M3 | Dashboard stats | 1. Complete a scan 2. Navigate to Dashboard | Stats cards show correct counts (scans, hosts, findings), severity chart renders, recent activity lists the scan | [ ] |
| M4 | Finding drill-down | 1. Navigate to Findings 2. Click any finding row | Detail panel shows: title, severity badge, description, evidence (request/response), curl command, references, host/port | [ ] |
| M5 | Report download (DOCX) | 1. Navigate to Reports 2. Click download for a DOCX report | File downloads, opens in Word/LibreOffice, contains formatted findings with severity colors and cover page | [ ] |
| M6 | Report re-render | 1. Change branding in Settings (report title, prepared by) 2. Navigate to a completed scan 3. Click "Regenerate Reports" | New reports generated with updated branding, old reports replaced | [ ] |
| M7 | Concurrent scans | 1. Start scan on `203.0.113.0/24` 2. Start scan on `198.51.100.0/24` 3. Start scan on `192.168.1.0/24` | All 3 run simultaneously, no data mixing between scans, each completes independently | [ ] |
| M8 | Scan cancellation | 1. Start a scan on a large range 2. Click "Cancel" while running | Status changes to "cancelled", partial results preserved, Celery task revoked | [ ] |
| M9 | Network topology | 1. Complete a multi-host scan 2. Navigate to Topology page | D3.js graph renders with host nodes, connections shown, nodes are draggable, tooltips show host info | [ ] |
| M10 | User creation | 1. Navigate to Users 2. Create user with role "engineer" 3. Log out, log in as new user | New user can log in, can create/view scans, cannot manage users | [ ] |
| M11 | RBAC enforcement | 1. Log in as viewer role user | Cannot: create scans, delete scans, manage users, modify settings. Can: view dashboard, findings, hosts, download reports | [ ] |
| M12 | MFA enrollment | 1. Navigate to Settings > Security 2. Enable Telegram MFA 3. Log out 4. Log in | Login requires 6-digit OTP code sent via Telegram, backup codes work | [ ] |
| M13 | API token auth | 1. Navigate to Settings > API Tokens 2. Generate new token 3. `curl -H "Authorization: Token <token>" https://localhost:18443/api/scans/` | Authenticated JSON response with scan list | [ ] |
| M14 | Scheduled scan | 1. Navigate to Schedules 2. Create daily schedule for 2 minutes from now 3. Wait | Scan auto-launches at scheduled time, schedule shows "last_run" updated | [ ] |
| M15 | Docker restart | 1. `docker compose restart` 2. Wait for services to recover 3. Navigate to dashboard | All services recover, data intact, previously completed scans still visible, no data loss | [ ] |
| M16 | CLI standalone | 1. `wireghost scan scanme.nmap.org --formats html` (outside Docker) | HTML report generated in output directory, contains findings and host data | [ ] |

---

## Notes

- Mark each test Pass/Fail in the rightmost column
- For failures, note the actual behavior below the table
- M2 and M14 require network access to external targets
- M12 requires Telegram bot token configured in Settings
- M16 requires the CLI installed locally (`pip install -e .`)
