# Wire_Ghost v2.0 — User Acceptance Testing (UAT)

12 scenarios across 3 roles. Each scenario has concrete acceptance criteria.

---

## Owner/Admin Role

| # | Scenario | Steps | Acceptance Criteria | Pass? |
|---|----------|-------|---------------------|-------|
| U1 | Setup to first scan | 1. Fresh install via Docker 2. Complete setup wizard 3. Launch scan 4. View report | End-to-end in under 10 minutes, no errors, report contains findings | [ ] |
| U2 | Manage team access | 1. Create Engineer user 2. Create Viewer user 3. Log in as each, verify permissions | Engineer can scan but not manage users; Viewer is read-only; permissions match role definitions | [ ] |
| U3 | Configure scan policy | 1. Create policy with custom settings (parallelism=3, quick scan, skip nuclei) 2. Create scheduled scan using this policy 3. Wait for scheduled run | Scan uses policy settings (visible in scan detail), not defaults | [ ] |
| U4 | Review full report | 1. Complete a scan with findings 2. Download DOCX, XLSX, and view Dashboard report | All 3 formats contain identical finding data, severity counts match, no missing fields | [ ] |

## Engineer/Operator Role

| # | Scenario | Steps | Acceptance Criteria | Pass? |
|---|----------|-------|---------------------|-------|
| U5 | Run a scan | 1. Log in as Engineer 2. Create and start a scan 3. Monitor progress | Can create scans, status updates visible, scan completes successfully | [ ] |
| U6 | View findings | 1. Navigate to Findings 2. Filter by severity 3. Filter by source 4. Search by keyword 5. Click finding for detail | All filters work correctly, detail view shows full evidence, curl command copyable | [ ] |
| U7 | Export data | 1. Navigate to Reports 2. Download each available format | All report formats download successfully, files are valid and non-empty | [ ] |
| U8 | Cannot manage users | 1. Navigate to Users page 2. Attempt to create/delete users | User management UI is hidden or disabled, API returns 403 on direct requests | [ ] |

## Viewer Role

| # | Scenario | Steps | Acceptance Criteria | Pass? |
|---|----------|-------|---------------------|-------|
| U9 | Read-only dashboard | 1. Log in as Viewer 2. Navigate Dashboard, Findings, Hosts | All read-only pages load with data, no errors | [ ] |
| U10 | Cannot start scans | 1. Look for "New Scan" button 2. Try `curl -X POST /api/scans/` with viewer session | Button hidden/disabled in UI, API returns 403 | [ ] |
| U11 | Cannot delete data | 1. Navigate to Scans 2. Look for delete buttons 3. Try `curl -X DELETE /api/scans/<id>/` | Delete buttons hidden in UI, API returns 403 | [ ] |
| U12 | Can download reports | 1. Navigate to Reports 2. Click download | Report files download successfully despite read-only role | [ ] |

---

## Sign-off

| Role | Tester | Date | All Pass? |
|------|--------|------|-----------|
| Owner | | | [ ] |
| Engineer | | | [ ] |
| Viewer | | | [ ] |
