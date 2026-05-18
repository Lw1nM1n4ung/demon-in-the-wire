# Active Directory Recon Tab — Design Spec

**Status:** Approved (all 6 sections validated)
**Date:** 2026-05-18
**Codebase:** `/home/demon/Tools/demon-in-the-wire`, branch `rewrite-v2`

---

## 1. Architecture Overview

The AD Recon tab is an **interactive, credential-driven workflow** added to the Wire_Ghost web portal. It is architecturally separate from the automated `asyncio.gather()` scan pipeline because it needs explicit credentials and a specific target domain controller. It uses the same Django REST + vanilla JS SPA + Celery Worker stack as the rest of the portal.

### Four-layer flow

```
Browser (vanilla JS SPA)
  → Django REST API (/api/ad-recon/*)
    → Celery Worker (ad_recon_task)
      → Linux subprocess tools (impacket, bloodhound-python, etc.)
        → Database (dedicated AD models)
          → Browser renders results
```

### Key architectural decisions

- **Separate from scan pipeline.** AD recon is interactive — user provides credentials, selects a DC, watches progress. It does not run inside `run_pipeline()`. It does not touch `ScanConfig`.
- **One Celery task per recon session.** The task orchestrates tools sequentially within a single session UUID. Sequential execution is intentional — later phases depend on data collected by earlier ones (user lists feed kerberoasting, domain SID feeds ACL analysis).
- **Credential profiles are stored encrypted.** AES-256-GCM via Django's `cryptography`/`Fernet`, encrypted before INSERT. Passwords never appear in logs, API responses, or task arguments.
- **No interactive tools.** Responder runs in analyze-only mode (-A). No tools prompt for input.

---

## 2. Data Models

All models use UUIDv7 primary keys (`uuid_utils.uuid7()`). All belong to a new `scanner/models/ad_recon.py` module (or an `ad_recon/` package if the file grows large).

### `CredentialProfile`

| Field | Type | Notes |
|-------|------|-------|
| `id` | UUIDv7 | PK |
| `owner` | FK → User | Created by; profiles are user-scoped |
| `name` | CharField(128) | Unique per user |
| `domain` | CharField(256) | FQDN of the AD domain |
| `username` | CharField(256) | sAMAccountName or UPN |
| `password` | TextField | AES-256-GCM encrypted at rest |
| `nt_hash` | TextField(nullable) | Optional; AES-256-GCM encrypted at rest |
| `created_at` | DateTime | auto_now_add |
| `updated_at` | DateTime | auto_now |

**Invariants:**
- At least one of `password` or `nt_hash` must be set
- `name` is unique per `owner` (unique_together)
- `repr()` and `str()` must never include plaintext password/nt_hash
- Encryption happens in `save()` override; `Fernet(settings.SECRET_KEY)`

### `ADReconSession`

| Field | Type | Notes |
|-------|------|-------|
| `id` | UUIDv7 | PK |
| `profile` | FK → CredentialProfile | Nullable (null = unauthenticated) |
| `scope` | CharField(8) | "authenticated" or "unauth" |
| `dc_ip` | GenericIPAddressField | Target domain controller |
| `domain` | CharField(256) | From profile or manual input |
| `status` | CharField(16) | pending / running / complete / failed |
| `error` | TextField(blank=True) | Phase 0 failure reason |
| `tool_status` | JSONField | `{"ldapdomaindump": {"status":"ok","count":142}, ...}` |
| `started_at` | DateTime | |
| `completed_at` | DateTime | |
| `created_at` | DateTime | |

### Domain object models (all scoped to session)

| Model | Key fields |
|-------|-----------|
| `ADDomain` | session FK, name, netbios_name, sid, functional_level, forest |
| `ADUser` | session FK, sam_account_name, upn, display_name, description, enabled, admin_count, last_logon, member_of (JSON list of group DNs), pwd_last_set, spn_count |
| `ADGroup` | session FK, name, sam_account_name, description, members (JSON list of user DNs), member_count, admin_count |
| `ADComputer` | session FK, name, dns_hostname, os, os_version, enabled, last_logon, member_of (JSON list) |
| `ADTrust` | session FK, source_domain, target_domain, direction, trust_type, transitive |
| `ADSPN` | session FK, service_name, sam_account_name, host, port, category |
| `ADACL` | session FK, object_dn, identity, active_directory_rights, access_control_type, interesting_rights (JSON list) |
| `ADShare` | session FK, name, path, description, access |
| `ADCertService` | session FK, ca_name, host, templates (JSON list), vulnerable_template |

---

## 3. Tool Execution Flow

Seven phases execute sequentially within a single Celery task. Phase 0 is the only hard gate — if it fails, nothing else runs.

### Phase 0 — Connectivity check (~5s)
- DNS resolution of domain FQDN
- LDAP port (389/636) reachability test
- Authenticated: LDAP bind attempt with credentials
- Sets `session.domain_joined`, `session.functional_level`
- **Failure → abort session, set status=failed**

### Phase 1 — Domain dump (authenticated only, ~240s)
- `ldapdomaindump` → ADUser/ADGroup/ADComputer rows (timeout 120s)
- `nxc smb <dc> --shares` → ADShare rows (timeout 60s)
- `nxc ldap <dc> --trusted-for-delegation` → delegation targets (timeout 60s)
- **If ldapdomaindump fails: abort authenticated path, flag session**

### Phase 2 — BloodHound collection (authenticated only, ~300s)
- `bloodhound-python -c All --zip` → parsed into ADTrust, ADSPN, ADACL rows, ADComputer enrichment (timeout 300s)

### Phase 3 — AS-REP roasting (~60s)
- Authenticated: `impacket-GetNPUsers` on derived user list (timeout 120s)
- Unauthenticated: `kerbrute userenum` reachability check only (timeout 60s)

### Phase 4 — Impacket suite (authenticated only, ~600s)
- `impacket-GetUserSPNs` → kerberoastable accounts (timeout 120s)
- `impacket-secretsdump` → SAM/LSA/NTDS hashes if DA rights (timeout 300s)
- `impacket-samrdump` → local SAM enumeration (timeout 60s)

### Phase 5 — SMB/RPC enumeration (~180s)
- `rpcclient -c <commands>` → domain users, groups, trusts (timeout 60s)
- `nxc smb --pass-pol` → password policy (timeout 60s)
- `nxc smb -M ioxid-resolver` → IPv6/DNS poisoning surface (timeout 60s)
- `nxc smb --wmi` → AV/EDR product detection (timeout 60s)

### Phase 6 — Certificate services (authenticated only, ~60s)
- `nxc ldap -M adcs` → ADCertService rows, ESC1-ESC8 vector detection (timeout 60s)

### Phase 7 — Network poisoning (always runs, ~60s)
- `responder -I eth0 -A -wrf --lm --disable-ess` → analyze-only, no spoofing (forced kill after 60s)

### Graceful degradation rules
- If any tool times out: skip it, continue with remaining tools
- If any tool exits non-zero: capture stderr in tool_status, continue
- If a tool binary is missing: skip with warning, continue
- Phase 0 is the only hard abort point

---

## 4. Frontend UI Design

Single-page cockpit layout with three panels.

### Layout

```
┌─────────────────────────────────────────────────────────┐
│  AD Recon                                [New Session]  │
├────────────────────┬────────────────────────────────────┤
│                    │                                    │
│  CREDENTIAL        │  SESSION HISTORY                   │
│  PROFILES          │  (paginated list of past sessions) │
│  (card list)       │                                    │
│                    │  Each row: session #, domain,      │
│  [+ Add Profile]   │  status, summary counts,           │
│                    │  [View] [Re-run] actions           │
│  QUICK START       │                                    │
│  (no credentials)  │  Click [View] → expands inline     │
│  Domain + DC IP    │  per-tool status detail            │
│  [Run Unauth]      │                                    │
└────────────────────┴────────────────────────────────────┘
```

### Interaction flow

**Authenticated session:** Click profile → highlights → "New Session" enables → modal asks for DC IP → session row appears with spinner → polls every 3s → complete with summary counts.

**Unauthenticated session:** Fill Domain + DC IP in quick-start → "Run Unauth" → same flow, no profile attached.

**Credential profiles:** "+" modal with Name, Domain, Username, Password, NT Hash (optional). Password always masked. Edit re-enters password or leaves blank to keep existing. Delete with confirmation.

### API endpoints

| Method | Path | Purpose | Auth |
|--------|------|---------|------|
| `GET` | `/api/ad-recon/profiles/` | List profiles (passwords redacted) | site:config |
| `POST` | `/api/ad-recon/profiles/` | Create profile | site:config |
| `PUT` | `/api/ad-recon/profiles/<id>/` | Update profile | site:config |
| `DELETE` | `/api/ad-recon/profiles/<id>/` | Delete profile | site:config |
| `POST` | `/api/ad-recon/sessions/` | Start recon session | site:config |
| `GET` | `/api/ad-recon/sessions/` | List sessions (paginated) | site:config |
| `GET` | `/api/ad-recon/sessions/<id>/` | Session detail + tool status | site:config |
| `GET` | `/api/ad-recon/sessions/<id>/users/` | Domain users (paginated) | site:config |
| `GET` | `/api/ad-recon/sessions/<id>/groups/` | Domain groups (paginated) | site:config |
| `GET` | `/api/ad-recon/sessions/<id>/computers/` | Computers (paginated) | site:config |
| `GET` | `/api/ad-recon/sessions/<id>/findings/` | SPNs, ACLs, cert issues | site:config |

### SPA registration
- New page: `web/js/app/pages/ad-recon.js` (render function returning HTML string)
- New module: `web/js/app/ad-recon.js` (event handlers, polling, CRUD)
- Script tag in `web/app.html`
- Route: `#ad-recon`, top-level sidebar item with `data-role="site:config"`
- All DOM updates via `textContent` (hardened against XSS)

---

## 5. Security Considerations

### Credential encryption
- `CredentialProfile.password` and `nt_hash` are AES-256-GCM encrypted via `Fernet(settings.SECRET_KEY)` before INSERT
- Encryption in `save()` method, not in view/serializer
- API responses ALWAYS redact password field — even for `site:config` users
- `__repr__` and `__str__` must never include plaintext

### Credential exposure prevention
- Celery task arguments: `session_id` only (UUID), never credentials
- Worker decrypts inline from DB row, uses credential, clears local variable immediately
- `.rc` files, command lines, spool output written to per-session dir (filesystem permissions, not web-served)
- Logging never includes password or nt_hash values

### Input validation
- Domain FQDN: regex `^([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$`
- DC IP: IPv4 or resolvable hostname
- Username: no null bytes, max 256 chars
- Password: max 256 chars
- Profile name: max 128 chars, unique per user

### Authorization
- All AD Recon endpoints require `site:config` role
- Credential profiles scoped to creating user
- Sessions visible to all `site:config` users (team visibility)

---

## 6. Testing Strategy

### Python tests (Django TestCase, `manage.py test scanner`)

**Model tests** (`tests/test_ad_models.py`):
- Password encryption round-trip, repr never leaks plaintext, unique profile name per user
- Session scope choices validation, cascade delete behavior

**View tests** (`tests/test_ad_views.py`):
- Profile CRUD with password redaction, session creation with/without profile
- 403 for non-site:config users, pagination, tool status in detail response

**Task tests** (`tests/test_ad_tasks.py`):
- Phase 0 DNS/auth failure aborts session
- Tool timeout does not abort session (subsequent tools run)
- Missing binary skipped gracefully
- Unauthenticated scope skips credential phases
- Full session success with mocked subprocess

### Frontend tests
- Page renders valid HTML, profile modal opens, session polling updates DOM

### Integration tests
- End-to-end: POST session → poll → GET users/groups/findings → all return 200 with expected structure (mock subprocess, no actual DC needed)
