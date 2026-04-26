# Telegram Bot Control Plane — Design Spec

## Summary

Add a Telegram bot that gives full bidirectional control of Wire_Ghost from a team group chat. Users link their Telegram accounts to Wire_Ghost accounts via one-time codes, then issue commands gated by the existing RBAC system. The bot also upgrades outbound notifications from plain text to rich messages with inline buttons and file attachments.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Access model | Chat-group with RBAC | Team operates in a shared group; bot enforces per-user permissions by linking Telegram IDs to Wire_Ghost accounts |
| Runtime | Django management command as dedicated Docker service | Direct ORM access, stays in sync with migrations, no API round-trip overhead |
| Transport | Long-polling (`getUpdates`) | Works behind NAT/firewall, no public endpoint or valid TLS cert required — fits on-prem appliance model |
| Account linking | One-time 6-digit code from web portal | Self-service, expiring, single-use; no manual mapping needed |
| Library | `python-telegram-bot` v21+ | Async, well-maintained (25k+ stars), supports handlers, callback queries, file sending |

---

## Architecture

```
Telegram Cloud
  │  getUpdates (long-poll, outbound from bot)
  │  sendMessage / sendDocument (outbound from bot)
  ▼
┌─────────────────────────────────────────────┐
│ Docker Compose (wireghost_net)              │
│                                             │
│  ┌──────┐  ┌────────┐  ┌──────┐  ┌──────┐ │
│  │ api  │  │ worker │  │ beat │  │ bot  │ │
│  └──┬───┘  └───┬────┘  └──────┘  └──┬───┘ │
│     │          │                     │      │
│  ┌──┴──────────┴─────────────────────┴──┐  │
│  │        MySQL  +  Redis               │  │
│  └──────────────────────────────────────┘  │
│                                             │
│  ┌──────┐                                  │
│  │portal│  (nginx, unchanged)              │
│  └──────┘                                  │
└─────────────────────────────────────────────┘
```

**`bot` service** — Same Docker image as api/worker/beat. Command: `python manage.py telegrambot`. Depends on `db` (healthy) + `redis` (healthy). No ports exposed. All connections outbound to `api.telegram.org:443`.

**No new containers to build.** The bot service reuses the existing `web_portal` image with a different entrypoint command.

---

## File Structure

| File | Purpose |
|---|---|
| `web_portal/scanner/management/commands/telegrambot.py` | Django management command — entry point, builds `python-telegram-bot` Application, starts long-polling |
| `web_portal/scanner/bot/handlers.py` | Command handler functions (one per command) |
| `web_portal/scanner/bot/auth.py` | Telegram→WireGhost user resolution, RBAC check decorator, link/unlink logic |
| `web_portal/scanner/bot/formatting.py` | Message formatting helpers (MarkdownV2 escaping, truncation, severity emoji) |
| `web_portal/scanner/bot/callbacks.py` | Inline button callback query handlers |
| `web_portal/scanner/bot/__init__.py` | Package init |
| `web_portal/scanner/notifications.py` | Modified — add `bot_send()` path alongside existing `send_telegram()` |
| `web_portal/scanner/models.py` | Modified — add `telegram_user_id` field to UserPreference (integer, unique, nullable) |
| `web_portal/scanner/auth_views.py` | Modified — add `POST /api/preferences/telegram-link/` endpoint for code generation |
| `docker-compose.yml` | Modified — add `bot` service |
| `web_portal/requirements.txt` | Modified — add `python-telegram-bot>=21.0,<22.0` |

---

## Account Linking

### Link flow

1. User opens Wire_Ghost web portal → Settings → Telegram → clicks "Generate Link Code"
2. `POST /api/preferences/telegram-link/` → generates 6-digit code via `secrets.randbelow(900000) + 100000`
3. Code stored in Redis: key `tg:link:<code>` → value `{"user_id": "<uuid>"}`, TTL 300 seconds
4. User sends `/link 482915` in the Telegram group or DM to the bot
5. Bot looks up `tg:link:482915` in Redis:
   - Found → loads User by user_id → sets `UserPreference.telegram_user_id = sender.id` (Telegram integer ID) → deletes Redis key → replies "Linked to `<username>` (role: engineer)"
   - Not found or expired → replies "Invalid or expired code"
6. Bot also stores `UserPreference.telegram_chat_id` with the sender's chat ID for DM delivery

### Unlink

`/unlink` → clears `telegram_user_id` and `telegram_chat_id` on the caller's UserPreference. Also available from the web portal Settings page.

### Constraints

- `telegram_user_id` has a unique constraint — one Telegram account maps to one Wire_Ghost account
- Link codes are single-use (deleted from Redis on successful link)
- Rate limit: max 3 failed `/link` attempts per Telegram user per hour (Redis key `tg:linkfail:<tg_user_id>`, TTL 3600, increment on failure)
- Deactivated Wire_Ghost users (`is_active=False`) are rejected at auth check even if linked

---

## Auth Enforcement

Every incoming message/callback goes through a resolution step before the handler executes:

```
message.from_user.id (Telegram integer)
  → UserPreference.objects.select_related('user').get(telegram_user_id=tg_id)
    → not found? "Not linked. Use /link <code> from the web portal."
    → found, user.is_active=False? "Account deactivated."
    → found, active? Check user.has_permission(handler.required_perm)
      → denied? "Permission denied (requires scan:write)"
      → allowed? Execute handler, pass user object as context
```

Implemented as a decorator `@require_permission('scan:read')` applied to each handler function. The `/help` and `/link` commands skip the permission check (but `/help` still filters the command list by the caller's resolved role).

All commands are logged to `AuditLog` with type `telegram`, the resolved username, and the command text.

---

## Commands

### Viewer tier (scan:read)

**`/status`** — Dashboard summary
```
Wire_Ghost Status
━━━━━━━━━━━━━━━━━
Active scans: 2
Total hosts: 147
Total findings: 891
  🔴 Critical: 12
  🟠 High: 45
  🟡 Medium: 203
  🔵 Low: 631
```

**`/scans`** — Last 10 scans
```
Recent Scans
━━━━━━━━━━━━
✅ a1b2c3d4 | 10.0.0.0/24 | full | 47 findings
✅ e5f6a7b8 | 192.168.1.0/24 | quick | 12 findings
🔄 c9d0e1f2 | 172.16.0.0/16 | full | running (34%)
❌ 1a2b3c4d | 10.10.0.5 | web | failed
```
Shows first 8 chars of scan UUID as short ID. Status icons: ✅ completed, 🔄 running, ❌ failed, ⏸ cancelled, ⏳ pending.

**`/scan <id>`** — Scan detail (accepts 8-char prefix or full UUID)
```
Scan: a1b2c3d4
━━━━━━━━━━━━━━
Target: 10.0.0.0/24
Type: full | Status: completed
Duration: 12m 34s
Hosts: 23 | Ports: 147
Findings: 47
  🔴 3  🟠 8  🟡 19  🔵 17
Reports: html, docx
```
Includes inline buttons: `[Findings]` `[Report]`

**`/findings [critical|high|medium|low]`** — Last 15 findings, optionally filtered
```
Critical Findings
━━━━━━━━━━━━━━━━━
🔴 CVE-2024-1234 — RCE in Apache (10.0.0.5:443)
🔴 MS17-010 — EternalBlue SMB (10.0.0.12:445)
🔴 Default credentials — admin:admin (10.0.0.1:80)
… and 2 more
```

**`/assets`** — Top 10 by risk score
```
High-Risk Assets
━━━━━━━━━━━━━━━━
⚠️ 10.0.0.5 | nginx/1.18 | risk: 92 | 5 findings
⚠️ 10.0.0.12 | Windows SMB | risk: 87 | 3 findings
```

**`/help`** — Lists commands available to the caller's role

### Engineer tier (scan:write)

**`/newscan <target> [full|quick|port|web]`** — Launch a scan
- Target: IP, CIDR, hostname, or comma-separated list
- Type defaults to `full` if omitted
- Creates a Scan row with `created_by` set to the linked Wire_Ghost user
- Fires `run_scan.delay(scan.id)`
- Reply: "Scan `<short_id>` launched against `<target>` (type: full)"
- Rate limited: 5 per hour per user

**`/cancel <id>`** — Cancel a running scan
- Looks up scan by prefix match
- Only the scan creator or an Owner can cancel
- Calls `celery.control.revoke(task_id, terminate=True)` and sets status to `cancelled`
- Reply: "Scan `<short_id>` cancelled"

**`/schedule list`** — List enabled schedules
```
Scheduled Scans
━━━━━━━━━━━━━━━
📅 sched_01 | 10.0.0.0/24 | daily 02:00 | next: 2026-04-27
📅 sched_02 | 192.168.1.0/24 | weekly Mon 06:00 | next: 2026-04-28
```

**`/schedule add <target> <daily|weekly|biweekly|monthly> <HH:MM>`** — Create schedule
- Uses SiteConfig.schedule_timezone for time interpretation
- Reply: "Schedule created: `<target>` every `<freq>` at `<time>`"

**`/schedule del <id>`** — Delete schedule
- Only creator or Owner can delete
- Reply: "Schedule deleted"

**`/report <id>`** — Regenerate reports
- Fires `generate_report.delay(scan_id)`
- Immediately replies: "Generating reports for scan `<short_id>`…"
- The `generate_report` task calls `notify('report.ready', scan=scan)` on completion
- `notify()` publishes to Redis pub/sub `wireghost:bot:notify` with `{"event": "report.ready", "scan_id": "...", "chat_id": "..."}`
- Bot picks up the event and sends the DOCX file to the originating chat as a document attachment
- If bot is not running, the direct `notify()` path sends a plain text "Report ready" message instead

### Owner tier

**`/users`** — List users
```
Users
━━━━━
👑 admin | owner | active | 🔗 linked
🔧 analyst1 | engineer | active | 🔗 linked
👁 viewer1 | viewer | active | ❌ not linked
```

**`/config`** — Site config
```
Site Config
━━━━━━━━━━━
Timezone: Asia/Yangon
Default parallelism: 10
Default timeout: 3600s
Telegram bot: ✅ configured
Shared chat: ✅ set
```

**`/health`** — Tools + system stats
```
System Health
━━━━━━━━━━━━━
CPU: 23% | RAM: 1.2/4.0 GB | Disk: 12/50 GB
Tools:
  ✅ nmap 7.94  ✅ nuclei 3.x  ✅ masscan 1.3
  ✅ httpx 1.x  ✅ naabu 2.x  ⚠️ openvas (not installed)
```

---

## Notifications (Outbound)

### Upgrade path

The `notify()` function runs inside the **worker** container (called from `run_scan` Celery task), while the bot runs in a **separate container**. They cannot share an in-process bot instance. Instead:

1. `notify()` continues to use `urllib.request` to call the Telegram Bot API directly (current behavior) — but upgrades the message format from plain text to MarkdownV2 with richer content
2. For features that require bot-specific capabilities (inline buttons, file attachments), `notify()` publishes a message to a Redis pub/sub channel (`wireghost:bot:notify`) with the event payload
3. The bot process subscribes to `wireghost:bot:notify` and handles rich delivery (inline keyboards, document uploads) using its `telegram.Bot` instance
4. If the bot is not running, the Redis message is simply undelivered — the `notify()` direct-send already handled basic delivery. No message loss for the core notification.

This two-path design means:
- **Bot running:** Users get rich messages with buttons + file attachments (via Redis pub/sub → bot)
- **Bot not running:** Users still get plain-text notifications (via direct `urllib.request` in worker) — backwards compatible, zero breakage

### Event messages

**scan.complete → Group**
```
✅ Scan Complete: a1b2c3d4
Target: 10.0.0.0/24
Duration: 12m 34s
Findings: 🔴 3  🟠 8  🟡 19  🔵 17
Started by: @analyst1

[View Findings]  [Download Report]
```

**scan.failed → Group**
```
❌ Scan Failed: e5f6a7b8
Target: 192.168.1.0/24
Error: Connection timeout on nmap phase
Started by: @analyst1
```

**critical.discovered → Group**
```
🚨 Critical Findings Discovered
Scan: a1b2c3d4 | Target: 10.0.0.0/24
3 critical vulnerabilities found:
  • CVE-2024-1234 — RCE in Apache (10.0.0.5)
  • MS17-010 — EternalBlue (10.0.0.12)
  • Default creds (10.0.0.1)

[Show All Criticals]
```

**report.ready → Group**
```
📄 Report Ready: a1b2c3d4
Formats: html, docx
```
Bot attaches DOCX file directly to the message.

### Creator DM delivery

Unchanged — respects `UserPreference` per-event toggles (`notif_scan_complete`, `notif_critical_finding`, etc.). DMs use the same rich format but without inline buttons (simpler for DM context).

### Group chat auto-detection

On the first `/link` command issued in a group chat, if `SiteConfig.telegram_shared_chat_id` is not set and the linking user is an Owner, the bot asks:

> "Use this group for Wire_Ghost notifications? Reply /yes or /no"

On `/yes`, stores the group's chat_id in `SiteConfig.telegram_shared_chat_id`.

---

## Callback Queries (Inline Buttons)

Inline buttons generate `CallbackQuery` events with data like `scan:a1b2c3d4:findings` or `scan:a1b2c3d4:report`.

**Handler routing:**
```
callback_data format: "<entity>:<id>:<action>"

scan:<id>:findings  → same as /scan <id> findings view
scan:<id>:report    → trigger /report <id> (send file)
findings:critical   → same as /findings critical
```

Auth is enforced on callbacks the same way as text commands — resolve the Telegram user, check permissions.

Callback responses use `answer_callback_query()` + `edit_message_text()` to update the original message inline (no new message spam).

---

## Model Changes

### UserPreference (modify existing)

Add field:
```python
telegram_user_id = models.BigIntegerField(unique=True, null=True, blank=True)
```

This is the Telegram integer user ID (distinct from `telegram_chat_id` which is the chat/DM channel ID). The unique constraint enforces one-to-one mapping.

The existing `telegram_chat_id` field (CharField) continues to serve as the DM delivery target. `telegram_user_id` is the identity key for auth resolution.

### Migration

One new migration: `0018_userpreference_telegram_user_id.py`
- Add `telegram_user_id` BigIntegerField, unique=True, null=True, blank=True
- No data migration needed (all existing values are null)

---

## New API Endpoint

### `POST /api/preferences/telegram-link/`

**Auth:** Session or Token (authenticated user only)
**Permission:** None beyond authentication (users link their own account)
**Rate limit:** 3 requests per 5 minutes per user

**Response:**
```json
{
  "code": "482915",
  "expires_in": 300
}
```

**Implementation:**
1. Generate code: `str(secrets.randbelow(900000) + 100000)`
2. Store in Redis: `SET tg:link:<code> '{"user_id":"<uuid>"}' EX 300`
3. If user already has an active code, delete the old one first (Redis key pattern `tg:link:*` — but since codes are random, store a reverse pointer: `tg:linkuser:<user_id>` → code, so we can find and delete the previous one)
4. Return code + TTL

---

## Docker Compose Changes

Add to `docker-compose.yml`:

```yaml
bot:
  build:
    context: ./web_portal
    dockerfile: Dockerfile
  command: python manage.py telegrambot
  environment:
    - MYSQL_HOST=db
    - MYSQL_PORT=3306
    - MYSQL_DATABASE=${MYSQL_DATABASE:-wireghost}
    - MYSQL_USER=${MYSQL_USER:-wireghost}
    - MYSQL_PASSWORD=${MYSQL_PASSWORD}
    - CELERY_BROKER_URL=redis://:${REDIS_PASSWORD}@redis:6379/0
    - DJANGO_SECRET_KEY=${DJANGO_SECRET_KEY}
  depends_on:
    db:
      condition: service_healthy
    redis:
      condition: service_healthy
  restart: unless-stopped
  networks:
    - wireghost_net
  cap_drop:
    - ALL
  security_opt:
    - no-new-privileges:true
  deploy:
    resources:
      limits:
        memory: 256M
        cpus: "0.5"
```

**No ports exposed.** Bot only makes outbound HTTPS connections to `api.telegram.org`.

**Conditional startup:** If `SiteConfig.telegram_bot_token` is empty, the management command logs "No Telegram bot token configured, exiting" and exits cleanly. The `restart: unless-stopped` policy will not restart it endlessly — we add a startup check with a 30-second sleep before retry to avoid tight restart loops.

---

## Security Considerations

| Threat | Mitigation |
|---|---|
| Unauthorized command execution | Every command checks Telegram user ID → Wire_Ghost user → RBAC permission |
| Link code brute-force | 6-digit code space (900k), 3 attempts/hour rate limit, 5-min expiry |
| Bot token exposure | Stored in `SiteConfig.telegram_bot_token` (DB, not env var). Never returned raw by API (only `token_tail` suffix shown to Owner) |
| Replay attacks on callbacks | Callback data includes entity ID — no state mutation without fresh RBAC check |
| Scan spam via Telegram | `/newscan` rate limited to 5/hour per user |
| Command injection via target string | Target validated the same way as `POST /api/scans/` — regex for IP/CIDR/hostname, reject shell metacharacters |
| Information leak in group chat | Finding details truncated (title + host only, no full evidence/response bodies). Full evidence only available in web portal or downloaded report |
| Deactivated user access | Auth check verifies `user.is_active` on every command |
| Unlinked group members see responses | Responses are visible to all group members (Telegram limitation). Sensitive commands (`/users`, `/config`) reply via DM to the caller instead of the group |

---

## Graceful Degradation

- **No bot token configured:** Bot service exits cleanly. All existing functionality (web portal, API, notifications via `send_telegram()`) continues unchanged.
- **Bot service down:** Outbound notifications fall back to `urllib.request` path. No command processing, but scans/schedules/web portal unaffected.
- **Telegram API unreachable:** Bot retries with exponential backoff (built into `python-telegram-bot`). Queued notifications logged as warnings, not errors. No scan failures.
- **Redis down:** Link codes and rate limits unavailable. Bot logs error, rejects `/link` attempts with "Service temporarily unavailable". Command processing continues (auth uses MySQL, not Redis).

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `python-telegram-bot` | `>=21.0,<22.0` | Async Telegram Bot API client with handler framework |

No other new dependencies. Redis client (`django.core.cache`) and all ORM dependencies already present.

---

## Testing Strategy

| Layer | What | How |
|---|---|---|
| Unit | Auth resolution, RBAC decorator, message formatting, link code generation | pytest with mocked Telegram objects |
| Integration | Command handlers against real DB | pytest-django with test fixtures (User, Scan, Finding rows), mock Telegram `Update` objects |
| Manual | Full flow: link account, issue commands, receive notifications | Real Telegram bot token in dev, test group |
| Security | Link brute-force, unlinked user rejection, deactivated user, permission escalation | Dedicated test cases per threat |
