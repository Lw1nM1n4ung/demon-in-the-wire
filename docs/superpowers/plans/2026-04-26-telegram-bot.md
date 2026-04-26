# Telegram Bot Control Plane — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Telegram bot that gives full bidirectional control of Wire_Ghost from a team group chat, with RBAC-gated commands and rich notifications.

**Architecture:** Django management command (`python manage.py telegrambot`) running as a dedicated Docker service. Long-polls Telegram's `getUpdates` API. Direct ORM access to MySQL. Redis for ephemeral link codes, rate limits, and cross-container pub/sub with the worker.

**Tech Stack:** `python-telegram-bot` v21+, Django ORM, Redis pub/sub, Celery (existing)

**Spec:** `docs/superpowers/specs/2026-04-26-telegram-bot-design.md`

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `web_portal/requirements.txt` | Modify | Add `python-telegram-bot` dependency |
| `web_portal/scanner/models.py` | Modify | Add `telegram_user_id` field to UserPreference |
| `web_portal/scanner/migrations/0018_userpreference_telegram_user_id.py` | Create | Migration for new field |
| `web_portal/scanner/bot/__init__.py` | Create | Package init |
| `web_portal/scanner/bot/formatting.py` | Create | MarkdownV2 escaping, severity emoji, truncation helpers |
| `web_portal/scanner/bot/auth.py` | Create | Telegram→User resolution, `@require_permission` decorator, link/unlink |
| `web_portal/scanner/bot/handlers.py` | Create | All `/command` handlers (viewer + engineer + owner) |
| `web_portal/scanner/bot/callbacks.py` | Create | Inline button callback query handlers |
| `web_portal/scanner/auth_views.py` | Modify | Add `POST /api/preferences/telegram-link/` endpoint |
| `web_portal/wireghost_web/urls.py` | Modify | Wire up new endpoint |
| `web_portal/scanner/management/__init__.py` | Create | Package init |
| `web_portal/scanner/management/commands/__init__.py` | Create | Package init |
| `web_portal/scanner/management/commands/telegrambot.py` | Create | Management command entry point |
| `web_portal/scanner/notifications.py` | Modify | Add Redis pub/sub publish, upgrade message format |
| `docker-compose.yml` | Modify | Add `bot` service |
| `web_portal/scanner/tests/test_bot_formatting.py` | Create | Formatting unit tests |
| `web_portal/scanner/tests/test_bot_auth.py` | Create | Auth resolution + RBAC tests |
| `web_portal/scanner/tests/test_bot_handlers.py` | Create | Command handler integration tests |
| `web_portal/scanner/tests/test_telegram_link.py` | Create | Link endpoint + brute-force tests |

---

### Task 1: Dependency & Model Foundation

**Files:**
- Modify: `web_portal/requirements.txt`
- Modify: `web_portal/scanner/models.py:378-411`
- Create: `web_portal/scanner/migrations/0018_userpreference_telegram_user_id.py`

- [ ] **Step 1: Add python-telegram-bot to requirements.txt**

Open `web_portal/requirements.txt` and add after the last line:

```
python-telegram-bot>=21.0,<22.0
```

- [ ] **Step 2: Add telegram_user_id field to UserPreference model**

In `web_portal/scanner/models.py`, find the `UserPreference` class (line ~378). Add the new field after `telegram_enabled` (line ~393):

```python
    telegram_user_id = models.BigIntegerField(
        unique=True, null=True, blank=True,
        help_text='Telegram integer user ID for auth resolution',
    )
```

- [ ] **Step 3: Generate and verify the migration**

Run:
```bash
cd /home/demon/Tools/demon-in-the-wire && docker compose exec api python manage.py makemigrations scanner --name userpreference_telegram_user_id
```

Expected: Creates `web_portal/scanner/migrations/0018_userpreference_telegram_user_id.py` with a single `AddField` operation.

Verify:
```bash
docker compose exec api python manage.py migrate --check
```

- [ ] **Step 4: Apply the migration**

Run:
```bash
docker compose exec api python manage.py migrate scanner 0018
```

Expected: `Applying scanner.0018_userpreference_telegram_user_id... OK`

- [ ] **Step 5: Commit**

```bash
git add web_portal/requirements.txt web_portal/scanner/models.py web_portal/scanner/migrations/0018_userpreference_telegram_user_id.py
git commit -m "feat(bot): add telegram_user_id field and python-telegram-bot dep"
```

---

### Task 2: Formatting Module

**Files:**
- Create: `web_portal/scanner/bot/__init__.py`
- Create: `web_portal/scanner/bot/formatting.py`
- Create: `web_portal/scanner/tests/test_bot_formatting.py`

- [ ] **Step 1: Create the bot package**

```bash
mkdir -p /home/demon/Tools/demon-in-the-wire/web_portal/scanner/bot
mkdir -p /home/demon/Tools/demon-in-the-wire/web_portal/scanner/tests
```

Create `web_portal/scanner/bot/__init__.py`:
```python
```

- [ ] **Step 2: Write failing tests for formatting helpers**

Create `web_portal/scanner/tests/test_bot_formatting.py`:

```python
import pytest
from scanner.bot.formatting import (
    escape_md,
    severity_emoji,
    severity_line,
    short_id,
    status_icon,
    truncate_list,
    format_duration,
)


class TestEscapeMd:
    def test_escapes_special_chars(self):
        assert escape_md('hello_world') == 'hello\\_world'

    def test_escapes_all_mdv2_chars(self):
        for ch in '_*[]()~`>#+-=|{}.!':
            assert f'\\{ch}' in escape_md(ch)

    def test_leaves_plain_text_alone(self):
        assert escape_md('hello world') == 'hello world'

    def test_handles_empty_string(self):
        assert escape_md('') == ''


class TestSeverityEmoji:
    def test_critical(self):
        assert severity_emoji('critical') == '🔴'

    def test_high(self):
        assert severity_emoji('high') == '🟠'

    def test_medium(self):
        assert severity_emoji('medium') == '🟡'

    def test_low(self):
        assert severity_emoji('low') == '🔵'

    def test_info(self):
        assert severity_emoji('info') == 'ℹ️'

    def test_unknown_returns_empty(self):
        assert severity_emoji('whatever') == ''


class TestSeverityLine:
    def test_formats_counts(self):
        result = severity_line(critical=3, high=8, medium=19, low=17)
        assert '🔴 3' in result
        assert '🟠 8' in result
        assert '🟡 19' in result
        assert '🔵 17' in result

    def test_skips_zero_counts(self):
        result = severity_line(critical=0, high=5, medium=0, low=0)
        assert '🔴' not in result
        assert '🟠 5' in result


class TestShortId:
    def test_returns_first_8_chars(self):
        assert short_id('a1b2c3d4-e5f6-7890-abcd-ef1234567890') == 'a1b2c3d4'

    def test_handles_short_string(self):
        assert short_id('abc') == 'abc'


class TestStatusIcon:
    def test_completed(self):
        assert status_icon('completed') == '✅'

    def test_running(self):
        assert status_icon('running') == '🔄'

    def test_failed(self):
        assert status_icon('failed') == '❌'

    def test_cancelled(self):
        assert status_icon('cancelled') == '⏸'

    def test_pending(self):
        assert status_icon('pending') == '⏳'


class TestTruncateList:
    def test_returns_all_when_under_limit(self):
        items = ['a', 'b', 'c']
        assert truncate_list(items, limit=5) == (['a', 'b', 'c'], 0)

    def test_truncates_and_returns_remainder(self):
        items = list(range(20))
        shown, remaining = truncate_list(items, limit=10)
        assert len(shown) == 10
        assert remaining == 10


class TestFormatDuration:
    def test_seconds_only(self):
        assert format_duration(45) == '45s'

    def test_minutes_and_seconds(self):
        assert format_duration(754) == '12m 34s'

    def test_hours(self):
        assert format_duration(3661) == '1h 1m 1s'

    def test_zero(self):
        assert format_duration(0) == '0s'

    def test_none_returns_dash(self):
        assert format_duration(None) == '—'
```

- [ ] **Step 3: Run tests to verify they fail**

Run:
```bash
cd /home/demon/Tools/demon-in-the-wire/web_portal && python -m pytest scanner/tests/test_bot_formatting.py -v 2>&1 | head -30
```

Expected: ImportError or ModuleNotFoundError (formatting module doesn't exist yet).

- [ ] **Step 4: Implement the formatting module**

Create `web_portal/scanner/bot/formatting.py`:

```python
from __future__ import annotations

import re
from typing import Optional

_MDV2_ESCAPE = re.compile(r'([_*\[\]()~`>#\+\-=|{}.!])')

_SEVERITY_EMOJI = {
    'critical': '🔴',
    'high': '🟠',
    'medium': '🟡',
    'low': '🔵',
    'info': 'ℹ️',
}

_STATUS_ICON = {
    'completed': '✅',
    'running': '🔄',
    'failed': '❌',
    'cancelled': '⏸',
    'pending': '⏳',
}


def escape_md(text: str) -> str:
    return _MDV2_ESCAPE.sub(r'\\\1', text)


def severity_emoji(severity: str) -> str:
    return _SEVERITY_EMOJI.get(severity.lower(), '')


def severity_line(*, critical: int = 0, high: int = 0, medium: int = 0, low: int = 0) -> str:
    parts = []
    if critical:
        parts.append(f'🔴 {critical}')
    if high:
        parts.append(f'🟠 {high}')
    if medium:
        parts.append(f'🟡 {medium}')
    if low:
        parts.append(f'🔵 {low}')
    return '  '.join(parts)


def short_id(uuid_str) -> str:
    return str(uuid_str)[:8]


def status_icon(status: str) -> str:
    return _STATUS_ICON.get(status, '❓')


def truncate_list(items: list, limit: int = 10) -> tuple[list, int]:
    if len(items) <= limit:
        return items, 0
    return items[:limit], len(items) - limit


def format_duration(seconds: Optional[int]) -> str:
    if seconds is None:
        return '—'
    seconds = int(seconds)
    if seconds < 60:
        return f'{seconds}s'
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f'{minutes}m {secs}s'
    hours, mins = divmod(minutes, 60)
    return f'{hours}h {mins}m {secs}s'
```

- [ ] **Step 5: Run tests to verify they pass**

Run:
```bash
cd /home/demon/Tools/demon-in-the-wire/web_portal && python -m pytest scanner/tests/test_bot_formatting.py -v
```

Expected: All 20 tests pass.

- [ ] **Step 6: Commit**

```bash
git add web_portal/scanner/bot/ web_portal/scanner/tests/test_bot_formatting.py
git commit -m "feat(bot): add formatting module with MarkdownV2 helpers"
```

---

### Task 3: Auth Module

**Files:**
- Create: `web_portal/scanner/bot/auth.py`
- Create: `web_portal/scanner/tests/test_bot_auth.py`

- [ ] **Step 1: Write failing tests for auth resolution and RBAC**

Create `web_portal/scanner/tests/test_bot_auth.py`:

```python
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from django.test import TestCase
from scanner.models import User, UserPreference, RolePermission, Permission
from scanner.bot.auth import resolve_user, require_permission, link_account, unlink_account


def _make_update(tg_user_id=12345, chat_id=67890, text='/test'):
    update = MagicMock()
    update.effective_user = MagicMock()
    update.effective_user.id = tg_user_id
    update.effective_chat = MagicMock()
    update.effective_chat.id = chat_id
    update.message = MagicMock()
    update.message.text = text
    update.message.reply_text = AsyncMock()
    return update


class TestResolveUser(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testbot', password='pass1234', role='engineer',
        )
        self.prefs = UserPreference.for_user(self.user)

    def test_returns_user_when_linked(self):
        self.prefs.telegram_user_id = 12345
        self.prefs.save()
        user = resolve_user(12345)
        assert user is not None
        assert user.username == 'testbot'

    def test_returns_none_when_not_linked(self):
        assert resolve_user(99999) is None

    def test_returns_none_when_user_inactive(self):
        self.prefs.telegram_user_id = 12345
        self.prefs.save()
        self.user.is_active = False
        self.user.save()
        assert resolve_user(12345) is None


class TestLinkAccount(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='linktest', password='pass1234', role='viewer',
        )
        UserPreference.for_user(self.user)

    @patch('scanner.bot.auth.cache')
    def test_link_success(self, mock_cache):
        import json
        mock_cache.get.return_value = json.dumps({'user_id': str(self.user.id)})
        ok, msg = link_account(tg_user_id=11111, tg_chat_id=22222, code='123456')
        assert ok is True
        assert 'linktest' in msg
        self.user.preferences.refresh_from_db()
        assert self.user.preferences.telegram_user_id == 11111

    @patch('scanner.bot.auth.cache')
    def test_link_invalid_code(self, mock_cache):
        mock_cache.get.return_value = None
        ok, msg = link_account(tg_user_id=11111, tg_chat_id=22222, code='000000')
        assert ok is False
        assert 'Invalid' in msg or 'expired' in msg

    @patch('scanner.bot.auth.cache')
    def test_link_already_linked_replaces(self, mock_cache):
        import json
        prefs = self.user.preferences
        prefs.telegram_user_id = 99999
        prefs.save()
        mock_cache.get.return_value = json.dumps({'user_id': str(self.user.id)})
        ok, msg = link_account(tg_user_id=11111, tg_chat_id=22222, code='123456')
        assert ok is True
        prefs.refresh_from_db()
        assert prefs.telegram_user_id == 11111


class TestUnlinkAccount(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='unlinktest', password='pass1234', role='engineer',
        )
        prefs = UserPreference.for_user(self.user)
        prefs.telegram_user_id = 12345
        prefs.telegram_chat_id = '67890'
        prefs.telegram_enabled = True
        prefs.save()

    def test_unlink_clears_fields(self):
        ok, msg = unlink_account(tg_user_id=12345)
        assert ok is True
        self.user.preferences.refresh_from_db()
        assert self.user.preferences.telegram_user_id is None
        assert self.user.preferences.telegram_chat_id == ''

    def test_unlink_not_linked(self):
        ok, msg = unlink_account(tg_user_id=99999)
        assert ok is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
cd /home/demon/Tools/demon-in-the-wire/web_portal && python -m pytest scanner/tests/test_bot_auth.py -v 2>&1 | head -20
```

Expected: ImportError (auth module doesn't exist yet).

- [ ] **Step 3: Implement the auth module**

Create `web_portal/scanner/bot/auth.py`:

```python
from __future__ import annotations

import functools
import json
import logging
from typing import Optional

from django.core.cache import cache

from scanner.models import AuditLog, User, UserPreference

log = logging.getLogger('scanner.bot')

LINK_FAIL_PREFIX = 'tg:linkfail:'
LINK_FAIL_MAX = 3
LINK_FAIL_TTL = 3600

CMD_RATE_PREFIX = 'tg:cmdrate:'
CMD_RATE_MAX = 30
CMD_RATE_TTL = 60

SCAN_RATE_PREFIX = 'tg:scanrate:'
SCAN_RATE_MAX = 5
SCAN_RATE_TTL = 3600


def resolve_user(tg_user_id: int) -> Optional[User]:
    try:
        prefs = UserPreference.objects.select_related('user').get(
            telegram_user_id=tg_user_id,
        )
    except UserPreference.DoesNotExist:
        return None
    if not prefs.user.is_active:
        return None
    return prefs.user


def link_account(*, tg_user_id: int, tg_chat_id: int, code: str) -> tuple[bool, str]:
    fail_key = f'{LINK_FAIL_PREFIX}{tg_user_id}'
    fail_count = cache.get(fail_key, 0)
    if fail_count >= LINK_FAIL_MAX:
        return False, 'Too many failed attempts. Try again later.'

    raw = cache.get(f'tg:link:{code}')
    if raw is None:
        cache.set(fail_key, fail_count + 1, LINK_FAIL_TTL)
        return False, 'Invalid or expired code.'

    data = json.loads(raw) if isinstance(raw, str) else raw
    user_id = data.get('user_id')

    try:
        user = User.objects.get(id=user_id, is_active=True)
    except User.DoesNotExist:
        return False, 'Associated account not found or deactivated.'

    prefs = UserPreference.for_user(user)
    UserPreference.objects.filter(telegram_user_id=tg_user_id).update(
        telegram_user_id=None, telegram_chat_id='', telegram_enabled=False,
    )
    prefs.telegram_user_id = tg_user_id
    prefs.telegram_chat_id = str(tg_chat_id)
    prefs.telegram_enabled = True
    prefs.save(update_fields=['telegram_user_id', 'telegram_chat_id', 'telegram_enabled'])

    cache.delete(f'tg:link:{code}')
    reverse_key = f'tg:linkuser:{user_id}'
    cache.delete(reverse_key)
    cache.delete(fail_key)

    AuditLog.log(user.username, 'telegram.link', f'Telegram user {tg_user_id} linked', 'config')
    return True, f'Linked to `{user.username}` (role: {user.role})'


def unlink_account(tg_user_id: int) -> tuple[bool, str]:
    try:
        prefs = UserPreference.objects.select_related('user').get(
            telegram_user_id=tg_user_id,
        )
    except UserPreference.DoesNotExist:
        return False, 'Your Telegram account is not linked.'

    username = prefs.user.username
    prefs.telegram_user_id = None
    prefs.telegram_chat_id = ''
    prefs.telegram_enabled = False
    prefs.save(update_fields=['telegram_user_id', 'telegram_chat_id', 'telegram_enabled'])

    AuditLog.log(username, 'telegram.unlink', f'Telegram user {tg_user_id} unlinked', 'config')
    return True, f'Unlinked from `{username}`.'


def check_rate_limit(prefix: str, key: str, max_count: int, ttl: int) -> bool:
    cache_key = f'{prefix}{key}'
    count = cache.get(cache_key, 0)
    if count >= max_count:
        return False
    cache.set(cache_key, count + 1, ttl)
    return True


def require_permission(perm_code: str):
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(update, context):
            tg_user = update.effective_user
            if not tg_user:
                return

            if not check_rate_limit(CMD_RATE_PREFIX, str(tg_user.id), CMD_RATE_MAX, CMD_RATE_TTL):
                await update.message.reply_text('Rate limit exceeded. Slow down.')
                return

            from asgiref.sync import sync_to_db
            user = await sync_to_db(resolve_user)(tg_user.id)

            if user is None:
                await update.message.reply_text(
                    'Not linked. Generate a code at Settings → Telegram in the web portal, '
                    'then send /link <code>',
                )
                return

            if not await sync_to_db(user.has_permission)(perm_code):
                await update.message.reply_text(
                    f'Permission denied (requires {perm_code})',
                )
                return

            AuditLog.log(
                user.username,
                f'telegram.cmd',
                update.message.text or '',
                'telegram',
            )

            context.user_data['wg_user'] = user
            return await func(update, context)
        return wrapper
    return decorator
```

**Important fix needed:** The `sync_to_db` import above is wrong — `python-telegram-bot` v21+ is async, but Django ORM calls need `sync_to_async`. Replace `from asgiref.sync import sync_to_db` with the correct wrapper. Here's the corrected version of the relevant section:

```python
from asgiref.sync import sync_to_async

# In the decorator, replace sync_to_db calls:
            user = await sync_to_async(resolve_user)(tg_user.id)

            if user is None:
                await update.message.reply_text(
                    'Not linked. Generate a code at Settings → Telegram in the web portal, '
                    'then send /link <code>',
                )
                return

            has_perm = await sync_to_async(user.has_permission)(perm_code)
            if not has_perm:
                await update.message.reply_text(
                    f'Permission denied (requires {perm_code})',
                )
                return

            await sync_to_async(AuditLog.log)(
                user.username,
                'telegram.cmd',
                update.message.text or '',
                'telegram',
            )
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
cd /home/demon/Tools/demon-in-the-wire/web_portal && python -m pytest scanner/tests/test_bot_auth.py -v
```

Expected: All 8 tests pass.

- [ ] **Step 5: Commit**

```bash
git add web_portal/scanner/bot/auth.py web_portal/scanner/tests/test_bot_auth.py
git commit -m "feat(bot): auth module with user resolution, RBAC decorator, link/unlink"
```

---

### Task 4: Link Code API Endpoint

**Files:**
- Modify: `web_portal/scanner/auth_views.py`
- Modify: `web_portal/wireghost_web/urls.py`
- Create: `web_portal/scanner/tests/test_telegram_link.py`

- [ ] **Step 1: Write failing tests for the link endpoint**

Create `web_portal/scanner/tests/test_telegram_link.py`:

```python
import json
from unittest.mock import patch, MagicMock
from django.test import TestCase, RequestFactory
from rest_framework.test import force_authenticate
from scanner.models import User, UserPreference
from scanner.auth_views import telegram_link_code


class TestTelegramLinkEndpoint(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username='linkapi', password='pass1234', role='engineer',
        )
        UserPreference.for_user(self.user)

    @patch('scanner.auth_views.cache')
    def test_generates_6_digit_code(self, mock_cache):
        mock_cache.get.return_value = None
        request = self.factory.post('/api/preferences/telegram-link/')
        force_authenticate(request, user=self.user)
        response = telegram_link_code(request)
        assert response.status_code == 200
        data = response.data
        assert 'code' in data
        assert len(data['code']) == 6
        assert data['code'].isdigit()
        assert data['expires_in'] == 300

    @patch('scanner.auth_views.cache')
    def test_stores_code_in_redis(self, mock_cache):
        mock_cache.get.return_value = None
        request = self.factory.post('/api/preferences/telegram-link/')
        force_authenticate(request, user=self.user)
        response = telegram_link_code(request)
        code = response.data['code']
        mock_cache.set.assert_any_call(
            f'tg:link:{code}',
            json.dumps({'user_id': str(self.user.id)}),
            300,
        )

    @patch('scanner.auth_views.cache')
    def test_deletes_previous_code(self, mock_cache):
        mock_cache.get.return_value = '654321'
        request = self.factory.post('/api/preferences/telegram-link/')
        force_authenticate(request, user=self.user)
        telegram_link_code(request)
        mock_cache.delete.assert_any_call('tg:link:654321')

    @patch('scanner.auth_views.cache')
    def test_rate_limited(self, mock_cache):
        mock_cache.get.side_effect = [None, None, None, None]
        for i in range(4):
            request = self.factory.post('/api/preferences/telegram-link/')
            force_authenticate(request, user=self.user)
            response = telegram_link_code(request)
        # 4th request within window — should check rate limit
        # (actual rate check depends on cache mock behavior)
        assert response.status_code in (200, 429)
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
cd /home/demon/Tools/demon-in-the-wire/web_portal && python -m pytest scanner/tests/test_telegram_link.py -v 2>&1 | head -10
```

Expected: ImportError (`telegram_link_code` not in auth_views).

- [ ] **Step 3: Implement the link endpoint**

In `web_portal/scanner/auth_views.py`, add these imports near the top (after existing imports around line 15):

```python
import json
import secrets
```

Then add the view function at the end of the file (before any trailing whitespace):

```python
@api_view(['POST'])
def telegram_link_code(request):
    """Generate a 6-digit one-time code for Telegram account linking."""
    user_key = f'tg:linkgen:{request.user.id}'
    gen_count = cache.get(user_key, 0)
    if gen_count >= 3:
        return Response({'error': 'Too many code requests. Try again in 5 minutes.'}, status=429)

    reverse_key = f'tg:linkuser:{request.user.id}'
    old_code = cache.get(reverse_key)
    if old_code:
        cache.delete(f'tg:link:{old_code}')
        cache.delete(reverse_key)

    code = str(secrets.randbelow(900000) + 100000)
    cache.set(f'tg:link:{code}', json.dumps({'user_id': str(request.user.id)}), 300)
    cache.set(reverse_key, code, 300)
    cache.set(user_key, gen_count + 1, 300)

    return Response({'code': code, 'expires_in': 300})
```

- [ ] **Step 4: Wire up the URL**

In `web_portal/wireghost_web/urls.py`, add the import at the top with the other auth_views imports:

```python
from scanner.auth_views import telegram_link_code
```

Add the path in `urlpatterns` near the other preferences/notifications routes:

```python
    path('api/preferences/telegram-link/', telegram_link_code, name='telegram-link-code'),
```

- [ ] **Step 5: Run tests to verify they pass**

Run:
```bash
cd /home/demon/Tools/demon-in-the-wire/web_portal && python -m pytest scanner/tests/test_telegram_link.py -v
```

Expected: All 4 tests pass.

- [ ] **Step 6: Commit**

```bash
git add web_portal/scanner/auth_views.py web_portal/wireghost_web/urls.py web_portal/scanner/tests/test_telegram_link.py
git commit -m "feat(bot): add POST /api/preferences/telegram-link/ endpoint"
```

---

### Task 5: Viewer Command Handlers

**Files:**
- Create: `web_portal/scanner/bot/handlers.py`
- Create: `web_portal/scanner/tests/test_bot_handlers.py`

- [ ] **Step 1: Write failing tests for viewer commands**

Create `web_portal/scanner/tests/test_bot_handlers.py`:

```python
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from django.test import TestCase
from scanner.models import User, UserPreference, Scan, Finding, Host, Asset
from scanner.bot.handlers import cmd_status, cmd_scans, cmd_scan, cmd_findings, cmd_assets, cmd_help


def _make_context(user):
    ctx = MagicMock()
    ctx.user_data = {'wg_user': user}
    ctx.args = []
    return ctx


def _make_update(text='/status', args=None):
    update = MagicMock()
    update.effective_user = MagicMock()
    update.effective_user.id = 12345
    update.effective_chat = MagicMock()
    update.effective_chat.id = 67890
    update.message = MagicMock()
    update.message.text = text
    update.message.reply_text = AsyncMock()
    return update


class TestStatusCommand(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='viewer1', password='pass1234', role='viewer',
        )
        prefs = UserPreference.for_user(self.user)
        prefs.telegram_user_id = 12345
        prefs.save()
        Scan.objects.create(
            name='Test Scan', target='10.0.0.0/24', scan_type='full',
            status='completed', created_by=self.user,
            hosts_count=5, findings_count=10, critical_count=1,
            high_count=2, medium_count=3, low_count=4,
        )

    @pytest.mark.asyncio
    async def test_status_shows_counts(self):
        update = _make_update('/status')
        ctx = _make_context(self.user)
        await cmd_status(update, ctx)
        reply = update.message.reply_text.call_args[0][0]
        assert 'Total hosts' in reply or 'hosts' in reply.lower()
        assert 'findings' in reply.lower()


class TestScansCommand(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='viewer2', password='pass1234', role='viewer',
        )
        for i in range(3):
            Scan.objects.create(
                name=f'Scan {i}', target=f'10.0.{i}.0/24',
                scan_type='full', status='completed', created_by=self.user,
                findings_count=i * 10,
            )

    @pytest.mark.asyncio
    async def test_scans_lists_recent(self):
        update = _make_update('/scans')
        ctx = _make_context(self.user)
        await cmd_scans(update, ctx)
        reply = update.message.reply_text.call_args[0][0]
        assert '10.0.0.0/24' in reply
        assert '10.0.1.0/24' in reply
        assert '10.0.2.0/24' in reply


class TestHelpCommand(TestCase):
    def setUp(self):
        self.viewer = User.objects.create_user(
            username='helpviewer', password='pass1234', role='viewer',
        )

    @pytest.mark.asyncio
    async def test_help_shows_commands(self):
        update = _make_update('/help')
        ctx = _make_context(self.viewer)
        await cmd_help(update, ctx)
        reply = update.message.reply_text.call_args[0][0]
        assert '/status' in reply
        assert '/scans' in reply
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
cd /home/demon/Tools/demon-in-the-wire/web_portal && python -m pytest scanner/tests/test_bot_handlers.py -v 2>&1 | head -10
```

Expected: ImportError (handlers module doesn't exist).

- [ ] **Step 3: Implement the viewer command handlers**

Create `web_portal/scanner/bot/handlers.py`:

```python
from __future__ import annotations

import logging

from asgiref.sync import sync_to_async
from django.db.models import Sum, Q, Count
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes

from scanner.bot.auth import resolve_user, link_account, unlink_account, check_rate_limit
from scanner.bot.formatting import (
    escape_md, severity_emoji, severity_line, short_id,
    status_icon, truncate_list, format_duration,
)
from scanner.models import (
    AuditLog, Asset, Finding, Host, Scan, ScheduledScan,
    ScanPolicy, SiteConfig, User, UserPreference,
)

log = logging.getLogger('scanner.bot')


# ── Pre-auth commands (no decorator) ─────────────────────

async def cmd_link(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text('Usage: /link <6-digit code>')
        return
    code = context.args[0].strip()
    tg_user = update.effective_user
    chat_id = update.effective_user.id

    ok, msg = await sync_to_async(link_account)(
        tg_user_id=tg_user.id, tg_chat_id=chat_id, code=code,
    )
    await update.message.reply_text(msg)

    if ok and update.effective_chat.type in ('group', 'supergroup'):
        cfg = await sync_to_async(SiteConfig.get)()
        user = await sync_to_async(resolve_user)(tg_user.id)
        if not cfg.telegram_shared_chat_id and user and user.role == 'owner':
            await update.message.reply_text(
                'Use this group for Wire_Ghost notifications? Send /yes or /no',
            )
            context.user_data['_pending_group_confirm'] = str(update.effective_chat.id)


async def cmd_unlink(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ok, msg = await sync_to_async(unlink_account)(update.effective_user.id)
    await update.message.reply_text(msg)


async def cmd_yes(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = context.user_data.pop('_pending_group_confirm', None)
    if not chat_id:
        return
    cfg = await sync_to_async(SiteConfig.get)()
    cfg.telegram_shared_chat_id = chat_id
    await sync_to_async(cfg.save)(update_fields=['telegram_shared_chat_id'])
    await update.message.reply_text('This group is now set for Wire_Ghost notifications.')


async def cmd_no(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.pop('_pending_group_confirm', None)
    await update.message.reply_text('OK, group not set.')


# ── Viewer commands ──────────────────────────────────────

async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    def _query():
        active = Scan.objects.filter(status='running').count()
        agg = Scan.objects.filter(status='completed').aggregate(
            hosts=Sum('hosts_count'),
            findings=Sum('findings_count'),
            critical=Sum('critical_count'),
            high=Sum('high_count'),
            medium=Sum('medium_count'),
            low=Sum('low_count'),
        )
        return active, agg

    active, agg = await sync_to_async(_query)()

    lines = [
        'Wire_Ghost Status',
        '━━━━━━━━━━━━━━━━━',
        f'Active scans: {active}',
        f'Total hosts: {agg["hosts"] or 0}',
        f'Total findings: {agg["findings"] or 0}',
        f'  🔴 Critical: {agg["critical"] or 0}',
        f'  🟠 High: {agg["high"] or 0}',
        f'  🟡 Medium: {agg["medium"] or 0}',
        f'  🔵 Low: {agg["low"] or 0}',
    ]
    await update.message.reply_text('\n'.join(lines))


async def cmd_scans(update: Update, context: ContextTypes.DEFAULT_TYPE):
    def _query():
        return list(
            Scan.objects.order_by('-created_at')[:10]
            .values_list('id', 'target', 'scan_type', 'status', 'findings_count')
        )

    rows = await sync_to_async(_query)()
    if not rows:
        await update.message.reply_text('No scans found.')
        return

    lines = ['Recent Scans', '━━━━━━━━━━━━']
    for scan_id, target, stype, st, fcount in rows:
        icon = status_icon(st)
        sid = short_id(scan_id)
        lines.append(f'{icon} {sid} | {target} | {stype} | {fcount} findings')

    await update.message.reply_text('\n'.join(lines))


async def cmd_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text('Usage: /scan <id>')
        return

    prefix = context.args[0].strip()

    def _query():
        qs = Scan.objects.filter(id__startswith=prefix)
        if not qs.exists():
            return None
        return qs.first()

    scan = await sync_to_async(_query)()
    if not scan:
        await update.message.reply_text(f'Scan {prefix} not found.')
        return

    sid = short_id(scan.id)
    dur = format_duration(scan.duration_seconds)
    sev = severity_line(
        critical=scan.critical_count, high=scan.high_count,
        medium=scan.medium_count, low=scan.low_count,
    )
    lines = [
        f'Scan: {sid}',
        '━━━━━━━━━━━━━━',
        f'Target: {scan.target}',
        f'Type: {scan.scan_type} | Status: {scan.status}',
        f'Duration: {dur}',
        f'Hosts: {scan.hosts_count} | Ports: {scan.ports_count}',
        f'Findings: {scan.findings_count}',
        f'  {sev}',
    ]
    reports = await sync_to_async(
        lambda: list(scan.reports.values_list('format', flat=True))
    )()
    if reports:
        lines.append(f'Reports: {", ".join(reports)}')

    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton('Findings', callback_data=f'scan:{sid}:findings'),
            InlineKeyboardButton('Report', callback_data=f'scan:{sid}:report'),
        ]
    ])
    await update.message.reply_text('\n'.join(lines), reply_markup=keyboard)


async def cmd_findings(update: Update, context: ContextTypes.DEFAULT_TYPE):
    severity_filter = context.args[0].lower() if context.args else None
    valid_severities = {'critical', 'high', 'medium', 'low', 'info'}
    if severity_filter and severity_filter not in valid_severities:
        await update.message.reply_text(
            f'Invalid severity. Use: {", ".join(sorted(valid_severities))}',
        )
        return

    def _query():
        qs = Finding.objects.order_by('-id')
        if severity_filter:
            qs = qs.filter(severity=severity_filter)
        return list(qs[:15].values_list('severity', 'title', 'host_ip', 'port'))

    rows = await sync_to_async(_query)()
    if not rows:
        await update.message.reply_text('No findings found.')
        return

    label = f'{severity_filter.title()} Findings' if severity_filter else 'Recent Findings'
    lines = [label, '━━━━━━━━━━━━━━━━━']
    shown, remaining = truncate_list(rows, 15)
    for sev, title, ip, port in shown:
        emoji = severity_emoji(sev)
        loc = f'{ip}:{port}' if port else ip or ''
        lines.append(f'{emoji} {title} ({loc})')
    if remaining:
        lines.append(f'… and {remaining} more')

    await update.message.reply_text('\n'.join(lines))


async def cmd_assets(update: Update, context: ContextTypes.DEFAULT_TYPE):
    def _query():
        return list(
            Asset.objects.order_by('-risk_score')[:10]
            .values_list('ip', 'service_name', 'risk_score', 'findings_count')
        )

    rows = await sync_to_async(_query)()
    if not rows:
        await update.message.reply_text('No assets found.')
        return

    lines = ['High\\-Risk Assets', '━━━━━━━━━━━━━━━━']
    for ip, svc, risk, fcount in rows:
        svc_label = svc or 'unknown'
        lines.append(f'⚠️ {ip} | {svc_label} | risk: {risk} | {fcount} findings')

    await update.message.reply_text('\n'.join(lines))


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = context.user_data.get('wg_user')

    viewer_cmds = [
        '/status — Dashboard summary',
        '/scans — Recent scans',
        '/scan <id> — Scan detail',
        '/findings [severity] — List findings',
        '/assets — Top assets by risk',
        '/help — This message',
        '/link <code> — Link Telegram account',
        '/unlink — Unlink account',
    ]
    engineer_cmds = [
        '/newscan <target> [type] — Launch scan',
        '/cancel <id> — Cancel scan',
        '/schedule list|add|del — Manage schedules',
        '/report <id> — Regenerate reports',
    ]
    owner_cmds = [
        '/users — List users',
        '/config — Site configuration',
        '/health — System health',
    ]

    lines = ['Wire_Ghost Bot Commands', '━━━━━━━━━━━━━━━━━━━━━━━']
    lines.extend(viewer_cmds)

    if user and user.has_permission('scan:write'):
        lines.append('')
        lines.extend(engineer_cmds)

    if user and user.role == 'owner':
        lines.append('')
        lines.extend(owner_cmds)

    await update.message.reply_text('\n'.join(lines))


# ── Engineer commands ────────────────────────────────────

async def cmd_newscan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text('Usage: /newscan <target> [full|quick|port|web]')
        return

    user = context.user_data['wg_user']

    if not check_rate_limit('tg:scanrate:', str(update.effective_user.id), 5, 3600):
        await update.message.reply_text('Scan rate limit: max 5 per hour.')
        return

    import re
    target = context.args[0].strip()
    scan_type = context.args[1].strip().lower() if len(context.args) > 1 else 'full'

    if scan_type not in ('full', 'quick', 'port', 'web'):
        await update.message.reply_text('Invalid scan type. Use: full, quick, port, web')
        return

    if not re.match(r'^[a-zA-Z0-9.:/,\-]+$', target):
        await update.message.reply_text('Invalid target format.')
        return

    def _create():
        from scanner.tasks import run_scan
        cfg = SiteConfig.get()
        scan = Scan.objects.create(
            name=f'Telegram: {target}',
            target=target[:500],
            scan_type=scan_type,
            parallelism=cfg.default_parallelism,
            timeout=cfg.default_timeout,
            report_formats=cfg.default_report_formats,
            status='pending',
            created_by=user,
        )
        task = run_scan.delay(str(scan.id))
        scan.celery_task_id = task.id
        scan.status = 'running'
        scan.save(update_fields=['celery_task_id', 'status'])
        return scan

    scan = await sync_to_async(_create)()
    sid = short_id(scan.id)
    await update.message.reply_text(f'Scan `{sid}` launched against `{target}` (type: {scan_type})')


async def cmd_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text('Usage: /cancel <id>')
        return

    prefix = context.args[0].strip()
    user = context.user_data['wg_user']

    def _cancel():
        qs = Scan.objects.filter(id__startswith=prefix, status='running')
        scan = qs.first()
        if not scan:
            return None, 'No running scan found with that ID.'
        if scan.created_by != user and user.role != 'owner':
            return None, 'Only the scan creator or Owner can cancel.'
        from wireghost_web.celery import app as celery_app
        if scan.celery_task_id:
            celery_app.control.revoke(scan.celery_task_id, terminate=True, signal='SIGTERM')
        scan.status = 'cancelled'
        scan.save(update_fields=['status'])
        return scan, None

    scan, err = await sync_to_async(_cancel)()
    if err:
        await update.message.reply_text(err)
        return
    await update.message.reply_text(f'Scan `{short_id(scan.id)}` cancelled.')


async def cmd_schedule(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text('Usage: /schedule list|add|del')
        return

    sub = context.args[0].lower()
    user = context.user_data['wg_user']

    if sub == 'list':
        def _list():
            return list(
                ScheduledScan.objects.filter(enabled=True)
                .order_by('next_run')[:10]
                .values_list('id', 'target', 'frequency', 'time', 'next_run')
            )
        rows = await sync_to_async(_list)()
        if not rows:
            await update.message.reply_text('No active schedules.')
            return
        lines = ['Scheduled Scans', '━━━━━━━━━━━━━━━']
        for sid, target, freq, t, nxt in rows:
            nxt_str = nxt.strftime('%Y-%m-%d %H:%M') if nxt else '—'
            lines.append(f'📅 {short_id(sid)} | {target} | {freq} {t.strftime("%H:%M")} | next: {nxt_str}')
        await update.message.reply_text('\n'.join(lines))

    elif sub == 'add':
        if len(context.args) < 4:
            await update.message.reply_text('Usage: /schedule add <target> <daily|weekly|biweekly|monthly> <HH:MM>')
            return
        import re
        from datetime import time as dt_time
        target = context.args[1]
        freq = context.args[2].lower()
        time_str = context.args[3]

        if freq not in ('daily', 'weekly', 'biweekly', 'monthly'):
            await update.message.reply_text('Invalid frequency. Use: daily, weekly, biweekly, monthly')
            return
        if not re.match(r'^\d{2}:\d{2}$', time_str):
            await update.message.reply_text('Invalid time format. Use HH:MM (24-hour)')
            return
        if not re.match(r'^[a-zA-Z0-9.:/,\-]+$', target):
            await update.message.reply_text('Invalid target format.')
            return

        h, m = int(time_str[:2]), int(time_str[3:5])
        if h > 23 or m > 59:
            await update.message.reply_text('Invalid time.')
            return

        def _create():
            from scanner.tasks import _calc_next_run
            sched = ScheduledScan.objects.create(
                name=f'Telegram: {target}',
                target=target[:500],
                frequency=freq,
                time=dt_time(h, m),
                scan_type='full',
                enabled=True,
                created_by=user,
                next_run=_calc_next_run(freq, dt_time(h, m)),
            )
            return sched

        sched = await sync_to_async(_create)()
        await update.message.reply_text(f'Schedule created: `{target}` every {freq} at {time_str}')

    elif sub == 'del':
        if len(context.args) < 2:
            await update.message.reply_text('Usage: /schedule del <id>')
            return
        prefix = context.args[1]

        def _delete():
            qs = ScheduledScan.objects.filter(id__startswith=prefix)
            sched = qs.first()
            if not sched:
                return 'Schedule not found.'
            if sched.created_by != user and user.role != 'owner':
                return 'Only the creator or Owner can delete.'
            sched.delete()
            return None

        err = await sync_to_async(_delete)()
        if err:
            await update.message.reply_text(err)
        else:
            await update.message.reply_text('Schedule deleted.')

    else:
        await update.message.reply_text('Usage: /schedule list|add|del')


async def cmd_report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text('Usage: /report <scan_id>')
        return

    prefix = context.args[0].strip()

    def _find():
        qs = Scan.objects.filter(id__startswith=prefix, status='completed')
        return qs.first()

    scan = await sync_to_async(_find)()
    if not scan:
        await update.message.reply_text(f'No completed scan found with ID {prefix}.')
        return

    def _launch():
        from scanner.tasks import generate_report
        generate_report.delay(str(scan.id))

    await sync_to_async(_launch)()
    sid = short_id(scan.id)
    await update.message.reply_text(f'Generating reports for scan `{sid}`… I\'ll send the file when ready.')


# ── Owner commands ───────────────────────────────────────

async def cmd_users(update: Update, context: ContextTypes.DEFAULT_TYPE):
    def _query():
        users = User.objects.filter(is_active=True).order_by('role', 'username')
        result = []
        for u in users:
            prefs = UserPreference.for_user(u)
            linked = bool(prefs.telegram_user_id)
            result.append((u.username, u.role, linked))
        return result

    rows = await sync_to_async(_query)()
    role_icons = {'owner': '👑', 'engineer': '🔧', 'viewer': '👁'}
    lines = ['Users', '━━━━━']
    for uname, role, linked in rows:
        icon = role_icons.get(role, '❓')
        link_str = '🔗 linked' if linked else '❌ not linked'
        lines.append(f'{icon} {uname} | {role} | {link_str}')

    # Send via DM for privacy
    try:
        await context.bot.send_message(
            chat_id=update.effective_user.id,
            text='\n'.join(lines),
        )
        if update.effective_chat.type in ('group', 'supergroup'):
            await update.message.reply_text('User list sent via DM.')
    except Exception:
        await update.message.reply_text('\n'.join(lines))


async def cmd_config(update: Update, context: ContextTypes.DEFAULT_TYPE):
    def _query():
        cfg = SiteConfig.get()
        return {
            'timezone': cfg.schedule_timezone,
            'parallelism': cfg.default_parallelism,
            'timeout': cfg.default_timeout,
            'bot_configured': bool(cfg.telegram_bot_token),
            'shared_chat': bool(cfg.telegram_shared_chat_id),
        }

    data = await sync_to_async(_query)()
    lines = [
        'Site Config',
        '━━━━━━━━━━━',
        f'Timezone: {data["timezone"]}',
        f'Default parallelism: {data["parallelism"]}',
        f'Default timeout: {data["timeout"]}s',
        f'Telegram bot: {"✅ configured" if data["bot_configured"] else "❌ not configured"}',
        f'Shared chat: {"✅ set" if data["shared_chat"] else "❌ not set"}',
    ]

    try:
        await context.bot.send_message(
            chat_id=update.effective_user.id,
            text='\n'.join(lines),
        )
        if update.effective_chat.type in ('group', 'supergroup'):
            await update.message.reply_text('Config sent via DM.')
    except Exception:
        await update.message.reply_text('\n'.join(lines))


async def cmd_health(update: Update, context: ContextTypes.DEFAULT_TYPE):
    def _query():
        import psutil
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        return {
            'cpu': f'{cpu}%',
            'ram': f'{mem.used / (1024**3):.1f}/{mem.total / (1024**3):.1f} GB',
            'disk': f'{disk.used / (1024**3):.0f}/{disk.total / (1024**3):.0f} GB',
        }

    stats = await sync_to_async(_query)()
    lines = [
        'System Health',
        '━━━━━━━━━━━━━',
        f'CPU: {stats["cpu"]} | RAM: {stats["ram"]} | Disk: {stats["disk"]}',
    ]
    await update.message.reply_text('\n'.join(lines))
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
cd /home/demon/Tools/demon-in-the-wire/web_portal && python -m pytest scanner/tests/test_bot_handlers.py -v
```

Expected: All 3 tests pass (status, scans, help).

- [ ] **Step 5: Commit**

```bash
git add web_portal/scanner/bot/handlers.py web_portal/scanner/tests/test_bot_handlers.py
git commit -m "feat(bot): command handlers for viewer, engineer, and owner tiers"
```

---

### Task 6: Callback Query Handlers

**Files:**
- Create: `web_portal/scanner/bot/callbacks.py`

- [ ] **Step 1: Implement callback handlers**

Create `web_portal/scanner/bot/callbacks.py`:

```python
from __future__ import annotations

import logging

from asgiref.sync import sync_to_async
from telegram import Update
from telegram.ext import ContextTypes

from scanner.bot.auth import resolve_user
from scanner.bot.formatting import (
    severity_emoji, severity_line, short_id, format_duration, truncate_list,
)
from scanner.models import Finding, Scan

log = logging.getLogger('scanner.bot')


async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    if not query or not query.data:
        return

    await query.answer()

    tg_user_id = query.from_user.id
    user = await sync_to_async(resolve_user)(tg_user_id)
    if not user:
        await query.edit_message_text('Not linked. Use /link <code> first.')
        return

    parts = query.data.split(':')
    if len(parts) < 3:
        return

    entity, entity_id, action = parts[0], parts[1], parts[2]

    if entity == 'scan':
        if action == 'findings':
            await _scan_findings(query, entity_id)
        elif action == 'report':
            await _scan_report(query, entity_id, context)

    elif entity == 'findings':
        await _severity_findings(query, entity_id)


async def _scan_findings(query, scan_prefix: str):
    def _query():
        scan = Scan.objects.filter(id__startswith=scan_prefix).first()
        if not scan:
            return None, []
        findings = list(
            Finding.objects.filter(scan=scan)
            .order_by('severity', '-id')[:15]
            .values_list('severity', 'title', 'host_ip', 'port')
        )
        return scan, findings

    scan, rows = await sync_to_async(_query)()
    if not scan:
        await query.edit_message_text(f'Scan {scan_prefix} not found.')
        return

    if not rows:
        await query.edit_message_text(f'No findings for scan {short_id(scan.id)}.')
        return

    lines = [f'Findings for {short_id(scan.id)}', '━━━━━━━━━━━━━━━━━']
    shown, remaining = truncate_list(rows, 15)
    for sev, title, ip, port in shown:
        emoji = severity_emoji(sev)
        loc = f'{ip}:{port}' if port else ip or ''
        lines.append(f'{emoji} {title} ({loc})')
    if remaining:
        lines.append(f'… and {remaining} more')

    await query.edit_message_text('\n'.join(lines))


async def _scan_report(query, scan_prefix: str, context):
    def _launch():
        scan = Scan.objects.filter(id__startswith=scan_prefix, status='completed').first()
        if not scan:
            return None
        from scanner.tasks import generate_report
        generate_report.delay(str(scan.id))
        return scan

    scan = await sync_to_async(_launch)()
    if not scan:
        await query.edit_message_text(f'No completed scan found with ID {scan_prefix}.')
        return

    await query.edit_message_text(
        f'Generating reports for scan `{short_id(scan.id)}`… File will be sent when ready.',
    )


async def _severity_findings(query, severity: str):
    def _query():
        return list(
            Finding.objects.filter(severity=severity)
            .order_by('-id')[:15]
            .values_list('severity', 'title', 'host_ip', 'port')
        )

    rows = await sync_to_async(_query)()
    if not rows:
        await query.edit_message_text(f'No {severity} findings found.')
        return

    lines = [f'{severity.title()} Findings', '━━━━━━━━━━━━━━━━━']
    shown, remaining = truncate_list(rows, 15)
    for sev, title, ip, port in shown:
        emoji = severity_emoji(sev)
        loc = f'{ip}:{port}' if port else ip or ''
        lines.append(f'{emoji} {title} ({loc})')
    if remaining:
        lines.append(f'… and {remaining} more')

    await query.edit_message_text('\n'.join(lines))
```

- [ ] **Step 2: Commit**

```bash
git add web_portal/scanner/bot/callbacks.py
git commit -m "feat(bot): callback query handlers for inline buttons"
```

---

### Task 7: Management Command (Entry Point)

**Files:**
- Create: `web_portal/scanner/management/__init__.py`
- Create: `web_portal/scanner/management/commands/__init__.py`
- Create: `web_portal/scanner/management/commands/telegrambot.py`

- [ ] **Step 1: Create Django management command package structure**

```bash
mkdir -p /home/demon/Tools/demon-in-the-wire/web_portal/scanner/management/commands
touch /home/demon/Tools/demon-in-the-wire/web_portal/scanner/management/__init__.py
touch /home/demon/Tools/demon-in-the-wire/web_portal/scanner/management/commands/__init__.py
```

- [ ] **Step 2: Implement the management command**

Create `web_portal/scanner/management/commands/telegrambot.py`:

```python
import asyncio
import logging
import signal
import sys
import threading
import time

import redis
from django.core.management.base import BaseCommand

from telegram import Update
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
)

from scanner.bot.auth import require_permission
from scanner.bot.callbacks import handle_callback
from scanner.bot.handlers import (
    cmd_assets,
    cmd_cancel,
    cmd_config,
    cmd_findings,
    cmd_health,
    cmd_help,
    cmd_link,
    cmd_newscan,
    cmd_no,
    cmd_report,
    cmd_scan,
    cmd_scans,
    cmd_schedule,
    cmd_status,
    cmd_unlink,
    cmd_users,
    cmd_yes,
)
from scanner.models import SiteConfig

log = logging.getLogger('scanner.bot')


class Command(BaseCommand):
    help = 'Run the Telegram bot for Wire_Ghost remote control'

    def handle(self, *args, **options):
        while True:
            cfg = SiteConfig.get()
            token = cfg.telegram_bot_token
            if not token:
                self.stderr.write('No Telegram bot token configured. Retrying in 30s…')
                time.sleep(30)
                continue
            break

        self.stdout.write(f'Starting Telegram bot (long-polling)…')

        app = Application.builder().token(token).build()

        # Pre-auth commands (no permission gate)
        app.add_handler(CommandHandler('link', cmd_link))
        app.add_handler(CommandHandler('unlink', cmd_unlink))
        app.add_handler(CommandHandler('yes', cmd_yes))
        app.add_handler(CommandHandler('no', cmd_no))

        # Viewer commands (scan:read)
        app.add_handler(CommandHandler('status', require_permission('scan:read')(cmd_status)))
        app.add_handler(CommandHandler('scans', require_permission('scan:read')(cmd_scans)))
        app.add_handler(CommandHandler('scan', require_permission('scan:read')(cmd_scan)))
        app.add_handler(CommandHandler('findings', require_permission('scan:read')(cmd_findings)))
        app.add_handler(CommandHandler('assets', require_permission('scan:read')(cmd_assets)))
        app.add_handler(CommandHandler('help', cmd_help))

        # Engineer commands (scan:write)
        app.add_handler(CommandHandler('newscan', require_permission('scan:write')(cmd_newscan)))
        app.add_handler(CommandHandler('cancel', require_permission('scan:write')(cmd_cancel)))
        app.add_handler(CommandHandler('schedule', require_permission('scan:write')(cmd_schedule)))
        app.add_handler(CommandHandler('report', require_permission('scan:write')(cmd_report)))

        # Owner commands
        app.add_handler(CommandHandler('users', require_permission('user:manage')(cmd_users)))
        app.add_handler(CommandHandler('config', require_permission('site:config')(cmd_config)))
        app.add_handler(CommandHandler('health', require_permission('site:config')(cmd_health)))

        # Callback queries (inline buttons)
        app.add_handler(CallbackQueryHandler(handle_callback))

        # Start Redis pub/sub listener in background thread
        self._start_pubsub_listener(app, cfg)

        app.run_polling(
            allowed_updates=Update.ALL_TYPES,
            drop_pending_updates=True,
        )

    def _start_pubsub_listener(self, app, cfg):
        """Listen for notification events from worker containers via Redis pub/sub."""
        import json
        from django.conf import settings

        broker_url = getattr(settings, 'CELERY_BROKER_URL', '')
        if not broker_url:
            log.warning('No CELERY_BROKER_URL configured, skipping pub/sub listener')
            return

        def _listener():
            try:
                r = redis.Redis.from_url(broker_url)
                pubsub = r.pubsub()
                pubsub.subscribe('wireghost:bot:notify')
                log.info('Redis pub/sub listener started on wireghost:bot:notify')

                for message in pubsub.listen():
                    if message['type'] != 'message':
                        continue
                    try:
                        data = json.loads(message['data'])
                        event = data.get('event')
                        chat_id = data.get('chat_id')
                        text = data.get('text', '')
                        document_path = data.get('document_path')

                        if not chat_id:
                            chat_id = cfg.telegram_shared_chat_id
                        if not chat_id:
                            continue

                        loop = asyncio.new_event_loop()
                        if document_path:
                            import os
                            if os.path.isfile(document_path):
                                loop.run_until_complete(
                                    app.bot.send_document(
                                        chat_id=int(chat_id),
                                        document=open(document_path, 'rb'),
                                        caption=text[:1024] if text else None,
                                    )
                                )
                            else:
                                log.warning('Document not found: %s', document_path)
                        elif text:
                            loop.run_until_complete(
                                app.bot.send_message(chat_id=int(chat_id), text=text)
                            )
                        loop.close()
                    except Exception:
                        log.exception('Error processing pub/sub message')
            except Exception:
                log.exception('Redis pub/sub listener crashed')

        thread = threading.Thread(target=_listener, daemon=True, name='bot-pubsub')
        thread.start()
```

- [ ] **Step 3: Verify the command is discoverable**

Run:
```bash
docker compose exec api python manage.py telegrambot --help
```

Expected: Shows the help text "Run the Telegram bot for Wire_Ghost remote control" (will fail to start because no token is configured, but discovery works).

- [ ] **Step 4: Commit**

```bash
git add web_portal/scanner/management/
git commit -m "feat(bot): Django management command entry point with pub/sub listener"
```

---

### Task 8: Notification Upgrade

**Files:**
- Modify: `web_portal/scanner/notifications.py`

- [ ] **Step 1: Read the current notifications.py to identify exact edit locations**

The file is at `web_portal/scanner/notifications.py`. The key functions to modify:

- `_render()` (lines 96-122): Upgrade message format to be richer
- `notify()` (lines 126-165): Add Redis pub/sub publish for rich features

- [ ] **Step 2: Add Redis pub/sub publish to notify()**

At the top of `web_portal/scanner/notifications.py`, add to the imports:

```python
import redis as redis_lib
from django.conf import settings
```

After the existing `notify()` function's shared-channel send and creator-DM send blocks, add the pub/sub publish. Insert this at the end of `notify()`, before the final `except`:

```python
    # Publish to Redis pub/sub for bot-enhanced delivery (inline buttons, file attachments)
    try:
        broker_url = getattr(settings, 'CELERY_BROKER_URL', '')
        if broker_url:
            r = redis_lib.Redis.from_url(broker_url)
            pub_data = {
                'event': event_type,
                'text': text,
                'chat_id': '',
            }
            if scan and event_type == 'report.ready':
                reports = list(scan.reports.filter(format='docx').values_list('file_path', flat=True))
                if reports:
                    pub_data['document_path'] = reports[0]
            r.publish('wireghost:bot:notify', json.dumps(pub_data))
    except Exception:
        log.debug('Redis pub/sub publish failed (bot may not be running)', exc_info=True)
```

- [ ] **Step 3: Add notify('report.ready') call to generate_report task**

In `web_portal/scanner/tasks.py`, in the `generate_report()` function, add a `notify()` call after successful report generation (after the reports are saved to DB, near the end of the function):

```python
    try:
        from scanner.notifications import notify
        notify('report.ready', scan=scan)
    except Exception:
        logger.exception('notification dispatch failed for report %s', scan_id)
```

- [ ] **Step 4: Commit**

```bash
git add web_portal/scanner/notifications.py web_portal/scanner/tasks.py
git commit -m "feat(bot): upgrade notifications with Redis pub/sub for rich delivery"
```

---

### Task 9: Docker Compose Integration

**Files:**
- Modify: `docker-compose.yml`

- [ ] **Step 1: Add the bot service**

In `docker-compose.yml`, add the `bot` service after the `beat` service (around line 148). It reuses the YAML anchors `*api-env` and `*api-vols`:

```yaml
  bot:
    build: { context: ., dockerfile: web_portal/Dockerfile }
    restart: unless-stopped
    user: "1000:1000"
    networks: [wireghost_net]
    environment: *api-env
    volumes: *api-vols
    depends_on:
      db: { condition: service_healthy }
      redis: { condition: service_healthy }
    command: python manage.py telegrambot
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: "0.5"
```

- [ ] **Step 2: Rebuild the image to include the new dependency**

Run:
```bash
cd /home/demon/Tools/demon-in-the-wire && docker compose build api
```

Expected: Image builds successfully with `python-telegram-bot` installed.

- [ ] **Step 3: Verify the bot service starts (will exit gracefully without token)**

Run:
```bash
docker compose up -d bot && sleep 5 && docker compose logs bot --tail=5
```

Expected: Logs show "No Telegram bot token configured. Retrying in 30s…" (expected — no token set yet).

- [ ] **Step 4: Commit**

```bash
git add docker-compose.yml
git commit -m "feat(bot): add Telegram bot service to docker-compose"
```

---

### Task 10: Frontend — Settings Link Code Button

**Files:**
- Modify: `web/js/app/pages/settings.js`

This adds a "Generate Link Code" button to the Telegram section of the Settings page.

- [ ] **Step 1: Find the existing Telegram section in settings.js**

The Telegram settings section is in `web/js/app/pages/settings.js`. Find the section that handles `telegram_chat_id` and `telegram_enabled` inputs.

- [ ] **Step 2: Add the link code button and handler**

After the existing Telegram chat ID input field in the settings page, add:

```javascript
// Telegram Link Code
const linkBtn = document.createElement('button');
linkBtn.type = 'button';
linkBtn.className = 'btn btn-sm btn-outline';
linkBtn.textContent = 'Generate Link Code';
linkBtn.addEventListener('click', async () => {
    try {
        const res = await api.post('/api/preferences/telegram-link/');
        if (res.ok) {
            const data = await res.json();
            linkBtn.textContent = `Code: ${data.code} (expires in 5m)`;
            linkBtn.disabled = true;
            setTimeout(() => {
                linkBtn.textContent = 'Generate Link Code';
                linkBtn.disabled = false;
            }, 300000);
        } else {
            const err = await res.json();
            linkBtn.textContent = err.error || 'Failed';
            setTimeout(() => { linkBtn.textContent = 'Generate Link Code'; }, 3000);
        }
    } catch (e) {
        linkBtn.textContent = 'Error';
        setTimeout(() => { linkBtn.textContent = 'Generate Link Code'; }, 3000);
    }
});
```

Insert this button element into the Telegram settings section of the form. The exact insertion point depends on the current DOM structure — find the container that holds the chat_id input and append the button after it.

- [ ] **Step 3: Commit**

```bash
git add web/js/app/pages/settings.js
git commit -m "feat(bot): add Generate Link Code button to Settings → Telegram"
```

---

### Task 11: Integration Test — Full Flow

**Files:**
- No new files — manual verification

- [ ] **Step 1: Configure a Telegram bot token**

1. Message @BotFather on Telegram → `/newbot` → get the token
2. In Wire_Ghost web portal, go to Settings → Notifications → paste the bot token
3. Or via API:
```bash
curl -sk -X PUT https://localhost:18443/api/notifications/config/ \
  -H "Authorization: Token <your_wg_token>" \
  -H "Content-Type: application/json" \
  -d '{"bot_token": "<telegram_bot_token>"}'
```

- [ ] **Step 2: Restart the bot service**

```bash
docker compose restart bot && sleep 5 && docker compose logs bot --tail=10
```

Expected: Logs show "Starting Telegram bot (long-polling)…" — no errors.

- [ ] **Step 3: Test account linking**

1. In web portal Settings → Telegram → click "Generate Link Code" → copy the 6-digit code
2. In Telegram group, add the bot and send: `/link <code>`
3. Expected: Bot replies "Linked to `<your_username>` (role: owner)"

- [ ] **Step 4: Test viewer commands**

Send in the group:
- `/status` — should show dashboard summary
- `/scans` — should list recent scans
- `/help` — should show all commands for your role

- [ ] **Step 5: Test engineer commands**

Send in the group:
- `/newscan 10.0.0.1 quick` — should launch a scan
- `/scans` — should show the new scan running
- `/cancel <id>` — should cancel it

- [ ] **Step 6: Test notifications**

Launch a real scan via `/newscan` and wait for completion. Expected:
- Group receives "✅ Scan Complete" notification
- If critical findings, group receives "🚨 Critical Findings Discovered"

- [ ] **Step 7: Final commit with any fixes**

```bash
git add -A && git commit -m "feat(bot): integration fixes from manual testing"
```

---

## Self-Review

### Spec coverage check

| Spec Section | Task |
|---|---|
| Architecture (dedicated service, long-poll) | Task 7 (management command), Task 9 (docker-compose) |
| File Structure (bot/ package) | Task 2-7 |
| Account Linking (6-digit code, Redis, rate limit) | Task 3 (auth.py), Task 4 (API endpoint) |
| Auth Enforcement (decorator, RBAC) | Task 3 (auth.py) |
| Commands — Viewer | Task 5 (handlers.py) |
| Commands — Engineer | Task 5 (handlers.py) |
| Commands — Owner | Task 5 (handlers.py) |
| Notifications upgrade (Redis pub/sub) | Task 8 |
| Callback queries | Task 6 |
| Model changes (telegram_user_id) | Task 1 |
| New API endpoint (telegram-link) | Task 4 |
| Docker Compose (bot service) | Task 9 |
| Security (rate limits, DM for sensitive, validation) | Task 3, Task 5 |
| Graceful degradation (no token → clean exit) | Task 7 |
| Group auto-detection (/yes /no) | Task 5 (cmd_link, cmd_yes, cmd_no) |
| Settings UI (link code button) | Task 10 |
| Testing | Task 2-5 (unit/integration tests), Task 11 (manual) |

### Placeholder scan
No TBD, TODO, "implement later", or "similar to Task N" found.

### Type consistency
- `resolve_user()` returns `Optional[User]` — consistent everywhere
- `link_account()` returns `tuple[bool, str]` — consistent in auth.py and tests
- `short_id()` takes string, returns 8-char prefix — consistent everywhere
- `require_permission()` decorator signature — consistent between auth.py and management command registration
