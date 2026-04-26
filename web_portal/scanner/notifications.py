"""Telegram notification dispatch.

Fires messages to the site-wide shared channel (if the Owner has configured
one) and to the scan-creator's personal chat_id (if they've enabled DMs).

Design goals:
- SSRF-safe: Telegram URL is a constant; chat_id is validated against a
  regex before interpolation.
- Fail-silent: any send error is logged, never raised — a broken Telegram
  config must never fail a scan.
- No retry: Telegram dedupes on user side; retry storms would spam.
"""

from __future__ import annotations

import html as _html
import json
import logging
import re
import urllib.request
import urllib.error
from typing import Optional

import redis as redis_lib
from django.conf import settings

log = logging.getLogger('scanner.notifications')

TELEGRAM_API = 'https://api.telegram.org'

# Telegram chat IDs are signed integers (channels are negative, e.g. -100…)
# or @username references (≥5 chars per Telegram's rules).
_CHAT_ID_RE = re.compile(r'^-?\d+$|^@[\w]{5,}$')

# Event-type → UserPreference attribute name. When present, a User's toggle
# for that event must be truthy for their DM to fire. Shared-channel delivery
# ignores user prefs and respects only the site-wide configuration.
_EVENT_PREF_FIELD = {
    'scan.complete':       'notif_scan_complete',
    'scan.failed':         'notif_scan_failed',
    'critical.discovered': 'notif_critical_finding',
    'report.ready':        'notif_report_ready',
    'digest.weekly':       'notif_weekly_digest',
}


class NotificationError(Exception):
    """Raised by send_telegram when config is unusable (bad chat_id, no token)."""


def _validate_chat_id(chat_id: str) -> None:
    if not chat_id or not _CHAT_ID_RE.match(chat_id):
        raise NotificationError(f'invalid chat_id: {chat_id!r}')


def send_telegram(chat_id: str, text: str, *, bot_token: str, timeout: float = 5.0) -> dict:
    """POST sendMessage to Telegram. Returns ``{'ok': bool, 'error': str|None}``.

    Never raises on network / API errors — returns the error in the dict so
    the caller can log + move on. Raises NotificationError only for
    obviously-broken config that the caller should surface to the user
    (e.g. blank token, malformed chat_id).
    """
    if not bot_token:
        raise NotificationError('bot_token not configured')
    _validate_chat_id(chat_id)

    url = f'{TELEGRAM_API}/bot{bot_token}/sendMessage'
    payload = json.dumps({
        'chat_id': chat_id,
        'text': text,
        'parse_mode': 'HTML',
        'disable_web_page_preview': True,
    }).encode('utf-8')
    req = urllib.request.Request(url, data=payload, method='POST')
    req.add_header('Content-Type', 'application/json')

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode('utf-8', errors='replace'))
            return {'ok': bool(body.get('ok')), 'error': body.get('description')}
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode('utf-8', errors='replace'))
            desc = body.get('description') or f'HTTP {e.code}'
        except Exception:
            desc = f'HTTP {e.code}'
        log.warning('telegram sendMessage failed: chat_id=%s status=%s %s',
                    chat_id, e.code, desc)
        return {'ok': False, 'error': desc}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        log.warning('telegram sendMessage network error: chat_id=%s %s', chat_id, e)
        return {'ok': False, 'error': f'network error: {e}'}
    except Exception as e:
        log.exception('telegram sendMessage unexpected error: chat_id=%s', chat_id)
        return {'ok': False, 'error': str(e)}


# ─── Message rendering ───────────────────────────────────────────────────

def _render(event_type: str, *, scan=None, extra: Optional[dict] = None) -> str:
    """HTML message body for an event."""
    e = _html.escape
    extra = extra or {}
    if event_type == 'scan.complete':
        return (
            f'✅ <b>Scan complete</b> — {e(scan.name)}\n'
            f'<b>Target:</b> <code>{e(scan.target)}</code>\n'
            f'<b>Hosts:</b> {scan.hosts_count}  <b>Findings:</b> {scan.findings_count}  '
            f'(🔴 {scan.critical_count} / 🟠 {scan.high_count} / 🟡 {scan.medium_count})\n'
            f'<b>Duration:</b> {scan.duration_seconds}s'
        )
    if event_type == 'scan.failed':
        err = (scan.error_message or 'unknown error')[:200]
        return (
            f'❌ <b>Scan failed</b> — {e(scan.name)}\n'
            f'<b>Target:</b> <code>{e(scan.target)}</code>\n'
            f'<b>Error:</b> {e(err)}'
        )
    if event_type == 'critical.discovered':
        count = extra.get('count', scan.critical_count if scan else 0)
        return (
            f'🚨 <b>Critical findings discovered</b> — {e(scan.name) if scan else "unknown scan"}\n'
            f'{count} critical-severity finding(s).\n'
            f'<b>Target:</b> <code>{e(scan.target) if scan else "?"}</code>'
        )
    return f'Wire_Ghost event: {e(event_type)}'


# ─── Fan-out ─────────────────────────────────────────────────────────────

def notify(event_type: str, *, scan=None, extra: Optional[dict] = None) -> None:
    """Dispatch a notification to shared + creator-DM targets, fail-silent.

    Call sites are Celery tasks that have already committed results to the DB.
    Any exception in here is logged and swallowed.
    """
    try:
        from scanner.models import SiteConfig, UserPreference
        cfg = SiteConfig.get()
        if not cfg.telegram_bot_token:
            return
        text = _render(event_type, scan=scan, extra=extra)
        bot_token = cfg.telegram_bot_token

        # Shared channel — fires regardless of user prefs when configured.
        if cfg.telegram_shared_chat_id:
            try:
                send_telegram(cfg.telegram_shared_chat_id, text, bot_token=bot_token)
            except NotificationError as e:
                log.warning('skipping shared channel: %s', e)

        # Creator DM — optional, respects per-user enable flag + event toggle.
        creator = getattr(scan, 'created_by', None)
        if creator is not None:
            try:
                prefs = UserPreference.for_user(creator)
            except Exception:
                prefs = None
            pref_field = _EVENT_PREF_FIELD.get(event_type)
            if (prefs
                and prefs.telegram_enabled
                and prefs.telegram_chat_id
                and (pref_field is None or getattr(prefs, pref_field, True))):
                try:
                    send_telegram(prefs.telegram_chat_id, text, bot_token=bot_token)
                except NotificationError as e:
                    log.warning('skipping DM for user=%s: %s', creator.username, e)

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
    except Exception:
        log.exception('notify() dispatch error event=%s', event_type)
