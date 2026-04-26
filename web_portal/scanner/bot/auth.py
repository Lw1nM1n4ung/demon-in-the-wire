from __future__ import annotations

import functools
import json
import logging
from typing import Optional

from asgiref.sync import sync_to_async
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
    # Clear any existing link for this Telegram user (one-to-one enforcement)
    UserPreference.objects.filter(telegram_user_id=tg_user_id).exclude(
        pk=prefs.pk
    ).update(telegram_user_id=None, telegram_chat_id='', telegram_enabled=False)

    prefs.telegram_user_id = tg_user_id
    prefs.telegram_chat_id = str(tg_chat_id)
    prefs.telegram_enabled = True
    prefs.save(update_fields=['telegram_user_id', 'telegram_chat_id', 'telegram_enabled'])

    cache.delete(f'tg:link:{code}')
    reverse_key = f'tg:linkuser:{user_id}'
    cache.delete(reverse_key)
    cache.delete(fail_key)

    AuditLog.log(user.username, 'telegram.link', f'Telegram user {tg_user_id} linked', 'config')
    return True, f'Linked to {user.username} (role: {user.role})'


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
    return True, f'Unlinked from {username}.'


def check_rate_limit(prefix: str, key: str, max_count: int, ttl: int) -> bool:
    cache_key = f'{prefix}{key}'
    try:
        count = cache.incr(cache_key)
    except ValueError:
        cache.set(cache_key, 1, ttl)
        count = 1
    return count <= max_count


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

            user = await sync_to_async(resolve_user)(tg_user.id)

            if user is None:
                await update.message.reply_text(
                    'Not linked. Generate a code at Settings → Telegram in the web portal, '
                    'then send <code>/link &lt;code&gt;</code>',
                    parse_mode='HTML',
                )
                return

            has_perm = await sync_to_async(user.has_permission)(perm_code)
            if not has_perm:
                await update.message.reply_text(
                    f'Permission denied (requires <code>{perm_code}</code>)',
                    parse_mode='HTML',
                )
                return

            await sync_to_async(AuditLog.log)(
                user.username,
                'telegram.cmd',
                update.message.text or '',
                'telegram',
            )

            context.user_data['wg_user'] = user
            return await func(update, context)
        return wrapper
    return decorator
