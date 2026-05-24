from __future__ import annotations

import functools
import json
import logging
from typing import Optional

from asgiref.sync import sync_to_async
from django.core.cache import cache

from scanner.models import AuditLog, User, UserPreference

log = logging.getLogger("scanner.bot")

LINK_FAIL_PREFIX = "tg:linkfail:"
LINK_FAIL_MAX = 3
LINK_FAIL_TTL = 3600

CMD_RATE_PREFIX = "tg:cmdrate:"
CMD_RATE_MAX = 30
CMD_RATE_TTL = 60

SCAN_RATE_PREFIX = "tg:scanrate:"
SCAN_RATE_MAX = 5
SCAN_RATE_TTL = 3600

UNLOCK_RATE_PREFIX = "tg:unlock:"
UNLOCK_RATE_MAX = 3
UNLOCK_RATE_TTL = 900

USER_CACHE_PREFIX = "tg:user:"
USER_CACHE_TTL = 60

PERM_CACHE_PREFIX = "tg:perm:"
PERM_CACHE_TTL = 120


def resolve_user(tg_user_id: int) -> Optional[User]:
    try:
        prefs = UserPreference.objects.select_related("user").get(
            telegram_user_id=tg_user_id,
        )
    except UserPreference.DoesNotExist:
        return None
    if not prefs.user.is_active:
        return None
    return prefs.user


def resolve_user_cached(tg_user_id: int) -> Optional[User]:
    cache_key = f"{USER_CACHE_PREFIX}{tg_user_id}"
    uid = cache.get(cache_key)
    if uid is not None:
        if uid == "":
            return None
        try:
            return User.objects.get(pk=uid, is_active=True)
        except User.DoesNotExist:
            cache.delete(cache_key)
    user = resolve_user(tg_user_id)
    cache.set(cache_key, str(user.pk) if user else "", USER_CACHE_TTL)
    return user


def check_perm_cached(user: User, perm_code: str) -> bool:
    cache_key = f"{PERM_CACHE_PREFIX}{user.pk}:{perm_code}"
    result = cache.get(cache_key)
    if result is not None:
        return result
    has_perm = user.has_permission(perm_code)
    cache.set(cache_key, has_perm, PERM_CACHE_TTL)
    return has_perm


def resolve_and_check(tg_user_id: int, perm_code: str | None) -> tuple[Optional[User], bool]:
    user = resolve_user_cached(tg_user_id)
    if user is None:
        return None, False
    if perm_code is None:
        return user, True
    return user, check_perm_cached(user, perm_code)


def invalidate_user_cache(tg_user_id: int):
    cache.delete(f"{USER_CACHE_PREFIX}{tg_user_id}")


def link_account(*, tg_user_id: int, tg_chat_id: int, code: str) -> tuple[bool, str]:
    fail_key = f"{LINK_FAIL_PREFIX}{tg_user_id}"
    fail_count = cache.get(fail_key, 0)
    if fail_count >= LINK_FAIL_MAX:
        return False, "Too many failed attempts. Try again later."

    raw = cache.get(f"tg:link:{code}")
    if raw is None:
        cache.set(fail_key, fail_count + 1, LINK_FAIL_TTL)
        return False, "Invalid or expired code."

    data = json.loads(raw) if isinstance(raw, str) else raw
    user_id = data.get("user_id")

    try:
        user = User.objects.get(id=user_id, is_active=True)
    except User.DoesNotExist:
        return False, "Associated account not found or deactivated."

    prefs = UserPreference.for_user(user)
    # Clear any existing link for this Telegram user (one-to-one enforcement)
    UserPreference.objects.filter(telegram_user_id=tg_user_id).exclude(pk=prefs.pk).update(
        telegram_user_id=None, telegram_chat_id="", telegram_enabled=False
    )

    prefs.telegram_user_id = tg_user_id
    prefs.telegram_chat_id = str(tg_chat_id)
    prefs.telegram_enabled = True
    prefs.save(update_fields=["telegram_user_id", "telegram_chat_id", "telegram_enabled"])

    cache.delete(f"tg:link:{code}")
    reverse_key = f"tg:linkuser:{user_id}"
    cache.delete(reverse_key)
    cache.delete(fail_key)

    invalidate_user_cache(tg_user_id)
    AuditLog.log(user.username, "telegram.link", f"Telegram user {tg_user_id} linked", "config")
    return True, f"Linked to {user.username} (role: {user.role})"


def unlink_account(tg_user_id: int) -> tuple[bool, str]:
    try:
        prefs = UserPreference.objects.select_related("user").get(
            telegram_user_id=tg_user_id,
        )
    except UserPreference.DoesNotExist:
        return False, "Your Telegram account is not linked."

    username = prefs.user.username
    prefs.telegram_user_id = None
    prefs.telegram_chat_id = ""
    prefs.telegram_enabled = False
    prefs.save(update_fields=["telegram_user_id", "telegram_chat_id", "telegram_enabled"])

    invalidate_user_cache(tg_user_id)
    AuditLog.log(username, "telegram.unlink", f"Telegram user {tg_user_id} unlinked", "config")
    return True, f"Unlinked from {username}."


def generate_magic_token(user) -> str:
    import secrets

    token = secrets.token_urlsafe(48)
    cache.set(
        f"unlock_token:{token}",
        json.dumps(
            {
                "user_id": str(user.id),
                "username": user.username,
            }
        ),
        300,
    )
    return token


def check_rate_limit(prefix: str, key: str, max_count: int, ttl: int) -> bool:
    cache_key = f"{prefix}{key}"
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
                await update.message.reply_text("Rate limit exceeded. Slow down.")
                return

            def _auth():
                user, ok = resolve_and_check(tg_user.id, perm_code)
                if user:
                    AuditLog.log(
                        user.username, "telegram.cmd", update.message.text or "", "telegram"
                    )
                return user, ok

            user, has_perm = await sync_to_async(_auth)()

            if user is None:
                await update.message.reply_text(
                    "Not linked. Generate a code at Settings → Telegram in the web portal, "
                    "then send <code>/link &lt;code&gt;</code>",
                    parse_mode="HTML",
                )
                return

            if not has_perm:
                await update.message.reply_text(
                    f"Permission denied (requires <code>{perm_code}</code>)",
                    parse_mode="HTML",
                )
                return

            context.user_data["wg_user"] = user
            return await func(update, context)

        return wrapper

    return decorator
