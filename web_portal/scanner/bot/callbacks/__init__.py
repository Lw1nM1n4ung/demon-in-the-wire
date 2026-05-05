from __future__ import annotations

import logging

from asgiref.sync import sync_to_async
from telegram import Update
from telegram.error import BadRequest
from telegram.ext import ContextTypes

from scanner.bot.auth import resolve_user

log = logging.getLogger('scanner.bot')

HTML = 'HTML'

PERMS = {
    'mn': None,
    'sl': 'scan:read', 'sd': 'scan:read', 'sf': 'scan:read',
    'sr': 'scan:write', 'sx': 'scan:write', 'sxc': 'scan:write',
    'sp': 'scan:read',
    'ns': 'scan:write',
    'fl': 'scan:read',
    'fd': 'scan:read',
    'al': 'scan:read', 'ad': 'scan:read',
    'cl': 'scan:write', 'cd': 'scan:write', 'ct': 'scan:write', 'cr': 'scan:write',
    'ul': 'user:manage',
    'hp': None,
    'hl': 'site:config', 'cf': 'site:config',
    'noop': None,
}


def _build_routes():
    from scanner.bot.callbacks import (
        assets, finding_detail, findings, menu, photos, scans, schedules, system, users,
    )
    return {
        'mn': menu.handle,
        'sl': scans.handle_list,
        'sd': scans.handle_detail,
        'sf': scans.handle_findings,
        'sr': scans.handle_report,
        'sx': scans.handle_cancel,
        'sxc': scans.handle_cancel_confirm,
        'sp': photos.handle,
        'ns': scans.handle_new,
        'fl': findings.handle,
        'fd': finding_detail.handle,
        'al': assets.handle_list,
        'ad': assets.handle_detail,
        'cl': schedules.handle_list,
        'cd': schedules.handle_detail,
        'ct': schedules.handle_toggle,
        'cr': schedules.handle_run_now,
        'ul': users.handle_list,
        'hp': menu.handle_help,
        'hl': system.handle_health,
        'cf': system.handle_config,
    }


ROUTES = None


async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global ROUTES
    if ROUTES is None:
        ROUTES = _build_routes()

    query = update.callback_query
    if not query or not query.data:
        return

    await query.answer()

    if query.data == 'noop':
        return

    tg_user_id = query.from_user.id
    user = await sync_to_async(resolve_user)(tg_user_id)
    if not user:
        await query.edit_message_text(
            'Not linked. Use <code>/link &lt;code&gt;</code> first.',
            parse_mode=HTML,
        )
        return

    parts = query.data.split(':')
    entity = parts[0]
    rest = [p for p in parts[1:] if p]

    perm = PERMS.get(entity)
    if perm is not None:
        has_perm = await sync_to_async(user.has_permission)(perm)
        if not has_perm:
            await query.edit_message_text(
                f'Permission denied (requires <code>{perm}</code>).',
                parse_mode=HTML,
            )
            return

    handler = ROUTES.get(entity)
    if handler:
        try:
            await handler(query, user, rest, context)
        except BadRequest as e:
            if 'message is not modified' in str(e).lower():
                pass
            else:
                log.exception('Callback error: %s', query.data)
                try:
                    await query.edit_message_text(
                        'Something went wrong. Try again.',
                        parse_mode=HTML,
                    )
                except Exception:
                    log.warning('Failed to send error message for callback %s', query.data)
        except Exception:
            log.exception('Callback error: %s', query.data)
            try:
                await query.edit_message_text(
                    'Something went wrong. Try again.',
                    parse_mode=HTML,
                )
            except Exception:
                log.warning('Failed to send error message for callback %s', query.data)
    else:
        log.warning('Unknown callback entity: %s', entity)
