from __future__ import annotations

from asgiref.sync import sync_to_async
from telegram import InlineKeyboardButton, InlineKeyboardMarkup

from scanner.bot.formatting import esc, time_ago
from scanner.bot.menus import PAGE_SIZE
from scanner.models import User, UserPreference

HTML = 'HTML'

ROLE_ICONS = {'owner': '👑', 'engineer': '🔧', 'viewer': '👁'}


async def handle_list(query, user, rest, context):
    page = int(rest[0]) if rest else 0

    def _q():
        qs = User.objects.filter(is_active=True).order_by('role', 'username')
        total = qs.count()
        total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
        rows = []
        for u in qs[page * PAGE_SIZE:(page + 1) * PAGE_SIZE]:
            prefs = UserPreference.for_user(u)
            linked = bool(prefs.telegram_user_id)
            rows.append((u.username, u.role, linked, u.last_login))
        return rows, total, total_pages

    rows, total, total_pages = await sync_to_async(_q)()

    lines = [f'<b>👥 Users</b> ({total})', '━━━━━━━━━━']
    if not rows:
        lines.append('<i>No users found.</i>')
    for uname, role, linked, last_login in rows:
        icon = ROLE_ICONS.get(role, '❓')
        link_str = '🔗' if linked else '—'
        login_str = time_ago(last_login) if last_login else 'never'
        lines.append(
            f'\n  {icon} <b>{esc(uname)}</b> │ {esc(role)}'
            f'\n     Telegram: {link_str} │ Last login: {login_str}'
        )

    from scanner.bot.menus import _pagination_row
    nav = [_pagination_row('ul', page, total_pages)]
    nav.append([InlineKeyboardButton('⬅ Menu', callback_data='mn')])
    kb = InlineKeyboardMarkup(nav)
    await query.edit_message_text('\n'.join(lines), reply_markup=kb, parse_mode=HTML)
