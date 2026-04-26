from __future__ import annotations

from asgiref.sync import sync_to_async
from telegram import InlineKeyboardButton, InlineKeyboardMarkup

from scanner.bot.formatting import esc, short_id
from scanner.bot.menus import PAGE_SIZE, photo_list_kb
from scanner.bot.screenshots import send_album, send_one
from scanner.models import Scan, Screenshot

HTML = 'HTML'


async def handle(query, user, rest, context):
    sid = rest[0] if rest else ''
    action = rest[1] if len(rest) > 1 else '0'

    def _get_scan():
        return Scan.objects.filter(id__startswith=sid).first()

    scan = await sync_to_async(_get_scan)()
    if not scan:
        await query.edit_message_text(
            f'Scan <code>{esc(sid)}</code> not found.', parse_mode=HTML,
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton('⬅ Scans', callback_data='sl:0')]]),
        )
        return

    if action == 'all':
        await _send_all(query, scan, context)
    else:
        page = int(action)
        await _list_screenshots(query, scan, page)


async def _send_all(query, scan, context):
    def _q():
        return list(Screenshot.objects.filter(scan=scan).select_related('host', 'scan')[:10])

    screenshots = await sync_to_async(_q)()
    chat_id = query.message.chat_id
    sid = short_id(scan.id)

    if not screenshots:
        await query.edit_message_text(
            f'<i>No screenshots for scan</i> <code>{sid}</code>.',
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton('⬅ Back', callback_data=f'sd:{sid}')]]),
            parse_mode=HTML,
        )
        return

    sent = await send_album(context.bot, chat_id, screenshots, f'Scan {sid}')
    if sent == 0:
        for ss in screenshots[:5]:
            caption = f'🌐 <code>{esc(ss.url[:60])}</code>'
            if await send_one(context.bot, chat_id, ss, caption):
                sent += 1

    label = f'📷 Sent {sent} screenshot{"s" if sent != 1 else ""}' if sent else '📷 No screenshots could be sent'
    await query.edit_message_text(
        f'{label} for scan <code>{sid}</code>.',
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton('⬅ Back', callback_data=f'sd:{sid}')]]),
        parse_mode=HTML,
    )


async def _list_screenshots(query, scan, page):
    def _q():
        qs = Screenshot.objects.filter(scan=scan).order_by('url')
        total = qs.count()
        total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
        rows = list(
            qs[page * PAGE_SIZE:(page + 1) * PAGE_SIZE]
            .values_list('url', 'title', 'status_code', 'host__ip')
        )
        return rows, total, total_pages

    rows, total, total_pages = await sync_to_async(_q)()
    sid = short_id(scan.id)

    lines = [
        f'<b>📷 Screenshots</b> — <code>{sid}</code> ({total})',
        '━━━━━━━━━━━━━━━━━━',
    ]
    if not rows:
        lines.append('<i>No screenshots captured.</i>')
    for url, title, status_code, host_ip in rows:
        title_str = f' — {esc(title[:30])}' if title else ''
        lines.append(f'🌐 <code>{esc(url[:50])}</code>{title_str}')
        lines.append(f'   {esc(host_ip or "—")} │ HTTP {status_code}')

    kb = photo_list_kb(sid, total, page, total_pages)
    await query.edit_message_text('\n'.join(lines), reply_markup=kb, parse_mode=HTML)
