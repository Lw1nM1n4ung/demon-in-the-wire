from __future__ import annotations

from asgiref.sync import sync_to_async
from telegram import InlineKeyboardButton, InlineKeyboardMarkup

from scanner.bot.formatting import esc, severity_line, time_ago
from scanner.bot.menus import main_menu_kb
from scanner.models import Finding, Scan, ScheduledScan

HTML = 'HTML'


async def handle(query, user, rest, context):
    action = rest[0] if rest else 'dash'
    if action == 'dash':
        await _dashboard(query, user)
    else:
        await _main_menu(query, user)


async def _main_menu(query, user):
    kb = main_menu_kb(user.role)
    await query.edit_message_text(
        '<b>🔰 Wire_Ghost Control Panel</b>\n'
        '━━━━━━━━━━━━━━━━━━━━━━\n'
        'Select a category:',
        reply_markup=kb, parse_mode=HTML,
    )


async def _dashboard(query, user):
    def _q():
        active = Scan.objects.filter(status='running').count()
        pending = Scan.objects.filter(status='pending').count()
        completed = Scan.objects.filter(status='completed').count()
        failed = Scan.objects.filter(status='failed').count()
        totals = Finding.objects.count()
        sev = {}
        for s in ('critical', 'high', 'medium', 'low', 'info'):
            sev[s] = Finding.objects.filter(severity=s).count()
        last = Scan.objects.filter(status='completed').order_by('-completed_at').first()
        nxt = ScheduledScan.objects.filter(enabled=True, next_run__isnull=False).order_by('next_run').first()
        return active, pending, completed, failed, totals, sev, last, nxt

    active, pending, completed, failed, totals, sev, last_scan, next_sched = await sync_to_async(_q)()

    lines = [
        '<b>📊 Wire_Ghost Dashboard</b>',
        '━━━━━━━━━━━━━━━━━━━━',
        '',
        '<b>Scans</b>',
        f'  🔄 Running: {active}   ⏳ Pending: {pending}',
        f'  ✅ Completed: {completed}   ❌ Failed: {failed}',
        '',
        f'<b>Findings</b> ({totals} total)',
        f'  {severity_line(critical=sev["critical"], high=sev["high"], medium=sev["medium"], low=sev["low"])}',
        '',
        '<b>Timeline</b>',
    ]
    if last_scan:
        lines.append(f'  📅 Last scan: {time_ago(last_scan.completed_at)}')
    if next_sched:
        lines.append(f'  ⏭ Next scheduled: {esc(next_sched.target[:30])}')

    kb = InlineKeyboardMarkup([
        [
            InlineKeyboardButton('🔄 Refresh', callback_data='mn:dash'),
            InlineKeyboardButton('🔍 Scans', callback_data='sl:0'),
        ],
        [
            InlineKeyboardButton('🛡 Findings', callback_data='fl:all:0'),
            InlineKeyboardButton('💻 Assets', callback_data='al:0'),
        ],
        [InlineKeyboardButton('⬅ Menu', callback_data='mn')],
    ])

    await query.edit_message_text('\n'.join(lines), reply_markup=kb, parse_mode=HTML)
