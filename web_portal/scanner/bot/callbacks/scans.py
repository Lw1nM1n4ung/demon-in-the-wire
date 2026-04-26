from __future__ import annotations

from asgiref.sync import sync_to_async
from telegram import InlineKeyboardButton, InlineKeyboardMarkup

from scanner.bot.formatting import (
    esc, format_duration, severity_emoji, severity_line,
    short_id, status_icon, time_ago, truncate_list,
)
from scanner.bot.menus import (
    PAGE_SIZE, confirm_cancel_kb, scan_detail_kb, scan_list_kb,
    findings_list_kb, new_scan_kb,
)
from scanner.models import Finding, Report, Scan, Screenshot

HTML = 'HTML'


async def handle_list(query, user, rest, context):
    page = int(rest[0]) if rest else 0

    def _q():
        qs = Scan.objects.order_by('-created_at')
        total = qs.count()
        total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
        rows = list(
            qs[page * PAGE_SIZE:(page + 1) * PAGE_SIZE]
            .values_list('id', 'target', 'status', 'scan_type', 'findings_count', 'created_at')
        )
        return rows, total_pages

    scans, total_pages = await sync_to_async(_q)()

    if not scans:
        await query.edit_message_text(
            '<b>🔍 Scans</b>\n━━━━━━━━\n\n<i>No scans yet.</i>',
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton('⬅ Menu', callback_data='mn')]]),
            parse_mode=HTML,
        )
        return

    lines = ['<b>🔍 Recent Scans</b>', '━━━━━━━━━━━━━━']
    for sid, target, status, stype, fcount, created in scans:
        icon = status_icon(status)
        lines.append(
            f'{icon} <code>{short_id(sid)}</code> │ <code>{esc(target[:30])}</code>\n'
            f'   {esc(stype)} │ {fcount} findings │ {time_ago(created)}'
        )

    kb = scan_list_kb(scans, page, total_pages)
    await query.edit_message_text('\n'.join(lines), reply_markup=kb, parse_mode=HTML)


async def handle_detail(query, user, rest, context):
    sid = rest[0] if rest else ''

    def _q():
        scan = Scan.objects.filter(id__startswith=sid).first()
        if not scan:
            return None, False, []
        has_ss = Screenshot.objects.filter(scan=scan).exists()
        reports = list(
            Report.objects.filter(scan=scan)
            .values_list('format', 'file_size')
        )
        return scan, has_ss, reports

    scan, has_ss, reports = await sync_to_async(_q)()
    if not scan:
        await query.edit_message_text(
            f'Scan <code>{esc(sid)}</code> not found.',
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton('⬅ Scans', callback_data='sl:0')]]),
            parse_mode=HTML,
        )
        return

    s = scan
    lines = [
        f'<b>📋 Scan</b> — <code>{short_id(s.id)}</code>',
        '━━━━━━━━━━━━━━━━━━',
        '',
        '<b>General</b>',
        f'  <b>Target:</b> <code>{esc(s.target)}</code>',
        f'  <b>Type:</b> {esc(s.scan_type)}',
        f'  <b>Status:</b> {status_icon(s.status)} {esc(s.status)}',
    ]
    if s.created_by:
        lines.append(f'  <b>By:</b> {esc(s.created_by.username)}')

    lines.append('')
    lines.append('<b>Timing</b>')
    lines.append(f'  <b>Started:</b> {time_ago(s.started_at)}')
    if s.duration_seconds:
        lines.append(f'  <b>Duration:</b> {format_duration(s.duration_seconds)}')

    lines.append('')
    lines.append('<b>Results</b>')
    lines.append(f'  <b>Hosts:</b> {s.hosts_count}  │  <b>Ports:</b> {s.ports_count}')
    lines.append(f'  <b>Findings:</b> {s.findings_count}')
    sev = severity_line(
        critical=s.critical_count, high=s.high_count,
        medium=s.medium_count, low=s.low_count,
    )
    if sev:
        lines.append(f'  {sev}')

    if reports:
        lines.append('')
        lines.append('<b>Reports</b>')
        for fmt, size in reports:
            size_str = f'{size / (1024 * 1024):.1f} MB' if size else '—'
            lines.append(f'  📄 {fmt.upper()} — {size_str}')

    kb = scan_detail_kb(short_id(s.id), s.status, has_ss)
    await query.edit_message_text('\n'.join(lines), reply_markup=kb, parse_mode=HTML)


async def handle_findings(query, user, rest, context):
    sid = rest[0] if rest else ''
    page = int(rest[1]) if len(rest) > 1 else 0
    severity = rest[2] if len(rest) > 2 else None

    def _q():
        scan = Scan.objects.filter(id__startswith=sid).first()
        if not scan:
            return None, [], 0
        qs = Finding.objects.filter(scan=scan).order_by('-severity', '-id')
        if severity and severity != 'all':
            qs = qs.filter(severity=severity)
        total = qs.count()
        total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
        rows = list(
            qs[page * PAGE_SIZE:(page + 1) * PAGE_SIZE]
            .values_list('severity', 'title', 'host_ip', 'port', 'cve', 'source')
        )
        return scan, rows, total_pages

    scan, rows, total_pages = await sync_to_async(_q)()
    if not scan:
        await query.edit_message_text(
            f'Scan <code>{esc(sid)}</code> not found.', parse_mode=HTML,
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton('⬅ Scans', callback_data='sl:0')]]),
        )
        return

    label = severity.title() if severity and severity != 'all' else 'All'
    lines = [
        f'<b>🛡 {esc(label)} Findings</b> — <code>{short_id(scan.id)}</code>',
        '━━━━━━━━━━━━━━━━━━',
    ]
    if not rows:
        lines.append('<i>No findings.</i>')
    for sev, title, ip, port, cve, source in rows:
        emoji = severity_emoji(sev)
        loc = f'{ip}:{port}' if port else ip or ''
        cve_str = f' — {esc(cve)}' if cve else ''
        lines.append(f'{emoji} {esc(title[:60])}{cve_str}')
        lines.append(f'   📍 <code>{esc(loc)}</code> │ {esc(source or "—")}')

    kb = findings_list_kb(page, total_pages, severity or 'all', short_id(scan.id))
    await query.edit_message_text('\n'.join(lines), reply_markup=kb, parse_mode=HTML)


async def handle_report(query, user, rest, context):
    sid = rest[0] if rest else ''

    def _launch():
        scan = Scan.objects.filter(id__startswith=sid, status='completed').first()
        if not scan:
            return None
        from scanner.tasks import generate_report
        generate_report.delay(str(scan.id))
        return scan

    scan = await sync_to_async(_launch)()
    if not scan:
        await query.edit_message_text(
            f'No completed scan <code>{esc(sid)}</code> found.',
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton('⬅ Back', callback_data=f'sd:{sid}')]]),
            parse_mode=HTML,
        )
        return

    await query.edit_message_text(
        f'📄 Generating reports for <code>{short_id(scan.id)}</code>…\n'
        f'File will be sent when ready.',
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton('⬅ Back', callback_data=f'sd:{short_id(scan.id)}')]]),
        parse_mode=HTML,
    )


async def handle_cancel(query, user, rest, context):
    sid = rest[0] if rest else ''
    await query.edit_message_text(
        f'Cancel scan <code>{esc(sid)}</code>?',
        reply_markup=confirm_cancel_kb(sid),
        parse_mode=HTML,
    )


async def handle_cancel_confirm(query, user, rest, context):
    sid = rest[0] if rest else ''

    def _cancel():
        scan = Scan.objects.filter(id__startswith=sid, status__in=('running', 'pending')).first()
        if not scan:
            return None
        if scan.celery_task_id:
            from wireghost_web.celery import app as celery_app
            celery_app.control.revoke(scan.celery_task_id, terminate=True)
        scan.status = 'cancelled'
        scan.error_message = 'Cancelled via Telegram'
        scan.save(update_fields=['status', 'error_message'])
        return scan

    scan = await sync_to_async(_cancel)()
    if not scan:
        await query.edit_message_text(
            f'Scan <code>{esc(sid)}</code> not found or already finished.',
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton('⬅ Scans', callback_data='sl:0')]]),
            parse_mode=HTML,
        )
        return

    await query.edit_message_text(
        f'⏸ Scan <code>{short_id(scan.id)}</code> cancelled.',
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton('⬅ Scans', callback_data='sl:0')]]),
        parse_mode=HTML,
    )


async def handle_new(query, user, rest, context):
    action = rest[0] if rest else 'pick'
    if action == 'pick':
        await query.edit_message_text(
            '<b>➕ New Scan</b>\n━━━━━━━━━━\n\nSelect scan type:',
            reply_markup=new_scan_kb(),
            parse_mode=HTML,
        )
    else:
        context.user_data['_newscan_type'] = action
        await query.edit_message_text(
            f'<b>➕ New Scan</b> — {esc(action)}\n\n'
            f'Send the target (IP, CIDR, or hostname) as a text message:',
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton('⬅ Cancel', callback_data='mn')]]),
            parse_mode=HTML,
        )
