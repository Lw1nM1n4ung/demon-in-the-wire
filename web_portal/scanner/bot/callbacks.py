from __future__ import annotations

import logging

from asgiref.sync import sync_to_async
from telegram import Update
from telegram.ext import ContextTypes

from scanner.bot.auth import resolve_user
from scanner.bot.formatting import severity_emoji, short_id, truncate_list
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
