from __future__ import annotations

from asgiref.sync import sync_to_async

from scanner.bot.formatting import (
    SEPARATOR, esc, severity_emoji, short_id,
)
from scanner.bot.menus import finding_detail_kb
from scanner.models import Finding

HTML = 'HTML'


async def handle(query, user, rest, context):
    fid = rest[0] if rest else ''
    back = ':'.join(rest[1:]) if len(rest) > 1 else 'fl:all:0'

    def _q():
        return (
            Finding.objects.select_related('scan')
            .filter(id__startswith=fid)
            .first()
        )

    finding = await sync_to_async(_q)()
    if not finding:
        await query.edit_message_text(
            f'Finding <code>{esc(fid)}</code> not found.',
            reply_markup=finding_detail_kb(back),
            parse_mode=HTML,
        )
        return

    f = finding
    emoji = severity_emoji(f.severity)
    lines = [
        f'{emoji} <b>{esc(f.severity.title())}: {esc(f.title[:80])}</b>',
        SEPARATOR,
    ]

    loc_parts = []
    if f.host_ip:
        loc_parts.append(f'<code>{esc(f.host_ip)}</code>')
        if f.port:
            loc_parts[-1] = f'<code>{esc(f.host_ip)}:{f.port}</code>'
    if f.endpoint:
        loc_parts.append(esc(f.endpoint[:60]))
    if f.protocol:
        loc_parts.append(f'Protocol: {esc(f.protocol)}')
    if loc_parts:
        lines.append(f'\n<b>📍 Location</b>')
        lines.append(f'  {" │ ".join(loc_parts)}')

    det_parts = []
    if f.source:
        det_parts.append(f'Source: {esc(f.source)}')
    if f.template_id:
        det_parts.append(f'Template: <code>{esc(f.template_id[:40])}</code>')
    if f.cve:
        det_parts.append(f'CVE: <code>{esc(f.cve)}</code>')
    if f.cvss is not None:
        det_parts.append(f'CVSS: <b>{f.cvss}</b>')
    if f.cwe:
        det_parts.append(f'CWE: {esc(f.cwe)}')
    if det_parts:
        lines.append(f'\n<b>🔍 Detection</b>')
        lines.append(f'  {" │ ".join(det_parts)}')

    if f.description:
        desc = f.description[:500]
        if len(f.description) > 500:
            desc += '…'
        lines.append(f'\n<b>📝 Description</b>')
        lines.append(f'  {esc(desc)}')

    if f.references:
        refs = f.references[:300]
        if len(f.references) > 300:
            refs += '…'
        lines.append(f'\n<b>🔗 References</b>')
        lines.append(f'  {esc(refs)}')

    if f.curl_command:
        curl = f.curl_command[:200]
        if len(f.curl_command) > 200:
            curl += '…'
        lines.append(f'\n<b>💡 Evidence</b>')
        lines.append(f'  <code>{esc(curl)}</code>')

    if f.scan:
        lines.append(f'\n<b>📋 Scan:</b> <code>{short_id(f.scan.id)}</code> │ {esc(f.scan.target[:30])}')

    kb = finding_detail_kb(back)
    await query.edit_message_text('\n'.join(lines), reply_markup=kb, parse_mode=HTML)
