from __future__ import annotations

from asgiref.sync import sync_to_async
from telegram import InlineKeyboardButton

from scanner.bot.formatting import (
    esc,
    severity_emoji,
    short_id,
)
from scanner.bot.menus import PAGE_SIZE, finding_filter_kb, findings_list_kb
from scanner.models import Finding

HTML = "HTML"


async def handle(query, user, rest, context):
    first = rest[0] if rest else "all"

    if first == "pick":
        kb = finding_filter_kb()
        await query.edit_message_text(
            "<b>🛡 Findings</b>\n━━━━━━━━━━\n\nFilter by severity:",
            reply_markup=kb,
            parse_mode=HTML,
        )
        return

    if first.isdigit():
        page = int(first)
        severity = rest[1] if len(rest) > 1 else "all"
    else:
        severity = first
        page = int(rest[1]) if len(rest) > 1 and rest[1].isdigit() else 0

    def _q():
        qs = Finding.objects.order_by("-severity", "-id")
        if severity != "all":
            qs = qs.filter(severity=severity)
        total = qs.count()
        total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
        rows = list(
            qs[page * PAGE_SIZE : (page + 1) * PAGE_SIZE].values_list(
                "id", "severity", "title", "host_ip", "port", "cve", "source", "scan__target"
            )
        )
        return rows, total, total_pages

    rows, total, total_pages = await sync_to_async(_q)()

    back_cb = f"fl:{severity}:{page}"
    label = severity.title() if severity != "all" else "All"
    lines = [
        f"<b>🛡 {esc(label)} Findings</b> ({total})",
        "━━━━━━━━━━━━━━━━━━",
    ]
    finding_buttons = []
    if not rows:
        lines.append(f"<i>No {esc(severity)} findings found.</i>")
    for fid, sev, title, ip, port, cve, source, scan_target in rows:
        emoji = severity_emoji(sev)
        loc = f"{ip}:{port}" if port else ip or ""
        cve_str = f" — {esc(cve)}" if cve else ""
        lines.append(f"{emoji} {esc(title[:60])}{cve_str}")
        parts = []
        if loc:
            parts.append(f"<code>{esc(loc)}</code>")
        if source:
            parts.append(esc(source))
        if scan_target:
            parts.append(f"scan: {esc(scan_target[:20])}")
        if parts:
            lines.append(f"   📍 {' │ '.join(parts)}")
        finding_buttons.append(
            [
                InlineKeyboardButton(
                    f"{emoji} {title[:35]}",
                    callback_data=f"fd:{short_id(fid)}:{back_cb}",
                )
            ]
        )

    kb = findings_list_kb(page, total_pages, severity, finding_buttons=finding_buttons)
    await query.edit_message_text("\n".join(lines), reply_markup=kb, parse_mode=HTML)
