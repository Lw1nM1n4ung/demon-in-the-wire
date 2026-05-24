from __future__ import annotations

from asgiref.sync import sync_to_async
from telegram import InlineKeyboardButton, InlineKeyboardMarkup

from scanner.bot.formatting import esc, progress_bar, short_id, time_ago
from scanner.bot.menus import PAGE_SIZE, asset_detail_kb, asset_list_kb
from scanner.models import Asset

HTML = "HTML"


async def handle_list(query, user, rest, context):
    page = int(rest[0]) if rest else 0

    def _q():
        qs = Asset.objects.order_by("-risk_score", "-last_seen")
        total = qs.count()
        total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
        rows = list(
            qs[page * PAGE_SIZE : (page + 1) * PAGE_SIZE].values_list(
                "id",
                "ip",
                "hostname",
                "service_name",
                "risk_score",
                "findings_count",
                "critical_count",
                "high_count",
                "last_seen",
            )
        )
        return rows, total, total_pages

    rows, total, total_pages = await sync_to_async(_q)()

    lines = [f"<b>💻 Assets</b> ({total})", "━━━━━━━━━━━━"]
    if not rows:
        lines.append("<i>No assets discovered yet.</i>")
    for aid, ip, hostname, svc, risk, fcount, crit, high, last_seen in rows:
        bar = progress_bar(risk, 100)
        host_label = f" ({esc(hostname[:20])})" if hostname else ""
        sev_parts = []
        if crit:
            sev_parts.append(f"🔴{crit}")
        if high:
            sev_parts.append(f"🟠{high}")
        sev_str = " ".join(sev_parts) if sev_parts else f"{fcount} findings"
        lines.append(
            f"⚠️ <code>{esc(ip)}</code>{host_label}\n"
            f"   {bar} {risk}% │ {sev_str} │ {time_ago(last_seen)}"
        )

    kb = asset_list_kb(rows, page, total_pages)
    await query.edit_message_text("\n".join(lines), reply_markup=kb, parse_mode=HTML)


async def handle_detail(query, user, rest, context):
    aid = rest[0] if rest else ""

    def _q():
        return Asset.objects.filter(id__startswith=aid).first()

    asset = await sync_to_async(_q)()
    if not asset:
        await query.edit_message_text(
            f"Asset <code>{esc(aid)}</code> not found.",
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("⬅ Assets", callback_data="al:0")]]
            ),
            parse_mode=HTML,
        )
        return

    a = asset
    bar = progress_bar(a.risk_score, 100)
    lines = [
        f"<b>💻 Asset</b> — <code>{esc(a.ip)}</code>",
        "━━━━━━━━━━━━━━━━━━",
        "",
        f"<b>Hostname:</b> {esc(a.hostname or '—')}",
        f"<b>Service:</b> {esc(a.service_name or '—')} {esc(a.service_product or '')} {esc(a.service_version or '')}",
        f"<b>OS:</b> {esc(a.os or '—')}",
        f"<b>Port:</b> {a.port or '—'}/{esc(a.protocol or 'tcp')}",
        f"<b>Status:</b> {esc(a.status)}",
        "",
        f"<b>Risk:</b> {bar} {a.risk_score}%",
        f"<b>Findings:</b> {a.findings_count} (🔴{a.critical_count} 🟠{a.high_count})",
        "",
        f"<b>First seen:</b> {time_ago(a.first_seen)}",
        f"<b>Last seen:</b> {time_ago(a.last_seen)}",
    ]

    kb = asset_detail_kb(short_id(a.id))
    await query.edit_message_text("\n".join(lines), reply_markup=kb, parse_mode=HTML)
