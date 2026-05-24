from __future__ import annotations

from asgiref.sync import sync_to_async
from telegram import InlineKeyboardButton, InlineKeyboardMarkup

from scanner.bot.formatting import esc, short_id, time_ago
from scanner.bot.menus import PAGE_SIZE, schedule_detail_kb, schedule_list_kb
from scanner.models import ScheduledScan

HTML = "HTML"


async def handle_list(query, user, rest, context):
    page = int(rest[0]) if rest else 0

    def _q():
        qs = ScheduledScan.objects.order_by("next_run")
        total = qs.count()
        total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
        rows = list(
            qs[page * PAGE_SIZE : (page + 1) * PAGE_SIZE].values_list(
                "id", "name", "target", "enabled", "frequency", "time", "next_run", "scan_type"
            )
        )
        return rows, total, total_pages

    rows, total, total_pages = await sync_to_async(_q)()

    lines = [f"<b>📅 Scheduled Scans</b> ({total})", "━━━━━━━━━━━━━━━━━━"]
    if not rows:
        lines.append("<i>No schedules configured.</i>")
    for sid, name, target, enabled, freq, time_val, next_run, stype in rows:
        icon = "✅" if enabled else "⏸"
        time_str = time_val.strftime("%H:%M") if time_val else "—"
        next_str = time_ago(next_run) if next_run else "—"
        lines.append(
            f"{icon} <code>{short_id(sid)}</code> │ <code>{esc(target[:25])}</code>\n"
            f"   {esc(freq)} {time_str} │ {esc(stype)} │ next: {next_str}"
        )

    kb = schedule_list_kb(rows, page, total_pages)
    await query.edit_message_text("\n".join(lines), reply_markup=kb, parse_mode=HTML)


async def handle_detail(query, user, rest, context):
    sid = rest[0] if rest else ""

    def _q():
        return ScheduledScan.objects.filter(id__startswith=sid).first()

    sched = await sync_to_async(_q)()
    if not sched:
        await query.edit_message_text(
            f"Schedule <code>{esc(sid)}</code> not found.",
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("⬅ Schedules", callback_data="cl:0")]]
            ),
            parse_mode=HTML,
        )
        return

    s = sched
    time_str = s.time.strftime("%H:%M") if s.time else "—"
    stop_str = s.stop_time.strftime("%H:%M") if s.stop_time else "—"
    lines = [
        f"<b>📅 Schedule</b> — <code>{short_id(s.id)}</code>",
        "━━━━━━━━━━━━━━━━━━",
        "",
        f"<b>Name:</b> {esc(s.name or '—')}",
        f"<b>Target:</b> <code>{esc(s.target)}</code>",
        f"<b>Type:</b> {esc(s.scan_type)}",
        f"<b>Frequency:</b> {esc(s.frequency)} at {time_str}",
        f"<b>Stop time:</b> {stop_str}",
        f"<b>Enabled:</b> {'✅ Yes' if s.enabled else '⏸ No'}",
        "",
        f"<b>Last run:</b> {time_ago(s.last_run)}",
        f"<b>Next run:</b> {time_ago(s.next_run)}",
    ]

    kb = schedule_detail_kb(short_id(s.id), s.enabled)
    await query.edit_message_text("\n".join(lines), reply_markup=kb, parse_mode=HTML)


async def handle_toggle(query, user, rest, context):
    sid = rest[0] if rest else ""

    def _toggle():
        sched = ScheduledScan.objects.filter(id__startswith=sid).first()
        if not sched:
            return None
        sched.enabled = not sched.enabled
        sched.save(update_fields=["enabled"])
        return sched

    sched = await sync_to_async(_toggle)()
    if not sched:
        await query.edit_message_text(
            f"Schedule <code>{esc(sid)}</code> not found.",
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("⬅ Schedules", callback_data="cl:0")]]
            ),
            parse_mode=HTML,
        )
        return

    await handle_detail(query, user, [short_id(sched.id)], context)


async def handle_run_now(query, user, rest, context):
    sid = rest[0] if rest else ""

    def _run():
        sched = ScheduledScan.objects.filter(id__startswith=sid).first()
        if not sched:
            return None, None
        from scanner.models import Scan

        scan = Scan.objects.create(
            name=sched.name or f"Manual: {sched.target}",
            target=sched.target,
            scan_type=sched.scan_type,
            created_by=user,
        )
        from scanner.tasks import run_scan

        run_scan.delay(str(scan.id))
        return sched, scan

    sched, scan = await sync_to_async(_run)()
    if not sched:
        await query.edit_message_text(
            f"Schedule <code>{esc(sid)}</code> not found.",
            parse_mode=HTML,
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("⬅ Schedules", callback_data="cl:0")]]
            ),
        )
        return

    await query.edit_message_text(
        f"🚀 Launched scan <code>{short_id(scan.id)}</code> for <code>{esc(sched.target[:30])}</code>",
        reply_markup=InlineKeyboardMarkup(
            [
                [InlineKeyboardButton("📋 View Scan", callback_data=f"sd:{short_id(scan.id)}")],
                [InlineKeyboardButton("⬅ Schedules", callback_data="cl:0")],
            ]
        ),
        parse_mode=HTML,
    )
