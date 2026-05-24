from __future__ import annotations

from asgiref.sync import sync_to_async
from telegram import InlineKeyboardButton, InlineKeyboardMarkup

from scanner.bot.formatting import (
    esc,
    format_duration,
    severity_emoji,
    severity_line,
    short_id,
    status_icon,
    time_ago,
)
from scanner.bot.menus import (
    PAGE_SIZE,
    confirm_cancel_kb,
    scan_detail_kb,
    scan_list_kb,
    findings_list_kb,
    new_scan_kb,
)
from scanner.models import Finding, Report, Scan, Screenshot

HTML = "HTML"


async def handle_list(query, user, rest, context):
    page = int(rest[0]) if rest else 0

    def _q():
        qs = Scan.objects.order_by("-created_at")
        total = qs.count()
        total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
        rows = list(
            qs[page * PAGE_SIZE : (page + 1) * PAGE_SIZE].values_list(
                "id", "target", "status", "scan_type", "findings_count", "created_at"
            )
        )
        return rows, total_pages

    scans, total_pages = await sync_to_async(_q)()

    if not scans:
        await query.edit_message_text(
            "<b>🔍 Scans</b>\n━━━━━━━━\n\n<i>No scans yet.</i>",
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("⬅ Menu", callback_data="mn")]]
            ),
            parse_mode=HTML,
        )
        return

    lines = ["<b>🔍 Recent Scans</b>", "━━━━━━━━━━━━━━"]
    for sid, target, status, stype, fcount, created in scans:
        icon = status_icon(status)
        lines.append(
            f"{icon} <code>{short_id(sid)}</code> │ <code>{esc(target[:30])}</code>\n"
            f"   {esc(stype)} │ {fcount} findings │ {time_ago(created)}"
        )

    kb = scan_list_kb(scans, page, total_pages)
    await query.edit_message_text("\n".join(lines), reply_markup=kb, parse_mode=HTML)


async def handle_detail(query, user, rest, context):
    sid = rest[0] if rest else ""

    def _q():
        scan = Scan.objects.select_related("created_by").filter(id__startswith=sid).first()
        if not scan:
            return None, False, [], None
        has_ss = Screenshot.objects.filter(scan=scan).exists()
        reports = list(Report.objects.filter(scan=scan).values_list("format", "file_size"))
        creator = scan.created_by.username if scan.created_by else None
        return scan, has_ss, reports, creator

    scan, has_ss, reports, creator = await sync_to_async(_q)()
    if not scan:
        await query.edit_message_text(
            f"Scan <code>{esc(sid)}</code> not found.",
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("⬅ Scans", callback_data="sl:0")]]
            ),
            parse_mode=HTML,
        )
        return

    s = scan
    lines = [
        f"<b>📋 Scan</b> — <code>{short_id(s.id)}</code>",
        "━━━━━━━━━━━━━━━━━━",
        "",
        "<b>General</b>",
        f"  <b>Target:</b> <code>{esc(s.target)}</code>",
        f"  <b>Type:</b> {esc(s.scan_type)}",
        f"  <b>Status:</b> {status_icon(s.status)} {esc(s.status)}",
    ]
    if creator:
        lines.append(f"  <b>By:</b> {esc(creator)}")

    lines.append("")
    lines.append("<b>Timing</b>")
    lines.append(f"  <b>Started:</b> {time_ago(s.started_at)}")
    if s.duration_seconds:
        lines.append(f"  <b>Duration:</b> {format_duration(s.duration_seconds)}")

    lines.append("")
    lines.append("<b>Results</b>")
    lines.append(f"  <b>Hosts:</b> {s.hosts_count}  │  <b>Ports:</b> {s.ports_count}")
    lines.append(f"  <b>Findings:</b> {s.findings_count}")
    sev = severity_line(
        critical=s.critical_count,
        high=s.high_count,
        medium=s.medium_count,
        low=s.low_count,
    )
    if sev:
        lines.append(f"  {sev}")

    if reports:
        lines.append("")
        lines.append("<b>Reports</b>")
        for fmt, size in reports:
            size_str = f"{size / (1024 * 1024):.1f} MB" if size else "—"
            lines.append(f"  📄 {fmt.upper()} — {size_str}")

    kb = scan_detail_kb(short_id(s.id), s.status, has_ss)
    await query.edit_message_text("\n".join(lines), reply_markup=kb, parse_mode=HTML)


async def handle_findings(query, user, rest, context):
    sid = rest[0] if rest else ""
    page = int(rest[1]) if len(rest) > 1 else 0
    severity = rest[2] if len(rest) > 2 else None

    def _q():
        scan = Scan.objects.filter(id__startswith=sid).first()
        if not scan:
            return None, [], 0
        qs = Finding.objects.filter(scan=scan).order_by("-severity", "-id")
        if severity and severity != "all":
            qs = qs.filter(severity=severity)
        total = qs.count()
        total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
        rows = list(
            qs[page * PAGE_SIZE : (page + 1) * PAGE_SIZE].values_list(
                "id", "severity", "title", "host_ip", "port", "cve", "source"
            )
        )
        return scan, rows, total_pages

    scan, rows, total_pages = await sync_to_async(_q)()
    if not scan:
        await query.edit_message_text(
            f"Scan <code>{esc(sid)}</code> not found.",
            parse_mode=HTML,
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("⬅ Scans", callback_data="sl:0")]]
            ),
        )
        return

    scan_sid = short_id(scan.id)
    sev_filter = severity or "all"
    back_cb = f"sf:{scan_sid}:{page}:{sev_filter}"
    label = severity.title() if severity and severity != "all" else "All"
    lines = [
        f"<b>🛡 {esc(label)} Findings</b> — <code>{scan_sid}</code>",
        "━━━━━━━━━━━━━━━━━━",
    ]
    finding_buttons = []
    if not rows:
        lines.append("<i>No findings.</i>")
    for fid, sev, title, ip, port, cve, source in rows:
        emoji = severity_emoji(sev)
        loc = f"{ip}:{port}" if port else ip or ""
        cve_str = f" — {esc(cve)}" if cve else ""
        lines.append(f"{emoji} {esc(title[:60])}{cve_str}")
        lines.append(f"   📍 <code>{esc(loc)}</code> │ {esc(source or '—')}")
        finding_buttons.append(
            [
                InlineKeyboardButton(
                    f"{emoji} {title[:35]}",
                    callback_data=f"fd:{short_id(fid)}:{back_cb}",
                )
            ]
        )

    kb = findings_list_kb(page, total_pages, sev_filter, scan_sid, finding_buttons=finding_buttons)
    await query.edit_message_text("\n".join(lines), reply_markup=kb, parse_mode=HTML)


async def handle_report(query, user, rest, context):
    sid = rest[0] if rest else ""

    def _launch():
        scan = Scan.objects.filter(id__startswith=sid, status="completed").first()
        if not scan:
            return None
        from scanner.tasks import generate_report

        generate_report.delay(str(scan.id))
        return scan

    scan = await sync_to_async(_launch)()
    if not scan:
        await query.edit_message_text(
            f"No completed scan <code>{esc(sid)}</code> found.",
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("⬅ Back", callback_data=f"sd:{sid}")]]
            ),
            parse_mode=HTML,
        )
        return

    await query.edit_message_text(
        f"📄 Generating reports for <code>{short_id(scan.id)}</code>…\n"
        f"File will be sent when ready.",
        reply_markup=InlineKeyboardMarkup(
            [[InlineKeyboardButton("⬅ Back", callback_data=f"sd:{short_id(scan.id)}")]]
        ),
        parse_mode=HTML,
    )


async def handle_cancel(query, user, rest, context):
    sid = rest[0] if rest else ""
    await query.edit_message_text(
        f"Cancel scan <code>{esc(sid)}</code>?",
        reply_markup=confirm_cancel_kb(sid),
        parse_mode=HTML,
    )


async def handle_cancel_confirm(query, user, rest, context):
    sid = rest[0] if rest else ""

    def _cancel():
        scan = Scan.objects.filter(id__startswith=sid, status__in=("running", "pending")).first()
        if not scan:
            return None
        if scan.celery_task_id:
            from wireghost_web.celery import app as celery_app

            celery_app.control.revoke(scan.celery_task_id, terminate=True)
        scan.status = "cancelled"
        scan.error_message = "Cancelled via Telegram"
        scan.save(update_fields=["status", "error_message"])
        return scan

    scan = await sync_to_async(_cancel)()
    if not scan:
        await query.edit_message_text(
            f"Scan <code>{esc(sid)}</code> not found or already finished.",
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("⬅ Scans", callback_data="sl:0")]]
            ),
            parse_mode=HTML,
        )
        return

    await query.edit_message_text(
        f"⏸ Scan <code>{short_id(scan.id)}</code> cancelled.",
        reply_markup=InlineKeyboardMarkup(
            [[InlineKeyboardButton("⬅ Scans", callback_data="sl:0")]]
        ),
        parse_mode=HTML,
    )


async def handle_new(query, user, rest, context):
    action = rest[0] if rest else "pick"
    if action == "pick":
        await query.edit_message_text(
            "<b>➕ New Scan</b>\n━━━━━━━━━━\n\nSelect scan type:",
            reply_markup=new_scan_kb(),
            parse_mode=HTML,
        )
    elif action == "go":
        scan_type = rest[1] if len(rest) > 1 else "full"
        idx = int(rest[2]) if len(rest) > 2 and rest[2].isdigit() else -1
        recent = context.user_data.get("_recent_targets", [])
        if 0 <= idx < len(recent):
            target = recent[idx]

            def _create():
                from scanner.tasks import run_scan
                from scanner.models import SiteConfig

                cfg = SiteConfig.get()
                scan = Scan.objects.create(
                    name=f"Telegram: {target}",
                    target=target[:500],
                    scan_type=scan_type,
                    parallelism=cfg.default_parallelism,
                    timeout=cfg.default_timeout,
                    report_formats=cfg.default_report_formats,
                    status="pending",
                    created_by=user,
                )
                task = run_scan.delay(str(scan.id))
                scan.celery_task_id = task.id
                scan.status = "running"
                scan.save(update_fields=["celery_task_id", "status"])
                return scan

            scan = await sync_to_async(_create)()
            sid = short_id(scan.id)
            await query.edit_message_text(
                f"🚀 <b>Scan Launched</b>\n━━━━━━━━━━━━━━\n\n"
                f"  <b>ID:</b> <code>{esc(sid)}</code>\n"
                f"  <b>Target:</b> <code>{esc(target)}</code>\n"
                f"  <b>Type:</b> {esc(scan_type)}",
                reply_markup=InlineKeyboardMarkup(
                    [
                        [InlineKeyboardButton("📋 View Scan", callback_data=f"sd:{sid}")],
                        [InlineKeyboardButton("⬅ Menu", callback_data="mn")],
                    ]
                ),
                parse_mode=HTML,
            )
        else:
            await query.edit_message_text(
                "Target not found. Try again.",
                reply_markup=InlineKeyboardMarkup(
                    [[InlineKeyboardButton("⬅ Menu", callback_data="mn")]]
                ),
                parse_mode=HTML,
            )
    elif action == "custom":
        scan_type = rest[1] if len(rest) > 1 else "full"
        context.user_data["_newscan_type"] = scan_type
        await query.edit_message_text(
            f"<b>➕ New Scan</b> — {esc(scan_type)}\n\n"
            f"Send the target (IP, CIDR, or hostname) as a text message:",
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("⬅ Cancel", callback_data="mn")]]
            ),
            parse_mode=HTML,
        )
    elif action in ("full", "quick", "port", "web", "service"):

        def _recent():
            return list(
                Scan.objects.order_by("-created_at").values_list("target", flat=True).distinct()[:5]
            )

        recent = await sync_to_async(_recent)()
        context.user_data["_recent_targets"] = recent
        context.user_data["_newscan_type"] = action

        rows = []
        for i, t in enumerate(recent):
            rows.append([InlineKeyboardButton(f"🎯 {t[:35]}", callback_data=f"ns:go:{action}:{i}")])
        rows.append([InlineKeyboardButton("⌨ Custom Target", callback_data=f"ns:custom:{action}")])
        rows.append([InlineKeyboardButton("⬅ Cancel", callback_data="mn")])

        await query.edit_message_text(
            f"<b>➕ New Scan</b> — {esc(action)}\n━━━━━━━━━━━━━━\n\n"
            f"Pick a recent target or enter a custom one:",
            reply_markup=InlineKeyboardMarkup(rows),
            parse_mode=HTML,
        )
    else:
        context.user_data["_newscan_type"] = action
        await query.edit_message_text(
            f"<b>➕ New Scan</b> — {esc(action)}\n\n"
            f"Send the target (IP, CIDR, or hostname) as a text message:",
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("⬅ Cancel", callback_data="mn")]]
            ),
            parse_mode=HTML,
        )
