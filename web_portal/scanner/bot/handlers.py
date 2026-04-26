from __future__ import annotations

import logging

from asgiref.sync import sync_to_async
from django.db.models import Sum, Q, Count
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes

from scanner.bot.auth import resolve_user, link_account, unlink_account, check_rate_limit
from scanner.bot.formatting import (
    esc, severity_emoji, severity_line, short_id,
    status_icon, truncate_list, format_duration,
)
from scanner.models import (
    AuditLog, Asset, Finding, Host, Scan, ScheduledScan,
    ScanPolicy, SiteConfig, User, UserPreference,
)

log = logging.getLogger('scanner.bot')

HTML = 'HTML'


# ── Pre-auth commands (no decorator) ─────────────────────

async def cmd_link(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            'Usage: <code>/link &lt;6-digit code&gt;</code>', parse_mode=HTML,
        )
        return
    code = context.args[0].strip()
    tg_user = update.effective_user
    chat_id = update.effective_user.id

    ok, msg = await sync_to_async(link_account)(
        tg_user_id=tg_user.id, tg_chat_id=chat_id, code=code,
    )
    await update.message.reply_text(esc(msg), parse_mode=HTML)

    if ok and update.effective_chat.type in ('group', 'supergroup'):
        cfg = await sync_to_async(SiteConfig.get)()
        user = await sync_to_async(resolve_user)(tg_user.id)
        if not cfg.telegram_shared_chat_id and user and user.role == 'owner':
            await update.message.reply_text(
                'Use this group for Wire_Ghost notifications? '
                'Send <code>/yes</code> or <code>/no</code>',
                parse_mode=HTML,
            )
            context.user_data['_pending_group_confirm'] = str(update.effective_chat.id)


async def cmd_unlink(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ok, msg = await sync_to_async(unlink_account)(update.effective_user.id)
    await update.message.reply_text(esc(msg), parse_mode=HTML)


async def cmd_yes(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = context.user_data.pop('_pending_group_confirm', None)
    if not chat_id:
        return
    cfg = await sync_to_async(SiteConfig.get)()
    cfg.telegram_shared_chat_id = chat_id
    await sync_to_async(cfg.save)(update_fields=['telegram_shared_chat_id'])
    await update.message.reply_text('✅ This group is now set for Wire_Ghost notifications.')


async def cmd_no(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.pop('_pending_group_confirm', None)
    await update.message.reply_text('OK, group not set.')


# ── Viewer commands ──────────────────────────────────────

async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    def _query():
        active = Scan.objects.filter(status='running').count()
        agg = Scan.objects.filter(status='completed').aggregate(
            hosts=Sum('hosts_count'),
            findings=Sum('findings_count'),
            critical=Sum('critical_count'),
            high=Sum('high_count'),
            medium=Sum('medium_count'),
            low=Sum('low_count'),
        )
        return active, agg

    active, agg = await sync_to_async(_query)()

    lines = [
        '<b>Wire_Ghost Status</b>',
        '━━━━━━━━━━━━━━━━━',
        f'<b>Active scans:</b> {active}',
        f'<b>Total hosts:</b> {agg["hosts"] or 0}',
        f'<b>Total findings:</b> {agg["findings"] or 0}',
        f'  🔴 Critical: {agg["critical"] or 0}',
        f'  🟠 High: {agg["high"] or 0}',
        f'  🟡 Medium: {agg["medium"] or 0}',
        f'  🔵 Low: {agg["low"] or 0}',
    ]
    await update.message.reply_text('\n'.join(lines), parse_mode=HTML)


async def cmd_scans(update: Update, context: ContextTypes.DEFAULT_TYPE):
    def _query():
        return list(
            Scan.objects.order_by('-created_at')[:10]
            .values_list('id', 'target', 'scan_type', 'status', 'findings_count')
        )

    rows = await sync_to_async(_query)()
    if not rows:
        await update.message.reply_text('<i>No scans found.</i>', parse_mode=HTML)
        return

    lines = ['<b>Recent Scans</b>', '━━━━━━━━━━━━']
    for scan_id, target, stype, st, fcount in rows:
        icon = status_icon(st)
        sid = short_id(scan_id)
        lines.append(f'{icon} <code>{esc(sid)}</code> │ <code>{esc(target)}</code> │ {esc(stype)} │ {fcount} findings')

    await update.message.reply_text('\n'.join(lines), parse_mode=HTML)


async def cmd_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            'Usage: <code>/scan &lt;id&gt;</code>', parse_mode=HTML,
        )
        return

    prefix = context.args[0].strip()

    def _query():
        qs = Scan.objects.filter(id__startswith=prefix)
        if not qs.exists():
            return None
        return qs.first()

    scan = await sync_to_async(_query)()
    if not scan:
        await update.message.reply_text(f'Scan <code>{esc(prefix)}</code> not found.', parse_mode=HTML)
        return

    sid = short_id(scan.id)
    dur = format_duration(scan.duration_seconds)
    sev = severity_line(
        critical=scan.critical_count, high=scan.high_count,
        medium=scan.medium_count, low=scan.low_count,
    )
    lines = [
        f'<b>Scan:</b> <code>{esc(sid)}</code>',
        '━━━━━━━━━━━━━━',
        f'<b>Target:</b> <code>{esc(scan.target)}</code>',
        f'<b>Type:</b> {esc(scan.scan_type)} │ <b>Status:</b> {esc(scan.status)}',
        f'<b>Duration:</b> {dur}',
        f'<b>Hosts:</b> {scan.hosts_count} │ <b>Ports:</b> {scan.ports_count}',
        f'<b>Findings:</b> {scan.findings_count}',
        f'  {sev}',
    ]
    reports = await sync_to_async(
        lambda: list(scan.reports.values_list('format', flat=True))
    )()
    if reports:
        lines.append(f'<b>Reports:</b> {esc(", ".join(reports))}')

    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton('Findings', callback_data=f'scan:{sid}:findings'),
            InlineKeyboardButton('Report', callback_data=f'scan:{sid}:report'),
        ]
    ])
    await update.message.reply_text('\n'.join(lines), reply_markup=keyboard, parse_mode=HTML)


async def cmd_findings(update: Update, context: ContextTypes.DEFAULT_TYPE):
    severity_filter = context.args[0].lower() if context.args else None
    valid_severities = {'critical', 'high', 'medium', 'low', 'info'}
    if severity_filter and severity_filter not in valid_severities:
        await update.message.reply_text(
            f'Invalid severity. Use: {", ".join(sorted(valid_severities))}',
        )
        return

    def _query():
        qs = Finding.objects.order_by('-id')
        if severity_filter:
            qs = qs.filter(severity=severity_filter)
        return list(qs[:15].values_list('severity', 'title', 'host_ip', 'port'))

    rows = await sync_to_async(_query)()
    if not rows:
        await update.message.reply_text('<i>No findings found.</i>', parse_mode=HTML)
        return

    label = f'{severity_filter.title()} Findings' if severity_filter else 'Recent Findings'
    lines = [f'<b>{esc(label)}</b>', '━━━━━━━━━━━━━━━━━']
    shown, remaining = truncate_list(rows, 15)
    for sev, title, ip, port in shown:
        emoji = severity_emoji(sev)
        loc = f'{ip}:{port}' if port else ip or ''
        lines.append(f'{emoji} {esc(title)} (<code>{esc(loc)}</code>)')
    if remaining:
        lines.append(f'<i>… and {remaining} more</i>')

    await update.message.reply_text('\n'.join(lines), parse_mode=HTML)


async def cmd_assets(update: Update, context: ContextTypes.DEFAULT_TYPE):
    def _query():
        return list(
            Asset.objects.order_by('-risk_score')[:10]
            .values_list('ip', 'service_name', 'risk_score', 'findings_count')
        )

    rows = await sync_to_async(_query)()
    if not rows:
        await update.message.reply_text('<i>No assets found.</i>', parse_mode=HTML)
        return

    lines = ['<b>High-Risk Assets</b>', '━━━━━━━━━━━━━━━━']
    for ip, svc, risk, fcount in rows:
        svc_label = svc or 'unknown'
        lines.append(f'⚠️ <code>{esc(ip)}</code> │ {esc(svc_label)} │ risk: {risk} │ {fcount} findings')

    await update.message.reply_text('\n'.join(lines), parse_mode=HTML)


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = context.user_data.get('wg_user')

    viewer_cmds = [
        '<code>/status</code> — Dashboard summary',
        '<code>/scans</code> — Recent scans',
        '<code>/scan</code> &lt;id&gt; — Scan detail',
        '<code>/findings</code> [severity] — List findings',
        '<code>/assets</code> — Top assets by risk',
        '<code>/help</code> — This message',
        '<code>/link</code> &lt;code&gt; — Link Telegram account',
        '<code>/unlink</code> — Unlink account',
    ]
    engineer_cmds = [
        '<code>/newscan</code> &lt;target&gt; [type] — Launch scan',
        '<code>/cancel</code> &lt;id&gt; — Cancel scan',
        '<code>/schedule</code> list|add|del — Manage schedules',
        '<code>/report</code> &lt;id&gt; — Regenerate reports',
    ]
    owner_cmds = [
        '<code>/users</code> — List users',
        '<code>/config</code> — Site configuration',
        '<code>/health</code> — System health',
    ]

    lines = ['<b>Wire_Ghost Bot Commands</b>', '━━━━━━━━━━━━━━━━━━━━━━━']
    lines.extend(viewer_cmds)

    if user:
        has_write = await sync_to_async(user.has_permission)('scan:write')
        if has_write:
            lines.append('')
            lines.extend(engineer_cmds)

    if user and user.role == 'owner':
        lines.append('')
        lines.extend(owner_cmds)

    await update.message.reply_text('\n'.join(lines), parse_mode=HTML)


# ── Engineer commands ────────────────────────────────────

async def cmd_newscan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            'Usage: <code>/newscan</code> &lt;target&gt; [full|quick|port|web]',
            parse_mode=HTML,
        )
        return

    user = context.user_data['wg_user']

    if not check_rate_limit('tg:scanrate:', str(update.effective_user.id), 5, 3600):
        await update.message.reply_text('Scan rate limit: max 5 per hour.')
        return

    import re
    target = context.args[0].strip()
    scan_type = context.args[1].strip().lower() if len(context.args) > 1 else 'full'

    if scan_type not in ('full', 'quick', 'port', 'web'):
        await update.message.reply_text('Invalid scan type. Use: full, quick, port, web')
        return

    if not re.match(r'^[a-zA-Z0-9.:/,\-]+$', target):
        await update.message.reply_text('Invalid target format.')
        return

    def _create():
        from scanner.tasks import run_scan
        cfg = SiteConfig.get()
        scan = Scan.objects.create(
            name=f'Telegram: {target}',
            target=target[:500],
            scan_type=scan_type,
            parallelism=cfg.default_parallelism,
            timeout=cfg.default_timeout,
            report_formats=cfg.default_report_formats,
            status='pending',
            created_by=user,
        )
        task = run_scan.delay(str(scan.id))
        scan.celery_task_id = task.id
        scan.status = 'running'
        scan.save(update_fields=['celery_task_id', 'status'])
        return scan

    scan = await sync_to_async(_create)()
    sid = short_id(scan.id)
    await update.message.reply_text(
        f'Scan <code>{esc(sid)}</code> launched against <code>{esc(target)}</code> (type: {esc(scan_type)})',
        parse_mode=HTML,
    )


async def cmd_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            'Usage: <code>/cancel</code> &lt;id&gt;', parse_mode=HTML,
        )
        return

    prefix = context.args[0].strip()
    user = context.user_data['wg_user']

    def _cancel():
        qs = Scan.objects.filter(id__startswith=prefix, status='running')
        scan = qs.first()
        if not scan:
            return None, 'No running scan found with that ID.'
        if scan.created_by != user and user.role != 'owner':
            return None, 'Only the scan creator or Owner can cancel.'
        from wireghost_web.celery import app as celery_app
        if scan.celery_task_id:
            celery_app.control.revoke(scan.celery_task_id, terminate=True, signal='SIGTERM')
        scan.status = 'cancelled'
        scan.save(update_fields=['status'])
        return scan, None

    scan, err = await sync_to_async(_cancel)()
    if err:
        await update.message.reply_text(err)
        return
    await update.message.reply_text(
        f'Scan <code>{esc(short_id(scan.id))}</code> cancelled.', parse_mode=HTML,
    )


async def cmd_schedule(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            'Usage: <code>/schedule</code> list|add|del', parse_mode=HTML,
        )
        return

    sub = context.args[0].lower()
    user = context.user_data['wg_user']

    if sub == 'list':
        def _list():
            return list(
                ScheduledScan.objects.filter(enabled=True)
                .order_by('next_run')[:10]
                .values_list('id', 'target', 'frequency', 'time', 'next_run')
            )
        rows = await sync_to_async(_list)()
        if not rows:
            await update.message.reply_text('<i>No active schedules.</i>', parse_mode=HTML)
            return
        lines = ['<b>Scheduled Scans</b>', '━━━━━━━━━━━━━━━']
        for sid, target, freq, t, nxt in rows:
            nxt_str = nxt.strftime('%Y-%m-%d %H:%M') if nxt else '—'
            lines.append(
                f'📅 <code>{esc(short_id(sid))}</code> │ <code>{esc(target)}</code> │ '
                f'{esc(freq)} {t.strftime("%H:%M")} │ next: {esc(nxt_str)}'
            )
        await update.message.reply_text('\n'.join(lines), parse_mode=HTML)

    elif sub == 'add':
        if len(context.args) < 4:
            await update.message.reply_text(
                'Usage: <code>/schedule add</code> &lt;target&gt; &lt;daily|weekly|biweekly|monthly&gt; &lt;HH:MM&gt;',
                parse_mode=HTML,
            )
            return
        import re
        from datetime import time as dt_time
        target = context.args[1]
        freq = context.args[2].lower()
        time_str = context.args[3]

        if freq not in ('daily', 'weekly', 'biweekly', 'monthly'):
            await update.message.reply_text('Invalid frequency. Use: daily, weekly, biweekly, monthly')
            return
        if not re.match(r'^\d{2}:\d{2}$', time_str):
            await update.message.reply_text('Invalid time format. Use HH:MM (24-hour)')
            return
        if not re.match(r'^[a-zA-Z0-9.:/,\-]+$', target):
            await update.message.reply_text('Invalid target format.')
            return

        h, m = int(time_str[:2]), int(time_str[3:5])
        if h > 23 or m > 59:
            await update.message.reply_text('Invalid time.')
            return

        def _create():
            from scanner.tasks import _calc_next_run
            sched = ScheduledScan.objects.create(
                name=f'Telegram: {target}',
                target=target[:500],
                frequency=freq,
                time=dt_time(h, m),
                scan_type='full',
                enabled=True,
                created_by=user,
                next_run=_calc_next_run(freq, dt_time(h, m)),
            )
            return sched

        sched = await sync_to_async(_create)()
        await update.message.reply_text(
            f'Schedule created: <code>{esc(target)}</code> every {esc(freq)} at {esc(time_str)}',
            parse_mode=HTML,
        )

    elif sub == 'del':
        if len(context.args) < 2:
            await update.message.reply_text(
                'Usage: <code>/schedule del</code> &lt;id&gt;', parse_mode=HTML,
            )
            return
        prefix = context.args[1]

        def _delete():
            qs = ScheduledScan.objects.filter(id__startswith=prefix)
            sched = qs.first()
            if not sched:
                return 'Schedule not found.'
            if sched.created_by != user and user.role != 'owner':
                return 'Only the creator or Owner can delete.'
            sched.delete()
            return None

        err = await sync_to_async(_delete)()
        if err:
            await update.message.reply_text(err)
        else:
            await update.message.reply_text('Schedule deleted.')

    else:
        await update.message.reply_text(
            'Usage: <code>/schedule</code> list|add|del', parse_mode=HTML,
        )


async def cmd_report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            'Usage: <code>/report</code> &lt;scan_id&gt;', parse_mode=HTML,
        )
        return

    prefix = context.args[0].strip()

    def _find():
        qs = Scan.objects.filter(id__startswith=prefix, status='completed')
        return qs.first()

    scan = await sync_to_async(_find)()
    if not scan:
        await update.message.reply_text(
            f'No completed scan found with ID <code>{esc(prefix)}</code>.', parse_mode=HTML,
        )
        return

    def _launch():
        from scanner.tasks import generate_report
        generate_report.delay(str(scan.id))

    await sync_to_async(_launch)()
    sid = short_id(scan.id)
    await update.message.reply_text(
        f'Generating reports for scan <code>{esc(sid)}</code>… I\'ll send the file when ready.',
        parse_mode=HTML,
    )


# ── Owner commands ───────────────────────────────────────

async def cmd_users(update: Update, context: ContextTypes.DEFAULT_TYPE):
    def _query():
        users = User.objects.filter(is_active=True).order_by('role', 'username')
        result = []
        for u in users:
            prefs = UserPreference.for_user(u)
            linked = bool(prefs.telegram_user_id)
            result.append((u.username, u.role, linked))
        return result

    rows = await sync_to_async(_query)()
    role_icons = {'owner': '👑', 'engineer': '🔧', 'viewer': '👁'}
    lines = ['<b>Users</b>', '━━━━━']
    for uname, role, linked in rows:
        icon = role_icons.get(role, '❓')
        link_str = '🔗 linked' if linked else '❌ not linked'
        lines.append(f'{icon} <b>{esc(uname)}</b> │ {esc(role)} │ {link_str}')

    try:
        await context.bot.send_message(
            chat_id=update.effective_user.id,
            text='\n'.join(lines),
            parse_mode=HTML,
        )
        if update.effective_chat.type in ('group', 'supergroup'):
            await update.message.reply_text('User list sent via DM.')
    except Exception:
        await update.message.reply_text('Could not send DM. Please start a private chat with me first, then retry.')


async def cmd_config(update: Update, context: ContextTypes.DEFAULT_TYPE):
    def _query():
        cfg = SiteConfig.get()
        return {
            'timezone': cfg.schedule_timezone,
            'parallelism': cfg.default_parallelism,
            'timeout': cfg.default_timeout,
            'bot_configured': bool(cfg.telegram_bot_token),
            'shared_chat': bool(cfg.telegram_shared_chat_id),
        }

    data = await sync_to_async(_query)()
    lines = [
        '<b>Site Config</b>',
        '━━━━━━━━━━━',
        f'<b>Timezone:</b> {esc(data["timezone"])}',
        f'<b>Default parallelism:</b> {data["parallelism"]}',
        f'<b>Default timeout:</b> {data["timeout"]}s',
        f'<b>Telegram bot:</b> {"✅ configured" if data["bot_configured"] else "❌ not configured"}',
        f'<b>Shared chat:</b> {"✅ set" if data["shared_chat"] else "❌ not set"}',
    ]

    try:
        await context.bot.send_message(
            chat_id=update.effective_user.id,
            text='\n'.join(lines),
            parse_mode=HTML,
        )
        if update.effective_chat.type in ('group', 'supergroup'):
            await update.message.reply_text('Config sent via DM.')
    except Exception:
        await update.message.reply_text('Could not send DM. Please start a private chat with me first, then retry.')


async def cmd_health(update: Update, context: ContextTypes.DEFAULT_TYPE):
    def _query():
        import psutil
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        return {
            'cpu': f'{cpu}%',
            'ram': f'{mem.used / (1024**3):.1f}/{mem.total / (1024**3):.1f} GB',
            'disk': f'{disk.used / (1024**3):.0f}/{disk.total / (1024**3):.0f} GB',
        }

    stats = await sync_to_async(_query)()
    lines = [
        '<b>System Health</b>',
        '━━━━━━━━━━━━━',
        f'<b>CPU:</b> {esc(stats["cpu"])} │ <b>RAM:</b> {esc(stats["ram"])} │ <b>Disk:</b> {esc(stats["disk"])}',
    ]
    await update.message.reply_text('\n'.join(lines), parse_mode=HTML)
