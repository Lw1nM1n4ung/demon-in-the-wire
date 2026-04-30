from __future__ import annotations

import logging

from asgiref.sync import sync_to_async
from django.db.models import Sum, Q, Count
from django.utils import timezone as dj_tz
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes

from scanner.bot.auth import resolve_user, link_account, unlink_account, check_rate_limit
from scanner.bot.formatting import (
    esc, severity_emoji, severity_line, short_id,
    status_icon, truncate_list, format_duration,
    time_ago, progress_bar,
)
from scanner.bot.menus import main_menu_kb, scan_detail_kb
from scanner.models import (
    AuditLog, Asset, Finding, Host, Scan, ScheduledScan,
    ScanPolicy, SiteConfig, User, UserPreference,
)

log = logging.getLogger('scanner.bot')

HTML = 'HTML'


# ── Pre-auth commands (no decorator) ─────────────────────

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Entry point — only linked users see the menu."""
    tg_user = update.effective_user
    if not tg_user:
        return
    user = await sync_to_async(resolve_user)(tg_user.id)
    if user is None:
        await update.message.reply_text(
            '\U0001f512 <b>Authorized Users Only</b>\n\n'
            'This bot is restricted to linked Wire_Ghost accounts.\n'
            'Use <code>/link &lt;code&gt;</code> to connect.',
            parse_mode=HTML,
        )
        return
    context.user_data['wg_user'] = user
    await cmd_menu(update, context)


async def cmd_link(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            '🔗 <b>Link Your Account</b>\n'
            '━━━━━━━━━━━━━━━━━━━\n'
            '1. Open Wire_Ghost web portal\n'
            '2. Go to <b>Settings → Telegram</b>\n'
            '3. Click <b>Generate Code</b>\n'
            '4. Send: <code>/link &lt;6-digit code&gt;</code>',
            parse_mode=HTML,
        )
        return
    code = context.args[0].strip()
    tg_user = update.effective_user
    chat_id = update.effective_user.id

    ok, msg = await sync_to_async(link_account)(
        tg_user_id=tg_user.id, tg_chat_id=chat_id, code=code,
    )
    if ok:
        await update.message.reply_text(f'✅ {esc(msg)}', parse_mode=HTML)
    else:
        await update.message.reply_text(f'❌ {esc(msg)}', parse_mode=HTML)

    if ok and update.effective_chat.type in ('group', 'supergroup'):
        cfg = await sync_to_async(SiteConfig.get)()
        user = await sync_to_async(resolve_user)(tg_user.id)
        if not cfg.telegram_shared_chat_id and user and user.role == 'owner':
            await update.message.reply_text(
                '📢 Use this group for Wire_Ghost notifications?\n'
                'Send <code>/yes</code> or <code>/no</code>',
                parse_mode=HTML,
            )
            context.user_data['_pending_group_confirm'] = str(update.effective_chat.id)


async def cmd_unlink(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ok, msg = await sync_to_async(unlink_account)(update.effective_user.id)
    prefix = '✅' if ok else '❌'
    await update.message.reply_text(f'{prefix} {esc(msg)}', parse_mode=HTML)


async def cmd_unlock(update: Update, context: ContextTypes.DEFAULT_TYPE):
    from scanner.bot.auth import (
        check_rate_limit, generate_magic_token,
        UNLOCK_RATE_PREFIX, UNLOCK_RATE_MAX, UNLOCK_RATE_TTL,
    )
    tg_user = update.effective_user
    if not tg_user:
        return
    if not check_rate_limit(UNLOCK_RATE_PREFIX, str(tg_user.id), UNLOCK_RATE_MAX, UNLOCK_RATE_TTL):
        await update.message.reply_text('Rate limit reached. Try again in a few minutes.')
        return
    user = await sync_to_async(resolve_user)(tg_user.id)
    if user is None:
        await update.message.reply_text(
            'Your Telegram is not linked to any Wire_Ghost account.\n'
            'Use <code>/link &lt;code&gt;</code> to connect first.',
            parse_mode=HTML,
        )
        return

    def _do_unlock():
        from django.core.cache import cache as djcache
        djcache.delete(f'login_user_attempts:{user.username.lower()}')
        token = generate_magic_token(user)
        AuditLog.log(user.username, 'auth.unlock',
            f'Account unlocked via Telegram (tg_user={tg_user.id})', 'auth')
        return token

    token = await sync_to_async(_do_unlock)()
    await update.message.reply_text(
        '\U0001f513 <b>Account Unlocked</b>\n'
        '━━━━━━━━━━━━━━━━━\n\n'
        'Your login lockout has been cleared.\n\n'
        '<b>Option 1:</b> Go back to the login page and sign in normally.\n\n'
        '<b>Option 2:</b> Use this one-time login token (expires in 5 min):\n'
        f'<code>/login?token={token}</code>\n\n'
        '<i>Append this to your portal URL to auto-login.</i>',
        parse_mode=HTML,
    )


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


async def cmd_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = context.user_data.get('wg_user')
    role = user.role if user else 'viewer'
    kb = main_menu_kb(role)
    await update.message.reply_text(
        '<b>🔰 Wire_Ghost Control Panel</b>\n'
        '━━━━━━━━━━━━━━━━━━━━━━\n'
        'Select a category:',
        reply_markup=kb,
        parse_mode=HTML,
    )


# ── Viewer commands ──────────────────────────────────────

async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    def _query():
        active = Scan.objects.filter(status='running').count()
        pending = Scan.objects.filter(status='pending').count()
        total_scans = Scan.objects.count()
        completed = Scan.objects.filter(status='completed').count()
        failed = Scan.objects.filter(status='failed').count()
        agg = Scan.objects.filter(status='completed').aggregate(
            hosts=Sum('hosts_count'),
            findings=Sum('findings_count'),
            critical=Sum('critical_count'),
            high=Sum('high_count'),
            medium=Sum('medium_count'),
            low=Sum('low_count'),
        )
        last_scan = Scan.objects.order_by('-created_at').first()
        next_sched = ScheduledScan.objects.filter(
            enabled=True, next_run__isnull=False,
        ).order_by('next_run').first()
        return {
            'active': active, 'pending': pending,
            'total': total_scans, 'completed': completed, 'failed': failed,
            'agg': agg, 'last_scan': last_scan, 'next_sched': next_sched,
        }

    d = await sync_to_async(_query)()
    agg = d['agg']
    total_findings = agg['findings'] or 0
    crit = agg['critical'] or 0
    high = agg['high'] or 0
    med = agg['medium'] or 0
    low = agg['low'] or 0

    last = d['last_scan']
    last_info = '—'
    if last:
        last_info = f'{status_icon(last.status)} <code>{esc(short_id(last.id))}</code> {esc(last.target)} ({time_ago(last.created_at)})'

    next_info = '—'
    if d['next_sched']:
        ns = d['next_sched']
        next_info = f'<code>{esc(ns.target)}</code> at {ns.time.strftime("%H:%M")} ({time_ago(ns.next_run) if ns.next_run and ns.next_run < dj_tz.now() else ns.next_run.strftime("%Y-%m-%d %H:%M") if ns.next_run else "—"})'

    lines = [
        '🛡 <b>Wire_Ghost Dashboard</b>',
        '━━━━━━━━━━━━━━━━━━━━━',
        '',
        f'<b>📊 Scan Activity</b>',
        f'  🔄 Running: <b>{d["active"]}</b>  │  ⏳ Pending: <b>{d["pending"]}</b>',
        f'  ✅ Completed: {d["completed"]}  │  ❌ Failed: {d["failed"]}',
        f'  📁 Total: {d["total"]}',
        '',
        f'<b>🎯 Findings Summary</b>',
        f'  🔴 Critical: <b>{crit}</b>',
        f'  🟠 High: <b>{high}</b>',
        f'  🟡 Medium: {med}',
        f'  🔵 Low: {low}',
        f'  📊 Total: <b>{total_findings}</b>  │  Hosts: <b>{agg["hosts"] or 0}</b>',
        '',
        f'<b>🕐 Timeline</b>',
        f'  Last scan: {last_info}',
        f'  Next scheduled: {next_info}',
    ]
    await update.message.reply_text('\n'.join(lines), parse_mode=HTML)


async def cmd_scans(update: Update, context: ContextTypes.DEFAULT_TYPE):
    def _query():
        return list(
            Scan.objects.order_by('-created_at')[:10]
            .values_list('id', 'name', 'target', 'scan_type', 'status',
                         'findings_count', 'critical_count', 'high_count',
                         'duration_seconds', 'created_at', 'created_by__username')
        )

    rows = await sync_to_async(_query)()
    if not rows:
        await update.message.reply_text(
            '📋 <b>Recent Scans</b>\n━━━━━━━━━━━━\n\n<i>No scans found.</i>',
            parse_mode=HTML,
        )
        return

    lines = [f'📋 <b>Recent Scans</b> ({len(rows)} shown)', '━━━━━━━━━━━━━━━━━━━']
    for scan_id, name, target, stype, st, fcount, crit, high, dur, created, creator in rows:
        icon = status_icon(st)
        sid = short_id(scan_id)
        sev_badges = ''
        if crit:
            sev_badges += f' 🔴{crit}'
        if high:
            sev_badges += f' 🟠{high}'
        dur_str = format_duration(dur) if dur else ''
        time_str = time_ago(created)
        lines.append(
            f'\n{icon} <code>{esc(sid)}</code> │ <b>{esc(target)}</b>'
            f'\n   {esc(stype)} │ {fcount} findings{sev_badges}'
            f' │ {dur_str} │ {time_str}'
        )

    lines.append(f'\n💡 <i>Detail: </i><code>/scan &lt;id&gt;</code>')
    await update.message.reply_text('\n'.join(lines), parse_mode=HTML)


async def cmd_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            'Usage: <code>/scan &lt;id&gt;</code>', parse_mode=HTML,
        )
        return

    prefix = context.args[0].strip()

    def _query():
        scan = Scan.objects.filter(id__startswith=prefix).first()
        if not scan:
            return None, [], 0
        reports = list(scan.reports.values_list('format', 'file_size'))
        top_findings = list(
            Finding.objects.filter(scan=scan, severity__in=['critical', 'high'])
            .order_by('severity', '-id')[:5]
            .values_list('severity', 'title', 'host_ip', 'port', 'cve', 'source')
        )
        return scan, reports, top_findings

    scan, reports, top_findings = await sync_to_async(_query)()
    if not scan:
        await update.message.reply_text(f'Scan <code>{esc(prefix)}</code> not found.', parse_mode=HTML)
        return

    sid = short_id(scan.id)
    dur = format_duration(scan.duration_seconds)
    started = scan.started_at.strftime('%Y-%m-%d %H:%M') if scan.started_at else '—'
    finished = scan.completed_at.strftime('%Y-%m-%d %H:%M') if scan.completed_at else '—'
    creator = scan.created_by.username if scan.created_by else '—'

    lines = [
        f'{status_icon(scan.status)} <b>Scan Detail</b> — <code>{esc(sid)}</code>',
        '━━━━━━━━━━━━━━━━━━━━━━',
        '',
        f'<b>📋 General</b>',
        f'  <b>Name:</b> {esc(scan.name)}',
        f'  <b>Target:</b> <code>{esc(scan.target)}</code>',
        f'  <b>Type:</b> {esc(scan.scan_type)} │ <b>Status:</b> {esc(scan.status)}',
        f'  <b>Created by:</b> {esc(creator)}',
        '',
        f'<b>⏱ Timing</b>',
        f'  <b>Started:</b> {esc(started)}',
        f'  <b>Finished:</b> {esc(finished)}',
        f'  <b>Duration:</b> {dur}',
    ]

    if scan.deadline:
        lines.append(f'  <b>Deadline:</b> {scan.deadline.strftime("%Y-%m-%d %H:%M %Z")}')

    lines.extend([
        '',
        f'<b>🎯 Results</b>',
        f'  <b>Hosts:</b> {scan.hosts_count} │ <b>Ports:</b> {scan.ports_count}',
        f'  <b>Findings:</b> {scan.findings_count}',
        f'  🔴 {scan.critical_count}  🟠 {scan.high_count}  🟡 {scan.medium_count}  🔵 {scan.low_count}  ℹ️ {scan.info_count}',
    ])

    if scan.error_message:
        err = scan.error_message[:200]
        lines.extend(['', f'<b>⚠️ Error:</b> {esc(err)}'])

    if top_findings:
        lines.extend(['', '<b>🔍 Top Findings</b>'])
        for sev, title, ip, port, cve, source in top_findings:
            emoji = severity_emoji(sev)
            loc = f'{ip}:{port}' if port else ip or ''
            cve_str = f' [{esc(cve)}]' if cve else ''
            lines.append(f'  {emoji} {esc(title)}{cve_str}')
            lines.append(f'     <code>{esc(loc)}</code> via {esc(source)}')

    if reports:
        report_parts = []
        for fmt, size in reports:
            size_str = f'{size // 1024}KB' if size else ''
            report_parts.append(f'{fmt} {size_str}'.strip())
        lines.extend(['', f'<b>📄 Reports:</b> {esc(", ".join(report_parts))}'])

    has_screenshots = await sync_to_async(lambda: scan.screenshots.exists())()
    kb = scan_detail_kb(sid, scan.status, has_screenshots)
    await update.message.reply_text('\n'.join(lines), reply_markup=kb, parse_mode=HTML)


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
        total = qs.count()
        rows = list(qs[:15].values_list(
            'severity', 'title', 'host_ip', 'port', 'cve', 'source', 'scan__target',
        ))
        return total, rows

    total, rows = await sync_to_async(_query)()
    if not rows:
        await update.message.reply_text(
            f'🔍 <b>Findings</b>\n━━━━━━━━━━━\n\n<i>No findings found.</i>',
            parse_mode=HTML,
        )
        return

    label = f'{severity_filter.title()}' if severity_filter else 'Recent'
    emoji_header = severity_emoji(severity_filter) + ' ' if severity_filter else '🔍 '
    lines = [
        f'{emoji_header}<b>{esc(label)} Findings</b> ({total} total)',
        '━━━━━━━━━━━━━━━━━━━━',
    ]
    shown, remaining = truncate_list(rows, 15)
    for sev, title, ip, port, cve, source, scan_target in shown:
        emoji = severity_emoji(sev)
        loc = f'{ip}:{port}' if port else ip or ''
        cve_str = f' <code>{esc(cve)}</code>' if cve else ''
        lines.append(f'\n  {emoji} <b>{esc(title)}</b>{cve_str}')
        lines.append(f'     <code>{esc(loc)}</code> │ {esc(source)} │ {esc(scan_target or "")}')
    if remaining:
        lines.append(f'\n<i>… and {remaining} more</i>')

    await update.message.reply_text('\n'.join(lines), parse_mode=HTML)


async def cmd_assets(update: Update, context: ContextTypes.DEFAULT_TYPE):
    def _query():
        return list(
            Asset.objects.order_by('-risk_score')[:10]
            .values_list('ip', 'hostname', 'service_name', 'risk_score',
                         'findings_count', 'port', 'last_seen')
        )

    rows = await sync_to_async(_query)()
    if not rows:
        await update.message.reply_text(
            '🏠 <b>Assets</b>\n━━━━━━━\n\n<i>No assets found.</i>',
            parse_mode=HTML,
        )
        return

    lines = [f'🏠 <b>High-Risk Assets</b> (top {len(rows)})', '━━━━━━━━━━━━━━━━━━━━━']
    for ip, hostname, svc, risk, fcount, ports, last_seen in rows:
        host_label = f'{ip}'
        if hostname:
            host_label += f' ({hostname})'
        svc_label = svc or '—'
        risk_bar = progress_bar(min(risk, 100), 100, 5)
        seen_str = time_ago(last_seen) if last_seen else '—'
        lines.append(
            f'\n  ⚠️ <code>{esc(ip)}</code>'
            + (f' <i>{esc(hostname)}</i>' if hostname else '')
        )
        lines.append(
            f'     Risk: {risk_bar} {risk} │ {fcount} findings │ {ports or 0} ports'
            f' │ {esc(svc_label)} │ {seen_str}'
        )

    await update.message.reply_text('\n'.join(lines), parse_mode=HTML)


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = context.user_data.get('wg_user')

    lines = [
        '🛡 <b>Wire_Ghost Bot Commands</b>',
        '━━━━━━━━━━━━━━━━━━━━━━━━━',
        '',
        '<b>📊 Information</b>',
        '  <code>/status</code> — Dashboard &amp; stats',
        '  <code>/scans</code> — Recent scan history',
        '  <code>/scan</code> <i>&lt;id&gt;</i> — Full scan detail',
        '  <code>/findings</code> <i>[severity]</i> — Browse findings',
        '  <code>/assets</code> — Top assets by risk score',
        '',
        '<b>🔗 Account</b>',
        '  <code>/link</code> <i>&lt;code&gt;</i> — Link Telegram account',
        '  <code>/unlink</code> — Unlink account',
        '  <code>/unlock</code> — Unlock account &amp; get login link',
        '  <code>/help</code> — This message',
    ]

    if user:
        has_write = await sync_to_async(user.has_permission)('scan:write')
        if has_write:
            lines.extend([
                '',
                '<b>⚡ Operations</b>',
                '  <code>/newscan</code> <i>&lt;target&gt;</i> [type] — Launch scan',
                '  <code>/cancel</code> <i>&lt;id&gt;</i> — Cancel running scan',
                '  <code>/schedule</code> list|add|del — Manage schedules',
                '  <code>/report</code> <i>&lt;id&gt;</i> — Regenerate reports',
            ])

    if user and user.role == 'owner':
        lines.extend([
            '',
            '<b>👑 Administration</b>',
            '  <code>/users</code> — User accounts &amp; link status',
            '  <code>/config</code> — Site configuration',
            '  <code>/health</code> — System resources',
        ])

    lines.extend([
        '',
        '<i>Scan types: full, quick, port, web, service</i>',
    ])

    await update.message.reply_text('\n'.join(lines), parse_mode=HTML)


# ── Engineer commands ────────────────────────────────────

async def cmd_newscan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            '⚡ <b>Launch New Scan</b>\n'
            '━━━━━━━━━━━━━━━━\n\n'
            'Usage: <code>/newscan &lt;target&gt; [type]</code>\n\n'
            '<b>Examples:</b>\n'
            '  <code>/newscan 192.168.1.0/24</code>\n'
            '  <code>/newscan example.com web</code>\n'
            '  <code>/newscan 10.0.0.0/16 quick</code>\n\n'
            '<b>Types:</b> full │ quick │ port │ web │ service',
            parse_mode=HTML,
        )
        return

    user = context.user_data['wg_user']

    if not check_rate_limit('tg:scanrate:', str(update.effective_user.id), 5, 3600):
        await update.message.reply_text('⏱ Scan rate limit: max 5 per hour.')
        return

    import re
    target = context.args[0].strip()
    scan_type = context.args[1].strip().lower() if len(context.args) > 1 else 'full'

    if scan_type not in ('full', 'quick', 'port', 'web', 'service'):
        await update.message.reply_text('Invalid scan type. Use: full, quick, port, web, service')
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
        f'🚀 <b>Scan Launched</b>\n'
        f'━━━━━━━━━━━━━━\n\n'
        f'  <b>ID:</b> <code>{esc(sid)}</code>\n'
        f'  <b>Target:</b> <code>{esc(target)}</code>\n'
        f'  <b>Type:</b> {esc(scan_type)}\n\n'
        f'Track: <code>/scan {esc(sid)}</code>',
        parse_mode=HTML,
    )


async def cmd_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            'Usage: <code>/cancel &lt;id&gt;</code>', parse_mode=HTML,
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
        await update.message.reply_text(f'❌ {err}')
        return
    await update.message.reply_text(
        f'⏹ Scan <code>{esc(short_id(scan.id))}</code> │ <code>{esc(scan.target)}</code> — cancelled.',
        parse_mode=HTML,
    )


async def cmd_schedule(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            '📅 <b>Schedule Management</b>\n'
            '━━━━━━━━━━━━━━━━━━━━\n\n'
            '<code>/schedule list</code> — View active schedules\n'
            '<code>/schedule add &lt;target&gt; &lt;freq&gt; &lt;HH:MM&gt;</code>\n'
            '<code>/schedule del &lt;id&gt;</code>\n\n'
            '<b>Frequencies:</b> daily │ weekly │ biweekly │ monthly',
            parse_mode=HTML,
        )
        return

    sub = context.args[0].lower()
    user = context.user_data['wg_user']

    if sub == 'list':
        def _list():
            return list(
                ScheduledScan.objects.filter(enabled=True)
                .order_by('next_run')[:10]
                .values_list('id', 'name', 'target', 'frequency', 'time',
                             'stop_time', 'next_run', 'last_run', 'scan_type')
            )
        rows = await sync_to_async(_list)()
        if not rows:
            await update.message.reply_text(
                '📅 <b>Scheduled Scans</b>\n━━━━━━━━━━━━━━━\n\n<i>No active schedules.</i>',
                parse_mode=HTML,
            )
            return
        lines = [f'📅 <b>Scheduled Scans</b> ({len(rows)} active)', '━━━━━━━━━━━━━━━━━━━━━']
        for sid, name, target, freq, t, stop, nxt, last, stype in rows:
            nxt_str = nxt.strftime('%Y-%m-%d %H:%M') if nxt else '—'
            last_str = time_ago(last) if last else 'never'
            time_str = t.strftime('%H:%M')
            stop_str = f' → {stop.strftime("%H:%M")}' if stop else ''
            lines.append(
                f'\n  <code>{esc(short_id(sid))}</code> <b>{esc(target)}</b>'
                f'\n     {esc(freq)} at {time_str}{stop_str} │ {esc(stype)}'
                f'\n     Next: {esc(nxt_str)} │ Last: {last_str}'
            )
        await update.message.reply_text('\n'.join(lines), parse_mode=HTML)

    elif sub == 'add':
        if len(context.args) < 4:
            await update.message.reply_text(
                'Usage: <code>/schedule add &lt;target&gt; &lt;daily|weekly|biweekly|monthly&gt; &lt;HH:MM&gt;</code>',
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
            f'✅ <b>Schedule Created</b>\n'
            f'━━━━━━━━━━━━━━━━\n\n'
            f'  <b>Target:</b> <code>{esc(target)}</code>\n'
            f'  <b>Frequency:</b> {esc(freq)}\n'
            f'  <b>Run at:</b> {esc(time_str)}\n'
            f'  <b>ID:</b> <code>{esc(short_id(sched.id))}</code>',
            parse_mode=HTML,
        )

    elif sub == 'del':
        if len(context.args) < 2:
            await update.message.reply_text(
                'Usage: <code>/schedule del &lt;id&gt;</code>', parse_mode=HTML,
            )
            return
        prefix = context.args[1]

        def _delete():
            qs = ScheduledScan.objects.filter(id__startswith=prefix)
            sched = qs.first()
            if not sched:
                return None, 'Schedule not found.'
            if sched.created_by != user and user.role != 'owner':
                return None, 'Only the creator or Owner can delete.'
            target = sched.target
            sched.delete()
            return target, None

        target, err = await sync_to_async(_delete)()
        if err:
            await update.message.reply_text(f'❌ {err}')
        else:
            await update.message.reply_text(
                f'🗑 Schedule for <code>{esc(target)}</code> deleted.',
                parse_mode=HTML,
            )

    else:
        await update.message.reply_text(
            'Usage: <code>/schedule</code> list │ add │ del', parse_mode=HTML,
        )


async def cmd_report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            'Usage: <code>/report &lt;scan_id&gt;</code>', parse_mode=HTML,
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
        f'📄 Generating reports for <code>{esc(sid)}</code> │ <code>{esc(scan.target)}</code>\n'
        f'<i>I\'ll send the file when ready.</i>',
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
            result.append((u.username, u.role, linked, u.last_login))
        return result

    rows = await sync_to_async(_query)()
    role_icons = {'owner': '👑', 'engineer': '🔧', 'viewer': '👁'}
    lines = [f'👥 <b>Users</b> ({len(rows)})', '━━━━━━━━━━']
    for uname, role, linked, last_login in rows:
        icon = role_icons.get(role, '❓')
        link_str = '🔗' if linked else '—'
        login_str = time_ago(last_login) if last_login else 'never'
        lines.append(
            f'\n  {icon} <b>{esc(uname)}</b> │ {esc(role)}'
            f'\n     Telegram: {link_str} │ Last login: {login_str}'
        )

    try:
        await context.bot.send_message(
            chat_id=update.effective_user.id,
            text='\n'.join(lines),
            parse_mode=HTML,
        )
        if update.effective_chat.type in ('group', 'supergroup'):
            await update.message.reply_text('<i>User list sent via DM.</i>', parse_mode=HTML)
    except Exception:
        await update.message.reply_text('Could not send DM. Please start a private chat with me first, then retry.')


async def cmd_config(update: Update, context: ContextTypes.DEFAULT_TYPE):
    def _query():
        cfg = SiteConfig.get()
        sched_count = ScheduledScan.objects.filter(enabled=True).count()
        return {
            'timezone': cfg.schedule_timezone or 'UTC',
            'parallelism': cfg.default_parallelism,
            'timeout': cfg.default_timeout,
            'report_formats': cfg.default_report_formats,
            'bot_configured': bool(cfg.telegram_bot_token),
            'shared_chat': bool(cfg.telegram_shared_chat_id),
            'sched_count': sched_count,
        }

    data = await sync_to_async(_query)()
    lines = [
        '⚙️ <b>Site Configuration</b>',
        '━━━━━━━━━━━━━━━━━━━',
        '',
        '<b>🔧 Scan Defaults</b>',
        f'  <b>Parallelism:</b> {data["parallelism"]} threads',
        f'  <b>Timeout:</b> {data["timeout"]}s per tool',
        f'  <b>Report formats:</b> {esc(data["report_formats"])}',
        '',
        '<b>🌐 System</b>',
        f'  <b>Timezone:</b> {esc(data["timezone"])}',
        f'  <b>Active schedules:</b> {data["sched_count"]}',
        '',
        '<b>📱 Telegram</b>',
        f'  <b>Bot token:</b> {"✅ configured" if data["bot_configured"] else "❌ not configured"}',
        f'  <b>Shared chat:</b> {"✅ set" if data["shared_chat"] else "❌ not set"}',
    ]

    try:
        await context.bot.send_message(
            chat_id=update.effective_user.id,
            text='\n'.join(lines),
            parse_mode=HTML,
        )
        if update.effective_chat.type in ('group', 'supergroup'):
            await update.message.reply_text('<i>Config sent via DM.</i>', parse_mode=HTML)
    except Exception:
        await update.message.reply_text('Could not send DM. Please start a private chat with me first, then retry.')


async def cmd_health(update: Update, context: ContextTypes.DEFAULT_TYPE):
    def _query():
        import psutil
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        boot = psutil.boot_time()
        from datetime import datetime
        uptime_secs = int((datetime.now() - datetime.fromtimestamp(boot)).total_seconds())
        return {
            'cpu': cpu,
            'ram_used': mem.used / (1024**3),
            'ram_total': mem.total / (1024**3),
            'ram_pct': mem.percent,
            'disk_used': disk.used / (1024**3),
            'disk_total': disk.total / (1024**3),
            'disk_pct': disk.percent,
            'uptime': uptime_secs,
        }

    s = await sync_to_async(_query)()
    cpu_bar = progress_bar(int(s['cpu']), 100, 10)
    ram_bar = progress_bar(int(s['ram_pct']), 100, 10)
    disk_bar = progress_bar(int(s['disk_pct']), 100, 10)

    lines = [
        '💻 <b>System Health</b>',
        '━━━━━━━━━━━━━━━',
        '',
        f'<b>CPU</b>  {cpu_bar} {s["cpu"]}%',
        f'<b>RAM</b>  {ram_bar} {s["ram_used"]:.1f}/{s["ram_total"]:.1f} GB ({s["ram_pct"]}%)',
        f'<b>Disk</b> {disk_bar} {s["disk_used"]:.0f}/{s["disk_total"]:.0f} GB ({s["disk_pct"]}%)',
        f'<b>Uptime:</b> {format_duration(s["uptime"])}',
    ]
    await update.message.reply_text('\n'.join(lines), parse_mode=HTML)
