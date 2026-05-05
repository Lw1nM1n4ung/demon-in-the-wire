"""Celery tasks — bridge between Django ORM and wireghost scan pipeline."""
import json
import logging
import asyncio
from datetime import timedelta
from pathlib import Path

from celery import shared_task
from django.utils import timezone

from scanner.policy_tools import normalize_policy_tools

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=0, time_limit=7200, soft_time_limit=7000)
def run_scan(self, scan_id):
    """Execute the full scan pipeline and persist results to DB."""
    from scanner.models import Scan, Host, Port, Finding, Technology, Report

    scan = Scan.objects.get(id=scan_id)
    scan.status = 'running'
    scan.started_at = timezone.now()
    scan.celery_task_id = self.request.id
    scan.save()

    try:
        # Import pipeline components
        from wireghost.pipeline.orchestrator import run_pipeline
        from wireghost.config import ScanConfig

        # Build config from scan record
        output_dir = Path(
            f"{scan.output_dir or '/data/output'}/{scan.target.replace('/', '_')}"
        )
        output_dir.mkdir(parents=True, exist_ok=True)
        scan.output_dir = str(output_dir)
        scan.save(update_fields=['output_dir'])

        config = ScanConfig.load(
            target=scan.target,
            parallelism=scan.parallelism,
            tool_timeout=scan.timeout,
            report_formats=scan.report_formats.split(','),
            version_detect=scan.version_detect,
            os_detect=scan.os_detect,
            service_enum=scan.service_enum,
            skip_nuclei=scan.skip_nuclei,
            skip_screenshots=scan.skip_screenshots,
            nuclei_templates=scan.nuclei_templates,
            nuclei_default_templates=scan.nuclei_default_templates,
            scan_unresponsive=scan.scan_unresponsive,
            skip_enum4linux=not scan.enum4linux,
            skip_nikto=scan.skip_nikto,
            skip_netexec=scan.skip_netexec,
            output_dir=str(output_dir),
        )

        # Run the async pipeline
        report = asyncio.run(run_pipeline(config))

        # ── Persist results to ORM ──
        _persist_results(scan, report)

        # ── Match MSF exploits ──
        try:
            from scanner.msf_matcher import match_exploits
            from scanner.models import ExploitMatch, Port, Host as HostModel
            ports_qs = Port.objects.filter(host__scan=scan).values(
                'id', 'number', 'service_name', 'service_product',
                'service_version', 'host__ip',
            )
            ports_for_match = [
                {'number': p['number'], 'service_name': p['service_name'],
                 'service_product': p['service_product'],
                 'service_version': p['service_version'],
                 'host_ip': p['host__ip'], '_port_id': p['id']}
                for p in ports_qs
            ]
            findings_qs = scan.findings.values('id', 'cve', 'host_ip', 'port', 'host_id')
            findings_for_match = [
                {'cve': f['cve'], 'host_ip': f['host_ip'], 'port': f['port'],
                 '_finding_id': f['id'], '_host_id': f['host_id']}
                for f in findings_qs
            ]
            matches = match_exploits(ports_for_match, findings_for_match)
            if matches:
                ip_to_host = dict(HostModel.objects.filter(scan=scan).values_list('ip', 'id'))
                ip_to_ports = {}
                for p in ports_qs:
                    ip_to_ports.setdefault(p['host__ip'], {})[p['number']] = p['id']
                objs = []
                for m in matches:
                    hip = m.get('host_ip', '')
                    host_id = ip_to_host.get(hip)
                    if not host_id:
                        continue
                    port_id = None
                    pn = m.get('port_number')
                    if pn and hip in ip_to_ports:
                        port_id = ip_to_ports[hip].get(pn)
                    objs.append(ExploitMatch(
                        scan=scan, host_id=host_id, port_id=port_id,
                        module_fullname=m['module_fullname'],
                        module_name=m['module_name'],
                        module_type=m['module_type'],
                        module_rank=m.get('module_rank', 0),
                        module_rank_name=m.get('module_rank_name', ''),
                        disclosure_date=m.get('disclosure_date', ''),
                        description=m.get('description', ''),
                        references=m.get('references', []),
                        platform=m.get('platform', ''),
                        confidence=m['confidence'],
                        match_reason=m['match_reason'],
                        host_ip=hip or None,
                        port_number=pn,
                    ))
                if objs:
                    ExploitMatch.objects.bulk_create(objs)
                    logger.info('Scan %s: %d MSF exploit matches stored', scan_id, len(objs))
        except Exception:
            logger.exception('MSF exploit matching failed for scan %s', scan_id)

        # ── Generate reports ──
        from wireghost.reports.engine import ReportEngine
        engine = ReportEngine(config, output_dir)
        report_paths = engine.generate(report)

        for path in report_paths:
            fmt = path.suffix.lstrip('.')
            if fmt == 'html' and 'dashboard' in path.stem:
                fmt = 'dashboard'
            Report.objects.create(
                scan=scan,
                format=fmt,
                file_path=str(path),
                file_size=path.stat().st_size if path.exists() else 0,
            )

        # ── Finalize ──
        scan.status = 'completed'
        scan.completed_at = timezone.now()
        scan.duration_seconds = int(
            (scan.completed_at - scan.started_at).total_seconds()
        )
        scan.save()

        logger.info(f"Scan {scan_id} completed: {scan.findings_count} findings")

        # Notifications — fire-and-forget; any dispatch error is swallowed
        # inside notify() so the scan result is never held up.
        try:
            from scanner.notifications import notify
            notify('scan.complete', scan=scan)
            if scan.critical_count:
                notify('critical.discovered', scan=scan,
                       extra={'count': scan.critical_count})
        except Exception:
            logger.exception('notification dispatch failed for scan %s', scan_id)

        return {'scan_id': scan_id, 'status': 'completed', 'findings': scan.findings_count}

    except Exception as e:
        logger.exception(f"Scan {scan_id} failed: {e}")
        scan.status = 'failed'
        scan.error_message = str(e)[:2000]
        scan.completed_at = timezone.now()
        if scan.started_at:
            scan.duration_seconds = int(
                (scan.completed_at - scan.started_at).total_seconds()
            )
        scan.save()

        try:
            from scanner.notifications import notify
            notify('scan.failed', scan=scan)
        except Exception:
            logger.exception('notification dispatch failed for scan %s', scan_id)

        return {'scan_id': scan_id, 'status': 'failed', 'error': str(e)[:500]}


def _persist_results(scan, report):
    """Write ScanReport data into Django ORM tables."""
    from scanner.models import Host as DBHost, Port as DBPort, Finding as DBFinding, Technology as DBTech, Screenshot as DBScreenshot

    host_map = {}  # pipeline_ip -> db_host

    # Hosts + Ports + Technologies
    for h in report.hosts:
        db_host = DBHost.objects.create(
            scan=scan,
            ip=h.ip,
            hostname=h.hostname or '',
            os=h.os or '',
            status=h.status or 'up',
            ports_count=len(h.open_ports),
            findings_count=0,  # updated below
        )
        host_map[h.ip] = db_host

        for p in h.ports:
            DBPort.objects.create(
                host=db_host,
                number=p.number,
                protocol=p.protocol,
                state=p.state,
                service_name=p.service.name if p.service else '',
                service_product=p.service.product if p.service else '',
                service_version=p.service.version if p.service else '',
            )

        for t in h.technologies:
            DBTech.objects.create(
                host=db_host,
                name=t.name,
                version=t.version or '',
                url=t.url or '',
            )

        for sc in getattr(h, 'screenshots', []):
            DBScreenshot.objects.create(
                host=db_host,
                scan=scan,
                url=sc.url,
                filename=sc.filename,
                title=sc.title or '',
                status_code=sc.status_code,
            )

    # Findings
    sev_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for f in report.findings:
        sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity).lower()
        db_host = host_map.get(f.host)

        DBFinding.objects.create(
            scan=scan,
            host=db_host,
            source=f.source,
            severity=sev,
            title=f.title,
            description=f.description or '',
            host_ip=f.host,
            port=str(f.port) if f.port else '',
            protocol=f.protocol or 'tcp',
            endpoint=f.endpoint or '',
            full_url=f.full_url or '',
            template_id=f.template_id or '',
            cve=f.cve or '',
            cwe=f.cwe or '',
            cvss=str(f.cvss) if f.cvss else '',
            request=f.request or '',
            response=f.response or '',
            curl_command=f.curl_command or '',
            raw_output=f.raw_output or '',
            references=json.dumps(f.references) if f.references else '[]',
        )

        if sev in sev_counts:
            sev_counts[sev] += 1
        if db_host:
            db_host.findings_count += 1
            db_host.save(update_fields=['findings_count'])

    # Update scan counters
    scan.hosts_count = len(report.hosts)
    scan.ports_count = sum(len(h.open_ports) for h in report.hosts)
    scan.findings_count = len(report.findings)
    scan.critical_count = sev_counts['critical']
    scan.high_count = sev_counts['high']
    scan.medium_count = sev_counts['medium']
    scan.low_count = sev_counts['low']
    scan.info_count = sev_counts['info']
    scan.save()

    # Refresh the deduped Asset inventory used by the ASM dashboard.
    _sync_assets(scan, report)


def _sev_str(sev):
    """Normalize a severity to its lowercase string form.

    Pipeline findings carry `Severity` enum values; DB-reconstructed findings
    carry plain strings. This helper lets comparisons work for both.
    """
    if hasattr(sev, 'value'):
        return str(sev.value).lower()
    return str(sev).lower()


def _compute_risk(critical, high, total):
    """0..100 asset risk score. Critical dominates; everything else contributes lightly."""
    other = max(0, total - critical - high)
    return min(100, critical * 30 + high * 10 + other * 2)


def _sync_assets(scan, report):
    """Upsert an Asset row for each (ip, port, protocol) seen in this scan.

    Preserves first_seen on existing rows, advances last_seen to now, recomputes
    findings counts and risk score from the current scan's findings.
    """
    from scanner.models import Asset

    now = timezone.now()
    for host in report.hosts:
        for port in host.open_ports:
            key = {
                'ip': host.ip,
                'port': port.number,
                'protocol': port.protocol or 'tcp',
            }
            # Findings pinned to this (ip, port) in this scan's report.
            host_findings = [
                f for f in report.findings
                if f.host == host.ip and str(f.port) == str(port.number)
            ]
            # Tolerate both Severity enum and plain string payloads.
            critical = sum(1 for f in host_findings if _sev_str(f.severity) == 'critical')
            high = sum(1 for f in host_findings if _sev_str(f.severity) == 'high')
            total = len(host_findings)

            svc = port.service
            defaults = {
                'first_seen': now, 'last_seen': now,
                'hostname': host.hostname or '', 'os': host.os or '',
                'service_name': (svc.name if svc else '') or '',
                'service_product': (svc.product if svc else '') or '',
                'service_version': (svc.version if svc else '') or '',
                'status': port.state if port.state in {'open', 'closed', 'filtered'} else 'open',
                'last_scan': scan,
                'findings_count': total,
                'critical_count': critical,
                'high_count': high,
                'risk_score': _compute_risk(critical, high, total),
            }
            asset, created = Asset.objects.get_or_create(**key, defaults=defaults)
            if not created:
                asset.last_seen = now
                asset.last_scan = scan
                asset.hostname = host.hostname or asset.hostname
                asset.os = host.os or asset.os
                if svc:
                    asset.service_name = svc.name or asset.service_name
                    asset.service_product = svc.product or asset.service_product
                    asset.service_version = svc.version or asset.service_version
                asset.status = port.state if port.state in {'open', 'closed', 'filtered'} else 'open'
                asset.findings_count = total
                asset.critical_count = critical
                asset.high_count = high
                asset.risk_score = _compute_risk(critical, high, total)
                asset.save()


@shared_task(bind=True, max_retries=1)
def generate_report(self, scan_id, formats=None):
    """Re-generate reports for an existing scan (used for report customization)."""
    from scanner.models import Scan, Report
    from wireghost.reports.engine import ReportEngine
    from wireghost.config import ScanConfig
    from wireghost.models.scan import Host as PHost, Port as PPort, Service as PService, WebTech as PWebTech
    from wireghost.models.finding import Finding as PFinding
    from wireghost.models.report import ScanReport

    scan = Scan.objects.get(id=scan_id)
    if not scan.output_dir:
        raise ValueError("Scan has no output directory")

    output_dir = Path(scan.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    reports_dir = output_dir / 'reports'
    reports_dir.mkdir(exist_ok=True)

    # Reconstruct ScanReport from DB
    hosts = []
    for db_host in scan.hosts.prefetch_related('ports', 'technologies').all():
        ports = [
            PPort(
                number=p.number, protocol=p.protocol, state=p.state,
                service=PService(name=p.service_name, product=p.service_product, version=p.service_version)
            )
            for p in db_host.ports.all()
        ]
        techs = [PWebTech(name=t.name, version=t.version, url=t.url) for t in db_host.technologies.all()]
        hosts.append(PHost(
            ip=db_host.ip, hostname=db_host.hostname, status=db_host.status,
            ports=ports, web_endpoints=[], web_titles={}, technologies=techs, os=db_host.os,
        ))

    findings = []
    for db_f in scan.findings.all():
        findings.append(PFinding(
            source=db_f.source, host=db_f.host_ip or '', port=db_f.port or '',
            protocol=db_f.protocol, severity=db_f.severity, title=db_f.title,
            description=db_f.description, endpoint=db_f.endpoint, full_url=db_f.full_url,
            template_id=db_f.template_id, cve=db_f.cve, cwe=db_f.cwe,
            cvss=db_f.cvss, request=db_f.request, response=db_f.response,
            curl_command=db_f.curl_command, raw_output=db_f.raw_output,
            references=json.loads(db_f.references) if db_f.references else [],
        ))

    report = ScanReport(
        target=scan.target, hosts=hosts, findings=findings,
        scan_start=scan.started_at, scan_end=scan.completed_at,
    )

    fmt_list = formats or scan.report_formats.split(',')
    config = ScanConfig.load(target=scan.target, report_formats=fmt_list, output_dir=str(output_dir))

    # Apply report branding from ReportConfig if it exists
    try:
        from scanner.models import ReportConfig
        rc = ReportConfig.objects.first()
        if rc:
            if rc.report_title:
                config.report_title = rc.report_title
            if rc.prepared_by:
                config.prepared_by = rc.prepared_by
            if rc.reviewed_by:
                config.reviewed_by = rc.reviewed_by
            if rc.approved_by:
                config.approved_by = rc.approved_by
            if rc.logo_path:
                config.logo_path = Path(rc.logo_path)
            if rc.brand_color:
                config.brand_color = rc.brand_color
    except Exception:
        pass

    # Delete old reports for this scan
    Report.objects.filter(scan=scan).delete()

    engine = ReportEngine(config, output_dir)
    report_paths = engine.generate(report)

    for path in report_paths:
        fmt = path.suffix.lstrip('.')
        if fmt == 'html' and 'dashboard' in path.stem:
            fmt = 'dashboard'
        Report.objects.create(
            scan=scan, format=fmt, file_path=str(path),
            file_size=path.stat().st_size if path.exists() else 0,
        )

    try:
        from scanner.notifications import notify
        notify('report.ready', scan=scan)
    except Exception:
        logger.exception('notification dispatch failed for report %s', scan_id)

    return {'scan_id': scan_id, 'reports': len(report_paths)}


@shared_task
def check_scheduled_scans():
    """Runs every 60s via Celery Beat. Launches scans that are due."""
    from scanner.models import ScheduledScan, Scan
    from datetime import timedelta, datetime, time as dtime

    now = timezone.now()
    due = ScheduledScan.objects.filter(enabled=True, next_run__lte=now)

    launched = 0
    for sched in due:
        # Apply policy settings if linked
        policy = sched.policy
        policy_tools = normalize_policy_tools(policy.tools if policy else {})
        scan = Scan.objects.create(
            name=f"{sched.name} (scheduled)",
            target=sched.target,
            scan_type=policy.scan_type if policy else sched.scan_type,
            parallelism=policy.parallelism if policy else 10,
            timeout=policy.timeout if policy else 3600,
            report_formats=policy.report_formats if policy else 'dashboard,docx,xlsx',
            version_detect=policy.version_detect if policy else True,
            os_detect=policy.os_detect if policy else True,
            service_enum=policy_tools.get('service_enum', True),
            skip_nuclei=not policy_tools.get('nuclei', True),
            skip_screenshots=policy.skip_screenshots if policy else False,
            nuclei_templates=policy_tools.get('nuclei_templates', ''),
            nuclei_default_templates=policy_tools.get('nuclei_default_templates', True),
            enum4linux=policy_tools.get('enum4linux', True),
            skip_nikto=not policy_tools.get('nikto', True),
            skip_netexec=not policy_tools.get('netexec', True),
            status='pending',
            created_by=sched.created_by,
        )

        deadline = _compute_deadline(sched.stop_time) if sched.stop_time else None
        task = run_scan.delay(str(scan.id))
        scan.celery_task_id = task.id
        scan.status = 'running'
        scan.deadline = deadline
        scan.save(update_fields=['celery_task_id', 'status', 'deadline'])

        # Update schedule timestamps
        sched.last_run = now
        sched.next_run = _calc_next_run(sched.frequency, sched.time)
        sched.save(update_fields=['last_run', 'next_run'])
        launched += 1

    if launched:
        logger.info(f"Scheduled scan checker: launched {launched} scan(s)")
    return {'launched': launched}


def _calc_next_run(frequency, run_time):
    """Calculate the next run datetime from frequency and time-of-day.

    The time-of-day is interpreted in ``SiteConfig.schedule_timezone`` (the
    Owner-configured zone). The returned datetime is UTC-aware so Django
    can store it against ``ScheduledScan.next_run``.
    """
    from datetime import timedelta, timezone as dt_timezone
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
    from scanner.models import SiteConfig

    tz_name = (SiteConfig.get().schedule_timezone or 'UTC')
    try:
        tz = ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError):
        tz = ZoneInfo('UTC')

    now_local = timezone.now().astimezone(tz)
    # Build today's run datetime in the configured zone
    next_dt = now_local.replace(hour=run_time.hour, minute=run_time.minute, second=0, microsecond=0)

    # Always advance past now
    if next_dt <= now_local:
        if frequency == 'daily':
            next_dt += timedelta(days=1)
        elif frequency == 'weekly':
            next_dt += timedelta(weeks=1)
        elif frequency == 'biweekly':
            next_dt += timedelta(weeks=2)
        elif frequency == 'monthly':
            month = next_dt.month % 12 + 1
            year = next_dt.year + (1 if next_dt.month == 12 else 0)
            next_dt = next_dt.replace(year=year, month=month)
    # Store as UTC so Django's timezone-aware filters compare correctly.
    return next_dt.astimezone(dt_timezone.utc)


def _compute_deadline(stop_time):
    """Convert a local stop_time (TimeField) into a UTC-aware deadline datetime.

    If stop_time is already past, the deadline rolls to the next day — handles
    overnight windows like start=22:00 / stop=06:00.
    """
    from datetime import timezone as dt_timezone
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
    from scanner.models import SiteConfig

    if not stop_time:
        return None

    tz_name = (SiteConfig.get().schedule_timezone or 'UTC')
    try:
        tz = ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError):
        tz = ZoneInfo('UTC')

    now_local = timezone.now().astimezone(tz)
    stop_dt = now_local.replace(hour=stop_time.hour, minute=stop_time.minute, second=0, microsecond=0)
    if stop_dt <= now_local:
        stop_dt += timedelta(days=1)
    return stop_dt.astimezone(dt_timezone.utc)


@shared_task
def enforce_scan_deadlines():
    """Cancel running scans that have passed their deadline. Runs every 60s via Beat."""
    from scanner.models import Scan

    now = timezone.now()
    overdue = Scan.objects.filter(status='running', deadline__isnull=False, deadline__lte=now)
    cancelled = 0
    for scan in overdue:
        if scan.celery_task_id:
            from wireghost_web.celery import app as celery_app
            celery_app.control.revoke(scan.celery_task_id, terminate=True)
        scan.status = 'cancelled'
        scan.error_message = f'Auto-cancelled: exceeded stop time ({scan.deadline.strftime("%H:%M %Z")})'
        scan.completed_at = now
        if scan.started_at:
            scan.duration_seconds = int((now - scan.started_at).total_seconds())
        scan.save(update_fields=['status', 'error_message', 'completed_at', 'duration_seconds'])
        cancelled += 1
        logger.info('Scan %s auto-cancelled (deadline %s)', scan.id, scan.deadline)
    return {'cancelled': cancelled}


@shared_task(bind=True, max_retries=2, soft_time_limit=30)
def send_mfa_otp(self, chat_id, otp_code, username):
    from scanner.models import SiteConfig
    from scanner.notifications import send_telegram
    cfg = SiteConfig.get()
    if not cfg.telegram_bot_token:
        logger.error('MFA OTP: no bot token configured')
        return
    text = (
        f'<b>Wire_Ghost — Login Verification</b>\n\n'
        f'Your code: <code>{otp_code}</code>\n\n'
        f'Expires in 5 minutes.\n'
        f'If you did not request this, ignore this message.'
    )
    result = send_telegram(chat_id, text, bot_token=cfg.telegram_bot_token)
    if not result.get('ok'):
        logger.warning('MFA OTP delivery failed for %s: %s', username, result.get('error'))


@shared_task
def check_for_updates():
    """Runs every 6h via Celery Beat. Checks GitHub for new releases."""
    from scanner.update_check import check_latest_release
    from django.core.cache import cache as _cache

    result = check_latest_release(force=True)
    if result.get('update_available') and result.get('latest'):
        notified_key = 'wg:update:last_notified_ver'
        if _cache.get(notified_key) != result['latest']:
            try:
                from scanner.notifications import notify
                notify('update.available', extra={
                    'current': result['current'],
                    'latest': result['latest'],
                    'url': result.get('latest_url', ''),
                })
            except Exception:
                logger.exception('update notification dispatch failed')
            _cache.set(notified_key, result['latest'], 30 * 24 * 3600)


@shared_task(bind=True, soft_time_limit=900, time_limit=960)
def update_security_feeds(self):
    """Update nuclei templates and searchsploit DB on worker."""
    from scanner.update_check import run_feed_update
    return run_feed_update()
