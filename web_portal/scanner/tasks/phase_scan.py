"""Celery task for phase-based scan workflow.

Executes a SINGLE pipeline phase per invocation — the scan stops after each
phase so the user can review results, skip phases, or retry failures before
proceeding.  Reuses the daemon-thread + Queue pattern from ``run_scan``.
"""

import logging
import asyncio
import threading
from pathlib import Path
from queue import Queue, Empty

from asgiref.sync import sync_to_async
from celery import shared_task
from django.utils import timezone

logger = logging.getLogger(__name__)


class _TaskCancelled(Exception):
    """Raised when the Celery task is cancelled by user request."""


@shared_task(bind=True, max_retries=0, time_limit=604800, soft_time_limit=518400)
def run_phase(self, scan_id, phase_name):
    """Execute a SINGLE pipeline phase. Sets scan to 'paused' when done.

    The task:
    1. Loads scan + PhaseRun, sets both to "running"
    2. Builds ScanConfig + OutputTree (same pattern as run_scan)
    3. Spawns daemon thread for DB writes (same Queue pattern)
    4. Calls asyncio.run(_execute_phase(phase_name, scan, config, tree, callbacks))
    5. On completion: marks PhaseRun completed, sets scan to paused (or completed if last)
    6. On exception: marks PhaseRun failed, sets scan to paused
    """
    from scanner.models import Scan, PhaseRun

    scan = Scan.objects.get(id=scan_id)
    phase_run = PhaseRun.objects.get(scan=scan, phase=phase_name)

    scan.status = "running"
    scan.current_phase = phase_name
    scan.save(update_fields=["status", "current_phase"])

    phase_run.status = "running"
    phase_run.started_at = timezone.now()
    phase_run.celery_task_id = self.request.id or ""
    phase_run.save(update_fields=["status", "started_at", "celery_task_id"])

    try:
        from wireghost.config import ScanConfig
        from wireghost.utils.fs import build_output_tree

        base_output = Path(scan.output_dir or "/data/output")
        target_normalized = scan.target.replace("/", "_")
        if len(target_normalized) > 200:
            import hashlib

            tag = hashlib.sha256(target_normalized.encode()).hexdigest()[:8]
            target_normalized = target_normalized[:200] + "_" + tag
        output_dir = base_output / target_normalized
        output_dir.mkdir(parents=True, exist_ok=True)
        scan.output_dir = str(output_dir)
        scan.save(update_fields=["output_dir"])

        config = ScanConfig.load(
            target=scan.target,
            parallelism=scan.parallelism,
            tool_timeout=scan.timeout,
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
            report_formats=scan.report_formats.split(","),
            output_dir=str(base_output),
        )

        tree = build_output_tree(str(base_output), target_normalized)

        # ── Daemon thread for DB writes ──
        _scan_id_hex = str(scan_id).replace("-", "")
        _progress_queue: Queue = Queue()
        _progress_stop = threading.Event()

        def _progress_thread():
            from django.db import connection as _conn
            from django.db.models import F as _F
            from scanner.models import (
                Host as _DBHost,
                Port as _DBPort,
                Finding as _DBFinding,
                Technology as _DBTech,
                Screenshot as _DBScreenshot,
                Scan as _Scan,
                ScanArtifact,
            )

            while not _progress_stop.is_set():
                try:
                    item = _progress_queue.get(timeout=0.5)
                except Empty:
                    continue
                if item is None:
                    break
                try:
                    action = item[0]
                    if action == "progress":
                        _, phase, done, total = item
                        with _conn.cursor() as cursor:
                            cursor.execute(
                                "UPDATE scanner_scan SET current_phase=%s, "
                                "hosts_scanned=%s "
                                "WHERE id=%s",
                                [phase, done, _scan_id_hex],
                            )
                    elif action == "discovery":
                        _, live_ips, mac_vendor_map, dns_hostnames = item
                        for ip in live_ips:
                            mac, vendor = mac_vendor_map.get(ip, ("", ""))
                            defaults = {
                                "mac_address": mac or "",
                                "vendor": vendor or "",
                                "status": "up",
                                "ports_count": 0,
                            }
                            dns_name = dns_hostnames.get(ip, "")
                            if dns_name:
                                host_obj = _DBHost.objects.filter(
                                    scan_id=scan_id, ip=ip
                                ).first()
                                if host_obj and not host_obj.hostname:
                                    defaults["hostname"] = dns_name
                            _DBHost.objects.get_or_create(
                                scan_id=scan_id, ip=ip, defaults=defaults,
                            )
                        _Scan.objects.filter(id=scan_id).update(
                            hosts_count=len(live_ips),
                            hosts_total=len(live_ips),
                        )
                    elif action == "subnet_hosts":
                        _, new_ips, mac_updates = item
                        for ip in new_ips:
                            mac, vendor = mac_updates.get(ip, ("", ""))
                            _DBHost.objects.get_or_create(
                                scan_id=scan_id,
                                ip=ip,
                                defaults={
                                    "mac_address": mac or "",
                                    "vendor": vendor or "",
                                    "status": "up",
                                    "ports_count": 0,
                                },
                            )
                        if mac_updates:
                            for ip, (mac, vendor) in mac_updates.items():
                                _DBHost.objects.filter(
                                    scan_id=scan_id, ip=ip
                                ).update(mac_address=mac or "", vendor=vendor or "")
                        if new_ips:
                            _Scan.objects.filter(id=scan_id).update(
                                hosts_count=_F("hosts_count") + len(new_ips),
                            )
                    elif action == "host_phase":
                        _, ip, phase = item
                        _DBHost.objects.filter(scan_id=scan_id, ip=ip).update(
                            current_phase=phase,
                        )
                    elif action == "artifact":
                        _, host_ip, tool, name, content, content_type = item
                        db_host = _DBHost.objects.filter(
                            scan_id=scan_id, ip=host_ip
                        ).first()
                        ScanArtifact.objects.create(
                            scan_id=scan_id,
                            host=db_host,
                            tool=tool,
                            name=name,
                            content=content,
                            content_type=content_type,
                            size=len(content),
                        )
                    elif action == "host_result":
                        _, host, findings = item
                        db_host, _ = _DBHost.objects.update_or_create(
                            scan_id=scan_id,
                            ip=host.ip,
                            defaults={
                                "hostname": host.hostname or "",
                                "os": host.os or "",
                                "status": host.status or "up",
                                "mac_address": getattr(host, "mac_address", "") or "",
                                "vendor": getattr(host, "vendor", "") or "",
                                "ports_count": len(host.open_ports),
                                "web_endpoints": list(getattr(host, "web_endpoints", []) or []),
                                "web_titles": dict(getattr(host, "web_titles", {}) or {}),
                            },
                        )
                        _DBPort.objects.filter(host=db_host).delete()
                        _DBTech.objects.filter(host=db_host).delete()
                        _DBScreenshot.objects.filter(host=db_host, scan_id=scan_id).delete()
                        for p in host.ports:
                            svc = p.service
                            _DBPort.objects.create(
                                host=db_host,
                                number=p.number,
                                protocol=p.protocol,
                                state=p.state,
                                service_name=svc.name if svc else "",
                                service_product=svc.product if svc else "",
                                service_version=svc.version if svc else "",
                                service_source=getattr(p, "service_source", "") or "",
                            )
                        for t in host.technologies:
                            _DBTech.objects.create(
                                host=db_host,
                                name=t.name,
                                version=t.version or "",
                                url=t.url or "",
                            )
                        for sc in getattr(host, "screenshots", []):
                            _DBScreenshot.objects.create(
                                host=db_host,
                                scan_id=scan_id,
                                url=sc.url,
                                filename=sc.filename,
                                title=sc.title or "",
                                status_code=sc.status_code,
                            )
                        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                        for f in findings:
                            sev = (
                                f.severity.value
                                if hasattr(f.severity, "value")
                                else str(f.severity).lower()
                            )
                            _DBFinding.objects.create(
                                scan_id=scan_id,
                                host=db_host,
                                source=f.source,
                                severity=sev,
                                title=f.title,
                                description=f.description or "",
                                host_ip=f.host,
                                port=str(f.port) if f.port else "",
                                protocol=f.protocol or "tcp",
                                endpoint=f.endpoint or "",
                                full_url=f.full_url or "",
                                template_id=f.template_id or "",
                                cve=f.cve or "",
                                cwe=f.cwe or "",
                                cvss=str(f.cvss) if f.cvss else "",
                                request=f.request or "",
                                response=f.response or "",
                                curl_command=f.curl_command or "",
                                raw_output=f.raw_output or "",
                                references=f.references or "[]",
                                tags=f.tags or "",
                                script_id=f.script_id or "",
                                matched_at=f.matched_at or "",
                            )
                            if sev in sev_counts:
                                sev_counts[sev] += 1
                            db_host.findings_count += 1
                        db_host.save(update_fields=["findings_count"])
                        _Scan.objects.filter(id=scan_id).update(
                            ports_count=_F("ports_count") + len(host.open_ports),
                            findings_count=_F("findings_count") + len(findings),
                            critical_count=_F("critical_count") + sev_counts["critical"],
                            high_count=_F("high_count") + sev_counts["high"],
                            medium_count=_F("medium_count") + sev_counts["medium"],
                            low_count=_F("low_count") + sev_counts["low"],
                            info_count=_F("info_count") + sev_counts["info"],
                        )
                except Exception as _exc:
                    import traceback as _tb

                    logger.error(
                        "Phase progress thread DB write failed: %s\n%s",
                        _exc,
                        _tb.format_exc(),
                    )
                finally:
                    _progress_queue.task_done()
            try:
                _conn.close()
            except Exception:
                pass

        _thread = threading.Thread(target=_progress_thread, daemon=True)
        _thread.start()

        # ── Callbacks ──
        def _on_progress(phase, done, total):
            try:
                _progress_queue.put_nowait(("progress", phase, done, total))
            except Exception:
                pass

        def _on_host_complete(host, findings):
            try:
                _progress_queue.put_nowait(("host_result", host, findings))
            except Exception:
                pass

        def _on_host_phase(ip, phase):
            try:
                _progress_queue.put_nowait(("host_phase", ip, phase))
            except Exception:
                pass

        def _on_artifact(host_ip, tool, name, content, content_type):
            try:
                _progress_queue.put_nowait(
                    ("artifact", host_ip, tool, name, content, content_type)
                )
            except Exception:
                pass

        def _on_discovery_complete(live_ips, mac_vendor_map, dns_hostnames=None):
            try:
                _progress_queue.put_nowait(
                    ("discovery", live_ips, mac_vendor_map, dns_hostnames or {})
                )
            except Exception:
                pass

        def _on_subnet_complete(new_ips, mac_updates):
            try:
                _progress_queue.put_nowait(("subnet_hosts", new_ips, mac_updates))
            except Exception:
                pass

        # Wrap callbacks for cancellation detection
        _is_aborted = getattr(self, "is_aborted", lambda: False)

        class _CancelWrapper:
            """Wrap a callback so _TaskCancelled propagates on abort."""

            def __init__(self, fn):
                self.fn = fn

            def __call__(self, *a, **kw):
                if _is_aborted():
                    raise _TaskCancelled("Task cancelled")
                return self.fn(*a, **kw)

        _wp = _CancelWrapper(_on_progress)
        _wh = _CancelWrapper(_on_host_complete)
        _wph = _CancelWrapper(_on_host_phase)
        _wa = _CancelWrapper(_on_artifact)
        _wd = _CancelWrapper(_on_discovery_complete)
        _ws = _CancelWrapper(_on_subnet_complete)

        try:
            asyncio.run(
                _execute_phase(
                    phase_name, scan, config, tree,
                    _wp, _wh, _wa, _wd, _ws, _wph,
                )
            )
        except _TaskCancelled:
            logger.warning("Phase %s cancelled for scan %s", phase_name, scan_id)
            scan.status = "paused"
            scan.save(update_fields=["status"])
            phase_run.status = "cancelled"
            phase_run.completed_at = timezone.now()
            if phase_run.started_at:
                phase_run.duration_seconds = int(
                    (phase_run.completed_at - phase_run.started_at).total_seconds()
                )
            phase_run.save(update_fields=["status", "completed_at", "duration_seconds"])
            _progress_stop.set()
            _progress_queue.put(None)
            _thread.join(timeout=10)
            return {"scan_id": scan_id, "phase": phase_name, "status": "cancelled"}
        finally:
            _progress_queue.put(None)
            _thread.join(timeout=30)
            if _thread.is_alive():
                _progress_stop.set()
                _thread.join(timeout=5)

        # ── Finalize phase run ──
        scan.refresh_from_db()
        phase_run.refresh_from_db()

        phase_run.status = "completed"
        phase_run.completed_at = timezone.now()
        if phase_run.started_at:
            phase_run.duration_seconds = int(
                (phase_run.completed_at - phase_run.started_at).total_seconds()
            )
        phase_run.output_summary = _compute_phase_summary(scan)
        phase_run.save()

        # Determine if this was the last phase
        remaining = scan.phase_runs.filter(status="pending").exclude(phase=phase_name).count()
        if remaining == 0:
            scan.status = "completed"
            scan.completed_at = timezone.now()
            if scan.started_at:
                scan.duration_seconds = int(
                    (scan.completed_at - scan.started_at).total_seconds()
                )
            scan.save(update_fields=["status", "completed_at", "duration_seconds"])
        else:
            scan.status = "paused"
            scan.save(update_fields=["status"])

        logger.info(
            "Phase %s completed for scan %s (remaining: %d)",
            phase_name, scan_id, remaining,
        )

        return {"scan_id": scan_id, "phase": phase_name, "status": "completed"}

    except Exception as e:
        logger.exception("Phase %s failed for scan %s: %s", phase_name, scan_id, e)

        scan.refresh_from_db()
        scan.status = "paused"
        scan.save(update_fields=["status"])

        phase_run.refresh_from_db()
        phase_run.status = "failed"
        phase_run.error_message = str(e)[:2000]
        phase_run.completed_at = timezone.now()
        if phase_run.started_at:
            phase_run.duration_seconds = int(
                (phase_run.completed_at - phase_run.started_at).total_seconds()
            )
        phase_run.save(
            update_fields=["status", "error_message", "completed_at", "duration_seconds"]
        )

        return {"scan_id": scan_id, "phase": phase_name, "status": "failed", "error": str(e)[:500]}


async def _execute_phase(
    phase_name, scan, config, tree,
    on_progress, on_host_complete, on_artifact,
    on_discovery_complete, on_subnet_complete, on_host_phase,
):
    """Dispatch to the correct pipeline function for *phase_name*.

    Each phase calls the same pipeline functions that ``run_pipeline`` uses,
    but in isolation. Phases after discovery operate on Host rows already
    persisted by earlier phases, reconstructing them into pipeline ``Host``
    objects via ``_reconstruct_host()``.
    """
    if phase_name == "discovery":
        from wireghost.pipeline.discovery import discover_hosts

        if on_progress:
            on_progress("discovery", 0, 0)

        live_ips, mac_vendor_map, dns_hostnames = await discover_hosts(
            config, tree,
            on_progress=on_progress,
            on_subnet_complete=on_subnet_complete,
        )
        if on_discovery_complete:
            on_discovery_complete(live_ips, mac_vendor_map, dns_hostnames)

    elif phase_name == "portscan":
        from scanner.models import Host as DBHost
        from wireghost.pipeline.portscan import scan_host

        db_hosts = await sync_to_async(list)(DBHost.objects.filter(scan=scan))
        if not db_hosts:
            return

        sem = asyncio.Semaphore(config.parallelism)

        async def _portscan_one(db_host):
            host = await scan_host(db_host.ip, config, tree, sem)
            if on_host_complete:
                on_host_complete(host, [])

        tasks = [_portscan_one(h) for h in db_hosts]
        await asyncio.gather(*tasks)

    elif phase_name == "webdetect":
        from scanner.models import Host as DBHost
        from wireghost.pipeline.webdetect import probe_host

        db_hosts = await sync_to_async(list)(
            DBHost.objects.filter(scan=scan).exclude(ports_count=0)
        )
        if not db_hosts:
            return

        sem = asyncio.Semaphore(config.parallelism)

        async def _webdetect_one(db_host):
            host = _reconstruct_host(db_host)
            await probe_host(host, config, tree, sem)
            if on_host_complete:
                on_host_complete(host, [])

        await asyncio.gather(*[_webdetect_one(h) for h in db_hosts])

    elif phase_name == "webcrawl":
        from scanner.models import Host as DBHost
        from wireghost.pipeline.web_crawl import crawl_host

        db_hosts = await sync_to_async(list)(
            DBHost.objects.filter(scan=scan).exclude(web_endpoints=[])
        )
        if not db_hosts:
            return

        sem = asyncio.Semaphore(config.parallelism)

        async def _webcrawl_one(db_host):
            host = _reconstruct_host(db_host)
            await crawl_host(host, config, tree, sem)
            if on_host_complete:
                on_host_complete(host, [])

        await asyncio.gather(*[_webcrawl_one(h) for h in db_hosts])

    elif phase_name == "vulnscan":
        from scanner.models import Host as DBHost
        from wireghost.pipeline.vulnscan import scan_host_vulns

        db_hosts = await sync_to_async(list)(
            DBHost.objects.filter(scan=scan).exclude(ports_count=0)
        )
        if not db_hosts:
            return

        sem = asyncio.Semaphore(config.parallelism)

        async def _vulnscan_one(db_host):
            host = _reconstruct_host(db_host)
            findings = await scan_host_vulns(host, config, tree, sem)
            if on_host_complete:
                on_host_complete(host, findings)

        await asyncio.gather(*[_vulnscan_one(h) for h in db_hosts])

    elif phase_name == "enumeration":
        from scanner.models import Host as DBHost
        from wireghost.pipeline.cms_scan import scan_cms
        from wireghost.pipeline.cve_search import scan_cve_search
        from wireghost.pipeline.ldap_enum import enumerate_ldap
        from wireghost.pipeline.netexec_enum import enumerate_netexec
        from wireghost.pipeline.nfs_enum import enumerate_nfs
        from wireghost.pipeline.service_enum import enumerate_services
        from wireghost.pipeline.smb_enum import enumerate_smb
        from wireghost.pipeline.snmp_enum import enumerate_snmp

        db_hosts = await sync_to_async(list)(
            DBHost.objects.filter(scan=scan).exclude(ports_count=0)
        )
        if not db_hosts:
            return

        sem = asyncio.Semaphore(config.parallelism)

        async def _enum_one(db_host):
            host = _reconstruct_host(db_host)
            all_findings = []

            async def _run(name, coro):
                try:
                    result = await coro
                    if isinstance(result, list):
                        all_findings.extend(result)
                except Exception:
                    logger.exception("Enum %s failed for %s", name, host.ip)

            await asyncio.gather(
                _run("services", enumerate_services(host, config, tree)),
                _run("smb", enumerate_smb(host, config, tree)),
                _run("snmp", enumerate_snmp(host, config, tree)),
                _run("netexec", enumerate_netexec(host, config, tree)),
                _run("nfs", enumerate_nfs(host, config, tree)),
                _run("ldap", enumerate_ldap(host, config, tree)),
                _run("cms", scan_cms(host, config, tree)),
                _run("cve", scan_cve_search(host, config, tree)),
            )
            if on_host_complete:
                on_host_complete(host, all_findings)

        await asyncio.gather(*[_enum_one(h) for h in db_hosts])


def _reconstruct_host(db_host):
    """Convert a DB Host row (with Ports/Technologies) back to a pipeline Host.

    Phases after discovery need previously-persisted data (ports, technologies,
    web endpoints) to feed into pipeline functions that expect a ``Host`` object.
    """
    from wireghost.models.scan import Host, Port, Service, WebTech

    ports = []
    for p in db_host.ports.all():
        svc = Service(
            name=p.service_name or "",
            product=p.service_product or "",
            version=p.service_version or "",
        )
        ports.append(
            Port(
                number=p.number,
                protocol=p.protocol,
                state=p.state,
                service=svc,
            )
        )
    techs = [
        WebTech(name=t.name, version=t.version or "", url=t.url or "")
        for t in db_host.technologies.all()
    ]
    return Host(
        ip=db_host.ip,
        hostname=db_host.hostname,
        os=db_host.os,
        status=db_host.status,
        mac_address=db_host.mac_address,
        vendor=db_host.vendor,
        ports=ports,
        technologies=techs,
        web_endpoints=db_host.web_endpoints or [],
        web_titles=db_host.web_titles or {},
    )


def _compute_phase_summary(scan):
    """Return cumulative counts for the phase_status endpoint."""
    from scanner.models import Host, Finding

    hosts = Host.objects.filter(scan=scan)
    total_hosts = hosts.count()
    hosts_with_ports = hosts.exclude(ports_count=0).count()
    total_ports = sum(h.ports_count for h in hosts)
    total_findings = Finding.objects.filter(scan=scan).count()

    return {
        "hosts": total_hosts,
        "hosts_with_ports": hosts_with_ports,
        "ports": total_ports,
        "findings": total_findings,
    }
