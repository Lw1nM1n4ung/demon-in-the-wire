"""Celery task for standalone host discovery scans.

Calls ``discover_hosts()`` directly — not the full pipeline — so discovery
scans are fast (minutes, not hours).  Reuses the same daemon-thread + queue
pattern as ``run_scan`` for DB persistence.
"""

import logging
import asyncio
import threading
from pathlib import Path
from queue import Queue, Empty

from celery import shared_task
from django.utils import timezone

logger = logging.getLogger(__name__)


class _TaskCancelled(Exception):
    """Raised when the Celery task is cancelled by user request.

    A distinct type (not RuntimeError) so it cannot be confused with
    genuine runtime errors from discover_hosts or asyncio.run."""





@shared_task(bind=True, max_retries=2, time_limit=7200, soft_time_limit=3600)
def run_discovery_scan(self, scan_id):
    """Execute a standalone host discovery scan and persist results to DB.

    Only runs the discovery phase (nmap ping-sweep, fping, arp-scan,
    passive DNS).  Does NOT port-scan, vuln-scan, or generate reports.
    """
    from scanner.models import Scan

    scan = Scan.objects.get(id=scan_id)
    scan.status = "running"
    scan.started_at = timezone.now()
    scan.celery_task_id = self.request.id or ""
    scan.current_phase = "discovery"
    scan.save()

    try:
        from wireghost.pipeline.discovery import discover_hosts
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

        tree = build_output_tree(str(base_output), target_normalized)

        config = ScanConfig.load(
            target=scan.target,
            parallelism=scan.parallelism,
            tool_timeout=scan.timeout,
            scan_unresponsive=scan.scan_unresponsive,
            output_dir=str(base_output),
        )

        # ── Daemon thread for DB writes ──
        _scan_id_hex = str(scan_id).replace("-", "")
        _progress_queue: Queue = Queue()
        _progress_stop = threading.Event()

        def _progress_thread():
            from django.db import connection as _conn
            from django.db.models import F as _F
            from scanner.models import Host as _DBHost, Scan as _Scan

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
                        _, phase, subnets_done, total_subnets = item
                        with _conn.cursor() as cursor:
                            cursor.execute(
                                "UPDATE scanner_scan SET current_phase=%s, "
                                "hosts_scanned=%s, hosts_total=%s "
                                "WHERE id=%s",
                                [phase, subnets_done, total_subnets, _scan_id_hex],
                            )
                    elif action == "subnet_hosts":
                        if len(item) >= 4:
                            _, new_ips, mac_updates, tool_provenance = item
                        else:
                            _, new_ips, mac_updates = item
                            tool_provenance = {}
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
                                    "discovered_by": list(tool_provenance.get(ip, [])),
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
                    elif action == "discovery":
                        if len(item) >= 5:
                            _, live_ips, mac_vendor_map, dns_hostnames, tool_provenance = item
                        else:
                            _, live_ips, mac_vendor_map, dns_hostnames = item
                            tool_provenance = {}
                        for ip in live_ips:
                            mac, vendor = mac_vendor_map.get(ip, ("", ""))
                            defaults = {
                                "mac_address": mac or "",
                                "vendor": vendor or "",
                                "status": "up",
                                "ports_count": 0,
                                "discovered_by": list(tool_provenance.get(ip, [])),
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
                        logger.info(
                            "Discovery finalized: %d host(s) total", len(live_ips)
                        )
                    elif action == "cancelled_check":
                        # The main task checks self.is_aborted() and pushes this
                        # sentinel so the daemon thread also knows to stop early.
                        pass
                except Exception as _exc:
                    import traceback as _tb

                    logger.error(
                        "Discovery progress thread DB write failed: %s\n%s",
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
        def _on_progress(phase, subnets_done, total_subnets):
            try:
                _progress_queue.put_nowait(
                    ("progress", phase, subnets_done, total_subnets)
                )
            except Exception:
                pass

        def _on_subnet_complete(new_ips, mac_updates, tool_provenance=None):
            try:
                _progress_queue.put_nowait(("subnet_hosts", new_ips, mac_updates, tool_provenance or {}))
            except Exception:
                pass

        def _on_discovery_complete(live_ips, mac_vendor_map, dns_hostnames, tool_provenance=None):
            try:
                _progress_queue.put_nowait(
                    ("discovery", live_ips, mac_vendor_map, dns_hostnames or {}, tool_provenance or {})
                )
            except Exception:
                pass

        # Wrap callbacks to check for task cancellation.
        # Celery's revoke(terminate=True) kills the worker process, but
        # revoke(terminate=False) sets self.is_aborted() — check it so
        # the scan status flips to cancelled instead of completed.
        # When called synchronously (tests), is_aborted doesn't exist.
        _is_aborted = getattr(self, 'is_aborted', lambda: False)

        def _wrap_progress(phase, subnets_done, total_subnets):
            if _is_aborted():
                raise _TaskCancelled("Task cancelled")
            _on_progress(phase, subnets_done, total_subnets)

        def _wrap_subnet(new_ips, mac_updates, tool_provenance=None):
            if _is_aborted():
                raise _TaskCancelled("Task cancelled")
            _on_subnet_complete(new_ips, mac_updates, tool_provenance)

        live_ips: list = []
        mac_vendor_map: dict = {}
        dns_hostnames: dict = {}
        try:
            live_ips, mac_vendor_map, dns_hostnames, tool_provenance = asyncio.run(
                discover_hosts(
                    config,
                    tree,
                    on_progress=_wrap_progress,
                    on_subnet_complete=_wrap_subnet,
                )
            )
        except _TaskCancelled:
            logger.warning("Discovery scan %s cancelled by user", scan_id)
            scan.status = "cancelled"
            scan.completed_at = timezone.now()
            if scan.started_at:
                scan.duration_seconds = int(
                    (scan.completed_at - scan.started_at).total_seconds()
                )
            scan.save()
            _progress_stop.set()
            _progress_queue.put(None)
            _thread.join(timeout=10)
            return {"scan_id": scan_id, "status": "cancelled"}
        finally:
            # Fire on_discovery_complete even if some subnets threw — hosts
            # that were already created incrementally are still valid.
            if not _is_aborted():
                _on_discovery_complete(live_ips, mac_vendor_map, dns_hostnames, tool_provenance)

            _progress_queue.put(None)
            _thread.join(timeout=30)
            if _thread.is_alive():
                _progress_stop.set()
                _thread.join(timeout=5)

        # ── Finalize ──
        scan.refresh_from_db()
        scan.status = "completed"
        scan.hosts_count = len(live_ips)
        scan.hosts_total = len(live_ips)
        scan.completed_at = timezone.now()
        scan.duration_seconds = (
            int((scan.completed_at - scan.started_at).total_seconds())
            if scan.started_at
            else 0
        )
        scan.save()

        logger.info(
            "Discovery scan %s completed: %d host(s) found",
            scan_id,
            scan.hosts_count,
        )

        # Fire-and-forget notification
        try:
            from scanner.notifications import notify

            notify("scan.complete", scan=scan)
        except Exception:
            logger.exception("notification dispatch failed for scan %s", scan_id)

        return {
            "scan_id": scan_id,
            "status": "completed",
            "hosts_found": scan.hosts_count,
        }

    except Exception as e:
        logger.exception("Discovery scan %s failed: %s", scan_id, e)
        scan.status = "failed"
        scan.error_message = str(e)[:2000]
        scan.completed_at = timezone.now()
        if scan.started_at:
            scan.duration_seconds = int(
                (scan.completed_at - scan.started_at).total_seconds()
            )
        scan.save()

        try:
            from scanner.notifications import notify
            notify("scan.failed", scan=scan)
        except Exception:
            pass

        # Retry on transient failures if retries remain
        if getattr(self.request, 'retries', self.max_retries) < self.max_retries:
            logger.info(
                "Retrying discovery scan %s (attempt %d/%d)",
                scan_id,
                getattr(self.request, 'retries', 0) + 1,
                self.max_retries,
            )
            try:
                raise self.retry(exc=e, countdown=60)
            except Exception:
                # Not running under Celery (e.g. synchronous test call)
                pass

        return {"scan_id": scan_id, "status": "failed", "error": str(e)[:500]}
