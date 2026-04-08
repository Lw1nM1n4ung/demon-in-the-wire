"""OpenVAS GMP client — creates targets, tasks, runs scans, fetches reports."""
from __future__ import annotations
import asyncio
import logging
import time
from pathlib import Path

log = logging.getLogger("wireghost")


class OpenVASClient:
    """Async wrapper around python-gvm for running OpenVAS scans."""

    FULL_AND_FAST_CONFIG = "daba56c8-73ec-11df-a475-002264764cea"
    OPENVAS_SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"
    IANA_TCP_UDP_PORTLIST = "4a4717fe-57d2-11e1-9a26-406186ea4fc5"

    def __init__(self, socket_path: str, username: str, password: str):
        self.socket_path = socket_path
        self.username = username
        self.password = password

    async def scan_host(self, ip: str, output_dir: Path, timeout: float = 3600) -> Path | None:
        """Run a full OpenVAS scan on a single host. Returns path to XML report or None."""
        # Run GMP operations in a thread (python-gvm is synchronous)
        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, self._scan_sync, ip, output_dir, timeout),
                timeout=timeout + 60,  # extra buffer
            )
        except asyncio.TimeoutError:
            log.warning("OpenVAS scan timed out for %s", ip)
            return None
        except Exception as e:
            log.error("OpenVAS scan failed for %s: %s", ip, e)
            return None

    def _scan_sync(self, ip: str, output_dir: Path, timeout: float) -> Path | None:
        """Synchronous GMP scan workflow."""
        try:
            from gvm.connections import UnixSocketConnection
            from gvm.protocols.gmp import Gmp
            from gvm.transforms import EtreeTransform
        except ImportError:
            log.warning("python-gvm not installed — skipping OpenVAS scan")
            return None

        try:
            connection = UnixSocketConnection(path=self.socket_path)
            transform = EtreeTransform()

            with Gmp(connection=connection, transform=transform) as gmp:
                gmp.authenticate(self.username, self.password)
                log.info("OpenVAS: connected to %s", self.socket_path)

                # 1. Create target
                import datetime
                target_name = f"wireghost-{ip}-{datetime.datetime.now().isoformat()}"
                resp = gmp.create_target(
                    name=target_name,
                    hosts=[ip],
                    port_list_id=self.IANA_TCP_UDP_PORTLIST,
                )
                target_id = resp.get("id")
                if not target_id:
                    log.error("OpenVAS: failed to create target for %s", ip)
                    return None
                log.info("OpenVAS: created target %s for %s", target_id, ip)

                # 2. Create task
                task_name = f"wireghost-scan-{ip}"
                resp = gmp.create_task(
                    name=task_name,
                    config_id=self.FULL_AND_FAST_CONFIG,
                    target_id=target_id,
                    scanner_id=self.OPENVAS_SCANNER_ID,
                )
                task_id = resp.get("id")
                if not task_id:
                    log.error("OpenVAS: failed to create task for %s", ip)
                    return None

                # 3. Start task
                resp = gmp.start_task(task_id)
                report_id = resp[0].text if len(resp) > 0 else None
                if not report_id:
                    log.error("OpenVAS: failed to start task for %s", ip)
                    return None
                log.info("OpenVAS: scan started for %s (report=%s)", ip, report_id)

                # 4. Wait for completion
                deadline = time.time() + timeout
                while time.time() < deadline:
                    task_resp = gmp.get_task(task_id)
                    status = task_resp.find(".//status")
                    if status is not None and status.text in ("Done", "Stopped"):
                        break
                    progress = task_resp.find(".//progress")
                    pct = progress.text if progress is not None else "?"
                    log.debug("OpenVAS: %s progress %s%%", ip, pct)
                    time.sleep(10)
                else:
                    log.warning("OpenVAS: scan timed out for %s", ip)
                    gmp.stop_task(task_id)

                # 5. Get report as XML
                report_resp = gmp.get_report(
                    report_id,
                    report_format_id="a994b278-1f62-11e1-96ac-406186ea4fc5",  # XML format
                    ignore_pagination=True,
                    details=True,
                )

                # Save XML
                from lxml import etree
                xml_path = output_dir / f"openvas_report_{ip}.xml"
                xml_str = etree.tostring(report_resp, pretty_print=True, encoding="unicode")
                xml_path.write_text(xml_str, encoding="utf-8")
                log.info("OpenVAS: report saved to %s", xml_path)
                return xml_path

        except Exception as e:
            log.error("OpenVAS GMP error for %s: %s", ip, e)
            return None
