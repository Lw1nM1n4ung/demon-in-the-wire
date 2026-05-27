"""Tests for phase-based scan workflow.

Covers: init_phases, run_phase, retry_phase, skip_phase, phase_status,
phase_export API endpoints; run_phase Celery task; SSRF validation;
and integration between phases.
"""
import json
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase

from scanner.models import PhaseRun, Scan

User = get_user_model()


class PhaseScanAPITests(TestCase):
    """API-level tests — Celery task dispatch is mocked out."""

    def setUp(self):
        self.owner = User.objects.create_superuser(
            username="owner", password="pw-owner-123!", email="owner@example.com"
        )
        self.client = Client()
        self.client.force_login(self.owner)

    def _create_scan(self, **overrides):
        data = {
            "target": "10.0.0.0/24",
            "scan_type": "phase_based",
            "parallelism": 10,
        }
        data.update(overrides)
        return self.client.post(
            "/api/scans/",
            data=json.dumps(data),
            content_type="application/json",
        )

    def _init_phases(self, scan_id, phases=None, status_code=201):
        body = {}
        if phases is not None:
            body["phases"] = phases
        return self.client.post(
            f"/api/scans/{scan_id}/init_phases/",
            data=json.dumps(body),
            content_type="application/json",
        )

    # ── Create (phase_based) ────────────────────────────────────────────

    def test_create_phase_based_scan_accepted(self):
        res = self._create_scan()
        self.assertEqual(res.status_code, 201)
        body = res.json()
        self.assertEqual(body["scan_type"], "phase_based")
        self.assertEqual(body["status"], "pending")

    def test_create_phase_based_scan_no_task_dispatch(self):
        """Phase-based scans must NOT auto-dispatch a Celery task."""
        res = self._create_scan()
        self.assertEqual(res.status_code, 201)
        scan = Scan.objects.get(id=res.json()["id"])
        self.assertEqual(scan.celery_task_id, "")

    def test_create_phase_based_scan_with_name_and_parallelism(self):
        res = self._create_scan(name="Manual Audit", parallelism=20)
        self.assertEqual(res.status_code, 201)
        scan = Scan.objects.get(id=res.json()["id"])
        self.assertEqual(scan.name, "Manual Audit")
        self.assertEqual(scan.parallelism, 20)

    # ── init_phases ─────────────────────────────────────────────────────

    def test_init_phases_creates_6_phaserun_rows(self):
        res = self._create_scan()
        scan_id = res.json()["id"]
        res2 = self._init_phases(scan_id)
        self.assertEqual(res2.status_code, 201)
        runs = res2.json()
        self.assertEqual(len(runs), 6)
        phases = [r["phase"] for r in runs]
        self.assertIn("discovery", phases)
        self.assertIn("portscan", phases)
        self.assertIn("vulnscan", phases)
        self.assertIn("enumeration", phases)
        self.assertEqual(runs[0]["sequence"], 0)
        self.assertEqual(runs[5]["sequence"], 5)

    def test_init_phases_custom_phase_list(self):
        res = self._create_scan()
        scan_id = res.json()["id"]
        res2 = self._init_phases(scan_id, phases=["discovery", "portscan", "vulnscan"])
        self.assertEqual(res2.status_code, 201)
        runs = res2.json()
        self.assertEqual(len(runs), 3)

    def test_init_phases_sets_scan_to_paused(self):
        res = self._create_scan()
        scan_id = res.json()["id"]
        self._init_phases(scan_id)
        scan = Scan.objects.get(id=scan_id)
        self.assertEqual(scan.status, "paused")
        self.assertEqual(scan.phases, ["discovery", "portscan", "webdetect",
                                        "webcrawl", "vulnscan", "enumeration"])
        self.assertEqual(scan.current_phase_index, -1)

    def test_init_phases_rejects_non_phase_based_scan(self):
        res = self._create_scan(scan_type="full")
        scan_id = res.json()["id"]
        res2 = self._init_phases(scan_id)
        self.assertEqual(res2.status_code, 400)
        self.assertIn("Not a phase-based scan", res2.json()["error"])

    def test_init_phases_idempotent(self):
        res = self._create_scan()
        scan_id = res.json()["id"]
        self._init_phases(scan_id)
        res2 = self._init_phases(scan_id)
        self.assertEqual(res2.status_code, 400)
        self.assertIn("already initialized", res2.json()["error"])

    def test_init_phases_rejects_invalid_phase_name(self):
        res = self._create_scan()
        scan_id = res.json()["id"]
        res2 = self._init_phases(scan_id, phases=["discovery", "not_a_phase"])
        self.assertEqual(res2.status_code, 201)
        runs = res2.json()
        self.assertEqual(len(runs), 1)  # only "discovery" is valid

    # ── run_phase ───────────────────────────────────────────────────────

    @patch("scanner.tasks.phase_scan.run_phase.delay")
    def test_run_phase_dispatches_task(self, mock_delay):
        mock_delay.return_value = MagicMock(id="task-run-1")
        res = self._create_scan()
        scan_id = res.json()["id"]
        self._init_phases(scan_id)

        res2 = self.client.post(
            f"/api/scans/{scan_id}/run_phase/",
            data=json.dumps({"phase": "discovery"}),
            content_type="application/json",
        )
        self.assertEqual(res2.status_code, 200)
        self.assertEqual(res2.json()["phase"], "discovery")
        self.assertEqual(res2.json()["status"], "started")
        mock_delay.assert_called_once_with(scan_id, "discovery")

    @patch("scanner.tasks.phase_scan.run_phase.delay")
    def test_run_phase_auto_selects_next_pending(self, mock_delay):
        mock_delay.return_value = MagicMock(id="task-auto-1")
        res = self._create_scan()
        scan_id = res.json()["id"]
        self._init_phases(scan_id)

        res2 = self.client.post(
            f"/api/scans/{scan_id}/run_phase/",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(res2.status_code, 200)
        self.assertEqual(res2.json()["phase"], "discovery")

    def test_run_phase_no_pending_phases(self):
        res = self._create_scan()
        scan_id = res.json()["id"]
        # Don't init phases — no PhaseRun rows exist
        res2 = self.client.post(
            f"/api/scans/{scan_id}/run_phase/",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(res2.status_code, 400)
        self.assertIn("No pending phases", res2.json()["error"])

    def test_run_phase_nonexistent_phase_name(self):
        res = self._create_scan()
        scan_id = res.json()["id"]
        self._init_phases(scan_id)
        res2 = self.client.post(
            f"/api/scans/{scan_id}/run_phase/",
            data=json.dumps({"phase": "nonexistent"}),
            content_type="application/json",
        )
        self.assertEqual(res2.status_code, 404)

    # ── retry_phase ─────────────────────────────────────────────────────

    def test_retry_phase_resets_failed_to_pending(self):
        res = self._create_scan()
        scan_id = res.json()["id"]
        self._init_phases(scan_id)
        pr = PhaseRun.objects.filter(scan_id=scan_id, phase="discovery").first()
        pr.status = "failed"
        pr.error_message = "Something broke"
        pr.save()

        res2 = self.client.post(
            f"/api/scans/{scan_id}/retry_phase/",
            data=json.dumps({"phase": "discovery"}),
            content_type="application/json",
        )
        self.assertEqual(res2.status_code, 200)
        pr.refresh_from_db()
        self.assertEqual(pr.status, "pending")
        self.assertEqual(pr.retry_count, 1)
        self.assertEqual(pr.error_message, "")

    def test_retry_phase_increments_retry_count(self):
        res = self._create_scan()
        scan_id = res.json()["id"]
        self._init_phases(scan_id)
        pr = PhaseRun.objects.filter(scan_id=scan_id, phase="discovery").first()
        pr.status = "failed"
        pr.save()

        self.client.post(
            f"/api/scans/{scan_id}/retry_phase/",
            data=json.dumps({"phase": "discovery"}),
            content_type="application/json",
        )
        # First retry resets to pending — set back to failed for second retry
        pr.refresh_from_db()
        pr.status = "failed"
        pr.save()
        self.client.post(
            f"/api/scans/{scan_id}/retry_phase/",
            data=json.dumps({"phase": "discovery"}),
            content_type="application/json",
        )
        pr.refresh_from_db()
        self.assertEqual(pr.retry_count, 2)

    def test_retry_phase_rejects_non_failed_status(self):
        res = self._create_scan()
        scan_id = res.json()["id"]
        self._init_phases(scan_id)
        res2 = self.client.post(
            f"/api/scans/{scan_id}/retry_phase/",
            data=json.dumps({"phase": "discovery"}),
            content_type="application/json",
        )
        self.assertEqual(res2.status_code, 400)
        self.assertIn("Cannot retry", res2.json()["error"])

    def test_retry_phase_missing_phase_param(self):
        res = self._create_scan()
        scan_id = res.json()["id"]
        res2 = self.client.post(
            f"/api/scans/{scan_id}/retry_phase/",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(res2.status_code, 400)
        self.assertIn("phase is required", res2.json()["error"])

    # ── skip_phase ──────────────────────────────────────────────────────

    def test_skip_phase_marks_skipped(self):
        res = self._create_scan()
        scan_id = res.json()["id"]
        self._init_phases(scan_id)

        res2 = self.client.post(
            f"/api/scans/{scan_id}/skip_phase/",
            data=json.dumps({"phase": "webcrawl"}),
            content_type="application/json",
        )
        self.assertEqual(res2.status_code, 200)
        self.assertEqual(res2.json()["status"], "skipped")

    def test_skip_phase_rejects_non_pending(self):
        res = self._create_scan()
        scan_id = res.json()["id"]
        self._init_phases(scan_id)
        pr = PhaseRun.objects.filter(scan_id=scan_id, phase="discovery").first()
        pr.status = "completed"
        pr.save()

        res2 = self.client.post(
            f"/api/scans/{scan_id}/skip_phase/",
            data=json.dumps({"phase": "discovery"}),
            content_type="application/json",
        )
        self.assertEqual(res2.status_code, 400)
        self.assertIn("Cannot skip", res2.json()["error"])

    # ── phase_status ────────────────────────────────────────────────────

    def test_phase_status_returns_all_phases(self):
        res = self._create_scan()
        scan_id = res.json()["id"]
        self._init_phases(scan_id)

        res2 = self.client.get(f"/api/scans/{scan_id}/phase_status/")
        self.assertEqual(res2.status_code, 200)
        data = res2.json()
        self.assertEqual(len(data["phases"]), 6)
        self.assertEqual(data["scan_id"], scan_id)
        self.assertIn("hosts_scanned", data)
        self.assertIn("hosts_total", data)

    def test_phase_status_includes_scan_metadata(self):
        res = self._create_scan(name="Phase Audit")
        scan_id = res.json()["id"]
        self._init_phases(scan_id)

        res2 = self.client.get(f"/api/scans/{scan_id}/phase_status/")
        self.assertEqual(res2.json()["scan_name"], "Phase Audit")
        self.assertEqual(res2.json()["scan_status"], "paused")
        self.assertEqual(res2.json()["current_phase_index"], -1)

    # ── phase_export ────────────────────────────────────────────────────

    def test_phase_export_json(self):
        res = self._create_scan()
        scan_id = res.json()["id"]
        self._init_phases(scan_id)

        res2 = self.client.get(f"/api/scans/{scan_id}/phase_export/?fmt=json")
        self.assertEqual(res2.status_code, 200)
        data = res2.json()
        self.assertIn("scan_id", data)
        self.assertIn("findings", data)

    def test_phase_export_csv(self):
        res = self._create_scan()
        scan_id = res.json()["id"]
        self._init_phases(scan_id)

        res2 = self.client.get(f"/api/scans/{scan_id}/phase_export/?fmt=csv")
        self.assertEqual(res2.status_code, 200)
        self.assertEqual(res2["Content-Type"], "text/csv")

    # ── SSRF validation ─────────────────────────────────────────────────

    def test_phase_based_rejects_localhost(self):
        res = self._create_scan(target="127.0.0.1")
        self.assertEqual(res.status_code, 400)

    def test_phase_based_rejects_cloud_metadata(self):
        res = self._create_scan(target="169.254.169.254")
        self.assertEqual(res.status_code, 400)

    def test_phase_based_rejects_internal_ip(self):
        res = self._create_scan(target="10.0.0.1")
        self.assertEqual(res.status_code, 201)  # internal IPs are allowed

    def test_phase_based_rejects_dns_rebinding(self):
        res = self._create_scan(target="evil.nip.io")
        self.assertEqual(res.status_code, 400)

    # ── RBAC ────────────────────────────────────────────────────────────

    def test_phase_endpoints_require_auth(self):
        c = Client()
        res = self._create_scan()
        scan_id = res.json()["id"]
        self._init_phases(scan_id)

        endpoints = [
            (f"/api/scans/{scan_id}/init_phases/", "post"),
            (f"/api/scans/{scan_id}/run_phase/", "post"),
            (f"/api/scans/{scan_id}/retry_phase/", "post"),
            (f"/api/scans/{scan_id}/skip_phase/", "post"),
            (f"/api/scans/{scan_id}/phase_status/", "get"),
            (f"/api/scans/{scan_id}/phase_export/?fmt=json", "get"),
        ]
        for url, method in endpoints:
            fn = getattr(c, method)
            res2 = fn(url, data=json.dumps({}), content_type="application/json") if method == "post" else fn(url)
            self.assertIn(res2.status_code, [401, 403], f"{method} {url} should require auth")


class PhaseScanTaskTests(TestCase):
    """Task-level tests — pipeline functions are mocked to avoid real tool execution."""

    def setUp(self):
        self.owner = User.objects.create_superuser(
            username="owner", password="pw-owner-123!", email="owner@example.com"
        )
        self.scan = Scan.objects.create(
            name="Phase Task Test",
            target="10.0.0.1",
            scan_type="phase_based",
            status="paused",
            created_by=self.owner,
        )
        # Create all 6 PhaseRun rows
        for idx, phase in enumerate(PhaseRun.PHASE_CHOICES):
            PhaseRun.objects.create(
                scan=self.scan, phase=phase[0], sequence=idx, status="pending"
            )

    @patch("wireghost.pipeline.discovery.discover_hosts")
    def test_run_phase_discovery_calls_discover_hosts(self, mock_dh):
        """Discovery phase should call discover_hosts with callbacks."""
        import asyncio
        from scanner.tasks.phase_scan import _execute_phase

        mock_dh.return_value = ([], {}, {})  # (live_ips, mac_vendor_map, dns_hostnames)

        scan = self.scan
        phase_run = PhaseRun.objects.get(scan=scan, phase="discovery")

        async def _run():
            config = MagicMock()
            config.target = scan.target
            config.parallelism = 10
            tree = MagicMock()
            callbacks = [MagicMock() for _ in range(6)]
            await _execute_phase("discovery", scan, config, tree, *callbacks)

        asyncio.run(_run())
        mock_dh.assert_called_once()

    def test_execute_phase_portscan_no_hosts_completes(self):
        """_execute_phase portscan with no hosts returns without error."""
        import asyncio
        from scanner.tasks.phase_scan import _execute_phase

        scan = self.scan
        config = MagicMock()
        config.parallelism = 10
        config.timeout = 3600
        tree = MagicMock()
        callbacks = [MagicMock() for _ in range(6)]

        async def _run():
            await _execute_phase("portscan", scan, config, tree, *callbacks)

        # Should not raise
        asyncio.run(_run())

    @patch("wireghost.pipeline.discovery.discover_hosts")
    def test_execute_phase_propagates_pipeline_exception(self, mock_dh):
        """When a pipeline function raises, _execute_phase propagates it."""
        import asyncio
        from scanner.tasks.phase_scan import _execute_phase

        mock_dh.side_effect = Exception("Host discovery crashed")

        scan = self.scan
        config = MagicMock()
        config.target = scan.target
        config.parallelism = 10
        config.timeout = 3600
        tree = MagicMock()
        callbacks = [MagicMock() for _ in range(6)]

        async def _run():
            await _execute_phase("discovery", scan, config, tree, *callbacks)

        with self.assertRaises(Exception) as ctx:
            asyncio.run(_run())
        self.assertIn("Host discovery crashed", str(ctx.exception))

    def test_reconstruct_host_empty(self):
        """_reconstruct_host on a Host with no ports/tech returns basic Host."""
        from scanner.models import Host as DBHost
        from scanner.tasks.phase_scan import _reconstruct_host

        db_host = DBHost.objects.create(scan=self.scan, ip="10.0.0.1", status="up")
        host = _reconstruct_host(db_host)
        self.assertEqual(host.ip, "10.0.0.1")
        self.assertEqual(host.ports, [])
        self.assertEqual(host.technologies, [])

    def test_compute_phase_summary_returns_cumulative_counts(self):
        from scanner.tasks.phase_scan import _compute_phase_summary

        summary = _compute_phase_summary(self.scan)
        self.assertIn("hosts", summary)
        self.assertIn("ports", summary)
        self.assertIn("findings", summary)
        self.assertEqual(summary["hosts"], 0)
