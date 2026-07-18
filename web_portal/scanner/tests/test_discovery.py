"""Tests for discovery scan API endpoints and Celery task.

Covers: create, status, cancel, retry, export, rate limiting, task
discovery phases, and SSRF input validation specific to discovery scans.
"""
import csv
import io
import json
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase

from scanner.models import Scan

User = get_user_model()


class DiscoveryAPITests(TestCase):
    """API-level tests — Celery task dispatch is mocked out."""

    def setUp(self):
        self.owner = User.objects.create_superuser(
            username="owner", password="pw-owner-123!", email="owner@example.com"
        )
        self.client = Client()
        self.client.force_login(self.owner)

    def _create(self, **overrides):
        data = {
            "target": "10.0.0.0/24",
            "scan_type": "discovery",
            "parallelism": 10,
        }
        data.update(overrides)
        return self.client.post(
            "/api/scans/",
            data=json.dumps(data),
            content_type="application/json",
        )

    # ── Create ──────────────────────────────────────────────────────────

    @patch("scanner.tasks.discovery.run_discovery_scan.delay")
    def test_create_discovery_scan_dispatches_correct_task(self, mock_delay):
        mock_delay.return_value = MagicMock(id="task-disc-1")
        res = self._create()
        self.assertEqual(res.status_code, 201)
        mock_delay.assert_called_once()
        body = res.json()
        self.assertEqual(body["scan_type"], "discovery")
        self.assertEqual(body["status"], "running")

    @patch("scanner.tasks.discovery.run_discovery_scan.delay")
    def test_create_discovery_scan_persists_to_db(self, mock_delay):
        mock_delay.return_value = MagicMock(id="task-disc-2")
        self._create(name="Office Discovery")
        scan = Scan.objects.first()
        self.assertEqual(scan.name, "Office Discovery")
        self.assertEqual(scan.scan_type, "discovery")
        self.assertEqual(scan.celery_task_id, "task-disc-2")

    @patch("scanner.tasks.discovery.run_discovery_scan.delay")
    def test_create_discovery_scan_with_custom_parallelism(self, mock_delay):
        mock_delay.return_value = MagicMock(id="task-disc-3")
        self._create(parallelism=50, timeout=7200)
        scan = Scan.objects.first()
        self.assertEqual(scan.parallelism, 50)
        self.assertEqual(scan.timeout, 7200)

    @patch("scanner.tasks.discovery.run_discovery_scan.delay")
    def test_create_discovery_with_scan_unresponsive(self, mock_delay):
        mock_delay.return_value = MagicMock(id="task-disc-4")
        self._create(scan_unresponsive=True)
        scan = Scan.objects.first()
        self.assertTrue(scan.scan_unresponsive)

    # ── Status / discovery endpoint ─────────────────────────────────────

    @patch("scanner.tasks.discovery.run_discovery_scan.delay")
    def test_discovery_endpoint_returns_live_hosts(self, mock_delay):
        mock_delay.return_value = MagicMock(id="task-disc-5")
        res = self._create(target="192.168.1.0/24")
        scan_id = res.json()["id"]
        status_res = self.client.get(f"/api/scans/{scan_id}/discovery/")
        self.assertEqual(status_res.status_code, 200)
        body = status_res.json()
        self.assertEqual(body["scan_id"], scan_id)
        self.assertEqual(body["target"], "192.168.1.0/24")
        self.assertIn("hosts", body)
        self.assertIn("live_hosts", body)

    # ── Cancel ──────────────────────────────────────────────────────────

    @patch("scanner.tasks.discovery.run_discovery_scan.delay")
    @patch("wireghost_web.celery.app.control.revoke")
    def test_cancel_running_discovery_scan(self, mock_revoke, mock_delay):
        mock_delay.return_value = MagicMock(id="task-disc-c")
        res = self._create()
        scan_id = res.json()["id"]
        cancel_res = self.client.post(f"/api/scans/{scan_id}/cancel/")
        self.assertEqual(cancel_res.status_code, 200)
        scan = Scan.objects.get(id=scan_id)
        self.assertEqual(scan.status, "cancelled")

    # ── Retry ───────────────────────────────────────────────────────────

    @patch("scanner.tasks.discovery.run_discovery_scan.delay")
    def test_retry_failed_discovery_scan(self, mock_delay):
        mock_delay.return_value = MagicMock(id="task-disc-r")
        res = self._create()
        scan_id = res.json()["id"]
        Scan.objects.filter(id=scan_id).update(status="failed", error_message="timeout")
        retry_res = self.client.post(f"/api/scans/{scan_id}/retry/")
        self.assertEqual(retry_res.status_code, 200)
        scan = Scan.objects.get(id=scan_id)
        self.assertEqual(scan.status, "running")
        self.assertEqual(scan.error_message, "")

    def test_retry_completed_scan_rejected(self):
        scan = Scan.objects.create(
            name="Done", target="10.0.0.0/24", scan_type="discovery",
            status="completed", created_by=self.owner,
        )
        res = self.client.post(f"/api/scans/{scan.id}/retry/")
        self.assertEqual(res.status_code, 400)

    # ── Export ──────────────────────────────────────────────────────────

    def test_discovery_export_json(self):
        from scanner.models import Host
        scan = Scan.objects.create(
            name="Export Me", target="10.0.0.0/24", scan_type="discovery",
            status="completed", hosts_count=2, created_by=self.owner,
        )
        Host.objects.create(scan=scan, ip="10.0.0.1", hostname="dc01.lab",
                            mac_address="aa:bb:cc:dd:ee:ff", vendor="Intel",
                            status="up", current_phase="discovery", ports_count=0)
        Host.objects.create(scan=scan, ip="10.0.0.2", status="up",
                            current_phase="discovery", ports_count=0)
        res = self.client.get(f"/api/scans/{scan.id}/discovery_export/?export=json")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(len(body["hosts"]), 2)
        self.assertEqual(body["hosts_found"], 2)

    def test_discovery_export_csv(self):
        from scanner.models import Host
        scan = Scan.objects.create(
            name="CSV Export", target="10.1.0.0/24", scan_type="discovery",
            status="completed", hosts_count=1, created_by=self.owner,
        )
        Host.objects.create(scan=scan, ip="10.1.0.1", hostname="web01",
                            mac_address="11:22:33:44:55:66", vendor="Dell",
                            status="up", current_phase="discovery", ports_count=0)
        scan_id = scan.id
        res = self.client.get(f"/api/scans/{scan_id}/discovery_export/?export=csv")
        self.assertEqual(res.status_code, 200)
        reader = csv.DictReader(io.StringIO(res.json()["csv"]))
        rows = list(reader)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ip"], "10.1.0.1")
        self.assertEqual(rows[0]["hostname"], "web01")

    def test_discovery_export_invalid_format(self):
        scan = Scan.objects.create(
            name="Bad", target="10.0.0.0/24", scan_type="discovery",
            status="completed", created_by=self.owner,
        )
        res = self.client.get(f"/api/scans/{scan.id}/discovery_export/?export=xml")
        self.assertEqual(res.status_code, 400)

    # ── Rate limiting ───────────────────────────────────────────────────

    @patch("scanner.tasks.discovery.run_discovery_scan.delay")
    def test_discovery_concurrency_limit(self, mock_delay):
        mock_delay.return_value = MagicMock(id="t")
        # Create 3 running discovery scans
        for i in range(3):
            Scan.objects.create(
                name=f"Running {i}", target=f"10.0.{i}.0/24",
                scan_type="discovery", status="running", created_by=self.owner,
            )
        res = self._create()
        self.assertEqual(res.status_code, 429)
        self.assertIn("discovery", res.json()["error"].lower())

    @patch("scanner.tasks.discovery.run_discovery_scan.delay")
    def test_general_concurrency_limit_still_enforced(self, mock_delay):
        mock_delay.return_value = MagicMock(id="t")
        for i in range(5):
            Scan.objects.create(
                name=f"Scan {i}", target=f"10.0.{i}.0/24",
                scan_type="full", status="running", created_by=self.owner,
            )
        res = self._create()
        self.assertEqual(res.status_code, 429)

    # ── SSRF validation (reuses existing validate_target) ──────────────

    def test_discovery_rejects_localhost(self):
        res = self._create(target="127.0.0.1")
        self.assertEqual(res.status_code, 400)

    def test_discovery_rejects_cloud_metadata(self):
        res = self._create(target="169.254.169.254")
        self.assertEqual(res.status_code, 400)

    def test_discovery_rejects_hex_notation(self):
        res = self._create(target="0x7f000001")
        self.assertEqual(res.status_code, 400)

    def test_discovery_rejects_octal_notation(self):
        res = self._create(target="127.0.0.01")
        self.assertEqual(res.status_code, 400)

    def test_discovery_accepts_valid_cidr(self):
        with patch("scanner.tasks.discovery.run_discovery_scan.delay") as m:
            m.return_value = MagicMock(id="ok")
            res = self._create(target="10.10.0.0/16")
            self.assertEqual(res.status_code, 201)

    def test_discovery_accepts_comma_separated_targets(self):
        with patch("scanner.tasks.discovery.run_discovery_scan.delay") as m:
            m.return_value = MagicMock(id="ok")
            res = self._create(target="10.0.0.0/24, 192.168.1.0/24", name="Multi Target Scan")
            self.assertEqual(res.status_code, 201)

    def test_discovery_rejects_empty_target(self):
        res = self._create(target="")
        self.assertEqual(res.status_code, 400)

    # ── History / listing ───────────────────────────────────────────────

    @patch("scanner.tasks.discovery.run_discovery_scan.delay")
    def test_discovery_scans_appear_in_scan_list(self, mock_delay):
        mock_delay.return_value = MagicMock(id="t-list")
        self._create(name="Disc History")
        res = self.client.get("/api/scans/")
        self.assertEqual(res.status_code, 200)
        results = res.json().get("results", res.json())
        self.assertTrue(any(s["scan_type"] == "discovery" for s in results))


class DiscoveryTaskTests(TestCase):
    """Unit tests for the run_discovery_scan Celery task.

    The task spawns a daemon thread for DB writes — all tests mock
    threading.Thread so no concurrent SQLite writes occur.  Host rows
    that the daemon would create are verified indirectly via the task
    result and scan state rather than querying the DB directly.
    """

    def setUp(self):
        self.owner = User.objects.create_superuser(
            username="owner", password="pw", email="o@ex.com"
        )

    @patch("scanner.tasks.discovery.threading.Thread")
    @patch("scanner.tasks.discovery.asyncio.run")
    def test_task_creates_hosts_on_discovery_complete(self, mock_async_run, mock_thread):
        from scanner.tasks.discovery import run_discovery_scan

        scan = Scan.objects.create(
            name="Task Test", target="10.0.0.0/24", scan_type="discovery",
            status="pending", created_by=self.owner, output_dir="/tmp/test-disc",
        )

        mock_async_run.return_value = (
            ["10.0.0.1", "10.0.0.2"],
            {"10.0.0.1": ("aa:bb:cc:dd:ee:ff", "Intel"),
             "10.0.0.2": ("11:22:33:44:55:66", "Dell")},
            {"10.0.0.1": "dc01.lab"},
            {},  # method_map
            {},  # tool_provenance
        )

        result = run_discovery_scan(str(scan.id))

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["hosts_found"], 2)

        scan.refresh_from_db()
        self.assertEqual(scan.status, "completed")

    @patch("scanner.tasks.discovery.threading.Thread")
    @patch("scanner.tasks.discovery.asyncio.run")
    def test_task_sets_failed_status_on_exception(self, mock_async_run, mock_thread):
        from scanner.tasks.discovery import run_discovery_scan

        scan = Scan.objects.create(
            name="Fail Task", target="10.0.0.0/24", scan_type="discovery",
            status="pending", created_by=self.owner, output_dir="/tmp/test-disc",
        )

        mock_async_run.side_effect = RuntimeError("nmap crashed")

        result = run_discovery_scan(str(scan.id))

        scan.refresh_from_db()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(scan.status, "failed")
        self.assertIn("nmap crashed", scan.error_message)

    @patch("scanner.tasks.discovery.threading.Thread")
    @patch("scanner.tasks.discovery.asyncio.run")
    def test_task_handles_empty_discovery(self, mock_async_run, mock_thread):
        from scanner.tasks.discovery import run_discovery_scan
        from scanner.models import Host

        scan = Scan.objects.create(
            name="Empty", target="10.99.0.0/24", scan_type="discovery",
            status="pending", created_by=self.owner, output_dir="/tmp/test-disc",
        )

        mock_async_run.return_value = ([], {}, {}, {}, {})

        result = run_discovery_scan(str(scan.id))

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["hosts_found"], 0)
        self.assertEqual(Host.objects.filter(scan=scan).count(), 0)

    @patch("scanner.tasks.discovery.threading.Thread")
    @patch("scanner.tasks.discovery.asyncio.run")
    def test_task_updates_progress_during_discovery(self, mock_async_run, mock_thread):
        from scanner.tasks.discovery import run_discovery_scan

        scan = Scan.objects.create(
            name="Progress", target="10.0.0.0/24", scan_type="discovery",
            status="pending", created_by=self.owner, output_dir="/tmp/test-disc",
        )

        mock_async_run.return_value = (
            ["10.0.0.1"],
            {"10.0.0.1": ("aa:bb:cc:dd:ee:ff", "Intel")},
            {},
            {},  # method_map
            {},  # tool_provenance
        )

        result = run_discovery_scan(str(scan.id))

        self.assertEqual(result["status"], "completed")
        scan.refresh_from_db()
        self.assertEqual(scan.status, "completed")
        self.assertEqual(scan.current_phase, "discovery")
