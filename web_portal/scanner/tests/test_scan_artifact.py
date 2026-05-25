"""Tests for ScanArtifact model, serializers, ViewSet, and queue handler logic."""
from django.contrib.auth import get_user_model
from django.test import Client, TestCase

from scanner.models import Host as DBHost, Scan, ScanArtifact

User = get_user_model()


# ── Helpers ──

def _make_scan_and_host():
    owner = User.objects.create_superuser(
        username="qa-owner", password="pw-qa-123!", email="qa@test.com"
    )
    scan = Scan.objects.create(
        name="artifact-test", target="192.168.1.0/24",
        status="completed", created_by=owner,
    )
    host = DBHost.objects.create(
        scan=scan, ip="192.168.1.10", hostname="web.local", status="up",
    )
    return owner, scan, host


def _artifact_create_from_queue_item(item, scan):
    """Replicate the queue handler logic: resolve host FK by scan+ip, create record.

    The actual handler lives inline inside ``_progress_thread`` in
    ``scanner/tasks/__init__.py`` and is not importable.  This helper runs
    the same logic so we can test it in isolation.
    """
    _, host_ip, tool, name, content, content_type = item
    db_host = DBHost.objects.filter(scan_id=scan.id, ip=host_ip).first()
    return ScanArtifact.objects.create(
        scan=scan,
        host=db_host,
        tool=tool,
        name=name,
        content=content,
        content_type=content_type,
        size=len(content),
    )


# ── Model Tests ──

class ScanArtifactModelTests(TestCase):

    def setUp(self):
        self.owner, self.scan, self.host = _make_scan_and_host()

    def test_creation_with_host(self):
        art = ScanArtifact.objects.create(
            scan=self.scan, host=self.host, tool="nmap",
            name="scan.xml", content="<nmaprun>...</nmaprun>",
            content_type="text/xml", size=42,
        )
        self.assertEqual(art.tool, "nmap")
        self.assertEqual(art.name, "scan.xml")
        self.assertEqual(art.content, "<nmaprun>...</nmaprun>")
        self.assertEqual(art.content_type, "text/xml")
        self.assertEqual(art.size, 42)
        self.assertEqual(art.host, self.host)
        self.assertEqual(art.scan, self.scan)
        self.assertTrue(str(art.id))  # UUIDv7

    def test_creation_without_host(self):
        art = ScanArtifact.objects.create(
            scan=self.scan, host=None, tool="report",
            name="summary.json", content='{"key":"val"}',
        )
        self.assertIsNone(art.host)
        self.assertEqual(art.content_type, "text/plain")  # default
        self.assertEqual(art.size, 0)  # default

    def test_str_with_host(self):
        art = ScanArtifact.objects.create(
            scan=self.scan, host=self.host, tool="nmap",
            name="scan.xml", content="data",
        )
        self.assertEqual(str(art), "nmap/scan.xml @ 192.168.1.10")

    def test_str_without_host(self):
        art = ScanArtifact.objects.create(
            scan=self.scan, host=None, tool="report",
            name="summary.json", content="{}",
        )
        self.assertEqual(str(art), "report/summary.json")

    def test_ordering_newest_first(self):
        art1 = ScanArtifact.objects.create(
            scan=self.scan, host=self.host, tool="a", name="old.txt", content="1",
        )
        art2 = ScanArtifact.objects.create(
            scan=self.scan, host=self.host, tool="b", name="new.txt", content="2",
        )
        ids = list(ScanArtifact.objects.values_list("id", flat=True))
        self.assertLess(ids.index(art2.id), ids.index(art1.id))

    def test_cascade_on_scan_delete(self):
        ScanArtifact.objects.create(
            scan=self.scan, host=self.host, tool="x", name="f", content="c",
        )
        self.scan.delete()
        self.assertEqual(ScanArtifact.objects.count(), 0)

    def test_cascade_on_host_delete(self):
        art = ScanArtifact.objects.create(
            scan=self.scan, host=self.host, tool="x", name="f", content="c",
        )
        self.host.delete()
        # The artifact should be gone (CASCADE on host FK)
        self.assertFalse(ScanArtifact.objects.filter(id=art.id).exists())

    def test_scan_level_artifact_survives_host_cascade(self):
        """Artifact with host=None is unaffected by host deletion."""
        art = ScanArtifact.objects.create(
            scan=self.scan, host=None, tool="x", name="f", content="c",
        )
        self.host.delete()
        self.assertTrue(ScanArtifact.objects.filter(id=art.id).exists())


# ── Serializer Tests ──

class ScanArtifactSerializerTests(TestCase):

    def setUp(self):
        self.owner, self.scan, self.host = _make_scan_and_host()
        self.art = ScanArtifact.objects.create(
            scan=self.scan, host=self.host, tool="nuclei",
            name="cve-2024.json", content='{"matched":"yes"}',
            content_type="application/json", size=1024,
        )

    def test_list_serializer_excludes_content(self):
        from scanner.serializers import ScanArtifactListSerializer
        ser = ScanArtifactListSerializer(self.art)
        data = ser.data
        self.assertNotIn("content", data)
        self.assertIn("tool", data)
        self.assertIn("name", data)
        self.assertIn("content_type", data)
        self.assertIn("size", data)
        self.assertIn("id", data)
        self.assertIn("scan", data)
        self.assertIn("host", data)

    def test_list_serializer_includes_host_ip(self):
        from scanner.serializers import ScanArtifactListSerializer
        ser = ScanArtifactListSerializer(self.art)
        self.assertEqual(ser.data["host_ip"], "192.168.1.10")

    def test_list_serializer_host_ip_null_host(self):
        from scanner.serializers import ScanArtifactListSerializer
        art_no_host = ScanArtifact.objects.create(
            scan=self.scan, host=None, tool="report",
            name="meta.json", content="{}",
        )
        ser = ScanArtifactListSerializer(art_no_host)
        self.assertEqual(ser.data["host_ip"], "")

    def test_detail_serializer_includes_content(self):
        from scanner.serializers import ScanArtifactSerializer
        ser = ScanArtifactSerializer(self.art)
        self.assertIn("content", ser.data)
        self.assertEqual(ser.data["content"], '{"matched":"yes"}')
        self.assertEqual(ser.data["host_ip"], "192.168.1.10")


# ── ViewSet Tests ──

class ScanArtifactViewSetTests(TestCase):

    def setUp(self):
        self.owner, self.scan, self.host = _make_scan_and_host()
        self.scan2 = Scan.objects.create(
            name="scan-two", target="10.0.0.0/24",
            status="completed", created_by=self.owner,
        )
        self.host2 = DBHost.objects.create(
            scan=self.scan2, ip="10.0.0.5", hostname="db.local", status="up",
        )
        self.art_a = ScanArtifact.objects.create(
            scan=self.scan, host=self.host, tool="nmap",
            name="scan.xml", content="<nmap/>", content_type="text/xml",
        )
        self.art_b = ScanArtifact.objects.create(
            scan=self.scan, host=self.host, tool="nuclei",
            name="cve.json", content="{}", content_type="application/json",
        )
        self.art_c = ScanArtifact.objects.create(
            scan=self.scan2, host=self.host2, tool="nmap",
            name="scan2.xml", content="<nmap2/>", content_type="text/xml",
        )
        self.art_no_host = ScanArtifact.objects.create(
            scan=self.scan, host=None, tool="report",
            name="report.json", content='{"sum":1}',
        )
        self.client = Client()
        self.client.force_login(self.owner)

    def _get_list(self, params=None):
        url = "/api/artifacts/"
        if params:
            qs = "&".join(f"{k}={v}" for k, v in params.items())
            url = f"{url}?{qs}"
        return self.client.get(url)

    @staticmethod
    def _results(res):
        """DRF DefaultRouter paginates: {count, results, ...}."""
        return res.json()["results"]

    # ── List endpoint ──

    def test_list_all(self):
        res = self._get_list()
        self.assertEqual(res.status_code, 200)
        self.assertEqual(len(self._results(res)), 4)

    def test_list_excludes_content(self):
        res = self._get_list()
        for item in self._results(res):
            self.assertNotIn("content", item)

    def test_list_includes_host_ip(self):
        res = self._get_list()
        for item in self._results(res):
            self.assertIn("host_ip", item)

    def test_filter_by_host(self):
        res = self._get_list({"host": str(self.host.id)})
        data = self._results(res)
        self.assertEqual(len(data), 2)
        host_ids = {item["host"] for item in data}
        self.assertEqual(host_ids, {str(self.host.id)})

    def test_filter_by_scan(self):
        res = self._get_list({"scan": str(self.scan2.id)})
        data = self._results(res)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["host_ip"], "10.0.0.5")

    def test_filter_by_tool(self):
        res = self._get_list({"tool": "nmap"})
        data = self._results(res)
        self.assertEqual(len(data), 2)
        for item in data:
            self.assertEqual(item["tool"], "nmap")

    def test_filter_by_tool_no_match(self):
        res = self._get_list({"tool": "nonexistent"})
        self.assertEqual(len(self._results(res)), 0)

    def test_filter_scan_and_tool_combined(self):
        res = self._get_list({"scan": str(self.scan.id), "tool": "nuclei"})
        data = self._results(res)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["name"], "cve.json")

    def test_list_includes_scan_level_artifacts(self):
        """Artifacts with host=None should appear in unfiltered list."""
        res = self._get_list()
        hostless = [item for item in self._results(res) if item["host"] is None]
        self.assertEqual(len(hostless), 1)
        self.assertEqual(hostless[0]["tool"], "report")

    # ── Detail endpoint ──

    def test_detail_includes_content(self):
        res = self.client.get(f"/api/artifacts/{self.art_a.id}/")
        self.assertEqual(res.status_code, 200)
        self.assertIn("content", res.json())
        self.assertEqual(res.json()["content"], "<nmap/>")

    def test_detail_404(self):
        res = self.client.get("/api/artifacts/00000000-0000-0000-0000-000000000000/")
        self.assertEqual(res.status_code, 404)

    # ── Read-only enforcement ──

    def test_post_forbidden(self):
        res = self.client.post("/api/artifacts/", data={}, content_type="application/json")
        self.assertEqual(res.status_code, 405)

    def test_put_forbidden(self):
        res = self.client.put(
            f"/api/artifacts/{self.art_a.id}/",
            data='{"tool":"x"}', content_type="application/json",
        )
        self.assertEqual(res.status_code, 405)

    def test_delete_forbidden(self):
        res = self.client.delete(f"/api/artifacts/{self.art_a.id}/")
        self.assertEqual(res.status_code, 405)

    # ── Permission ──

    def test_unauthenticated_denied(self):
        anon = Client()
        res = anon.get("/api/artifacts/")
        self.assertIn(res.status_code, (401, 403))

    def test_viewer_can_read_list(self):
        viewer = User.objects.create_user(
            username="viewer", password="pw-view-123!", email="v@test.com"
        )
        viewer.role = "viewer"
        viewer.save()
        self.client.force_login(viewer)
        res = self._get_list()
        self.assertEqual(res.status_code, 200)

    def test_viewer_can_read_detail(self):
        viewer = User.objects.create_user(
            username="viewer2", password="pw-view-123!", email="v2@test.com"
        )
        viewer.role = "viewer"
        viewer.save()
        self.client.force_login(viewer)
        res = self.client.get(f"/api/artifacts/{self.art_a.id}/")
        self.assertEqual(res.status_code, 200)


# ── Queue Handler Logic Tests ──

class ScanArtifactQueueHandlerTests(TestCase):

    def setUp(self):
        self.owner, self.scan, self.host = _make_scan_and_host()

    def test_handler_creates_record_with_host(self):
        """Replicate what the queue handler does with a known host IP."""
        art = _artifact_create_from_queue_item(
            ("artifact", "192.168.1.10", "nmap", "scan.xml",
             "<nmaprun/>", "text/xml"),
            self.scan,
        )
        self.assertEqual(art.tool, "nmap")
        self.assertEqual(art.name, "scan.xml")
        self.assertEqual(art.content, "<nmaprun/>")
        self.assertEqual(art.content_type, "text/xml")
        self.assertEqual(art.size, len("<nmaprun/>"))
        self.assertEqual(art.host, self.host)

    def test_handler_unknown_host_ip_null_host(self):
        """If host IP doesn't match any host in scan, host FK stays null."""
        art = _artifact_create_from_queue_item(
            ("artifact", "10.99.99.99", "enum4linux", "users.txt",
             "Administrator:500", "text/plain"),
            self.scan,
        )
        self.assertIsNone(art.host)
        self.assertEqual(art.size, len("Administrator:500"))

    def test_handler_multiple_artifacts_same_host(self):
        for i in range(3):
            _artifact_create_from_queue_item(
                ("artifact", "192.168.1.10", "test", f"file{i}.txt",
                 f"content-{i}", "text/plain"),
                self.scan,
            )
        self.assertEqual(
            ScanArtifact.objects.filter(scan=self.scan, host=self.host).count(), 3
        )

    def test_handler_computes_size_from_content(self):
        """size should be len(content) — the handler does size=len(content)."""
        content = "A" * 5000
        art = _artifact_create_from_queue_item(
            ("artifact", "192.168.1.10", "tool", "name.txt",
             content, "text/plain"),
            self.scan,
        )
        self.assertEqual(art.size, 5000)
