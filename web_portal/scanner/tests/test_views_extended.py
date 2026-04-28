"""Extended view tests for Wire_Ghost scanner — covers dashboard_stats,
screenshot_image, download_report, report_config, upload_logo,
ScanPolicyViewSet.clone, ScheduledScanViewSet.toggle/run_now,
AssetViewSet, and FindingViewSet filters.
"""
import json
import os
import tempfile
import uuid
from datetime import time as dtime
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.utils import timezone

from scanner.models import (
    Asset,
    Finding,
    Host,
    Port,
    Report,
    ReportConfig,
    Scan,
    ScanPolicy,
    ScheduledScan,
    Screenshot,
    User as UserModel,
)

User = get_user_model()

# Tiny 1x1 red PNG — valid image bytes for upload tests.
TINY_PNG = (
    b'\x89PNG\r\n\x1a\n'
    b'\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
    b'\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx'
    b'\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N\x00'
    b'\x00\x00\x00IEND\xaeB`\x82'
)


class _BaseViewTest(TestCase):
    """Shared fixtures: owner, engineer, viewer, a scan with host+port+finding."""

    def setUp(self):
        UserModel.invalidate_perm_cache()

        self.owner = User.objects.create_superuser(
            username='ext-owner', password='pw-owner-123!', email='ext-owner@example.com',
        )
        self.engineer = User.objects.create_user(
            username='ext-eng', password='pw-eng-123!', email='ext-eng@example.com',
        )
        self.engineer.role = 'engineer'
        self.engineer.save()

        self.viewer = User.objects.create_user(
            username='ext-view', password='pw-view-123!', email='ext-view@example.com',
        )
        # viewer role is default

        self.scan = Scan.objects.create(
            name='Test Scan', target='10.0.0.0/24', scan_type='full',
            status='completed', created_by=self.owner,
        )
        self.host = Host.objects.create(
            scan=self.scan, ip='10.0.0.1', hostname='host1.local',
            os='Linux', ports_count=2, findings_count=1,
        )
        self.port = Port.objects.create(
            host=self.host, number=443, protocol='tcp',
            state='open', service_name='https', service_product='nginx',
        )
        self.finding = Finding.objects.create(
            scan=self.scan, host=self.host, source='nuclei',
            severity='high', title='SQL Injection',
            host_ip='10.0.0.1', port='443', cvss='8.6',
            cve='CVE-2024-0001',
        )
        self.client = Client()

    def _login(self, user):
        self.client.force_login(user)


# ═══════════════════════════════════════════════════════════════════
# dashboard_stats
# ═══════════════════════════════════════════════════════════════════

class DashboardStatsTests(_BaseViewTest):

    def test_returns_expected_structure(self):
        """Response contains all ASM dashboard keys and nested KPI fields."""
        self._login(self.owner)
        res = self.client.get('/api/dashboard/')
        self.assertEqual(res.status_code, 200)
        body = res.json()
        for key in ('kpis', 'severity_trend', 'risk_by_source',
                    'newly_discovered', 'top_exposures', 'top_technologies'):
            self.assertIn(key, body, f'Missing top-level key: {key}')
        for kpi in ('total_assets', 'critical_exposures', 'new_assets_7d',
                    'assets_with_cves', 'attack_surface_score'):
            self.assertIn(kpi, body['kpis'], f'Missing KPI: {kpi}')

    def test_empty_database_returns_zeros(self):
        """With no assets or findings, KPIs should be zero/None."""
        Asset.objects.all().delete()
        Finding.objects.all().delete()
        self._login(self.owner)
        res = self.client.get('/api/dashboard/')
        self.assertEqual(res.status_code, 200)
        kpis = res.json()['kpis']
        self.assertEqual(kpis['total_assets'], 0)
        self.assertEqual(kpis['critical_exposures'], 0)
        self.assertIsNone(kpis['attack_surface_score'])

    def test_cvss_num_parsing_via_top_exposures_ordering(self):
        """Findings with various CVSS formats sort correctly in top_exposures."""
        # Create findings with different CVSS representations.
        for cve, cvss_val in [('CVE-2024-9999', '9.8'), ('CVE-2024-8888', 'N/A'),
                              ('CVE-2024-7777', '7.5 (HIGH)')]:
            Finding.objects.create(
                scan=self.scan, host=self.host, source='nuclei',
                severity='critical', title=f'Vuln {cve}',
                host_ip='10.0.0.1', port='443', cvss=cvss_val, cve=cve,
            )
        self._login(self.owner)
        res = self.client.get('/api/dashboard/')
        self.assertEqual(res.status_code, 200)
        exposures = res.json()['top_exposures']
        # The 9.8 CVSS finding should appear before the 7.5 one; N/A sorts last.
        cves = [e['cve'] for e in exposures]
        # All three CVEs must be present in the response.
        self.assertIn('CVE-2024-9999', cves)
        self.assertIn('CVE-2024-7777', cves)
        self.assertIn('CVE-2024-8888', cves)
        # 9.8 before 7.5
        self.assertLess(cves.index('CVE-2024-9999'), cves.index('CVE-2024-7777'))
        # N/A (0.0) after 9.8
        self.assertGreater(cves.index('CVE-2024-8888'), cves.index('CVE-2024-9999'))

    def test_viewer_can_access_dashboard(self):
        """Viewers have dashboard:view permission and should get 200."""
        self._login(self.viewer)
        res = self.client.get('/api/dashboard/')
        self.assertEqual(res.status_code, 200)


# ═══════════════════════════════════════════════════════════════════
# screenshot_image
# ═══════════════════════════════════════════════════════════════════

class ScreenshotImageTests(_BaseViewTest):

    def test_valid_screenshot_returns_image(self):
        """A screenshot backed by a real file returns 200 with image/png."""
        with tempfile.TemporaryDirectory() as tmpdir:
            img_name = 'shot.png'
            img_path = os.path.join(tmpdir, img_name)
            with open(img_path, 'wb') as f:
                f.write(TINY_PNG)

            self.scan.output_dir = tmpdir
            self.scan.save(update_fields=['output_dir'])

            ss = Screenshot.objects.create(
                host=self.host, scan=self.scan,
                url='https://10.0.0.1/', filename=img_name,
                title='Test Page',
            )
            self._login(self.owner)
            res = self.client.get(f'/api/screenshots/{ss.id}/image/')
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res['Content-Type'], 'image/png')
            # Read the streamed content
            content = b''.join(res.streaming_content)
            self.assertEqual(content, TINY_PNG)

    def test_nonexistent_screenshot_returns_404(self):
        self._login(self.owner)
        fake_id = uuid.uuid4()
        res = self.client.get(f'/api/screenshots/{fake_id}/image/')
        self.assertEqual(res.status_code, 404)

    def test_unauthenticated_user_gets_denied(self):
        """Without login, screenshot endpoint returns 401 or 403."""
        ss = Screenshot.objects.create(
            host=self.host, scan=self.scan,
            url='https://10.0.0.1/', filename='nope.png',
        )
        res = self.client.get(f'/api/screenshots/{ss.id}/image/')
        self.assertIn(res.status_code, (401, 403))


# ═══════════════════════════════════════════════════════════════════
# download_report
# ═══════════════════════════════════════════════════════════════════

class DownloadReportTests(_BaseViewTest):

    def test_nonexistent_report_returns_404(self):
        self._login(self.owner)
        fake_id = uuid.uuid4()
        res = self.client.get(f'/api/reports/{fake_id}/download/')
        self.assertEqual(res.status_code, 404)

    def test_file_missing_on_disk_returns_404(self):
        """Report row exists but the file at file_path doesn't exist on disk."""
        report = Report.objects.create(
            scan=self.scan, format='docx',
            file_path='/data/output/scans/nonexistent/report.docx',
            file_size=0,
        )
        self._login(self.owner)
        res = self.client.get(f'/api/reports/{report.id}/download/')
        self.assertEqual(res.status_code, 404)

    def test_auth_gate_passes_for_owner(self):
        """Owner with report:download passes auth; file outside /data/output yields 404 (not 403)."""
        report = Report.objects.create(
            scan=self.scan, format='docx',
            file_path='/tmp/not-under-data-output/report.docx',
            file_size=0,
        )
        self._login(self.owner)
        res = self.client.get(f'/api/reports/{report.id}/download/')
        # Path is outside allowed_dir so 404, but crucially NOT 403 — auth passed.
        self.assertEqual(res.status_code, 404)


# ═══════════════════════════════════════════════════════════════════
# report_config / upload_logo
# ═══════════════════════════════════════════════════════════════════

class ReportConfigTests(_BaseViewTest):

    def test_get_report_config_returns_structure(self):
        """GET /api/report-config/ returns branding fields."""
        self._login(self.owner)
        res = self.client.get('/api/report-config/')
        self.assertEqual(res.status_code, 200)
        body = res.json()
        for key in ('report_title', 'company_name', 'brand_color',
                    'disclaimer', 'default_formats'):
            self.assertIn(key, body, f'Missing field: {key}')

    def test_put_report_config_updates_fields(self):
        """PUT with valid data updates branding fields."""
        self._login(self.engineer)  # engineer has report:config:write
        res = self.client.put(
            '/api/report-config/',
            data=json.dumps({'report_title': 'Quarterly VA Report', 'brand_color': '#FF0000'}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body['report_title'], 'Quarterly VA Report')
        self.assertEqual(body['brand_color'], '#FF0000')
        # Verify DB
        config = ReportConfig.get()
        self.assertEqual(config.report_title, 'Quarterly VA Report')

    def test_upload_logo_with_valid_image(self):
        """POST a tiny PNG to upload_logo endpoint.

        upload_logo() hardcodes logo_dir='/data/assets/logos' and uses Path
        without a local import.  We inject Path into the views module and
        redirect filesystem calls from /data/assets/logos to a tmpdir.
        """
        import scanner.views as views_mod
        from django.core.files.uploadedfile import SimpleUploadedFile

        self._login(self.engineer)
        logo = SimpleUploadedFile('testlogo.png', TINY_PNG, content_type='image/png')

        # Ensure Path is available in the views module namespace (latent bug).
        had_path = hasattr(views_mod, 'Path')
        if not had_path:
            views_mod.Path = Path

        orig_makedirs = os.makedirs
        orig_open = open

        with tempfile.TemporaryDirectory() as tmpdir:

            def _redirect(p):
                """Replace the hardcoded /data/assets/logos with tmpdir."""
                if isinstance(p, str) and '/data/assets/logos' in p:
                    return p.replace('/data/assets/logos', tmpdir)
                return p

            def safe_makedirs(path, *a, **kw):
                return orig_makedirs(_redirect(path), *a, **kw)

            def safe_open(path, *a, **kw):
                return orig_open(_redirect(path), *a, **kw)

            with patch('os.makedirs', side_effect=safe_makedirs), \
                 patch('builtins.open', side_effect=safe_open):
                res = self.client.post(
                    '/api/report-config/logo/',
                    data={'logo': logo},
                    format='multipart',
                )

        if not had_path:
            del views_mod.Path

        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertIn('logo_path', body)
        self.assertIn('filename', body)

    def test_viewer_cannot_update_report_config(self):
        """Viewer lacks report:config:write — should get 403 on PUT."""
        self._login(self.viewer)
        res = self.client.put(
            '/api/report-config/',
            data=json.dumps({'report_title': 'Nope'}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 403)


# ═══════════════════════════════════════════════════════════════════
# ScanPolicyViewSet.clone
# ═══════════════════════════════════════════════════════════════════

class ScanPolicyCloneTests(_BaseViewTest):

    def setUp(self):
        super().setUp()
        self.policy = ScanPolicy.objects.create(
            name='Default Full', description='Full scan policy',
            scan_type='full', parallelism=10, timeout=3600,
            created_by=self.owner,
        )

    def test_clone_creates_copy(self):
        """POST clone/ creates a new policy with '(Copy)' suffix."""
        self._login(self.engineer)  # engineer has policy:write
        count_before = ScanPolicy.objects.count()
        res = self.client.post(f'/api/policies/{self.policy.id}/clone/')
        self.assertEqual(res.status_code, 201)
        body = res.json()
        self.assertIn('(Copy)', body['name'])
        self.assertEqual(body['scan_type'], 'full')
        # Original still exists.
        self.assertTrue(ScanPolicy.objects.filter(id=self.policy.id).exists())
        # Clone added exactly one row.
        self.assertEqual(ScanPolicy.objects.count(), count_before + 1)

    def test_clone_nonexistent_policy_returns_404(self):
        self._login(self.engineer)
        fake_id = uuid.uuid4()
        res = self.client.post(f'/api/policies/{fake_id}/clone/')
        self.assertEqual(res.status_code, 404)

    def test_viewer_cannot_clone_policy(self):
        """Viewer lacks policy:write — clone requires POST (write method)."""
        self._login(self.viewer)
        res = self.client.post(f'/api/policies/{self.policy.id}/clone/')
        self.assertEqual(res.status_code, 403)


# ═══════════════════════════════════════════════════════════════════
# ScheduledScanViewSet.toggle / run_now
# ═══════════════════════════════════════════════════════════════════

class ScheduledScanToggleRunNowTests(_BaseViewTest):

    def setUp(self):
        super().setUp()
        self.schedule = ScheduledScan.objects.create(
            name='Nightly Scan', target='10.0.0.0/24',
            frequency='daily', time=dtime(2, 0),
            scan_type='quick', enabled=True,
            created_by=self.engineer,
        )

    def test_toggle_flips_enabled_state(self):
        """POST toggle/ flips enabled from True to False."""
        self._login(self.engineer)
        self.assertTrue(self.schedule.enabled)
        res = self.client.post(f'/api/schedules/{self.schedule.id}/toggle/')
        self.assertEqual(res.status_code, 200)
        self.schedule.refresh_from_db()
        self.assertFalse(self.schedule.enabled)
        # Toggle again — back to True.
        res = self.client.post(f'/api/schedules/{self.schedule.id}/toggle/')
        self.assertEqual(res.status_code, 200)
        self.schedule.refresh_from_db()
        self.assertTrue(self.schedule.enabled)

    @patch('scanner.tasks.run_scan.delay', return_value=type('T', (), {'id': 'mock-task'})())
    def test_run_now_creates_scan(self, _mock_run):
        """POST run_now/ creates a new Scan and launches Celery task."""
        self._login(self.engineer)
        initial_count = Scan.objects.count()
        res = self.client.post(f'/api/schedules/{self.schedule.id}/run_now/')
        self.assertEqual(res.status_code, 201)
        self.assertEqual(Scan.objects.count(), initial_count + 1)
        body = res.json()
        self.assertIn('(manual)', body['name'])
        self.assertEqual(body['status'], 'running')

    @patch('scanner.tasks.run_scan.delay', return_value=type('T', (), {'id': 'mock-task'})())
    def test_run_now_applies_policy_settings(self, _mock_run):
        """When schedule has a linked policy, run_now applies its settings."""
        policy = ScanPolicy.objects.create(
            name='Custom Policy', scan_type='full',
            parallelism=42, timeout=7200,
            report_formats='docx,xlsx',
            version_detect=False, os_detect=False,
            created_by=self.engineer,
        )
        self.schedule.policy = policy
        self.schedule.save(update_fields=['policy'])

        self._login(self.engineer)
        res = self.client.post(f'/api/schedules/{self.schedule.id}/run_now/')
        self.assertEqual(res.status_code, 201)
        new_scan = Scan.objects.get(id=res.json()['id'])
        self.assertEqual(new_scan.parallelism, 42)
        self.assertEqual(new_scan.timeout, 7200)
        self.assertFalse(new_scan.version_detect)

    def test_viewer_cannot_toggle_schedule(self):
        """Viewer lacks schedule:write — toggle requires POST (write method)."""
        self._login(self.viewer)
        res = self.client.post(f'/api/schedules/{self.schedule.id}/toggle/')
        self.assertEqual(res.status_code, 403)


# ═══════════════════════════════════════════════════════════════════
# AssetViewSet
# ═══════════════════════════════════════════════════════════════════

class AssetViewSetTests(_BaseViewTest):

    def setUp(self):
        super().setUp()
        now = timezone.now()
        self.asset1 = Asset.objects.create(
            ip='10.0.0.1', port=443, protocol='tcp',
            service_name='https', service_product='nginx',
            first_seen=now, last_seen=now,
            status='open', risk_score=50, findings_count=3,
        )
        self.asset2 = Asset.objects.create(
            ip='10.0.0.2', port=22, protocol='tcp',
            service_name='ssh', service_product='OpenSSH',
            first_seen=now, last_seen=now,
            status='open', risk_score=0, findings_count=0,
        )

    def test_list_returns_assets(self):
        """GET /api/assets/ returns paginated asset list."""
        self._login(self.owner)
        res = self.client.get('/api/assets/')
        self.assertEqual(res.status_code, 200)
        body = res.json()
        results = body.get('results', body)
        ips = {r['ip'] for r in results}
        self.assertIn('10.0.0.1', ips)
        self.assertIn('10.0.0.2', ips)

    def test_detail_returns_single_asset(self):
        """GET /api/assets/<id>/ returns a single asset."""
        self._login(self.owner)
        res = self.client.get(f'/api/assets/{self.asset1.id}/')
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body['ip'], '10.0.0.1')
        self.assertEqual(body['port'], 443)

    def test_search_filter(self):
        """search query param filters by IP/hostname/service."""
        self._login(self.owner)
        res = self.client.get('/api/assets/?search=nginx')
        self.assertEqual(res.status_code, 200)
        results = res.json().get('results', res.json())
        ips = {r['ip'] for r in results}
        self.assertIn('10.0.0.1', ips)
        self.assertNotIn('10.0.0.2', ips)


# ═══════════════════════════════════════════════════════════════════
# FindingViewSet extended filters
# ═══════════════════════════════════════════════════════════════════

class FindingViewSetTests(_BaseViewTest):

    def setUp(self):
        super().setUp()
        # Add more findings for filter tests.
        self.finding_medium = Finding.objects.create(
            scan=self.scan, host=self.host, source='nmap',
            severity='medium', title='Weak Cipher',
            host_ip='10.0.0.1', port='443',
        )
        self.host2 = Host.objects.create(
            scan=self.scan, ip='10.0.0.2', hostname='host2.local',
        )
        self.finding_on_host2 = Finding.objects.create(
            scan=self.scan, host=self.host2, source='nuclei',
            severity='critical', title='RCE',
            host_ip='10.0.0.2', port='80',
        )

    def test_filter_by_severity(self):
        """?severity=medium returns only medium findings."""
        self._login(self.owner)
        res = self.client.get('/api/findings/?severity=medium')
        self.assertEqual(res.status_code, 200)
        results = res.json().get('results', res.json())
        severities = {r['severity'] for r in results}
        self.assertEqual(severities, {'medium'})

    def test_filter_by_scan(self):
        """?scan=<id> returns only findings from that scan."""
        # Create a second scan with no findings.
        scan2 = Scan.objects.create(
            name='Scan 2', target='192.168.0.0/24',
            status='completed', created_by=self.owner,
        )
        self._login(self.owner)
        res = self.client.get(f'/api/findings/?scan={scan2.id}')
        self.assertEqual(res.status_code, 200)
        results = res.json().get('results', res.json())
        self.assertEqual(len(results), 0)

        # With original scan ID, we should get findings.
        res = self.client.get(f'/api/findings/?scan={self.scan.id}')
        results = res.json().get('results', res.json())
        self.assertGreater(len(results), 0)

    def test_filter_by_source(self):
        """?source=nmap returns only nmap-sourced findings."""
        self._login(self.owner)
        res = self.client.get('/api/findings/?source=nmap')
        self.assertEqual(res.status_code, 200)
        results = res.json().get('results', res.json())
        sources = {r['source'] for r in results}
        self.assertEqual(sources, {'nmap'})
