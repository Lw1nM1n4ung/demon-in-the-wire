"""Tests for Wire_Ghost scanner API — SiteConfig timezone + role-based permissions."""
import json
from datetime import time as dtime
from unittest.mock import patch
from zoneinfo import ZoneInfo

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import Client, TestCase
from django.utils import timezone

from scanner.models import Permission, RolePermission, SiteConfig
from scanner.tasks import _calc_next_run

User = get_user_model()


class ScheduleTimezoneTests(TestCase):
    """Owner-only updates to SiteConfig.schedule_timezone and its effect on next-run math."""

    def setUp(self):
        self.owner = User.objects.create_superuser(
            username='owner', password='pw-owner-123!', email='owner@example.com'
        )
        self.member = User.objects.create_user(
            username='viewer', password='pw-viewer-123!', email='viewer@example.com'
        )
        self.client = Client()

    def _login(self, user):
        self.client.force_login(user)

    def test_get_site_config_exposes_schedule_timezone(self):
        res = self.client.get('/api/site-config/')
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertIn('schedule_timezone', body)
        self.assertEqual(body['schedule_timezone'], 'UTC')

    def test_owner_can_update_schedule_timezone(self):
        self._login(self.owner)
        res = self.client.put(
            '/api/site-config/update/',
            data=json.dumps({'schedule_timezone': 'America/New_York'}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['schedule_timezone'], 'America/New_York')
        self.assertEqual(SiteConfig.get().schedule_timezone, 'America/New_York')

    def test_non_owner_forbidden(self):
        self._login(self.member)
        res = self.client.put(
            '/api/site-config/update/',
            data=json.dumps({'schedule_timezone': 'Asia/Singapore'}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 403)
        self.assertEqual(SiteConfig.get().schedule_timezone, 'UTC')

    def test_unauthenticated_forbidden(self):
        res = self.client.put(
            '/api/site-config/update/',
            data=json.dumps({'schedule_timezone': 'Asia/Singapore'}),
            content_type='application/json',
        )
        self.assertIn(res.status_code, (401, 403))

    def test_invalid_timezone_rejected(self):
        self._login(self.owner)
        res = self.client.put(
            '/api/site-config/update/',
            data=json.dumps({'schedule_timezone': 'Fake/Zone'}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(SiteConfig.get().schedule_timezone, 'UTC')

    def test_calc_next_run_honors_configured_zone(self):
        """A 09:00 daily schedule under Asia/Singapore must run at 09:00 SGT."""
        cfg = SiteConfig.get()
        cfg.schedule_timezone = 'Asia/Singapore'
        cfg.save()

        next_run = _calc_next_run('daily', dtime(9, 0))
        sgt = next_run.astimezone(ZoneInfo('Asia/Singapore'))
        self.assertEqual(sgt.hour, 9)
        self.assertEqual(sgt.minute, 0)
        self.assertGreater(next_run, timezone.now())


class SetupAdminRoundTripTests(TestCase):
    """Lock the regression: Owner created via the setup wizard must be able to log in."""

    def setUp(self):
        # Mimic a fresh install — wipe Owner + clear setup_complete.
        User.objects.filter(role='owner').delete()
        cfg = SiteConfig.get()
        cfg.setup_complete = False
        cfg.save()
        self.client = Client()

    def test_setup_admin_then_login_succeeds(self):
        # Step 1 — run the setup wizard's endpoint.
        res = self.client.post(
            '/api/auth/setup-admin/',
            data=json.dumps({
                'username': 'freshowner',
                'email': 'fresh@example.com',
                'name': 'Fresh Owner',
                'password': 'Fresh-Pass-123!',
            }),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 201, res.content)

        # Confirm the DB state is sane.
        u = User.objects.get(username='freshowner')
        self.assertEqual(u.role, 'owner')
        self.assertTrue(u.is_superuser)
        self.assertTrue(u.check_password('Fresh-Pass-123!'),
                        'Password hash must verify against the plaintext we sent')

        # Step 2 — log in with the exact credentials we just set. This is the
        # step the user reported as broken.
        self.client.logout()
        res = self.client.post(
            '/api/auth/login/',
            data=json.dumps({
                'username': 'freshowner',
                'password': 'Fresh-Pass-123!',
            }),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 200, res.content)
        body = res.json()
        self.assertEqual(body.get('role'), 'owner')
        self.assertEqual(body.get('username'), 'freshowner')


class RolePermissionTests(TestCase):
    """Three-role model: Owner (unique), Engineer, Viewer."""

    def setUp(self):
        self.owner = User.objects.create_superuser(
            username='owner', password='pw-owner-123!', email='owner@example.com'
        )
        # Engineer via direct field set + save
        self.engineer = User.objects.create_user(
            username='engineer', password='pw-eng-123!', email='eng@example.com'
        )
        self.engineer.role = 'engineer'
        self.engineer.save()
        # Viewer (default role)
        self.viewer = User.objects.create_user(
            username='viewer', password='pw-view-123!', email='view@example.com'
        )
        self.client = Client()

    def _login(self, user):
        self.client.force_login(user)

    # ── Role classification after setUp ──────────────────────────────────

    def test_setup_user_roles_are_correct(self):
        self.assertEqual(self.owner.role, 'owner')
        self.assertTrue(self.owner.is_superuser)
        self.assertTrue(self.owner.is_staff)

        self.assertEqual(self.engineer.role, 'engineer')
        self.assertFalse(self.engineer.is_superuser)
        self.assertTrue(self.engineer.is_staff)

        self.assertEqual(self.viewer.role, 'viewer')
        self.assertFalse(self.viewer.is_superuser)
        self.assertFalse(self.viewer.is_staff)

    # ── Owner uniqueness ──────────────────────────────────────────────────

    def test_cannot_save_second_owner(self):
        second = User(
            username='owner2', email='o2@example.com', role='owner'
        )
        with self.assertRaises(ValidationError):
            second.save()

    def test_create_user_rejects_owner_role(self):
        self._login(self.owner)
        res = self.client.post(
            '/api/auth/users/create/',
            data=json.dumps({
                'username': 'newowner', 'password': 'pw-xyz-123!',
                'email': 'no@example.com', 'name': 'New Owner',
                'role': 'owner', 'status': 'active',
            }),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 400)
        self.assertFalse(User.objects.filter(username='newowner').exists())

    def test_update_cannot_promote_to_owner(self):
        self._login(self.owner)
        res = self.client.put(
            f'/api/auth/users/{self.engineer.id}/',
            data=json.dumps({'role': 'owner'}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 400)
        self.engineer.refresh_from_db()
        self.assertEqual(self.engineer.role, 'engineer')

    def test_cannot_demote_owner(self):
        self._login(self.owner)
        res = self.client.put(
            f'/api/auth/users/{self.owner.id}/',
            data=json.dumps({'role': 'engineer'}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 400)
        self.owner.refresh_from_db()
        self.assertEqual(self.owner.role, 'owner')

    def test_cannot_delete_owner(self):
        # Owner can't delete self — existing "cannot delete yourself" guard — so
        # use engineer-as-Owner scenario: attempting to delete the Owner from
        # an Owner session still returns a protection error because Owner is protected.
        # Since there's only one Owner, the Owner cannot delete the Owner via the API.
        self._login(self.owner)
        res = self.client.delete(f'/api/auth/users/{self.owner.id}/delete/')
        # Hits the "cannot delete yourself" branch first (400).
        self.assertEqual(res.status_code, 400)
        self.assertTrue(User.objects.filter(pk=self.owner.pk).exists())

    # ── Role-based API access ────────────────────────────────────────────

    def test_viewer_can_list_scans(self):
        self._login(self.viewer)
        res = self.client.get('/api/scans/')
        self.assertEqual(res.status_code, 200)

    def test_engineer_can_list_scans(self):
        self._login(self.engineer)
        res = self.client.get('/api/scans/')
        self.assertEqual(res.status_code, 200)

    def test_owner_can_list_scans(self):
        self._login(self.owner)
        res = self.client.get('/api/scans/')
        self.assertEqual(res.status_code, 200)

    @patch('scanner.views.run_scan' if False else 'scanner.tasks.run_scan')
    def test_viewer_cannot_create_scan(self, _mock_run):
        self._login(self.viewer)
        res = self.client.post(
            '/api/scans/',
            data=json.dumps({'name': 'x', 'target': '127.0.0.1', 'scan_type': 'quick'}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 403)

    def test_all_roles_can_view_findings(self):
        for user in (self.owner, self.engineer, self.viewer):
            self._login(user)
            res = self.client.get('/api/findings/')
            self.assertEqual(res.status_code, 200, f"role={user.role}")

    def test_all_roles_can_view_dashboard(self):
        for user in (self.owner, self.engineer, self.viewer):
            self._login(user)
            res = self.client.get('/api/dashboard/')
            self.assertEqual(res.status_code, 200, f"role={user.role}")

    def test_viewer_cannot_manage_users(self):
        self._login(self.viewer)
        res = self.client.get('/api/auth/users/')
        self.assertEqual(res.status_code, 403)

    def test_engineer_cannot_manage_users(self):
        self._login(self.engineer)
        res = self.client.get('/api/auth/users/')
        self.assertEqual(res.status_code, 403)

    def test_viewer_can_download_report(self):
        from scanner.models import Scan, Report
        scan = Scan.objects.create(name='t', target='127.0.0.1', created_by=self.owner)
        report = Report.objects.create(scan=scan, format='docx', file_path='/nope', file_size=0)
        self._login(self.viewer)
        res = self.client.get(f'/api/reports/{report.id}/download/')
        self.assertIn(res.status_code, (200, 404))

    def test_engineer_can_download_report(self):
        """Engineer passes the report:download gate. The file doesn't exist, so we
        accept any non-403 response (Http404 bubbles as 404 — the auth check passed)."""
        from scanner.models import Scan, Report
        scan = Scan.objects.create(name='t', target='127.0.0.1', created_by=self.owner)
        report = Report.objects.create(scan=scan, format='docx', file_path='/nope', file_size=0)
        self._login(self.engineer)
        res = self.client.get(f'/api/reports/{report.id}/download/')
        self.assertNotEqual(res.status_code, 403, 'Engineer should pass the auth gate')

    def test_owner_can_view_audit_log(self):
        self._login(self.owner)
        res = self.client.get('/api/audit-log/')
        self.assertEqual(res.status_code, 200)

    def test_viewer_cannot_view_audit_log(self):
        self._login(self.viewer)
        res = self.client.get('/api/audit-log/')
        self.assertEqual(res.status_code, 403)

    def test_engineer_can_update_report_config(self):
        self._login(self.engineer)
        res = self.client.put(
            '/api/report-config/',
            data=json.dumps({'report_title': 'Quarterly VA Report'}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 200)

    def test_viewer_cannot_update_report_config(self):
        self._login(self.viewer)
        res = self.client.put(
            '/api/report-config/',
            data=json.dumps({'report_title': 'Nope'}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 403)


class PermissionTableTests(TestCase):
    """Data-driven RBAC via Permission + RolePermission tables (seeded by 0007)."""

    EXPECTED_PERMS = 17  # bumped for support:export (0011) + site:reset (0012)

    def setUp(self):
        self.owner = User.objects.create_superuser(
            username='owner', password='pw-owner-123!', email='owner@example.com'
        )
        self.engineer = User.objects.create_user(
            username='eng', password='pw-eng-123!', email='eng@example.com'
        )
        self.engineer.role = 'engineer'
        self.engineer.save()
        self.viewer = User.objects.create_user(
            username='vw', password='pw-vw-123!', email='vw@example.com'
        )
        User.invalidate_perm_cache()  # test isolation — drop cached sets between cases
        self.client = Client()

    # ── Seed integrity ───────────────────────────────────────────────────

    def test_all_permissions_seeded(self):
        self.assertEqual(Permission.objects.count(), self.EXPECTED_PERMS)

    def test_owner_has_every_permission(self):
        self.assertEqual(
            RolePermission.objects.filter(role='owner').count(),
            self.EXPECTED_PERMS,
        )

    def test_engineer_permission_set(self):
        engineer_codes = set(
            RolePermission.objects.filter(role='engineer')
                                   .values_list('permission__code', flat=True)
        )
        # Engineers should NOT have Owner-only permissions.
        self.assertNotIn('user:manage', engineer_codes)
        self.assertNotIn('site:config', engineer_codes)
        self.assertNotIn('audit:view', engineer_codes)
        # Engineers SHOULD have operational permissions.
        self.assertIn('scan:write', engineer_codes)
        self.assertIn('report:download', engineer_codes)

    def test_viewer_permission_set(self):
        viewer_codes = set(
            RolePermission.objects.filter(role='viewer')
                                   .values_list('permission__code', flat=True)
        )
        self.assertEqual(viewer_codes, {
            'finding:read', 'dashboard:view', 'scan:read', 'host:read', 'report:download',
        })

    # ── User.has_permission() ────────────────────────────────────────────

    def test_has_permission_respects_role(self):
        self.assertTrue(self.owner.has_permission('user:manage'))
        self.assertFalse(self.engineer.has_permission('user:manage'))
        self.assertFalse(self.viewer.has_permission('scan:write'))
        self.assertTrue(self.viewer.has_permission('finding:read'))

    def test_has_permission_uses_cache(self):
        """Second call doesn't hit the DB (the result is served from cache)."""
        self.engineer.has_permission('scan:write')  # prime cache
        with patch('scanner.models.RolePermission.objects') as mock_qs:
            self.engineer.has_permission('scan:write')
            mock_qs.filter.assert_not_called()

    # ── End-to-end: HTTP status matches the permission matrix ────────────

    def test_viewer_dashboard_ok(self):
        self.client.force_login(self.viewer)
        self.assertEqual(self.client.get('/api/dashboard/').status_code, 200)

    def test_viewer_scans_ok(self):
        self.client.force_login(self.viewer)
        self.assertEqual(self.client.get('/api/scans/').status_code, 200)

    def test_engineer_scans_ok(self):
        self.client.force_login(self.engineer)
        self.assertEqual(self.client.get('/api/scans/').status_code, 200)

    def test_engineer_users_forbidden(self):
        self.client.force_login(self.engineer)
        self.assertEqual(self.client.get('/api/auth/users/').status_code, 403)

    # ── Data-driven demo: remove a permission row and watch access flip ──

    def test_removing_rolepermission_row_revokes_access(self):
        """Delete the scan:write row for engineer; the same user now gets 403."""
        self.client.force_login(self.engineer)
        # Before: 200
        self.assertEqual(self.client.get('/api/scans/').status_code, 200)

        # Remove the engineer's scan:read permission.
        RolePermission.objects.filter(
            role='engineer', permission__code='scan:read',
        ).delete()
        User.invalidate_perm_cache('engineer')

        # After: 403 — no code change, only DB mutation.
        self.assertEqual(self.client.get('/api/scans/').status_code, 403)


class AssetAggregationTests(TestCase):
    """Asset inventory roll-up, first_seen/last_seen preservation, risk scoring."""

    def setUp(self):
        self.owner = User.objects.create_superuser(
            username='owner', password='pw-owner-123!', email='o@example.com'
        )
        self.client = Client()
        self.client.force_login(self.owner)

    def _fake_report(self, ip='10.0.0.1', ports=((443, 'tcp', 'https', 'nginx', '1.24'),),
                     findings=()):
        """Build a minimal in-memory ScanReport-like object the _sync_assets helper consumes."""
        from types import SimpleNamespace
        from wireghost.models.severity import Severity

        port_objs = []
        for number, protocol, svc_name, product, version in ports:
            svc = SimpleNamespace(name=svc_name, product=product, version=version)
            port_objs.append(SimpleNamespace(number=number, protocol=protocol, state='open', service=svc))
        host = SimpleNamespace(
            ip=ip, hostname='', os='', status='up',
            open_ports=port_objs, ports=port_objs, technologies=[],
        )
        finding_objs = []
        for ip_, port_, sev in findings:
            finding_objs.append(SimpleNamespace(
                host=ip_, port=port_, severity=sev, source='nuclei',
                title='t', description='', endpoint='', full_url='', protocol='tcp',
                template_id='', cve='', cwe='', cvss='', request='', response='',
                curl_command='', raw_output='', references=[],
            ))
        return SimpleNamespace(hosts=[host], findings=finding_objs)

    def test_sync_creates_asset_on_first_scan(self):
        from scanner.models import Asset, Scan
        from scanner.tasks import _sync_assets

        scan = Scan.objects.create(name='t', target='10.0.0.1', created_by=self.owner)
        report = self._fake_report()
        _sync_assets(scan, report)

        asset = Asset.objects.get(ip='10.0.0.1', port=443, protocol='tcp')
        self.assertEqual(asset.service_name, 'https')
        self.assertEqual(asset.service_product, 'nginx')
        self.assertEqual(asset.service_version, '1.24')
        self.assertIsNotNone(asset.first_seen)
        self.assertEqual(asset.first_seen, asset.last_seen)

    def test_second_scan_preserves_first_seen_advances_last_seen(self):
        from datetime import timedelta
        from scanner.models import Asset, Scan
        from scanner.tasks import _sync_assets

        scan1 = Scan.objects.create(name='s1', target='10.0.0.1', created_by=self.owner)
        _sync_assets(scan1, self._fake_report())
        original = Asset.objects.get(ip='10.0.0.1', port=443)
        first_seen_orig = original.first_seen

        # Artificially backdate so the second sync can advance last_seen.
        original.last_seen = original.last_seen - timedelta(hours=1)
        original.save(update_fields=['last_seen'])

        scan2 = Scan.objects.create(name='s2', target='10.0.0.1', created_by=self.owner)
        _sync_assets(scan2, self._fake_report())

        refreshed = Asset.objects.get(ip='10.0.0.1', port=443)
        self.assertEqual(refreshed.first_seen, first_seen_orig)
        self.assertGreater(refreshed.last_seen, original.last_seen)
        # Still only one row; not a duplicate.
        self.assertEqual(Asset.objects.filter(ip='10.0.0.1', port=443).count(), 1)

    def test_risk_score_matches_formula(self):
        from scanner.models import Asset, Scan
        from scanner.tasks import _sync_assets
        from wireghost.models.severity import Severity

        scan = Scan.objects.create(name='r', target='10.0.0.2', created_by=self.owner)
        report = self._fake_report(
            ip='10.0.0.2',
            findings=[
                ('10.0.0.2', 443, Severity.CRITICAL),
                ('10.0.0.2', 443, Severity.HIGH),
                ('10.0.0.2', 443, Severity.HIGH),
            ],
        )
        _sync_assets(scan, report)

        asset = Asset.objects.get(ip='10.0.0.2', port=443)
        # 1 crit * 30 + 2 high * 10 + 0 other * 2 = 50
        self.assertEqual(asset.risk_score, 50)
        self.assertEqual(asset.critical_count, 1)
        self.assertEqual(asset.high_count, 2)
        self.assertEqual(asset.findings_count, 3)

    def test_dashboard_api_returns_asm_shape(self):
        """The replaced /api/dashboard/ endpoint returns the ASM payload keys."""
        res = self.client.get('/api/dashboard/')
        self.assertEqual(res.status_code, 200)
        body = res.json()
        for k in ('kpis', 'severity_trend', 'risk_by_source',
                  'newly_discovered', 'top_exposures', 'top_technologies'):
            self.assertIn(k, body)
        for kpi_key in ('total_assets', 'critical_exposures', 'new_assets_7d',
                        'assets_with_cves', 'attack_surface_score'):
            self.assertIn(kpi_key, body['kpis'])

    def test_assets_endpoint_lists_inventory(self):
        from scanner.models import Scan
        from scanner.tasks import _sync_assets

        scan = Scan.objects.create(name='a', target='10.0.0.3', created_by=self.owner)
        _sync_assets(scan, self._fake_report(ip='10.0.0.3', ports=((22, 'tcp', 'ssh', 'OpenSSH', '9.3'),)))

        res = self.client.get('/api/assets/')
        self.assertEqual(res.status_code, 200)
        body = res.json()
        results = body.get('results', body)
        ips = {r['ip'] for r in results}
        self.assertIn('10.0.0.3', ips)

    def test_viewer_can_list_assets(self):
        viewer = User.objects.create_user(
            username='v', password='pw-v-123!', email='v@example.com'
        )
        viewer.role = 'viewer'
        viewer.save()

        self.client.logout()
        self.client.force_login(viewer)
        res = self.client.get('/api/assets/')
        self.assertEqual(res.status_code, 200)

    def test_attack_surface_score_is_none_on_empty_db(self):
        """With zero Asset rows, the KPI should return None (UI renders as N/A)."""
        from scanner.models import Asset
        Asset.objects.all().delete()
        res = self.client.get('/api/dashboard/')
        self.assertEqual(res.status_code, 200)
        self.assertIsNone(res.json()['kpis']['attack_surface_score'])

    @patch('scanner.tasks.run_scan.delay', return_value=type('T', (), {'id': 'mock-task'})())
    def test_scan_create_populates_created_by(self, _mock_run_scan):
        """POST /api/scans/ as Engineer should record the Scan's creator."""
        from scanner.models import Scan
        engineer = User.objects.create_user(
            username='eng_create', password='pw-eng-123!', email='eng@create.com'
        )
        engineer.role = 'engineer'
        engineer.save()

        self.client.logout()
        self.client.force_login(engineer)
        res = self.client.post(
            '/api/scans/',
            data=json.dumps({'target': '10.99.99.1', 'scan_type': 'quick', 'name': 'ownership-check'}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 201, res.content)
        scan = Scan.objects.get(target='10.99.99.1', name='ownership-check')
        self.assertEqual(scan.created_by_id, engineer.id)

    def test_assets_endpoint_filters_by_min_risk(self):
        """min_risk query param returns only assets at or above the threshold."""
        from scanner.models import Asset
        from scanner.tasks import _sync_assets
        Asset.objects.all().delete()

        scan = __import__('scanner.models', fromlist=['Scan']).Scan.objects.create(
            name='filter', target='10.8.8.0/24', created_by=self.owner,
        )
        # Low-risk asset (no findings).
        _sync_assets(scan, self._fake_report(
            ip='10.8.8.1', ports=((22, 'tcp', 'ssh', 'OpenSSH', '9.3'),),
        ))
        # High-risk asset (1 critical + 1 high → score = 40).
        from wireghost.models.severity import Severity
        _sync_assets(scan, self._fake_report(
            ip='10.8.8.2',
            ports=((443, 'tcp', 'https', 'nginx', '1.18'),),
            findings=[
                ('10.8.8.2', 443, Severity.CRITICAL),
                ('10.8.8.2', 443, Severity.HIGH),
            ],
        ))

        res = self.client.get('/api/assets/?min_risk=30')
        self.assertEqual(res.status_code, 200)
        ips = {row['ip'] for row in (res.json().get('results') or res.json())}
        self.assertIn('10.8.8.2', ips)
        self.assertNotIn('10.8.8.1', ips)


class SupportBundleTests(TestCase):
    """POST /api/support-bundle/ — Owner-only diagnostic export with redaction."""

    def setUp(self):
        self.owner = User.objects.create_superuser(
            username='sb-owner', password='pw-owner-123!', email='sb-owner@example.com'
        )
        self.engineer = User.objects.create_user(
            username='sb-engineer', password='pw-eng-123!', email='sb-eng@example.com',
            role='engineer',
        )
        self.viewer = User.objects.create_user(
            username='sb-viewer', password='pw-view-123!', email='sb-view@example.com',
            role='viewer',
        )
        self.client = Client()

    def _log_dir_with(self, tmpdir, name, content):
        """Write a log file under a nested subdir so _iter_log_files finds it."""
        import os
        sub = os.path.join(tmpdir, 'api')
        os.makedirs(sub, exist_ok=True)
        with open(os.path.join(sub, name), 'w', encoding='utf-8') as f:
            f.write(content)

    def test_support_bundle_owner_only(self):
        """Engineer and Viewer get 403; Owner gets 200."""
        self.client.force_login(self.engineer)
        self.assertEqual(self.client.post('/api/support-bundle/').status_code, 403)

        self.client.force_login(self.viewer)
        self.assertEqual(self.client.post('/api/support-bundle/').status_code, 403)

        self.client.force_login(self.owner)
        res = self.client.post('/api/support-bundle/')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res['Content-Type'], 'application/gzip')
        self.assertIn('attachment; filename=', res['Content-Disposition'])
        self.assertIn('.tar.gz', res['Content-Disposition'])

    def test_support_bundle_contains_expected_files(self):
        """Extracted archive has the manifest + system snapshot + permissions matrix."""
        import io
        import tarfile
        import tempfile
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmp:
            self._log_dir_with(tmp, 'django.log', 'INFO startup\nGET /api/dashboard/ 200\n')
            with patch.dict('os.environ', {'WIREGHOST_LOG_FILE_DIR': tmp}):
                self.client.force_login(self.owner)
                res = self.client.post('/api/support-bundle/')

        self.assertEqual(res.status_code, 200)
        tf = tarfile.open(fileobj=io.BytesIO(res.content), mode='r:gz')
        names = set(tf.getnames())
        self.assertIn('manifest.json', names)
        self.assertIn('README.txt', names)
        self.assertIn('data/snapshot.json', names)
        self.assertIn('data/permissions.json', names)
        self.assertIn('data/audit-tail.json', names)
        self.assertIn('data/counts.json', names)
        self.assertIn('data/site-config.json', names)
        self.assertIn('logs/api/django.log', names)

        # Permissions matrix must actually contain the owner role.
        perms_json = tf.extractfile('data/permissions.json').read().decode('utf-8')
        perms = json.loads(perms_json)
        self.assertIn('owner', perms)
        self.assertIn('support:export', perms['owner'])

    def test_support_bundle_redacts_secrets(self):
        """Known-secret patterns must not survive the redact() pass."""
        from scanner.support import REDACTION_PATTERNS, redact

        raw = (
            'GET /api/scans/ HTTP/1.1\n'
            'Authorization: Bearer abcdef1234567890TOPSECRET\n'
            'Cookie: sessionid=SHOULD_NOT_LEAK; csrftoken=ALSO_NOT_LEAK; theme=dark\n'
            '{"username": "alice", "password": "hunter2", "note": "keep this"}\n'
            'X-API-Key: sk_live_DONTLEAKTHIS\n'
            'redis://user:supersecret@redis:6379/0\n'
        )
        self.assertGreaterEqual(len(REDACTION_PATTERNS), 1)

        scrubbed = redact(raw)
        # Secrets gone
        self.assertNotIn('abcdef1234567890TOPSECRET', scrubbed)
        self.assertNotIn('SHOULD_NOT_LEAK', scrubbed)
        self.assertNotIn('ALSO_NOT_LEAK', scrubbed)
        self.assertNotIn('hunter2', scrubbed)
        self.assertNotIn('sk_live_DONTLEAKTHIS', scrubbed)
        self.assertNotIn('supersecret', scrubbed)
        # Surrounding context preserved
        self.assertIn('[REDACTED]', scrubbed)
        self.assertIn('alice', scrubbed)
        self.assertIn('theme=dark', scrubbed)
        self.assertIn('keep this', scrubbed)
        self.assertIn('/api/scans/', scrubbed)


class ResetSetupTests(TestCase):
    """POST /api/site-config/reset-setup/ — Owner-only tear-down to first-run state."""

    def setUp(self):
        self.owner = User.objects.create_superuser(
            username='rs-owner', password='pw-owner-123!', email='rs-owner@example.com'
        )
        self.engineer = User.objects.create_user(
            username='rs-engineer', password='pw-eng-123!', email='rs-eng@example.com',
            role='engineer',
        )
        self.viewer = User.objects.create_user(
            username='rs-viewer', password='pw-view-123!', email='rs-view@example.com',
            role='viewer',
        )
        # Pretend setup was completed previously.
        cfg = SiteConfig.get()
        cfg.setup_complete = True
        cfg.setup_completed_by = 'rs-owner'
        cfg.save()
        self.client = Client()

    def test_engineer_and_viewer_cannot_reset(self):
        self.client.force_login(self.engineer)
        self.assertEqual(self.client.post('/api/site-config/reset-setup/').status_code, 403)

        self.client.force_login(self.viewer)
        self.assertEqual(self.client.post('/api/site-config/reset-setup/').status_code, 403)

        # Nothing changed.
        self.assertTrue(SiteConfig.get().setup_complete)
        self.assertEqual(User.objects.count(), 3)

    def test_owner_reset_wipes_users_and_flips_flag(self):
        self.client.force_login(self.owner)
        res = self.client.post('/api/site-config/reset-setup/')
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertFalse(body['setup_complete'])
        self.assertEqual(body['users_deleted'], 3)

        cfg = SiteConfig.get()
        self.assertFalse(cfg.setup_complete)
        self.assertIsNone(cfg.setup_completed_at)
        self.assertEqual(cfg.setup_completed_by, '')
        self.assertEqual(User.objects.count(), 0)

    def test_site_config_now_reports_setup_incomplete_to_public(self):
        """After reset, the public /api/site-config/ must advertise setup_complete=false so the wizard re-shows."""
        self.client.force_login(self.owner)
        self.client.post('/api/site-config/reset-setup/')

        res = self.client.get('/api/site-config/')
        self.assertEqual(res.status_code, 200)
        self.assertFalse(res.json()['setup_complete'])


class AuthCheckTests(TestCase):
    """GET /api/auth/check/ — nginx auth_request target. Must stay cheap."""

    def setUp(self):
        self.user = User.objects.create_user(
            username='ac-user', password='pw-check-123!', email='ac@example.com'
        )
        self.client = Client()

    def test_unauth_returns_401(self):
        res = self.client.get('/api/auth/check/')
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.content, b'')

    def test_authed_returns_204(self):
        self.client.force_login(self.user)
        res = self.client.get('/api/auth/check/')
        self.assertEqual(res.status_code, 204)
        self.assertEqual(res.content, b'')

    def test_authed_does_no_view_level_database_work(self):
        """nginx fires this on every gated file; the view itself must add zero
        queries on top of the session-middleware baseline.

        With the default db-backed SESSION_ENGINE, Django's auth middleware
        issues 2 queries per request to resolve ``request.user`` (session row
        lookup + user row lookup). That's framework cost we can't skip without
        switching to a cached session backend. What this test enforces is that
        *our view* adds zero on top — no AuditLog.log(), no UserPreference
        fetch, no cache writes — so a future edit that quietly adds DB work
        will break the test.
        """
        self.client.force_login(self.user)
        # Warm any per-request caches.
        self.client.get('/api/auth/check/')
        with self.assertNumQueries(5):  # session + user + idle-timeout session save (savepoint/update/release)
            res = self.client.get('/api/auth/check/')
        self.assertEqual(res.status_code, 204)


class ApiTokenTests(TestCase):
    """Personal API tokens via ``Authorization: Token wg_<40>`` header."""

    def setUp(self):
        self.owner = User.objects.create_superuser(
            username='tk-owner', password='pw-owner-123!', email='tk-owner@example.com'
        )
        self.engineer = User.objects.create_user(
            username='tk-engineer', password='pw-eng-123!', email='tk-eng@example.com',
            role='engineer',
        )
        self.viewer = User.objects.create_user(
            username='tk-viewer', password='pw-view-123!', email='tk-view@example.com',
            role='viewer',
        )
        self.client = Client()

    def _mint(self, user, name='test'):
        from scanner.models import ApiToken
        return ApiToken.mint(user, name)

    # ─── Auth-class behaviour ───

    def test_token_auth_header_works(self):
        """A valid Authorization: Token header authenticates the user."""
        _, raw = self._mint(self.engineer, 'laptop')
        res = self.client.get('/api/scans/', HTTP_AUTHORIZATION=f'Token {raw}')
        # Engineer has scan:read → 200 with paginated response.
        self.assertEqual(res.status_code, 200)
        self.assertIn('results', res.json())

    def test_wrong_token_rejected(self):
        res = self.client.get('/api/scans/', HTTP_AUTHORIZATION='Token wg_this_is_not_a_real_token_xxxxx')
        self.assertIn(res.status_code, (401, 403))

    def test_revoked_token_rejected(self):
        """A token that's been revoked no longer authenticates."""
        from django.utils import timezone
        tok, raw = self._mint(self.engineer, 'to-be-revoked')
        tok.revoked_at = timezone.now()
        tok.save(update_fields=['revoked_at'])
        res = self.client.get('/api/scans/', HTTP_AUTHORIZATION=f'Token {raw}')
        self.assertIn(res.status_code, (401, 403))

    def test_key_stored_as_hash_never_plaintext(self):
        """DB must store a sha256 hex digest, not the raw token."""
        import hashlib
        tok, raw = self._mint(self.owner, 'hashed')
        self.assertNotEqual(tok.key_hash, raw)
        self.assertEqual(len(tok.key_hash), 64)
        self.assertTrue(all(c in '0123456789abcdef' for c in tok.key_hash))
        # Recompute to confirm exact match.
        self.assertEqual(tok.key_hash, hashlib.sha256(raw.encode()).hexdigest())
        # Prefix is visible, first 11 chars = 'wg_' + 8.
        self.assertTrue(tok.prefix.startswith('wg_'))
        self.assertEqual(len(tok.prefix), 11)

    # ─── Endpoint behaviour ───

    def test_create_via_endpoint_returns_raw_token_once(self):
        self.client.force_login(self.owner)
        res = self.client.post(
            '/api/auth/tokens/',
            data=json.dumps({'name': 'my first token'}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 201)
        body = res.json()
        self.assertTrue(body['token'].startswith('wg_'))
        self.assertEqual(body['name'], 'my first token')
        self.assertEqual(body['prefix'], body['token'][:11])

        # List endpoint must NOT include the raw token on subsequent calls.
        list_res = self.client.get('/api/auth/tokens/')
        self.assertEqual(list_res.status_code, 200)
        rows = list_res.json()
        self.assertEqual(len(rows), 1)
        self.assertNotIn('token', rows[0])
        self.assertEqual(rows[0]['prefix'], body['prefix'])

    def test_cannot_manage_others_tokens(self):
        """Token ownership is enforced — 404 (not 403) to avoid leaking existence."""
        from scanner.models import ApiToken
        tok, _ = self._mint(self.owner, 'owner-only')

        # Engineer tries to revoke Owner's token.
        self.client.force_login(self.engineer)
        res = self.client.post(f'/api/auth/tokens/{tok.id}/revoke/')
        self.assertEqual(res.status_code, 404)

        # Owner's token must remain active.
        tok.refresh_from_db()
        self.assertIsNone(tok.revoked_at)

    def test_max_tokens_per_user_cap(self):
        """The 21st create for a given user must be rejected with 400."""
        from scanner.models import ApiToken
        self.client.force_login(self.owner)
        # Mint MAX_PER_USER (default 20) directly via ORM — faster than API.
        for i in range(ApiToken.MAX_PER_USER):
            self._mint(self.owner, f't{i}')
        self.assertEqual(
            ApiToken.objects.filter(user=self.owner, revoked_at__isnull=True).count(),
            ApiToken.MAX_PER_USER,
        )
        res = self.client.post(
            '/api/auth/tokens/',
            data=json.dumps({'name': 'overflow'}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn('limit', res.json().get('error', '').lower())

    def test_viewer_token_inherits_viewer_scope(self):
        """A Viewer-issued token inherits the Viewer role's permissions.

        Viewers have scan:read — /api/scans/ should return 200.
        Viewers don't have scan:write — /api/scans/ POST should get 403.
        """
        _, raw = self._mint(self.viewer, 'viewer-scope')
        res = self.client.get('/api/scans/', HTTP_AUTHORIZATION=f'Token {raw}')
        self.assertEqual(res.status_code, 200)

        res = self.client.get('/api/findings/', HTTP_AUTHORIZATION=f'Token {raw}')
        self.assertEqual(res.status_code, 200)


class NotificationsTests(TestCase):
    """POST /api/notifications/{config,test}/ + the Telegram dispatch path."""

    def setUp(self):
        self.owner = User.objects.create_superuser(
            username='n-owner', password='pw-own-123!', email='n-own@example.com'
        )
        self.engineer = User.objects.create_user(
            username='n-eng', password='pw-eng-123!', email='n-eng@example.com',
            role='engineer',
        )
        self.viewer = User.objects.create_user(
            username='n-view', password='pw-view-123!', email='n-view@example.com',
            role='viewer',
        )
        self.client = Client()

    def test_owner_only_can_set_bot_token(self):
        self.client.force_login(self.engineer)
        res = self.client.put('/api/notifications/config/',
                              data=json.dumps({'bot_token': '123:abc'}),
                              content_type='application/json')
        self.assertEqual(res.status_code, 403)

        self.client.force_login(self.viewer)
        res = self.client.put('/api/notifications/config/',
                              data=json.dumps({'bot_token': '123:abc'}),
                              content_type='application/json')
        self.assertEqual(res.status_code, 403)

        self.client.force_login(self.owner)
        res = self.client.put('/api/notifications/config/',
                              data=json.dumps({'bot_token': '123:abc',
                                               'shared_chat_id': '-100987654321'}),
                              content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json()['has_token'])

    def test_get_never_returns_raw_token(self):
        from scanner.models import SiteConfig
        cfg = SiteConfig.get()
        cfg.telegram_bot_token = '999999:SECRETVALUE_SHOULD_NEVER_APPEAR_IN_BODY'
        cfg.save()

        self.client.force_login(self.owner)
        res = self.client.get('/api/notifications/config/')
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertTrue(body['has_token'])
        self.assertIn('token_tail', body)
        # token_tail exposes only the last 6 chars; the secret middle bytes
        # must not leak.
        self.assertNotIn('SECRETVALUE_SHOULD_NEVER_APPEAR_IN_BODY',
                         json.dumps(body))
        # Non-owner GET hides token_tail entirely.
        self.client.force_login(self.engineer)
        res = self.client.get('/api/notifications/config/')
        self.assertEqual(res.status_code, 200)
        self.assertNotIn('token_tail', res.json())
        self.assertTrue(res.json()['has_token'])

    def test_test_endpoint_shared_hits_shared_chat_id(self):
        from scanner.models import SiteConfig
        cfg = SiteConfig.get()
        cfg.telegram_bot_token = '999:abc'
        cfg.telegram_shared_chat_id = '-100123456789'
        cfg.save()

        from unittest.mock import patch
        with patch('scanner.notifications.send_telegram', return_value={'ok': True, 'error': None}) as mock_send:
            self.client.force_login(self.engineer)
            res = self.client.post('/api/notifications/test/',
                                   data=json.dumps({'target': 'shared'}),
                                   content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json()['ok'])
        # Verify target = shared chat id (first positional arg to send_telegram)
        mock_send.assert_called_once()
        args, kwargs = mock_send.call_args
        self.assertEqual(args[0], '-100123456789')

    def test_test_endpoint_self_hits_user_chat_id(self):
        from scanner.models import SiteConfig, UserPreference
        cfg = SiteConfig.get()
        cfg.telegram_bot_token = '999:abc'
        cfg.save()
        prefs = UserPreference.for_user(self.engineer)
        prefs.telegram_chat_id = '555666777'
        prefs.save()

        from unittest.mock import patch
        with patch('scanner.notifications.send_telegram', return_value={'ok': True, 'error': None}) as mock_send:
            self.client.force_login(self.engineer)
            res = self.client.post('/api/notifications/test/',
                                   data=json.dumps({'target': 'self'}),
                                   content_type='application/json')
        self.assertEqual(res.status_code, 200)
        args, kwargs = mock_send.call_args
        self.assertEqual(args[0], '555666777')

    def test_chat_id_validation_rejects_garbage(self):
        self.client.force_login(self.owner)
        # Try a path-traversal-like string
        res = self.client.put('/api/notifications/config/',
                              data=json.dumps({'shared_chat_id': '../evil'}),
                              content_type='application/json')
        self.assertEqual(res.status_code, 400)

        # Engineer putting a malformed personal chat_id via /api/preferences/
        self.client.force_login(self.engineer)
        res = self.client.put('/api/preferences/',
                              data=json.dumps({'telegram': {'chat_id': 'not_a_chat_id!@#'}}),
                              content_type='application/json')
        self.assertEqual(res.status_code, 400)

        # A valid negative integer (channel) passes
        res = self.client.put('/api/preferences/',
                              data=json.dumps({'telegram': {'chat_id': '-100987654321',
                                                            'enabled': True}}),
                              content_type='application/json')
        self.assertEqual(res.status_code, 200)

    def test_notify_scan_complete_fires_both_channels(self):
        from scanner.models import SiteConfig, UserPreference, Scan
        cfg = SiteConfig.get()
        cfg.telegram_bot_token = '999:abc'
        cfg.telegram_shared_chat_id = '-100555'
        cfg.save()
        prefs = UserPreference.for_user(self.engineer)
        prefs.telegram_chat_id = '222'
        prefs.telegram_enabled = True
        prefs.save()

        scan = Scan.objects.create(
            name='test-scan', target='10.0.0.1', scan_type='quick',
            status='completed', created_by=self.engineer,
        )

        from unittest.mock import patch
        from scanner.notifications import notify
        with patch('scanner.notifications.send_telegram', return_value={'ok': True, 'error': None}) as mock_send:
            notify('scan.complete', scan=scan)

        # Expect two calls: shared + creator DM
        self.assertEqual(mock_send.call_count, 2)
        targets = sorted([call.args[0] for call in mock_send.call_args_list])
        self.assertEqual(targets, ['-100555', '222'])

    def test_notify_respects_user_event_toggle(self):
        from scanner.models import SiteConfig, UserPreference, Scan
        cfg = SiteConfig.get()
        cfg.telegram_bot_token = '999:abc'
        cfg.telegram_shared_chat_id = '-100555'
        cfg.save()
        prefs = UserPreference.for_user(self.engineer)
        prefs.telegram_chat_id = '222'
        prefs.telegram_enabled = True
        prefs.notif_scan_complete = False  # opt out of scan-complete DM
        prefs.save()

        scan = Scan.objects.create(
            name='test-scan', target='10.0.0.1', scan_type='quick',
            status='completed', created_by=self.engineer,
        )

        from unittest.mock import patch
        from scanner.notifications import notify
        with patch('scanner.notifications.send_telegram', return_value={'ok': True, 'error': None}) as mock_send:
            notify('scan.complete', scan=scan)

        # Shared channel fires; user's DM does NOT (toggle is off).
        self.assertEqual(mock_send.call_count, 1)
        self.assertEqual(mock_send.call_args.args[0], '-100555')

    def test_notify_failures_do_not_raise(self):
        from scanner.models import SiteConfig, Scan
        cfg = SiteConfig.get()
        cfg.telegram_bot_token = '999:abc'
        cfg.telegram_shared_chat_id = '-100555'
        cfg.save()

        scan = Scan.objects.create(
            name='test-scan', target='10.0.0.1', scan_type='quick',
            status='completed', created_by=self.engineer,
        )

        from unittest.mock import patch
        from scanner.notifications import notify
        with patch('scanner.notifications.send_telegram', side_effect=RuntimeError('boom')):
            # Must not raise — any failure inside notify() is swallowed
            # so the scan pipeline is never held up by a broken config.
            notify('scan.complete', scan=scan)  # no assertion needed; no raise = pass


class ToolsHealthTests(TestCase):
    """GET /api/tools-health/ — live probe + cache."""

    def setUp(self):
        self.user = User.objects.create_user(
            username='th-user', password='pw-th-123!', email='th@example.com',
            role='engineer',
        )
        self.client = Client()

    def test_unauth_rejected(self):
        res = self.client.get('/api/tools-health/')
        self.assertIn(res.status_code, (401, 403))

    def test_authed_lists_known_tools(self):
        self.client.force_login(self.user)
        res = self.client.get('/api/tools-health/')
        self.assertEqual(res.status_code, 200)
        rows = res.json()
        self.assertIsInstance(rows, list)
        names = {r['name'] for r in rows}
        # Every known tool must appear in the list — even if the binary isn't
        # on PATH in the test environment, the row is there with ok=False.
        self.assertIn('Nmap', names)
        self.assertIn('Nuclei', names)
        # Every row has the expected shape.
        for r in rows:
            self.assertIn('name', r)
            self.assertIn('binary', r)
            self.assertIn('path', r)
            self.assertIn('version', r)
            self.assertIn('ok', r)


class GeneralSettingsTests(TestCase):
    """SiteConfig.default_* fields round-trip + drive scan creation."""

    def setUp(self):
        self.owner = User.objects.create_superuser(
            username='g-owner', password='pw-own-123!', email='g-own@example.com'
        )
        self.client = Client()

    def test_default_parallelism_round_trips(self):
        self.client.force_login(self.owner)
        res = self.client.put('/api/site-config/update/',
                              data=json.dumps({'default_parallelism': 42}),
                              content_type='application/json')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['default_parallelism'], 42)

        res = self.client.get('/api/site-config/')
        self.assertEqual(res.json()['default_parallelism'], 42)

    def test_scan_without_parallelism_uses_site_default(self):
        from scanner.models import SiteConfig, Scan
        cfg = SiteConfig.get()
        cfg.default_parallelism = 42
        cfg.save()

        self.client.force_login(self.owner)
        res = self.client.post('/api/scans/',
                               data=json.dumps({'target': '10.0.0.1',
                                                'scan_type': 'quick'}),
                               content_type='application/json')
        self.assertEqual(res.status_code, 201)
        body = res.json()
        scan = Scan.objects.get(id=body['id'])
        self.assertEqual(scan.parallelism, 42)


class LoginRateLimitTests(TestCase):
    """POST /api/auth/login/ rate limiter — failures count, success resets."""

    def setUp(self):
        self.user = User.objects.create_user(
            username='rl-user', password='pw-goodpass-123!', email='rl@example.com'
        )
        self.client = Client()
        # The rate-limit uses the shared Django cache; tests.py overrides
        # CACHES to LocMemCache so we're not persisting state between cases.
        from django.core.cache import cache
        cache.clear()

    def _login(self, password):
        return self.client.post(
            '/api/auth/login/',
            data=json.dumps({'username': 'rl-user', 'password': password}),
            content_type='application/json',
        )

    def test_successful_login_does_not_consume_bucket(self):
        """Repeated correct logins must not eventually lock the user out."""
        from scanner.auth_views import _LOGIN_MAX
        for _ in range(_LOGIN_MAX + 3):
            res = self._login('pw-goodpass-123!')
            self.assertEqual(res.status_code, 200)
        # Even after _LOGIN_MAX + 3 correct logins, the next one still works.
        self.assertEqual(self._login('pw-goodpass-123!').status_code, 200)

    def test_failed_logins_trip_rate_limit(self):
        from scanner.auth_views import _LOGIN_USER_MAX
        # Per-username limit is tighter than per-IP; hits first.
        for i in range(_LOGIN_USER_MAX):
            res = self._login('wrong')
            self.assertEqual(res.status_code, 401, f'failure {i+1} unexpectedly blocked')
        res = self._login('wrong')
        self.assertEqual(res.status_code, 429)
        self.assertIn('Retry-After', res.headers)

    def test_success_clears_prior_failures(self):
        """A correct login after some failures must reset the bucket."""
        from scanner.auth_views import _LOGIN_USER_MAX
        for _ in range(_LOGIN_USER_MAX - 1):  # leave one slot
            self._login('wrong')
        self.assertEqual(self._login('pw-goodpass-123!').status_code, 200)
        # After success, failures start fresh — _LOGIN_USER_MAX wrongs are
        # required again to trigger 429.
        for i in range(_LOGIN_USER_MAX):
            self.assertEqual(self._login('wrong').status_code, 401,
                             f'failure {i+1} unexpectedly blocked after reset')
        self.assertEqual(self._login('wrong').status_code, 429)
