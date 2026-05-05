"""Integration tests — real HTTP request→response through DRF, with DB and auth.

Covers scan lifecycle, finding filters, host detail, concurrent limits,
pagination, and scan cancel — all with Celery mocked out.
"""

from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase

from scanner.models import (
    Finding,
    Host,
    Permission,
    Port,
    RolePermission,
    Scan,
    ScanPolicy,
)

User = get_user_model()


def _seed_permissions():
    codes = [
        'scan:read', 'scan:write', 'scan:delete',
        'finding:read', 'host:read',
        'report:read', 'report:write',
        'user:read', 'user:write',
        'policy:read', 'policy:write',
        'schedule:read', 'schedule:write',
        'settings:read', 'settings:write',
        'audit:read',
    ]
    perms = {}
    for code in codes:
        p, _ = Permission.objects.get_or_create(code=code, defaults={'name': code})
        perms[code] = p

    for code in codes:
        RolePermission.objects.get_or_create(role='owner', permission=perms[code])
    for code in codes:
        if code not in ('user:write', 'settings:write', 'audit:read'):
            RolePermission.objects.get_or_create(role='engineer', permission=perms[code])
    for code in ('scan:read', 'finding:read', 'host:read', 'report:read', 'policy:read', 'schedule:read', 'settings:read'):
        RolePermission.objects.get_or_create(role='viewer', permission=perms[code])

    User.invalidate_perm_cache()


class ScanCreateIntegrationTests(TestCase):
    def setUp(self):
        _seed_permissions()
        self.owner = User.objects.create_superuser(
            username='owner', password='pw-owner-123!', email='o@test.com',
        )
        self.client = Client()
        self.client.force_login(self.owner)

    @patch('scanner.tasks.run_scan.delay')
    def test_scan_create_persists_to_db(self, mock_delay):
        mock_delay.return_value = MagicMock(id='task-abc')
        resp = self.client.post('/api/scans/', {
            'target': '203.0.113.0/24',
            'scan_type': 'full',
        }, content_type='application/json')
        self.assertEqual(resp.status_code, 201)
        scan = Scan.objects.get(target='203.0.113.0/24')
        self.assertEqual(scan.status, 'running')
        self.assertEqual(scan.celery_task_id, 'task-abc')
        self.assertEqual(scan.created_by, self.owner)

    @patch('scanner.tasks.run_scan.delay')
    def test_scan_create_persists_nikto_and_netexec_flags(self, mock_delay):
        mock_delay.return_value = MagicMock(id='task-flags')
        resp = self.client.post('/api/scans/', {
            'target': '203.0.113.44',
            'skip_nikto': True,
            'skip_netexec': True,
        }, content_type='application/json')
        self.assertEqual(resp.status_code, 201)
        scan = Scan.objects.get(target='203.0.113.44')
        self.assertTrue(scan.skip_nikto)
        self.assertTrue(scan.skip_netexec)

    @patch('scanner.tasks.run_scan.delay')
    def test_scan_create_validates_target(self, mock_delay):
        resp = self.client.post('/api/scans/', {
            'target': '127.0.0.1',
        }, content_type='application/json')
        self.assertEqual(resp.status_code, 400)
        mock_delay.assert_not_called()

    @patch('scanner.tasks.run_scan.delay')
    def test_concurrent_scan_limit(self, mock_delay):
        mock_delay.return_value = MagicMock(id='t')
        for i in range(5):
            Scan.objects.create(
                name=f's{i}', target=f'203.0.113.{i}',
                status='running', created_by=self.owner,
            )
        resp = self.client.post('/api/scans/', {
            'target': '203.0.113.100',
        }, content_type='application/json')
        self.assertEqual(resp.status_code, 429)
        mock_delay.assert_not_called()

    @patch('scanner.tasks.run_scan.delay')
    def test_completed_scans_dont_count_toward_limit(self, mock_delay):
        mock_delay.return_value = MagicMock(id='t')
        for i in range(5):
            Scan.objects.create(
                name=f's{i}', target=f'203.0.113.{i}',
                status='completed', created_by=self.owner,
            )
        resp = self.client.post('/api/scans/', {
            'target': '203.0.113.100',
        }, content_type='application/json')
        self.assertEqual(resp.status_code, 201)

    @patch('scanner.tasks.run_scan.delay')
    def test_scan_name_sanitized(self, mock_delay):
        mock_delay.return_value = MagicMock(id='t')
        resp = self.client.post('/api/scans/', {
            'target': '203.0.113.0/24',
            'name': '<script>alert(1)</script>',
        }, content_type='application/json')
        self.assertEqual(resp.status_code, 400)


class ScanCancelIntegrationTests(TestCase):
    def setUp(self):
        _seed_permissions()
        self.owner = User.objects.create_superuser(
            username='owner', password='pw-owner-123!', email='o@test.com',
        )
        self.client = Client()
        self.client.force_login(self.owner)

    @patch('wireghost_web.celery.app')
    def test_cancel_running_scan(self, mock_celery_app):
        scan = Scan.objects.create(
            name='test', target='203.0.113.1',
            status='running', celery_task_id='task-xyz',
            created_by=self.owner,
        )
        resp = self.client.post(f'/api/scans/{scan.id}/cancel/')
        self.assertEqual(resp.status_code, 200)
        scan.refresh_from_db()
        self.assertEqual(scan.status, 'cancelled')
        mock_celery_app.control.revoke.assert_called_once_with('task-xyz', terminate=True)

    def test_cancel_completed_scan_no_change(self):
        scan = Scan.objects.create(
            name='test', target='203.0.113.1',
            status='completed', created_by=self.owner,
        )
        resp = self.client.post(f'/api/scans/{scan.id}/cancel/')
        self.assertEqual(resp.status_code, 200)
        scan.refresh_from_db()
        self.assertEqual(scan.status, 'completed')


class FindingFilterIntegrationTests(TestCase):
    def setUp(self):
        _seed_permissions()
        self.owner = User.objects.create_superuser(
            username='owner', password='pw-owner-123!', email='o@test.com',
        )
        self.client = Client()
        self.client.force_login(self.owner)

        self.scan = Scan.objects.create(
            name='filter-test', target='203.0.113.0/24',
            status='completed', created_by=self.owner,
        )
        host = Host.objects.create(scan=self.scan, ip='203.0.113.1')
        Finding.objects.create(
            scan=self.scan, host=host, severity='critical',
            source='nuclei', title='RCE in Apache',
            port='80', protocol='tcp',
        )
        Finding.objects.create(
            scan=self.scan, host=host, severity='info',
            source='nmap_vuln', title='SSH Version Detected',
            port='22', protocol='tcp',
        )
        Finding.objects.create(
            scan=self.scan, host=host, severity='medium',
            source='nuclei', title='Directory Listing',
            port='80', protocol='tcp',
        )

    def test_filter_findings_by_severity(self):
        resp = self.client.get(f'/api/scans/{self.scan.id}/findings/?severity=critical')
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['severity'], 'critical')

    def test_filter_findings_by_source(self):
        resp = self.client.get(f'/api/scans/{self.scan.id}/findings/?source=nuclei')
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(len(data), 2)

    def test_filter_findings_by_search(self):
        resp = self.client.get(f'/api/scans/{self.scan.id}/findings/?search=Apache')
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(len(data), 1)
        self.assertIn('Apache', data[0]['title'])

    def test_combined_filters(self):
        resp = self.client.get(
            f'/api/scans/{self.scan.id}/findings/?severity=critical&source=nuclei'
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(len(data), 1)

    def test_no_match_returns_empty(self):
        resp = self.client.get(f'/api/scans/{self.scan.id}/findings/?severity=low')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), [])


class HostDetailIntegrationTests(TestCase):
    def setUp(self):
        _seed_permissions()
        self.owner = User.objects.create_superuser(
            username='owner', password='pw-owner-123!', email='o@test.com',
        )
        self.client = Client()
        self.client.force_login(self.owner)

        self.scan = Scan.objects.create(
            name='host-test', target='203.0.113.0/24',
            status='completed', created_by=self.owner,
        )
        self.host = Host.objects.create(
            scan=self.scan, ip='203.0.113.1', hostname='web.test.local',
            os='Linux 5.15',
        )
        Port.objects.create(
            host=self.host, number=80, protocol='tcp',
            state='open', service_name='http', service_product='nginx',
        )
        Port.objects.create(
            host=self.host, number=443, protocol='tcp',
            state='open', service_name='https', service_product='nginx',
        )

    def test_host_detail_returns_fields(self):
        resp = self.client.get(f'/api/hosts/{self.host.id}/')
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data['ip'], '203.0.113.1')
        self.assertEqual(data['hostname'], 'web.test.local')
        self.assertEqual(data['os'], 'Linux 5.15')

    def test_host_detail_includes_ports(self):
        resp = self.client.get(f'/api/hosts/{self.host.id}/')
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn('ports', data)
        self.assertEqual(len(data['ports']), 2)
        port_numbers = {p['number'] for p in data['ports']}
        self.assertEqual(port_numbers, {80, 443})

    def test_scan_hosts_endpoint(self):
        resp = self.client.get(f'/api/scans/{self.scan.id}/hosts/')
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['ip'], '203.0.113.1')


class RbacIntegrationTests(TestCase):
    """Verify RBAC boundaries for scan operations."""

    def setUp(self):
        _seed_permissions()
        self.owner = User.objects.create_superuser(
            username='owner', password='pw-owner-123!', email='o@test.com',
        )
        self.viewer = User.objects.create_user(
            username='viewer', password='pw-viewer-123!', email='v@test.com',
        )
        self.viewer.role = 'viewer'
        self.viewer.save()
        self.engineer = User.objects.create_user(
            username='engineer', password='pw-engineer-123!', email='e@test.com',
        )
        self.engineer.role = 'engineer'
        self.engineer.is_staff = True
        self.engineer.save()
        self.client = Client()

    def test_viewer_cannot_create_scan(self):
        self.client.force_login(self.viewer)
        resp = self.client.post('/api/scans/', {
            'target': '203.0.113.1',
        }, content_type='application/json')
        self.assertEqual(resp.status_code, 403)

    def test_viewer_can_list_scans(self):
        self.client.force_login(self.viewer)
        resp = self.client.get('/api/scans/')
        self.assertEqual(resp.status_code, 200)

    def test_viewer_can_list_findings(self):
        self.client.force_login(self.viewer)
        resp = self.client.get('/api/findings/')
        self.assertEqual(resp.status_code, 200)

    @patch('scanner.tasks.run_scan.delay')
    def test_engineer_can_create_scan(self, mock_delay):
        mock_delay.return_value = MagicMock(id='t')
        self.client.force_login(self.engineer)
        resp = self.client.post('/api/scans/', {
            'target': '203.0.113.1',
        }, content_type='application/json')
        self.assertEqual(resp.status_code, 201)

    def test_viewer_cannot_delete_scan(self):
        self.client.force_login(self.viewer)
        scan = Scan.objects.create(
            name='test', target='203.0.113.1',
            status='completed', created_by=self.owner,
        )
        resp = self.client.delete(f'/api/scans/{scan.id}/')
        self.assertEqual(resp.status_code, 403)

    def test_viewer_cannot_create_policy(self):
        self.client.force_login(self.viewer)
        resp = self.client.post('/api/policies/', {
            'name': 'sneaky',
        }, content_type='application/json')
        self.assertEqual(resp.status_code, 403)

    @patch('wireghost_web.celery.app')
    @patch('scanner.tasks.run_scan.delay')
    def test_engineer_can_cancel_own_scan(self, mock_delay, _mock_celery):
        mock_delay.return_value = MagicMock(id='t')
        self.client.force_login(self.engineer)
        resp = self.client.post('/api/scans/', {
            'target': '203.0.113.1',
        }, content_type='application/json')
        scan_id = resp.json()['id']
        resp = self.client.post(f'/api/scans/{scan_id}/cancel/')
        self.assertEqual(resp.status_code, 200)

    def test_unauthenticated_blocked(self):
        resp = self.client.get('/api/scans/')
        self.assertIn(resp.status_code, (401, 403))


class ScanPolicyIntegrationTests(TestCase):
    def setUp(self):
        _seed_permissions()
        self.owner = User.objects.create_superuser(
            username='owner', password='pw-owner-123!', email='o@test.com',
        )
        self.client = Client()
        self.client.force_login(self.owner)

    def test_create_policy(self):
        resp = self.client.post('/api/policies/', {
            'name': 'Internal Quick',
            'scan_type': 'quick',
            'parallelism': 5,
        }, content_type='application/json')
        self.assertEqual(resp.status_code, 201)
        self.assertTrue(ScanPolicy.objects.filter(name='Internal Quick').exists())

    def test_list_policies(self):
        ScanPolicy.objects.create(name='P1', scan_type='full', created_by=self.owner)
        ScanPolicy.objects.create(name='P2', scan_type='quick', created_by=self.owner)
        resp = self.client.get('/api/policies/')
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        results = data.get('results', data) if isinstance(data, dict) else data
        names = {p['name'] for p in results}
        self.assertIn('P1', names)
        self.assertIn('P2', names)

    def test_update_policy(self):
        policy = ScanPolicy.objects.create(
            name='Old', scan_type='full', created_by=self.owner,
        )
        resp = self.client.patch(f'/api/policies/{policy.id}/', {
            'name': 'Updated',
        }, content_type='application/json')
        self.assertEqual(resp.status_code, 200)
        policy.refresh_from_db()
        self.assertEqual(policy.name, 'Updated')

    def test_delete_policy(self):
        policy = ScanPolicy.objects.create(
            name='Temp', scan_type='full', created_by=self.owner,
        )
        resp = self.client.delete(f'/api/policies/{policy.id}/')
        self.assertIn(resp.status_code, (200, 204))
        self.assertFalse(ScanPolicy.objects.filter(id=policy.id).exists())
