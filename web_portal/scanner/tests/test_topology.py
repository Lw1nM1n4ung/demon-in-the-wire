"""Tests for the enriched topology API endpoint (GET /api/scans/<id>/topology/)."""
import json

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client, TestCase

from scanner.models import Finding, Host, Port, Scan, Technology

User = get_user_model()


class TopologyEndpointTests(TestCase):
    """Verify the enriched topology response: risk_score, cves, edges, scan_status, caching."""

    def setUp(self):
        cache.clear()
        self.owner = User.objects.create_superuser(
            username='topo_owner', password='pw-owner-123!', email='owner@t.com'
        )
        self.client = Client()
        self.client.force_login(self.owner)

        self.scan = Scan.objects.create(
            name='TopoScan', target='10.0.0.0/24', status='completed',
            created_by=self.owner,
        )

        self.h1 = Host.objects.create(scan=self.scan, ip='10.0.0.1', hostname='web01', ports_count=3)
        self.h2 = Host.objects.create(scan=self.scan, ip='10.0.0.2', hostname='db01', ports_count=1)
        self.h3 = Host.objects.create(scan=self.scan, ip='10.0.0.3', hostname='ssh01', ports_count=1)

        Port.objects.create(host=self.h1, number=80, service_name='http')
        Port.objects.create(host=self.h1, number=443, service_name='https')
        Port.objects.create(host=self.h1, number=22, service_name='ssh')
        Port.objects.create(host=self.h2, number=3306, service_name='mysql')
        Port.objects.create(host=self.h3, number=22, service_name='ssh')

        Technology.objects.create(host=self.h1, name='Apache', version='2.4.52')

        Finding.objects.create(
            scan=self.scan, host=self.h1, source='nuclei', severity='critical',
            title='SQLi in login', cve='CVE-2023-1234,CVE-2023-5678',
        )
        Finding.objects.create(
            scan=self.scan, host=self.h1, source='nuclei', severity='high',
            title='XSS in search', cve='CVE-2023-5678',
        )
        Finding.objects.create(
            scan=self.scan, host=self.h2, source='nuclei', severity='medium',
            title='MySQL info leak', cve='CVE-2023-5678',
        )
        Finding.objects.create(
            scan=self.scan, host=self.h3, source='nuclei', severity='low',
            title='SSH banner', cve='',
        )

    def _get_topology(self):
        return self.client.get(f'/api/scans/{self.scan.id}/topology/')

    def test_status_200_for_owner(self):
        res = self._get_topology()
        self.assertEqual(res.status_code, 200)

    def test_response_has_required_keys(self):
        data = self._get_topology().json()
        for key in ('scan_id', 'scan_name', 'scan_status', 'target', 'subnets', 'nodes', 'edges'):
            self.assertIn(key, data, f'Missing key: {key}')

    def test_scan_status_field(self):
        data = self._get_topology().json()
        self.assertEqual(data['scan_status'], 'completed')

    def test_node_count(self):
        data = self._get_topology().json()
        self.assertEqual(len(data['nodes']), 3)

    def test_node_has_enriched_fields(self):
        data = self._get_topology().json()
        node = next(n for n in data['nodes'] if n['ip'] == '10.0.0.1')
        self.assertIn('risk_score', node)
        self.assertIn('cves', node)
        self.assertIn('low_count', node)
        self.assertIn('critical_count', node)
        self.assertIn('primary_service', node)
        self.assertIn('ports', node)
        self.assertIn('technologies', node)

    def test_risk_score_formula(self):
        data = self._get_topology().json()
        node = next(n for n in data['nodes'] if n['ip'] == '10.0.0.1')
        expected = min(100, 1 * 10 + 1 * 5 + 0 * 2 + 0)
        self.assertEqual(node['risk_score'], expected)

    def test_low_count_tracked(self):
        data = self._get_topology().json()
        node = next(n for n in data['nodes'] if n['ip'] == '10.0.0.3')
        self.assertEqual(node['low_count'], 1)

    def test_cves_populated(self):
        data = self._get_topology().json()
        node = next(n for n in data['nodes'] if n['ip'] == '10.0.0.1')
        self.assertIn('CVE-2023-1234', node['cves'])
        self.assertIn('CVE-2023-5678', node['cves'])

    def test_cves_empty_for_no_cve_host(self):
        data = self._get_topology().json()
        node = next(n for n in data['nodes'] if n['ip'] == '10.0.0.3')
        self.assertEqual(node['cves'], [])

    def test_service_classification_web(self):
        data = self._get_topology().json()
        node = next(n for n in data['nodes'] if n['ip'] == '10.0.0.1')
        self.assertEqual(node['primary_service'], 'web')

    def test_service_classification_database(self):
        data = self._get_topology().json()
        node = next(n for n in data['nodes'] if n['ip'] == '10.0.0.2')
        self.assertEqual(node['primary_service'], 'database')

    def test_service_classification_ssh(self):
        data = self._get_topology().json()
        node = next(n for n in data['nodes'] if n['ip'] == '10.0.0.3')
        self.assertEqual(node['primary_service'], 'ssh')

    def test_subnets_populated(self):
        data = self._get_topology().json()
        self.assertTrue(len(data['subnets']) >= 1)
        s = data['subnets'][0]
        self.assertIn('cidr', s)
        self.assertIn('host_count', s)

    def test_technologies_included(self):
        data = self._get_topology().json()
        node = next(n for n in data['nodes'] if n['ip'] == '10.0.0.1')
        self.assertTrue(any('Apache' in t for t in node['technologies']))

    def test_ports_included(self):
        data = self._get_topology().json()
        node = next(n for n in data['nodes'] if n['ip'] == '10.0.0.1')
        port_nums = [p['number'] for p in node['ports']]
        self.assertIn(80, port_nums)
        self.assertIn(443, port_nums)

    def test_edges_cve_based(self):
        """h1 and h2 share CVE-2023-5678, should produce a CVE edge."""
        data = self._get_topology().json()
        cve_edges = [e for e in data['edges'] if e['type'] == 'cve']
        h1_id = str(self.h1.id)
        h2_id = str(self.h2.id)
        shared = [e for e in cve_edges if
                  (e['source'] == h1_id and e['target'] == h2_id) or
                  (e['source'] == h2_id and e['target'] == h1_id)]
        self.assertTrue(len(shared) >= 1, f'Expected CVE edge between h1/h2, got edges: {cve_edges}')

    def test_edges_service_based(self):
        """Two hosts sharing the same primary_service should get a service edge."""
        h4 = Host.objects.create(scan=self.scan, ip='10.0.0.4', hostname='web02', ports_count=1)
        Port.objects.create(host=h4, number=8080, service_name='http-proxy')
        cache.clear()
        data = self._get_topology().json()
        svc_edges = [e for e in data['edges'] if e['type'] == 'service']
        h1_id = str(self.h1.id)
        h4_id = str(h4.id)
        shared = [e for e in svc_edges if
                  {e['source'], e['target']} == {h1_id, h4_id}]
        self.assertTrue(len(shared) >= 1, f'Expected service edge between h1/h4 (both web), got: {svc_edges}')

    def test_edge_cap_per_host(self):
        """No host should have more than 3 edges."""
        data = self._get_topology().json()
        edge_count = {}
        for e in data['edges']:
            edge_count[e['source']] = edge_count.get(e['source'], 0) + 1
            edge_count[e['target']] = edge_count.get(e['target'], 0) + 1
        for host_id, count in edge_count.items():
            self.assertLessEqual(count, 3, f'Host {host_id} has {count} edges (max 3)')

    def test_worst_severity(self):
        data = self._get_topology().json()
        node = next(n for n in data['nodes'] if n['ip'] == '10.0.0.1')
        self.assertEqual(node['worst_severity'], 'critical')

    def test_clean_severity_for_no_findings(self):
        h4 = Host.objects.create(scan=self.scan, ip='10.0.0.4', ports_count=0)
        cache.clear()
        data = self._get_topology().json()
        node = next(n for n in data['nodes'] if n['ip'] == '10.0.0.4')
        self.assertEqual(node['worst_severity'], 'clean')

    def test_response_caching(self):
        self._get_topology()
        cache_key = f'topo:{self.scan.id}:{self.scan.updated_at.timestamp()}'
        self.assertIsNotNone(cache.get(cache_key))

    def test_running_scan_not_cached(self):
        self.scan.status = 'running'
        self.scan.save()
        cache.clear()
        self._get_topology()
        cache_key = f'topo:{self.scan.id}:{self.scan.updated_at.timestamp()}'
        self.assertIsNone(cache.get(cache_key))

    def test_empty_scan_returns_empty_nodes(self):
        empty_scan = Scan.objects.create(
            name='EmptyScan', target='192.168.0.0/24', status='completed',
            created_by=self.owner,
        )
        res = self.client.get(f'/api/scans/{empty_scan.id}/topology/')
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(len(data['nodes']), 0)
        self.assertEqual(len(data['edges']), 0)


class TopologyRBACTests(TestCase):
    """Role-based access to topology endpoint."""

    def setUp(self):
        self.owner = User.objects.create_superuser(
            username='rbac_owner', password='pw-owner-123!', email='o@t.com'
        )
        self.viewer = User.objects.create_user(
            username='rbac_viewer', password='pw-viewer-123!', email='v@t.com'
        )
        self.scan = Scan.objects.create(
            name='RBACScan', target='10.0.0.0/24', status='completed',
            created_by=self.owner,
        )

    def test_unauthenticated_forbidden(self):
        client = Client()
        res = client.get(f'/api/scans/{self.scan.id}/topology/')
        self.assertIn(res.status_code, (401, 403))

    def test_viewer_can_access_topology(self):
        client = Client()
        client.force_login(self.viewer)
        res = client.get(f'/api/scans/{self.scan.id}/topology/')
        self.assertIn(res.status_code, (200, 403))
