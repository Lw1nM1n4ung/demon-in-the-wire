"""Integration tests — _persist_results bridge from pipeline dataclasses to Django ORM.

Verifies that hosts, ports, findings, technologies, screenshots, severity
counters, and asset inventory are correctly written to the database.
"""

import json
from datetime import datetime
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from scanner.models import (
    Asset,
    Finding as DBFinding,
    Host as DBHost,
    Port as DBPort,
    Scan,
    Screenshot as DBScreenshot,
    Technology as DBTech,
)

User = get_user_model()


def _make_pipeline_report(hosts=None, findings=None, target='203.0.113.0/24'):
    from wireghost.models.report import ScanReport
    return ScanReport(
        target=target,
        hosts=hosts or [],
        findings=findings or [],
        scan_start=datetime(2024, 1, 15, 10, 0),
    )


def _make_pipeline_host(ip, hostname='', os_val='', ports=None, techs=None):
    from wireghost.models.scan import Host, WebTech
    return Host(
        ip=ip,
        hostname=hostname,
        os=os_val,
        ports=ports or [],
        technologies=techs or [],
    )


def _make_pipeline_port(number, state='open', svc_name='', svc_product='', svc_version=''):
    from wireghost.models.scan import Port, Service
    svc = Service(name=svc_name, product=svc_product, version=svc_version) if svc_name else None
    return Port(number=number, state=state, service=svc)


def _make_pipeline_finding(host, severity, title='Test Finding', port='80', **kwargs):
    from wireghost.models.finding import Finding
    from wireghost.models.severity import Severity
    sev_map = {
        'critical': Severity.CRITICAL, 'high': Severity.HIGH,
        'medium': Severity.MEDIUM, 'low': Severity.LOW, 'info': Severity.INFO,
    }
    return Finding(
        source=kwargs.get('source', 'nuclei'),
        host=host,
        port=port,
        protocol=kwargs.get('protocol', 'tcp'),
        severity=sev_map.get(severity, Severity.INFO),
        title=title,
        description=kwargs.get('description', 'desc'),
        cve=kwargs.get('cve', ''),
        cwe=kwargs.get('cwe', ''),
        cvss=kwargs.get('cvss', ''),
        request=kwargs.get('request', ''),
        response=kwargs.get('response', ''),
        curl_command=kwargs.get('curl_command', ''),
        raw_output=kwargs.get('raw_output', ''),
        references=kwargs.get('references', []),
        endpoint=kwargs.get('endpoint', '/'),
        full_url=kwargs.get('full_url', ''),
        template_id=kwargs.get('template_id', ''),
    )


class PersistResultsHostTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_superuser(
            username='owner', password='pw-owner-123!', email='o@test.com',
        )
        self.scan = Scan.objects.create(
            name='bridge-test', target='203.0.113.0/24',
            status='running', created_by=self.owner,
        )

    def test_host_persisted(self):
        from scanner.tasks import _persist_results
        report = _make_pipeline_report(hosts=[
            _make_pipeline_host('203.0.113.1', hostname='web.local', os_val='Linux 5.15'),
        ])
        _persist_results(self.scan, report)
        db_host = DBHost.objects.get(scan=self.scan, ip='203.0.113.1')
        self.assertEqual(db_host.hostname, 'web.local')
        self.assertEqual(db_host.os, 'Linux 5.15')
        self.assertEqual(db_host.status, 'up')

    def test_multiple_hosts_persisted(self):
        from scanner.tasks import _persist_results
        report = _make_pipeline_report(hosts=[
            _make_pipeline_host('203.0.113.1'),
            _make_pipeline_host('203.0.113.2'),
            _make_pipeline_host('203.0.113.3'),
        ])
        _persist_results(self.scan, report)
        self.assertEqual(DBHost.objects.filter(scan=self.scan).count(), 3)

    def test_host_counts_updated(self):
        from scanner.tasks import _persist_results
        report = _make_pipeline_report(hosts=[
            _make_pipeline_host('203.0.113.1'),
        ])
        _persist_results(self.scan, report)
        self.scan.refresh_from_db()
        self.assertEqual(self.scan.hosts_count, 1)


class PersistResultsPortTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_superuser(
            username='owner', password='pw-owner-123!', email='o@test.com',
        )
        self.scan = Scan.objects.create(
            name='bridge-test', target='203.0.113.0/24',
            status='running', created_by=self.owner,
        )

    def test_ports_persisted(self):
        from scanner.tasks import _persist_results
        host = _make_pipeline_host('203.0.113.1', ports=[
            _make_pipeline_port(80, svc_name='http', svc_product='nginx', svc_version='1.24'),
            _make_pipeline_port(443, svc_name='https', svc_product='nginx'),
        ])
        report = _make_pipeline_report(hosts=[host])
        _persist_results(self.scan, report)
        db_host = DBHost.objects.get(scan=self.scan)
        ports = DBPort.objects.filter(host=db_host).order_by('number')
        self.assertEqual(ports.count(), 2)
        self.assertEqual(ports[0].service_name, 'http')
        self.assertEqual(ports[0].service_product, 'nginx')
        self.assertEqual(ports[0].service_version, '1.24')

    def test_port_without_service(self):
        from scanner.tasks import _persist_results
        host = _make_pipeline_host('203.0.113.1', ports=[
            _make_pipeline_port(8080),
        ])
        report = _make_pipeline_report(hosts=[host])
        _persist_results(self.scan, report)
        port = DBPort.objects.get(host__scan=self.scan)
        self.assertEqual(port.service_name, '')

    def test_ports_count_updated(self):
        from scanner.tasks import _persist_results
        host = _make_pipeline_host('203.0.113.1', ports=[
            _make_pipeline_port(22, state='open'),
            _make_pipeline_port(80, state='open'),
            _make_pipeline_port(3306, state='filtered'),
        ])
        report = _make_pipeline_report(hosts=[host])
        _persist_results(self.scan, report)
        self.scan.refresh_from_db()
        self.assertEqual(self.scan.ports_count, 2)


class PersistResultsFindingTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_superuser(
            username='owner', password='pw-owner-123!', email='o@test.com',
        )
        self.scan = Scan.objects.create(
            name='bridge-test', target='203.0.113.0/24',
            status='running', created_by=self.owner,
        )

    def test_findings_persisted(self):
        from scanner.tasks import _persist_results
        host = _make_pipeline_host('203.0.113.1')
        findings = [
            _make_pipeline_finding('203.0.113.1', 'critical', 'RCE in Apache'),
            _make_pipeline_finding('203.0.113.1', 'info', 'SSH Banner'),
        ]
        report = _make_pipeline_report(hosts=[host], findings=findings)
        _persist_results(self.scan, report)
        self.assertEqual(DBFinding.objects.filter(scan=self.scan).count(), 2)

    def test_finding_fields_complete(self):
        from scanner.tasks import _persist_results
        host = _make_pipeline_host('203.0.113.1')
        finding = _make_pipeline_finding(
            '203.0.113.1', 'high', 'SQLi',
            cve='CVE-2021-41773', cwe='CWE-89', cvss='9.8',
            request='GET /vuln', response='200 OK',
            curl_command='curl https://target/vuln',
            raw_output='found sqli', template_id='sqli-detect',
            references=['https://cve.mitre.org/CVE-2021-41773'],
        )
        report = _make_pipeline_report(hosts=[host], findings=[finding])
        _persist_results(self.scan, report)
        db_f = DBFinding.objects.get(scan=self.scan)
        self.assertEqual(db_f.cve, 'CVE-2021-41773')
        self.assertEqual(db_f.cwe, 'CWE-89')
        self.assertEqual(db_f.cvss, '9.8')
        self.assertEqual(db_f.request, 'GET /vuln')
        self.assertEqual(db_f.response, '200 OK')
        self.assertEqual(db_f.curl_command, 'curl https://target/vuln')
        self.assertEqual(db_f.template_id, 'sqli-detect')
        self.assertEqual(json.loads(db_f.references), ['https://cve.mitre.org/CVE-2021-41773'])

    def test_severity_counters(self):
        from scanner.tasks import _persist_results
        host = _make_pipeline_host('203.0.113.1')
        findings = [
            _make_pipeline_finding('203.0.113.1', 'critical', 'F1'),
            _make_pipeline_finding('203.0.113.1', 'critical', 'F2'),
            _make_pipeline_finding('203.0.113.1', 'high', 'F3'),
            _make_pipeline_finding('203.0.113.1', 'medium', 'F4'),
            _make_pipeline_finding('203.0.113.1', 'low', 'F5'),
            _make_pipeline_finding('203.0.113.1', 'info', 'F6'),
        ]
        report = _make_pipeline_report(hosts=[host], findings=findings)
        _persist_results(self.scan, report)
        self.scan.refresh_from_db()
        self.assertEqual(self.scan.critical_count, 2)
        self.assertEqual(self.scan.high_count, 1)
        self.assertEqual(self.scan.medium_count, 1)
        self.assertEqual(self.scan.low_count, 1)
        self.assertEqual(self.scan.info_count, 1)
        self.assertEqual(self.scan.findings_count, 6)

    def test_finding_linked_to_host(self):
        from scanner.tasks import _persist_results
        host = _make_pipeline_host('203.0.113.1')
        finding = _make_pipeline_finding('203.0.113.1', 'high', 'Linked')
        report = _make_pipeline_report(hosts=[host], findings=[finding])
        _persist_results(self.scan, report)
        db_f = DBFinding.objects.get(scan=self.scan)
        self.assertIsNotNone(db_f.host)
        self.assertEqual(db_f.host.ip, '203.0.113.1')

    def test_finding_host_count_incremented(self):
        from scanner.tasks import _persist_results
        host = _make_pipeline_host('203.0.113.1')
        findings = [
            _make_pipeline_finding('203.0.113.1', 'high', 'F1'),
            _make_pipeline_finding('203.0.113.1', 'medium', 'F2'),
        ]
        report = _make_pipeline_report(hosts=[host], findings=findings)
        _persist_results(self.scan, report)
        db_host = DBHost.objects.get(scan=self.scan)
        self.assertEqual(db_host.findings_count, 2)

    def test_finding_unknown_host_still_saved(self):
        from scanner.tasks import _persist_results
        finding = _make_pipeline_finding('203.0.113.99', 'info', 'Orphan')
        report = _make_pipeline_report(findings=[finding])
        _persist_results(self.scan, report)
        db_f = DBFinding.objects.get(scan=self.scan)
        self.assertIsNone(db_f.host)
        self.assertEqual(db_f.host_ip, '203.0.113.99')


class PersistResultsTechTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_superuser(
            username='owner', password='pw-owner-123!', email='o@test.com',
        )
        self.scan = Scan.objects.create(
            name='bridge-test', target='203.0.113.0/24',
            status='running', created_by=self.owner,
        )

    def test_technologies_persisted(self):
        from scanner.tasks import _persist_results
        from wireghost.models.scan import WebTech
        host = _make_pipeline_host('203.0.113.1', techs=[
            WebTech(name='jQuery', version='3.6.0', url='https://203.0.113.1/'),
            WebTech(name='nginx', version=''),
        ])
        report = _make_pipeline_report(hosts=[host])
        _persist_results(self.scan, report)
        techs = DBTech.objects.filter(host__scan=self.scan).order_by('name')
        self.assertEqual(techs.count(), 2)
        self.assertEqual(techs[0].name, 'jQuery')
        self.assertEqual(techs[0].version, '3.6.0')


class PersistResultsAssetTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_superuser(
            username='owner', password='pw-owner-123!', email='o@test.com',
        )
        self.scan = Scan.objects.create(
            name='bridge-test', target='203.0.113.0/24',
            status='running', created_by=self.owner,
        )

    def test_assets_created(self):
        from scanner.tasks import _persist_results
        host = _make_pipeline_host('203.0.113.1', ports=[
            _make_pipeline_port(80, svc_name='http'),
            _make_pipeline_port(443, svc_name='https'),
        ])
        report = _make_pipeline_report(hosts=[host])
        _persist_results(self.scan, report)
        assets = Asset.objects.filter(ip='203.0.113.1')
        self.assertEqual(assets.count(), 2)

    def test_asset_risk_score_computed(self):
        from scanner.tasks import _persist_results
        host = _make_pipeline_host('203.0.113.1', ports=[
            _make_pipeline_port(80, svc_name='http'),
        ])
        findings = [
            _make_pipeline_finding('203.0.113.1', 'critical', 'RCE'),
        ]
        report = _make_pipeline_report(hosts=[host], findings=findings)
        _persist_results(self.scan, report)
        asset = Asset.objects.get(ip='203.0.113.1', port=80)
        self.assertGreater(asset.risk_score, 0)
        self.assertEqual(asset.critical_count, 1)

    def test_asset_upsert_on_rescan(self):
        from scanner.tasks import _persist_results
        host = _make_pipeline_host('203.0.113.1', ports=[
            _make_pipeline_port(80, svc_name='http'),
        ])
        report = _make_pipeline_report(hosts=[host])
        _persist_results(self.scan, report)
        first_seen = Asset.objects.get(ip='203.0.113.1', port=80).first_seen

        scan2 = Scan.objects.create(
            name='rescan', target='203.0.113.0/24',
            status='running', created_by=self.owner,
        )
        _persist_results(scan2, report)
        asset = Asset.objects.get(ip='203.0.113.1', port=80)
        self.assertEqual(asset.first_seen, first_seen)
        self.assertEqual(asset.last_scan, scan2)


class PersistResultsEmptyTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_superuser(
            username='owner', password='pw-owner-123!', email='o@test.com',
        )
        self.scan = Scan.objects.create(
            name='bridge-test', target='203.0.113.0/24',
            status='running', created_by=self.owner,
        )

    def test_empty_report_no_crash(self):
        from scanner.tasks import _persist_results
        report = _make_pipeline_report()
        _persist_results(self.scan, report)
        self.scan.refresh_from_db()
        self.assertEqual(self.scan.hosts_count, 0)
        self.assertEqual(self.scan.findings_count, 0)

    def test_host_without_ports(self):
        from scanner.tasks import _persist_results
        report = _make_pipeline_report(hosts=[
            _make_pipeline_host('203.0.113.1'),
        ])
        _persist_results(self.scan, report)
        self.assertEqual(DBPort.objects.filter(host__scan=self.scan).count(), 0)
