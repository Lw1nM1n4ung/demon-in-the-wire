"""Backfill Asset rows from existing Host/Port data across all past scans."""
import uuid

from django.db import migrations
from uuid_utils import uuid7


def _uuid7():
    return uuid.UUID(str(uuid7()))


def _compute_risk(critical, high, total):
    other = max(0, total - critical - high)
    return min(100, critical * 30 + high * 10 + other * 2)


def backfill(apps, schema_editor):
    Scan = apps.get_model('scanner', 'Scan')
    Host = apps.get_model('scanner', 'Host')
    Port = apps.get_model('scanner', 'Port')
    Finding = apps.get_model('scanner', 'Finding')
    Asset = apps.get_model('scanner', 'Asset')

    for host in Host.objects.select_related('scan').all():
        scan = host.scan
        seen_at = scan.started_at or scan.created_at
        for port in Port.objects.filter(host=host):
            # findings pinned to this (ip, port)
            findings = Finding.objects.filter(scan=scan, host_ip=host.ip, port=str(port.number))
            critical = findings.filter(severity='critical').count()
            high = findings.filter(severity='high').count()
            total = findings.count()

            key = {'ip': host.ip, 'port': port.number, 'protocol': port.protocol or 'tcp'}
            asset = Asset.objects.filter(**key).first()
            if asset is None:
                asset = Asset(id=_uuid7(), first_seen=seen_at, last_seen=seen_at, **key)
            else:
                # Advance last_seen only if this scan is newer.
                if seen_at and (asset.last_seen is None or seen_at > asset.last_seen):
                    asset.last_seen = seen_at
                if seen_at and (asset.first_seen is None or seen_at < asset.first_seen):
                    asset.first_seen = seen_at

            asset.hostname = host.hostname or asset.hostname
            asset.os = host.os or asset.os
            asset.service_name = port.service_name or asset.service_name
            asset.service_product = port.service_product or asset.service_product
            asset.service_version = port.service_version or asset.service_version
            asset.status = port.state if port.state in {'open', 'closed', 'filtered'} else 'open'
            asset.last_scan = scan
            asset.findings_count = total
            asset.critical_count = critical
            asset.high_count = high
            asset.risk_score = _compute_risk(critical, high, total)
            asset.save()


def unbackfill(apps, schema_editor):
    Asset = apps.get_model('scanner', 'Asset')
    Asset.objects.all().delete()


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0008_asset_model'),
    ]

    operations = [
        migrations.RunPython(backfill, unbackfill),
    ]
