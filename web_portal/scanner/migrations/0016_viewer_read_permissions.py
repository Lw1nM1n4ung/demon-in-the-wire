"""Grant viewer role read-only access to scans, hosts, and report downloads.

The original 0007 seed only gave viewers finding:read + dashboard:view,
which locked them out of the scans and hosts list endpoints entirely.
"""
import uuid

from django.db import migrations
from uuid_utils import uuid7


def _uuid7():
    return uuid.UUID(str(uuid7()))


VIEWER_ADDITIONS = ['scan:read', 'host:read', 'report:download']


def forwards(apps, schema_editor):
    Permission = apps.get_model('scanner', 'Permission')
    RolePermission = apps.get_model('scanner', 'RolePermission')

    for code in VIEWER_ADDITIONS:
        try:
            perm = Permission.objects.get(code=code)
        except Permission.DoesNotExist:
            continue
        RolePermission.objects.get_or_create(
            role='viewer', permission=perm,
            defaults={'id': _uuid7()},
        )


def backwards(apps, schema_editor):
    RolePermission = apps.get_model('scanner', 'RolePermission')
    RolePermission.objects.filter(
        role='viewer', permission__code__in=VIEWER_ADDITIONS,
    ).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0015_scan_scan_unresponsive'),
    ]

    operations = [
        migrations.RunPython(forwards, backwards),
    ]
