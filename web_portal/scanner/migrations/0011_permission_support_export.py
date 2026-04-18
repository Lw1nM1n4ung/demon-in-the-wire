"""Add the support:export permission (Owner only).

Grants Owners the ability to download a diagnostic bundle from
Settings → Support. Engineers and Viewers intentionally cannot
export because the bundle contains full audit trail + logs.
"""
import uuid

from django.db import migrations
from uuid_utils import uuid7


def _uuid7():
    return uuid.UUID(str(uuid7()))


PERM = (
    'support:export',
    'Export support bundle',
    'Download a .tar.gz diagnostic bundle containing redacted logs + system snapshot.',
)


def seed(apps, schema_editor):
    Permission = apps.get_model('scanner', 'Permission')
    RolePermission = apps.get_model('scanner', 'RolePermission')

    code, name, description = PERM
    perm, _ = Permission.objects.get_or_create(
        code=code,
        defaults={'id': _uuid7(), 'name': name, 'description': description},
    )
    RolePermission.objects.get_or_create(
        role='owner', permission=perm,
        defaults={'id': _uuid7()},
    )


def unseed(apps, schema_editor):
    Permission = apps.get_model('scanner', 'Permission')
    RolePermission = apps.get_model('scanner', 'RolePermission')
    code = PERM[0]
    RolePermission.objects.filter(permission__code=code).delete()
    Permission.objects.filter(code=code).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0010_drop_apikey'),
    ]

    operations = [
        migrations.RunPython(seed, unseed),
    ]
