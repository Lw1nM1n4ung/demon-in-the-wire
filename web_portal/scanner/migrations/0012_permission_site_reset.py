"""Add the site:reset permission (Owner only).

Grants Owners the ability to tear the portal back down to first-run
state via Settings → Export/Import → "Re-run Setup Wizard" — wipes
all users and flips SiteConfig.setup_complete back to False so the
wizard can run again.
"""
import uuid

from django.db import migrations
from uuid_utils import uuid7


def _uuid7():
    return uuid.UUID(str(uuid7()))


PERM = (
    'site:reset',
    'Reset portal setup',
    'Wipe all users and mark setup incomplete so the first-run wizard can run again.',
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
        ('scanner', '0011_permission_support_export'),
    ]

    operations = [
        migrations.RunPython(seed, unseed),
    ]
