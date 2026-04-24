"""Seed the Permission catalog and role → permission mappings.

Seed-only by design: editing the matrix means writing a new migration.
"""
import uuid

from django.db import migrations
from uuid_utils import uuid7


def _uuid7():
    return uuid.UUID(str(uuid7()))


# (code, name, description)
PERMISSIONS = [
    ('user:manage',         'Manage users',            'Create, update, and delete user accounts.'),
    ('site:config',         'Site configuration',      'Edit site-wide configuration (timezone, etc.).'),
    ('audit:view',          'View audit log',          'Read the system audit trail.'),
    ('scan:read',           'View scans',              'List and read scan records.'),
    ('scan:write',          'Run and manage scans',    'Create, cancel, delete, and regenerate scan reports.'),
    ('host:read',           'View hosts',              'List discovered hosts and their services.'),
    ('finding:read',        'View findings',           'List and read vulnerability findings.'),
    ('dashboard:view',      'View dashboard',          'Read aggregated dashboard statistics.'),
    ('report:download',     'Download reports',        'Download generated report files.'),
    ('report:config:write', 'Edit report branding',    'Update report title, company name, disclaimer, etc.'),
    ('report:logo:upload',  'Upload report logo',      'Upload a custom logo used in reports.'),
    ('policy:read',         'View scan policies',      'List and read reusable scan policy templates.'),
    ('policy:write',        'Manage scan policies',    'Create, edit, and delete scan policy templates.'),
    ('schedule:read',       'View scheduled scans',    'List and read recurring scan schedules.'),
    ('schedule:write',      'Manage scheduled scans',  'Create, edit, and delete recurring scan schedules.'),
]


# Role → set of permission codes
ROLE_MATRIX = {
    'owner': {code for code, _, _ in PERMISSIONS},  # Owner gets everything.
    'engineer': {
        'scan:read', 'scan:write', 'host:read',
        'finding:read', 'dashboard:view',
        'report:download', 'report:config:write', 'report:logo:upload',
        'policy:read', 'policy:write',
        'schedule:read', 'schedule:write',
    },
    'viewer': {
        'scan:read', 'host:read', 'finding:read',
        'dashboard:view', 'report:download',
    },
}


def seed(apps, schema_editor):
    Permission = apps.get_model('scanner', 'Permission')
    RolePermission = apps.get_model('scanner', 'RolePermission')

    code_to_perm = {}
    for code, name, description in PERMISSIONS:
        perm, _ = Permission.objects.get_or_create(
            code=code,
            defaults={'id': _uuid7(), 'name': name, 'description': description},
        )
        code_to_perm[code] = perm

    for role, codes in ROLE_MATRIX.items():
        for code in codes:
            RolePermission.objects.get_or_create(
                role=role, permission=code_to_perm[code],
                defaults={'id': _uuid7()},
            )


def unseed(apps, schema_editor):
    Permission = apps.get_model('scanner', 'Permission')
    RolePermission = apps.get_model('scanner', 'RolePermission')
    RolePermission.objects.filter(permission__code__in=[c for c, _, _ in PERMISSIONS]).delete()
    Permission.objects.filter(code__in=[c for c, _, _ in PERMISSIONS]).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0006_permission_model'),
    ]

    operations = [
        migrations.RunPython(seed, unseed),
    ]
