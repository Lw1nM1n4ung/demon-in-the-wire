from django.db import migrations


DEFAULT_POLICIES = [
    {
        'name': 'Full Assessment',
        'description': 'All scanners enabled — maximum depth and coverage',
        'scan_type': 'full',
        'parallelism': 10,
        'timeout': 3600,
        'port_range': '1-65535',
        'tools': {'nmap': True, 'nuclei': True, 'dirsearch': True, 'searchsploit': True, 'wpscan': True, 'service_enum': True, 'openvas': False},
        'version_detect': True,
        'os_detect': True,
        'severity_filter': 'all',
        'report_formats': 'dashboard,docx,xlsx',
        'is_default': True,
    },
    {
        'name': 'Quick Recon',
        'description': 'Fast port scan + nuclei critical/high only for rapid triage',
        'scan_type': 'quick',
        'parallelism': 20,
        'timeout': 1800,
        'port_range': '1-10000',
        'tools': {'nmap': True, 'nuclei': True, 'dirsearch': False, 'searchsploit': False, 'wpscan': False, 'service_enum': False, 'openvas': False},
        'version_detect': True,
        'os_detect': False,
        'severity_filter': 'critical,high',
        'report_formats': 'dashboard',
        'is_default': False,
    },
    {
        'name': 'Web Application',
        'description': 'Web-focused scanning with directory brute force and CMS detection',
        'scan_type': 'web',
        'parallelism': 10,
        'timeout': 5400,
        'port_range': '80,443,8080,8443,8000,3000',
        'tools': {'nmap': True, 'nuclei': True, 'dirsearch': True, 'searchsploit': False, 'wpscan': True, 'service_enum': False, 'openvas': False},
        'version_detect': True,
        'os_detect': False,
        'severity_filter': 'all',
        'report_formats': 'dashboard,docx',
        'is_default': False,
    },
    {
        'name': 'Service Audit',
        'description': 'Service enumeration — check default creds, banners, misconfigs',
        'scan_type': 'service',
        'parallelism': 5,
        'timeout': 2400,
        'port_range': '1-65535',
        'tools': {'nmap': True, 'nuclei': False, 'dirsearch': False, 'searchsploit': True, 'wpscan': False, 'service_enum': True, 'openvas': False},
        'version_detect': True,
        'os_detect': True,
        'severity_filter': 'all',
        'report_formats': 'dashboard,xlsx',
        'is_default': False,
    },
    {
        'name': 'Stealth Scan',
        'description': 'SYN scan only, no scripts, low parallelism for quiet recon',
        'scan_type': 'port',
        'parallelism': 2,
        'timeout': 7200,
        'port_range': '1-10000',
        'tools': {'nmap': True, 'nuclei': False, 'dirsearch': False, 'searchsploit': False, 'wpscan': False, 'service_enum': False, 'openvas': False},
        'version_detect': False,
        'os_detect': False,
        'severity_filter': 'all',
        'report_formats': 'xlsx',
        'is_default': False,
    },
]


def seed_policies(apps, schema_editor):
    ScanPolicy = apps.get_model('scanner', 'ScanPolicy')
    for p in DEFAULT_POLICIES:
        ScanPolicy.objects.get_or_create(name=p['name'], defaults=p)


def remove_policies(apps, schema_editor):
    ScanPolicy = apps.get_model('scanner', 'ScanPolicy')
    names = [p['name'] for p in DEFAULT_POLICIES]
    ScanPolicy.objects.filter(name__in=names, is_default=True).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(seed_policies, remove_policies),
    ]
