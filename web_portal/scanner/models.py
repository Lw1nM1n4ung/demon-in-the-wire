import uuid

from django.contrib.auth.models import AbstractUser
from django.db import models
from uuid_utils import uuid7


def generate_uuid7():
    return uuid.UUID(str(uuid7()))


# ═══════════════ Singleton UUIDs ═══════════════
REPORT_CONFIG_UUID = uuid.UUID('00000000-0000-7000-8000-000000000001')
SITE_CONFIG_UUID = uuid.UUID('00000000-0000-7000-8000-000000000002')


# ═══════════════ Custom User ═══════════════

class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)

    class Meta:
        db_table = 'scanner_user'


# ═══════════════ Scanner Models ═══════════════

class Scan(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    SCAN_TYPE_CHOICES = [
        ('full', 'Full Scan'),
        ('quick', 'Quick Scan'),
        ('port', 'Port Scan Only'),
        ('web', 'Web Application Scan'),
        ('service', 'Service Enumeration'),
    ]

    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    name = models.CharField(max_length=255)
    target = models.CharField(max_length=500)
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPE_CHOICES, default='full')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    parallelism = models.IntegerField(default=10)
    timeout = models.IntegerField(default=3600)
    report_formats = models.CharField(max_length=100, default='dashboard,html,docx,xlsx')

    # Options
    version_detect = models.BooleanField(default=True)
    os_detect = models.BooleanField(default=True)
    service_enum = models.BooleanField(default=True)
    skip_nuclei = models.BooleanField(default=False)
    skip_openvas = models.BooleanField(default=True)

    # Results
    hosts_count = models.IntegerField(default=0)
    ports_count = models.IntegerField(default=0)
    findings_count = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    info_count = models.IntegerField(default=0)

    # Timing
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration_seconds = models.IntegerField(default=0)

    # Output
    output_dir = models.CharField(max_length=500, blank=True)
    celery_task_id = models.CharField(max_length=255, blank=True)
    error_message = models.TextField(blank=True)

    # Meta
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} ({self.target})"


class Host(models.Model):
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='hosts')
    ip = models.GenericIPAddressField()
    hostname = models.CharField(max_length=255, blank=True)
    os = models.CharField(max_length=255, blank=True)
    status = models.CharField(max_length=20, default='up')
    ports_count = models.IntegerField(default=0)
    findings_count = models.IntegerField(default=0)

    class Meta:
        ordering = ['ip']

    def __str__(self):
        return self.ip


class Port(models.Model):
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name='ports')
    number = models.IntegerField()
    protocol = models.CharField(max_length=10, default='tcp')
    state = models.CharField(max_length=20, default='open')
    service_name = models.CharField(max_length=100, blank=True)
    service_product = models.CharField(max_length=200, blank=True)
    service_version = models.CharField(max_length=200, blank=True)

    class Meta:
        ordering = ['number']


class Finding(models.Model):
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]

    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='findings')
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name='findings', null=True)
    source = models.CharField(max_length=50)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    title = models.CharField(max_length=500)
    description = models.TextField(blank=True)
    host_ip = models.GenericIPAddressField(null=True)
    port = models.CharField(max_length=10, blank=True)
    protocol = models.CharField(max_length=10, default='tcp')
    endpoint = models.CharField(max_length=500, blank=True)
    full_url = models.CharField(max_length=1000, blank=True)
    template_id = models.CharField(max_length=200, blank=True)
    cve = models.CharField(max_length=500, blank=True)
    cwe = models.CharField(max_length=200, blank=True)
    cvss = models.CharField(max_length=200, blank=True)
    request = models.TextField(blank=True)
    response = models.TextField(blank=True)
    curl_command = models.TextField(blank=True)
    raw_output = models.TextField(blank=True)
    references = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-severity', '-created_at']

    def __str__(self):
        return f"[{self.severity}] {self.title}"


class Technology(models.Model):
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name='technologies')
    name = models.CharField(max_length=200)
    version = models.CharField(max_length=200, blank=True)
    url = models.CharField(max_length=500, blank=True)


class Report(models.Model):
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='reports')
    format = models.CharField(max_length=20)
    file_path = models.CharField(max_length=500)
    file_size = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)


class ReportConfig(models.Model):
    """Singleton — report branding & section configuration."""
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)

    # Branding
    report_title = models.CharField(max_length=255, default='Vulnerability Assessment Report')
    company_name = models.CharField(max_length=255, blank=True)
    prepared_by = models.CharField(max_length=255, blank=True)
    reviewed_by = models.CharField(max_length=255, blank=True)
    approved_by = models.CharField(max_length=255, blank=True)
    logo_path = models.CharField(max_length=500, blank=True)
    brand_color = models.CharField(max_length=7, default='#006D38')

    # Sections to include in DOCX
    include_cover = models.BooleanField(default=True)
    include_executive_summary = models.BooleanField(default=True)
    include_target_subnets = models.BooleanField(default=True)
    include_live_hosts = models.BooleanField(default=True)
    include_open_ports = models.BooleanField(default=True)
    include_findings = models.BooleanField(default=True)
    include_evidence = models.BooleanField(default=True)

    # Default formats
    default_formats = models.CharField(max_length=100, default='dashboard,docx,xlsx')

    # Disclaimer text
    disclaimer = models.TextField(
        default='This report is confidential and intended solely for the use of the organization to which it is addressed.'
    )

    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Report Configuration'
        verbose_name_plural = 'Report Configuration'

    def __str__(self):
        return f"Report Config ({self.company_name or 'Default'})"

    def save(self, *args, **kwargs):
        self.pk = REPORT_CONFIG_UUID
        super().save(*args, **kwargs)

    @classmethod
    def get(cls):
        obj, _ = cls.objects.get_or_create(pk=REPORT_CONFIG_UUID)
        return obj


class SiteConfig(models.Model):
    """Singleton — site-wide configuration (setup state, etc.)."""
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    setup_complete = models.BooleanField(default=False)
    setup_completed_at = models.DateTimeField(null=True, blank=True)
    setup_completed_by = models.CharField(max_length=255, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Site Configuration'
        verbose_name_plural = 'Site Configuration'

    def save(self, *args, **kwargs):
        self.pk = SITE_CONFIG_UUID
        super().save(*args, **kwargs)

    @classmethod
    def get(cls):
        obj, _ = cls.objects.get_or_create(pk=SITE_CONFIG_UUID)
        return obj


class UserPreference(models.Model):
    """Per-user preferences (theme, notifications, etc.)."""
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='preferences')

    # Theme
    theme_mode = models.CharField(max_length=20, default='dark')
    accent_color = models.CharField(max_length=20, default='blue')
    font_size = models.CharField(max_length=20, default='default')

    # Notifications
    notif_scan_complete = models.BooleanField(default=True)
    notif_scan_failed = models.BooleanField(default=True)
    notif_critical_finding = models.BooleanField(default=True)
    notif_report_ready = models.BooleanField(default=True)
    notif_weekly_digest = models.BooleanField(default=False)
    notif_email = models.BooleanField(default=False)

    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Preferences for {self.user.username}"

    @classmethod
    def for_user(cls, user):
        obj, _ = cls.objects.get_or_create(user=user)
        return obj


class ApiKey(models.Model):
    """API keys for programmatic access."""
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='api_keys')
    name = models.CharField(max_length=255)
    key = models.CharField(max_length=64, unique=True)
    scopes = models.CharField(max_length=500, default='scans:read,findings:read')
    last_used = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} ({self.user.username})"


class AuditLog(models.Model):
    """Audit trail for user actions."""
    ACTION_TYPES = [
        ('auth', 'Authentication'),
        ('scan', 'Scan'),
        ('report', 'Report'),
        ('admin', 'Admin'),
        ('config', 'Configuration'),
    ]
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    user = models.CharField(max_length=255)
    action = models.CharField(max_length=100)
    detail = models.TextField(blank=True)
    type = models.CharField(max_length=20, choices=ACTION_TYPES, default='admin')
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.user} — {self.action}"

    @classmethod
    def log(cls, user, action, detail='', log_type='admin', ip=None):
        cls.objects.create(user=str(user), action=action, detail=detail, type=log_type, ip_address=ip)


class ScanPolicy(models.Model):
    """Reusable scan configuration templates."""
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    scan_type = models.CharField(max_length=20, choices=Scan.SCAN_TYPE_CHOICES, default='full')
    parallelism = models.IntegerField(default=10)
    timeout = models.IntegerField(default=3600)
    port_range = models.CharField(max_length=500, default='1-65535')
    tools = models.JSONField(default=dict)
    version_detect = models.BooleanField(default=True)
    os_detect = models.BooleanField(default=True)
    severity_filter = models.CharField(max_length=100, default='all')
    report_formats = models.CharField(max_length=100, default='dashboard,docx,xlsx')
    is_default = models.BooleanField(default=False)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-is_default', 'name']

    def __str__(self):
        return self.name


class ScheduledScan(models.Model):
    """Recurring scan schedules executed via Celery Beat."""
    FREQUENCY_CHOICES = [
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('biweekly', 'Every 2 Weeks'),
        ('monthly', 'Monthly'),
    ]

    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    name = models.CharField(max_length=255)
    target = models.CharField(max_length=500)
    frequency = models.CharField(max_length=20, choices=FREQUENCY_CHOICES)
    time = models.TimeField()
    scan_type = models.CharField(max_length=20, choices=Scan.SCAN_TYPE_CHOICES, default='full')
    policy = models.ForeignKey(ScanPolicy, on_delete=models.SET_NULL, null=True, blank=True)
    enabled = models.BooleanField(default=True)
    last_run = models.DateTimeField(null=True, blank=True)
    next_run = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['next_run']

    def __str__(self):
        return f"{self.name} ({self.frequency})"
