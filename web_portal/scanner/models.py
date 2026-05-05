import uuid

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from uuid_utils import uuid7


def generate_uuid7():
    return uuid.UUID(str(uuid7()))


# ═══════════════ Singleton UUIDs ═══════════════
REPORT_CONFIG_UUID = uuid.UUID('00000000-0000-7000-8000-000000000001')
SITE_CONFIG_UUID = uuid.UUID('00000000-0000-7000-8000-000000000002')


# ═══════════════ Custom User ═══════════════

class User(AbstractUser):
    ROLE_OWNER = 'owner'
    ROLE_ENGINEER = 'engineer'
    ROLE_VIEWER = 'viewer'
    ROLE_CHOICES = [
        (ROLE_OWNER, 'Owner'),
        (ROLE_ENGINEER, 'Engineer'),
        (ROLE_VIEWER, 'Viewer'),
    ]

    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    role = models.CharField(max_length=16, choices=ROLE_CHOICES, default=ROLE_VIEWER)

    class Meta:
        db_table = 'scanner_user'

    @property
    def is_owner(self):
        return self.role == self.ROLE_OWNER

    @property
    def is_engineer(self):
        return self.role == self.ROLE_ENGINEER

    @property
    def is_viewer(self):
        return self.role == self.ROLE_VIEWER

    def has_permission(self, code):
        """Does this user's role grant the given permission code?

        Uses a per-role Redis cache (1 hour TTL) to avoid a DB lookup on
        every request. Cache is invalidated implicitly via TTL; callers
        that mutate RolePermission should call `User.invalidate_perm_cache(role)`.
        """
        from django.core.cache import cache
        key = f'perms:{self.role}'
        perms = cache.get(key)
        if perms is None:
            perms = set(
                RolePermission.objects.filter(role=self.role)
                                       .values_list('permission__code', flat=True)
            )
            cache.set(key, perms, 3600)
        return code in perms

    @classmethod
    def invalidate_perm_cache(cls, role=None):
        """Drop cached permission sets for one role (or all if role is None)."""
        from django.core.cache import cache
        if role:
            cache.delete(f'perms:{role}')
        else:
            for r, _ in cls.ROLE_CHOICES:
                cache.delete(f'perms:{r}')

    def save(self, *args, **kwargs):
        # Reconcile role when callers use Django's built-in create_superuser/create_user
        # with is_superuser=True: treat the intent as Owner (only for newly-created rows
        # so that role changes on existing users aren't silently overridden).
        # NOTE: `self.pk is None` doesn't work here because UUIDField default runs at
        # instance construction time; use Django's adding flag instead.
        is_new = getattr(self._state, 'adding', self.pk is None)
        if is_new and self.is_superuser and self.role == self.ROLE_VIEWER:
            self.role = self.ROLE_OWNER

        # Enforce: at most one Owner ever.
        if self.role == self.ROLE_OWNER:
            from django.core.exceptions import ValidationError
            clashes = type(self).objects.filter(role=self.ROLE_OWNER).exclude(pk=self.pk)
            if clashes.exists():
                raise ValidationError('Only one Owner account is permitted.')

        # Keep Django's built-in flags mirrored to the role so Django admin and
        # any legacy is_superuser/is_staff checks behave consistently.
        self.is_superuser = (self.role == self.ROLE_OWNER)
        self.is_staff = self.role in (self.ROLE_OWNER, self.ROLE_ENGINEER)
        super().save(*args, **kwargs)


# ═══════════════ Permissions (data-driven RBAC) ═══════════════

class Permission(models.Model):
    """A single named capability (e.g. 'scan:write'). Mapped to roles via RolePermission."""
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=255, blank=True)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['code']

    def __str__(self):
        return self.code


class RolePermission(models.Model):
    """Which permissions each role holds. Seeded by migration; edit via migration only."""
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    role = models.CharField(max_length=16, choices=User.ROLE_CHOICES)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE, related_name='role_assignments')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = (('role', 'permission'),)
        indexes = [models.Index(fields=['role'])]
        ordering = ['role', 'permission__code']

    def __str__(self):
        return f"{self.role} → {self.permission.code}"


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
    skip_screenshots = models.BooleanField(default=False)
    nuclei_templates = models.CharField(max_length=500, blank=True)
    nuclei_default_templates = models.BooleanField(default=True)
    # If True, ICMP-silent hosts get port-scanned too (nmap -Pn path). Default
    # False because it can blow up scope on big CIDRs.
    scan_unresponsive = models.BooleanField(default=False)
    enum4linux = models.BooleanField(default=True)
    skip_nikto = models.BooleanField(default=False)
    skip_netexec = models.BooleanField(default=False)

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
    deadline = models.DateTimeField(null=True, blank=True)

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
    # IANA zone used to interpret ScheduledScan.time (e.g. "02:00" means 02:00 in this zone).
    schedule_timezone = models.CharField(max_length=64, default='UTC')

    # Scan defaults — fall-back when a Scan is created without these fields set.
    default_parallelism = models.IntegerField(default=10)
    default_timeout = models.IntegerField(default=3600)
    default_report_formats = models.CharField(max_length=100, default='dashboard,docx,xlsx')

    # Telegram notifications — Owner-only writes via /api/notifications/config/.
    # bot_token is plaintext (Telegram API requires the full value on each call);
    # never returned raw from any GET endpoint. telegram_shared_chat_id is the
    # team-wide channel/group (e.g. "-1001234567890" or "@wireghost_alerts").
    telegram_bot_token = models.CharField(max_length=128, blank=True)
    telegram_shared_chat_id = models.CharField(max_length=64, blank=True)

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

    # Telegram DM routing — optional per-user. The bot token lives on
    # SiteConfig; this is just the chat the user wants their personal
    # scan events delivered to. Master switch controls whether we dispatch.
    telegram_chat_id = models.CharField(max_length=64, blank=True)
    telegram_enabled = models.BooleanField(default=False)
    telegram_user_id = models.BigIntegerField(
        unique=True, null=True, blank=True,
        help_text='Telegram integer user ID for auth resolution',
    )

    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Preferences for {self.user.username}"

    @classmethod
    def for_user(cls, user):
        obj, _ = cls.objects.get_or_create(user=user)
        return obj


class UserMfaConfig(models.Model):
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='mfa_config')
    enabled = models.BooleanField(default=False)
    enabled_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"MFA({'on' if self.enabled else 'off'}) {self.user.username}"


class MfaBackupCode(models.Model):
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='mfa_backup_codes')
    code_hash = models.CharField(max_length=64)
    used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    @classmethod
    def generate_for_user(cls, user):
        import hashlib
        import secrets as _s
        cls.objects.filter(user=user).delete()
        codes = []
        for _ in range(8):
            raw = _s.token_hex(4)
            cls.objects.create(
                user=user,
                code_hash=hashlib.sha256(raw.encode()).hexdigest(),
            )
            codes.append(raw)
        return codes

    @classmethod
    def verify_and_consume(cls, user, code):
        import hashlib
        from django.utils import timezone as tz
        h = hashlib.sha256(code.strip().encode()).hexdigest()
        bc = cls.objects.filter(user=user, code_hash=h, used_at__isnull=True).first()
        if bc:
            bc.used_at = tz.now()
            bc.save(update_fields=['used_at'])
            return True
        return False


class ExploitMatch(models.Model):
    CONFIDENCE_CHOICES = [
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='exploit_matches')
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name='exploit_matches')
    port = models.ForeignKey(Port, on_delete=models.SET_NULL, null=True, blank=True, related_name='exploit_matches')
    finding = models.ForeignKey(Finding, on_delete=models.SET_NULL, null=True, blank=True, related_name='exploit_matches')
    module_fullname = models.CharField(max_length=500)
    module_name = models.CharField(max_length=500)
    module_type = models.CharField(max_length=20)
    module_rank = models.IntegerField(default=0)
    module_rank_name = models.CharField(max_length=20, blank=True)
    disclosure_date = models.CharField(max_length=30, blank=True)
    description = models.TextField(blank=True)
    references = models.JSONField(default=list)
    platform = models.CharField(max_length=100, blank=True)
    confidence = models.CharField(max_length=10, choices=CONFIDENCE_CHOICES)
    match_reason = models.CharField(max_length=500)
    host_ip = models.GenericIPAddressField(null=True, blank=True)
    port_number = models.IntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['confidence', '-module_rank']

    def __str__(self):
        return f"{self.confidence.upper()} {self.module_fullname}"


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
    skip_screenshots = models.BooleanField(default=False)
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
    stop_time = models.TimeField(null=True, blank=True)
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


# ═══════════════ Attack Surface — Asset aggregate ═══════════════

class Asset(models.Model):
    """Deduped inventory of (ip, port, protocol) seen across every scan.

    One row per unique network asset. Populated by `_sync_assets` after each
    scan writes its findings. Drives the ASM dashboard's KPIs and trend panels.
    """
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('closed', 'Closed'),
        ('filtered', 'Filtered'),
        ('inactive', 'Inactive'),
    ]

    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    ip = models.CharField(max_length=45)           # IPv4 or IPv6 text form
    port = models.IntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=8, default='tcp')

    hostname = models.CharField(max_length=255, blank=True)
    os = models.CharField(max_length=128, blank=True)
    service_name = models.CharField(max_length=64, blank=True)
    service_product = models.CharField(max_length=128, blank=True)
    service_version = models.CharField(max_length=64, blank=True)

    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()
    last_scan = models.ForeignKey(
        Scan, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='assets_last_scanned',
    )

    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default='open')
    risk_score = models.IntegerField(default=0)        # 0..100
    findings_count = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)

    class Meta:
        unique_together = (('ip', 'port', 'protocol'),)
        indexes = [
            models.Index(fields=['last_seen']),
            models.Index(fields=['first_seen']),
            models.Index(fields=['status']),
            models.Index(fields=['risk_score']),
            models.Index(fields=['ip']),
        ]
        ordering = ['-risk_score', '-last_seen']

    def __str__(self):
        return f"{self.ip}:{self.port}/{self.protocol}"


class ApiToken(models.Model):
    """User-issued token for programmatic /api/* access.

    The plaintext token value is returned ONCE at creation time — from then
    on only a SHA-256 hash is kept on disk. A DB leak therefore cannot
    reveal usable tokens. The `wg_` prefix is intentional: it lets
    TruffleHog / gitleaks / GitHub Secret Scanning detect accidentally-
    committed tokens.
    """
    MAX_PER_USER = 20

    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='api_tokens')
    name = models.CharField(max_length=80)
    prefix = models.CharField(max_length=12, db_index=True)   # e.g. 'wg_abc1234'
    key_hash = models.CharField(max_length=64, unique=True)   # sha256 hex
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [models.Index(fields=['user', 'revoked_at'])]

    def __str__(self):
        return f"{self.prefix}… ({self.user.username})"

    @property
    def is_active(self):
        if self.revoked_at is not None:
            return False
        if self.expires_at and self.expires_at <= timezone.now():
            return False
        return True

    @classmethod
    def mint(cls, user, name, expires_in_days=None):
        """Create a new token for ``user``. Returns ``(token_row, raw_plaintext)``.

        The caller must return ``raw_plaintext`` to the end user exactly once
        and then forget it — it's never stored.  Defaults to 90-day expiry.
        """
        import secrets
        import hashlib
        from datetime import timedelta
        body = secrets.token_urlsafe(32).replace('-', '').replace('_', '')[:40]
        raw = f'wg_{body}'
        prefix = raw[:11]
        key_hash = hashlib.sha256(raw.encode('utf-8')).hexdigest()
        if expires_in_days is None:
            expires_in_days = 90
        expires_at = timezone.now() + timedelta(days=int(expires_in_days))
        obj = cls.objects.create(
            user=user, name=(name or '')[:80], prefix=prefix,
            key_hash=key_hash, expires_at=expires_at,
        )
        return obj, raw


class Screenshot(models.Model):
    """Web endpoint screenshot captured by gowitness during a scan."""
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name='screenshots')
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='screenshots')
    url = models.CharField(max_length=500)
    filename = models.CharField(max_length=500)
    title = models.CharField(max_length=500, blank=True)
    status_code = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['url']
        indexes = [models.Index(fields=['scan'], name='scanner_scr_scan_id_idx')]

    def __str__(self):
        return f"{self.url} ({self.host.ip})"
