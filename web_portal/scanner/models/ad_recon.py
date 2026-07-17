"""AD Recon data models — credential profiles, recon sessions, domain objects."""

from __future__ import annotations

from django.conf import settings
from django.db import models
from cryptography.fernet import Fernet

from . import generate_uuid7, User


def _fernet():
    key = settings.SECRET_KEY
    if isinstance(key, str):
        key = key.encode()
    # Fernet requires a 32-byte URL-safe base64-encoded key
    # Use Django's SECRET_KEY to derive it
    import base64
    import hashlib

    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(key).digest()))


class CredentialProfile(models.Model):
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="ad_profiles")
    name = models.CharField(max_length=128)
    domain = models.CharField(max_length=256)
    username = models.CharField(max_length=256)
    password = models.TextField()  # AES-256-GCM encrypted at rest
    nt_hash = models.TextField(blank=True)  # AES-256-GCM encrypted at rest
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (("owner", "name"),)
        ordering = ["name"]

    def __str__(self):
        return f"{self.name} ({self.domain})"

    def __repr__(self):
        return f"<CredentialProfile {self.id} name={self.name!r}>"

    def clean(self):
        if not self.password and not self.nt_hash:
            from django.core.exceptions import ValidationError

            raise ValidationError("At least one of password or nt_hash must be set")

    def save(self, *args, **kwargs):
        self.clean()
        f = _fernet()
        if self.password and not self.password.startswith("gAAAAA"):
            self.password = f.encrypt(self.password.encode()).decode()
        if self.nt_hash and not self.nt_hash.startswith("gAAAAA"):
            self.nt_hash = f.encrypt(self.nt_hash.encode()).decode()
        super().save(*args, **kwargs)

    def decrypt_password(self):
        if not self.password:
            return ""
        f = _fernet()
        return f.decrypt(self.password.encode()).decode()

    def decrypt_nt_hash(self):
        if not self.nt_hash:
            return ""
        f = _fernet()
        return f.decrypt(self.nt_hash.encode()).decode()


class ADReconSession(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("running", "Running"),
        ("complete", "Complete"),
        ("failed", "Failed"),
    ]
    SCOPE_CHOICES = [("authenticated", "Authenticated"), ("unauth", "Unauthenticated")]

    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    profile = models.ForeignKey(CredentialProfile, on_delete=models.SET_NULL, null=True, blank=True)
    scope = models.CharField(max_length=16, choices=SCOPE_CHOICES, default="authenticated")
    dc_ip = models.GenericIPAddressField()
    domain = models.CharField(max_length=256)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default="pending")
    error = models.TextField(blank=True)
    tool_status = models.JSONField(default=dict)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]


class ADDomain(models.Model):
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    session = models.ForeignKey(ADReconSession, on_delete=models.CASCADE, related_name="domains")
    name = models.CharField(max_length=256)
    netbios_name = models.CharField(max_length=64, blank=True)
    sid = models.CharField(max_length=256, blank=True)
    functional_level = models.CharField(max_length=64, blank=True)
    forest = models.CharField(max_length=256, blank=True)

    class Meta:
        ordering = ["name"]


class ADUser(models.Model):
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    session = models.ForeignKey(ADReconSession, on_delete=models.CASCADE, related_name="users")
    sam_account_name = models.CharField(max_length=256)
    upn = models.CharField(max_length=256, blank=True)
    display_name = models.CharField(max_length=256, blank=True)
    dn = models.CharField(max_length=1024, blank=True)
    description = models.TextField(blank=True)
    enabled = models.BooleanField(default=True)
    admin_count = models.IntegerField(default=0)
    last_logon = models.DateTimeField(null=True, blank=True)
    member_of = models.JSONField(default=list)
    pwd_last_set = models.DateTimeField(null=True, blank=True)
    spn_count = models.IntegerField(default=0)

    class Meta:
        ordering = ["sam_account_name"]


class ADGroup(models.Model):
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    session = models.ForeignKey(ADReconSession, on_delete=models.CASCADE, related_name="groups")
    name = models.CharField(max_length=256)
    sam_account_name = models.CharField(max_length=256, blank=True)
    dn = models.CharField(max_length=1024, blank=True)
    description = models.TextField(blank=True)
    members = models.JSONField(default=list)
    member_count = models.IntegerField(default=0)
    admin_count = models.IntegerField(default=0)

    class Meta:
        ordering = ["name"]


class ADComputer(models.Model):
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    session = models.ForeignKey(ADReconSession, on_delete=models.CASCADE, related_name="computers")
    name = models.CharField(max_length=256)
    dns_hostname = models.CharField(max_length=256, blank=True)
    os = models.CharField(max_length=256, blank=True)
    os_version = models.CharField(max_length=256, blank=True)
    dn = models.CharField(max_length=1024, blank=True)
    enabled = models.BooleanField(default=True)
    last_logon = models.DateTimeField(null=True, blank=True)
    member_of = models.JSONField(default=list)

    class Meta:
        ordering = ["name"]


class ADTrust(models.Model):
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    session = models.ForeignKey(ADReconSession, on_delete=models.CASCADE, related_name="trusts")
    source_domain = models.CharField(max_length=256)
    target_domain = models.CharField(max_length=256)
    direction = models.CharField(max_length=32)
    trust_type = models.CharField(max_length=64)
    transitive = models.BooleanField(default=False)

    class Meta:
        ordering = ["source_domain", "target_domain"]


class ADSPN(models.Model):
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    session = models.ForeignKey(ADReconSession, on_delete=models.CASCADE, related_name="spns")
    service_name = models.CharField(max_length=256)
    sam_account_name = models.CharField(max_length=256)
    host = models.CharField(max_length=256, blank=True)
    port = models.IntegerField(null=True, blank=True)
    category = models.CharField(max_length=64, blank=True)

    class Meta:
        ordering = ["service_name"]


class ADACL(models.Model):
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    session = models.ForeignKey(ADReconSession, on_delete=models.CASCADE, related_name="acls")
    object_dn = models.CharField(max_length=512)
    identity = models.CharField(max_length=256)
    active_directory_rights = models.CharField(max_length=256)
    access_control_type = models.CharField(max_length=64)
    interesting_rights = models.JSONField(default=list)

    class Meta:
        ordering = ["object_dn"]


class ADShare(models.Model):
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    session = models.ForeignKey(ADReconSession, on_delete=models.CASCADE, related_name="shares")
    name = models.CharField(max_length=256)
    path = models.CharField(max_length=512, blank=True)
    description = models.TextField(blank=True)
    access = models.CharField(max_length=256, blank=True)

    class Meta:
        ordering = ["name"]


class ADCertService(models.Model):
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    session = models.ForeignKey(
        ADReconSession, on_delete=models.CASCADE, related_name="cert_services"
    )
    ca_name = models.CharField(max_length=256)
    host = models.CharField(max_length=256, blank=True)
    templates = models.JSONField(default=list)
    vulnerable_template = models.BooleanField(default=False)

    class Meta:
        ordering = ["ca_name"]


class ADSprayResult(models.Model):
    """Password spray attempt result — one row per successful credential pair."""
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    session = models.ForeignKey(
        ADReconSession, on_delete=models.CASCADE, related_name="spray_results"
    )
    password = models.CharField(max_length=256)
    username = models.CharField(max_length=256)
    status = models.CharField(
        max_length=32,
        choices=[
            ("success", "Success"),
            ("failed", "Failed"),
            ("locked", "Account Locked"),
            ("error", "Error"),
        ],
        default="failed",
    )
    output = models.TextField(blank=True)
    sprayed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-sprayed_at", "status", "username"]


# ── ViperOne-inspired pipeline additions ──


class CredentialFinding(models.Model):
    """Harvested credential — cleartext or hash found during passive hunting.

    Sources: GPP cpassword XML, LAPS, user description/info fields,
    UnixUserPassword, userPassword LDAP attributes.
    """
    SOURCE_CHOICES = [
        ("gpp_password", "GPP Password (cpassword)"),
        ("gpp_autologin", "GPP Auto-login"),
        ("laps", "LAPS Password"),
        ("user_desc", "User Description"),
        ("user_info", "User Info Field"),
        ("unix_password", "UnixUserPassword Attribute"),
        ("user_password", "UserPassword Attribute"),
        ("spider_plus", "SMB Share Spider"),
    ]
    TYPE_CHOICES = [
        ("cleartext", "Cleartext Password"),
        ("ntlm_hash", "NTLM Hash"),
        ("laps", "LAPS Password"),
    ]

    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    session = models.ForeignKey(
        ADReconSession, on_delete=models.CASCADE, related_name="credential_findings"
    )
    source = models.CharField(max_length=32, choices=SOURCE_CHOICES)
    credential_type = models.CharField(max_length=16, choices=TYPE_CHOICES, default="cleartext")
    target = models.CharField(max_length=512, blank=True)  # host, FQDN, or file path
    username = models.CharField(max_length=256)
    password = models.TextField()  # Fernet AES-256-GCM encrypted at rest
    details = models.JSONField(default=dict)  # XML path, LDAP attr, file path context
    found_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["source", "username"]

    def __str__(self):
        return f"{self.source}: {self.username} @ {self.target}"

    def save(self, *args, **kwargs):
        f = _fernet()
        if self.password and not self.password.startswith("gAAAAA"):
            self.password = f.encrypt(self.password.encode()).decode()
        super().save(*args, **kwargs)

    def decrypt_password(self):
        if not self.password:
            return ""
        f = _fernet()
        return f.decrypt(self.password.encode()).decode()


class ACLFinding(models.Model):
    """Dangerous ACL discovered on a key AD object.

    Stored from nxc ldap -M daclread output. Risk levels follow BloodHound
    semantics: GenericAll / WriteDacl / WriteOwner on high-value objects are
    'critical'; similar on lower-value objects are 'high'.
    """
    RISK_CHOICES = [
        ("critical", "Critical"),
        ("high", "High"),
        ("medium", "Medium"),
        ("low", "Low"),
    ]

    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    session = models.ForeignKey(
        ADReconSession, on_delete=models.CASCADE, related_name="acl_findings"
    )
    object_dn = models.CharField(max_length=1024)
    principal = models.CharField(max_length=512)  # who has the right
    right_name = models.CharField(max_length=256)
    right_type = models.CharField(max_length=32)  # Allow / Deny
    is_inherited = models.BooleanField(default=False)
    risk_level = models.CharField(max_length=16, choices=RISK_CHOICES, default="medium")
    attack_path = models.TextField(blank=True)

    class Meta:
        ordering = ["-risk_level", "object_dn", "principal"]

    def __str__(self):
        return f"{self.risk_level}: {self.principal} → {self.right_name} on {self.object_dn}"


class VulnCheck(models.Model):
    """Vulnerability check result from privilege-escalation path detection.

    Checks: zerologon, nopac, petitpotam, printerbug, shadowcoerce, dfscoerce.
    """
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    session = models.ForeignKey(
        ADReconSession, on_delete=models.CASCADE, related_name="vuln_checks"
    )
    check_name = models.CharField(max_length=128)
    host = models.CharField(max_length=256)
    vulnerable = models.BooleanField(default=False)
    details = models.JSONField(default=dict)  # raw module output / CVE info
    checked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-vulnerable", "check_name"]
        constraints = [
            models.UniqueConstraint(
                fields=["session", "check_name", "host"],
                name="uq_vuln_check_session_host",
            )
        ]

    def __str__(self):
        status = "VULN" if self.vulnerable else "SAFE"
        return f"{self.check_name} @ {self.host}: {status}"


class ADCSExploitSession(models.Model):
    """Interactive step-by-step ADCS exploitation session.

    Each session targets one ESC vulnerability detected by a VulnCheck.
    Steps are pre-defined per ESC type. The Celery task runs one step at a
    time, saves output, and sets ``status=awaiting_confirm``. The user
    approves/rejects via the API, which re-dispatches the task for the
    next step.
    """

    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    ad_session = models.ForeignKey(
        ADReconSession, on_delete=models.CASCADE, related_name="exploit_sessions",
    )
    vuln_check = models.ForeignKey(
        VulnCheck, on_delete=models.CASCADE, related_name="exploit_sessions",
    )
    esc_type = models.CharField(
        max_length=32, help_text="ESC1-ESC8 or ESC15"
    )
    current_step = models.PositiveSmallIntegerField(default=0)
    total_steps = models.PositiveSmallIntegerField(default=0)
    status = models.CharField(
        max_length=32,
        default="running",
        choices=(
            ("running", "Running"),
            ("awaiting_confirm", "Awaiting Confirmation"),
            ("completed", "Completed"),
            ("failed", "Failed"),
            ("cancelled", "Cancelled"),
        ),
    )
    steps = models.JSONField(
        default=list,
        help_text="List of step objects: {num, name, description, command, output, status}",
    )
    output_dir = models.CharField(
        max_length=512, blank=True,
        help_text="Temporary directory for PFX files and command output",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"ADCS {self.esc_type} exploit — {self.status}"
