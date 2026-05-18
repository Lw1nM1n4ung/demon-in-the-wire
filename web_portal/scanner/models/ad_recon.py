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
    import base64, hashlib
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(key).digest()))


class CredentialProfile(models.Model):
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='ad_profiles')
    name = models.CharField(max_length=128)
    domain = models.CharField(max_length=256)
    username = models.CharField(max_length=256)
    password = models.TextField()            # AES-256-GCM encrypted at rest
    nt_hash = models.TextField(blank=True)   # AES-256-GCM encrypted at rest
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (('owner', 'name'),)
        ordering = ['name']

    def __str__(self):
        return f"{self.name} ({self.domain})"

    def __repr__(self):
        return f"<CredentialProfile {self.id} name={self.name!r}>"

    def save(self, *args, **kwargs):
        f = _fernet()
        if self.password and not self.password.startswith('gAAAAA'):
            self.password = f.encrypt(self.password.encode()).decode()
        if self.nt_hash and not self.nt_hash.startswith('gAAAAA'):
            self.nt_hash = f.encrypt(self.nt_hash.encode()).decode()
        super().save(*args, **kwargs)

    def decrypt_password(self):
        f = _fernet()
        return f.decrypt(self.password.encode()).decode()

    def decrypt_nt_hash(self):
        if not self.nt_hash:
            return ''
        f = _fernet()
        return f.decrypt(self.nt_hash.encode()).decode()


class ADReconSession(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'), ('running', 'Running'),
        ('complete', 'Complete'), ('failed', 'Failed'),
    ]
    SCOPE_CHOICES = [('authenticated', 'Authenticated'), ('unauth', 'Unauthenticated')]

    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    profile = models.ForeignKey(CredentialProfile, on_delete=models.SET_NULL, null=True, blank=True)
    scope = models.CharField(max_length=16, choices=SCOPE_CHOICES, default='authenticated')
    dc_ip = models.GenericIPAddressField()
    domain = models.CharField(max_length=256)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default='pending')
    error = models.TextField(blank=True)
    tool_status = models.JSONField(default=dict)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']


class ADDomain(models.Model):
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    session = models.ForeignKey(ADReconSession, on_delete=models.CASCADE, related_name='domains')
    name = models.CharField(max_length=256)
    netbios_name = models.CharField(max_length=64, blank=True)
    sid = models.CharField(max_length=256, blank=True)
    functional_level = models.CharField(max_length=64, blank=True)
    forest = models.CharField(max_length=256, blank=True)


class ADUser(models.Model):
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    session = models.ForeignKey(ADReconSession, on_delete=models.CASCADE, related_name='users')
    sam_account_name = models.CharField(max_length=256)
    upn = models.CharField(max_length=256, blank=True)
    display_name = models.CharField(max_length=256, blank=True)
    description = models.TextField(blank=True)
    enabled = models.BooleanField(default=True)
    admin_count = models.IntegerField(default=0)
    last_logon = models.DateTimeField(null=True, blank=True)
    member_of = models.JSONField(default=list)
    pwd_last_set = models.DateTimeField(null=True, blank=True)
    spn_count = models.IntegerField(default=0)


class ADGroup(models.Model):
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    session = models.ForeignKey(ADReconSession, on_delete=models.CASCADE, related_name='groups')
    name = models.CharField(max_length=256)
    sam_account_name = models.CharField(max_length=256, blank=True)
    description = models.TextField(blank=True)
    members = models.JSONField(default=list)
    member_count = models.IntegerField(default=0)
    admin_count = models.IntegerField(default=0)


class ADComputer(models.Model):
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    session = models.ForeignKey(ADReconSession, on_delete=models.CASCADE, related_name='computers')
    name = models.CharField(max_length=256)
    dns_hostname = models.CharField(max_length=256, blank=True)
    os = models.CharField(max_length=256, blank=True)
    os_version = models.CharField(max_length=256, blank=True)
    enabled = models.BooleanField(default=True)
    last_logon = models.DateTimeField(null=True, blank=True)
    member_of = models.JSONField(default=list)


class ADTrust(models.Model):
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    session = models.ForeignKey(ADReconSession, on_delete=models.CASCADE, related_name='trusts')
    source_domain = models.CharField(max_length=256)
    target_domain = models.CharField(max_length=256)
    direction = models.CharField(max_length=32)
    trust_type = models.CharField(max_length=64)
    transitive = models.BooleanField(default=False)


class ADSPN(models.Model):
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    session = models.ForeignKey(ADReconSession, on_delete=models.CASCADE, related_name='spns')
    service_name = models.CharField(max_length=256)
    sam_account_name = models.CharField(max_length=256)
    host = models.CharField(max_length=256, blank=True)
    port = models.IntegerField(null=True, blank=True)
    category = models.CharField(max_length=64, blank=True)


class ADACL(models.Model):
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    session = models.ForeignKey(ADReconSession, on_delete=models.CASCADE, related_name='acls')
    object_dn = models.CharField(max_length=512)
    identity = models.CharField(max_length=256)
    active_directory_rights = models.CharField(max_length=256)
    access_control_type = models.CharField(max_length=64)
    interesting_rights = models.JSONField(default=list)


class ADShare(models.Model):
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    session = models.ForeignKey(ADReconSession, on_delete=models.CASCADE, related_name='shares')
    name = models.CharField(max_length=256)
    path = models.CharField(max_length=512, blank=True)
    description = models.TextField(blank=True)
    access = models.CharField(max_length=256, blank=True)


class ADCertService(models.Model):
    id = models.UUIDField(primary_key=True, default=generate_uuid7, editable=False)
    session = models.ForeignKey(ADReconSession, on_delete=models.CASCADE, related_name='cert_services')
    ca_name = models.CharField(max_length=256)
    host = models.CharField(max_length=256, blank=True)
    templates = models.JSONField(default=list)
    vulnerable_template = models.BooleanField(default=False)
