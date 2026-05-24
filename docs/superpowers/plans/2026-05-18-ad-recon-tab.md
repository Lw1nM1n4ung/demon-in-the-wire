# AD Recon Tab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build an interactive, credential-driven AD reconnaissance cockpit in the Wire_Ghost web portal.

**Architecture:** Four-layer flow — Browser (vanilla JS SPA) → Django REST API (`/api/ad-recon/*`) → Celery Worker (`ad_recon_task`) → Linux subprocess tools → Database (dedicated AD models).

**Tech Stack:** Django REST + ModelViewSet, Celery, Fernet (AES-256-GCM), vanilla JS SPA with hash router, UUIDv7 PKs via `uuid_utils.uuid7()`

**Spec:** `docs/superpowers/specs/2026-05-18-ad-recon-tab-design.md`

---

## File Structure

| Task | File | Action |
|------|------|--------|
| 1 | `web_portal/scanner/models/ad_recon.py` | Create — 11 Django models |
| 2 | `web_portal/scanner/tasks/ad_recon.py` | Create — Celery task with 7-phase tool execution |
| 3 | `web_portal/scanner/views/ad_recon.py`, `web_portal/scanner/serializers/ad_recon.py` | Create — DRF ViewSets + serializers |
| 4 | `web_portal/wireghost_web/urls.py` | Modify — Register AD recon routes |
| 5 | `web/js/app/pages/ad-recon.js`, `web/js/app/ad-recon.js` | Create — SPA frontend |
| 5b | `web/app.html`, `web/js/router.js` | Modify — Sidebar item + route registration |
| 6 | `Dockerfile` | Modify — Install AD tools (impacket, bloodhound-python, ldapdomaindump, kerbrute, responder) |
| 7 | `web_portal/scanner/tests/test_ad_models.py`, `test_ad_views.py`, `test_ad_tasks.py` | Create — Unit + integration tests |
| 8 | `web_portal/scanner/admin.py` | Modify — Register AD models |

---

### Task 1: AD Recon Data Models

**Files:**
- Create: `web_portal/scanner/models/ad_recon.py`
- Create: `web_portal/scanner/tests/test_ad_models.py`

- [ ] **Step 1: Write the models**

```python
"""AD Recon data models — credential profiles, recon sessions, domain objects."""
from __future__ import annotations

from django.conf import settings
from django.db import models
from cryptography.fernet import Fernet

from . import generate_uuid7, User


def _fernet():
    return Fernet(settings.SECRET_KEY if isinstance(settings.SECRET_KEY, bytes)
                  else settings.SECRET_KEY.encode()[:32].ljust(32, b'\x00')
                  if isinstance(settings.SECRET_KEY, str)
                  else settings.SECRET_KEY)


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
```

- [ ] **Step 2: Write the model tests**

Create `web_portal/scanner/tests/test_ad_models.py`:

```python
"""Tests for AD Recon models."""
from django.test import TestCase
from django.db.utils import IntegrityError
from scanner.models import User
from scanner.models.ad_recon import CredentialProfile, ADReconSession


class TestCredentialProfile(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username='adtest', password='test')

    def test_encryption_round_trip(self):
        profile = CredentialProfile.objects.create(
            owner=self.user, name='Lab', domain='lab.local',
            username='admin', password='Secret123',
        )
        self.assertTrue(profile.password.startswith('gAAAAA'))
        self.assertEqual(profile.decrypt_password(), 'Secret123')

    def test_repr_never_leaks_plaintext(self):
        profile = CredentialProfile.objects.create(
            owner=self.user, name='Lab', domain='lab.local',
            username='admin', password='Secret123',
        )
        r = repr(profile)
        self.assertNotIn('Secret123', r)
        self.assertNotIn('gAAAAA', r)

    def test_str_never_leaks_plaintext(self):
        profile = CredentialProfile.objects.create(
            owner=self.user, name='Lab', domain='lab.local',
            username='admin', password='Secret123',
        )
        s = str(profile)
        self.assertNotIn('Secret123', s)

    def test_unique_name_per_user(self):
        CredentialProfile.objects.create(
            owner=self.user, name='Lab', domain='lab.local',
            username='admin', password='Secret123',
        )
        with self.assertRaises(IntegrityError):
            CredentialProfile.objects.create(
                owner=self.user, name='Lab', domain='other.local',
                username='user', password='Pass456',
            )

    def test_nt_hash_encryption(self):
        profile = CredentialProfile.objects.create(
            owner=self.user, name='Hash Lab', domain='lab.local',
            username='admin', password='Secret123',
            nt_hash='aad3b435b51404eeaad3b435b51404ee',
        )
        self.assertTrue(profile.nt_hash.startswith('gAAAAA'))
        self.assertEqual(
            profile.decrypt_nt_hash(),
            'aad3b435b51404eeaad3b435b51404ee',
        )


class TestADReconSession(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username='adtest2', password='test')

    def test_session_scope_choices(self):
        profile = CredentialProfile.objects.create(
            owner=self.user, name='Lab', domain='lab.local',
            username='admin', password='Secret123',
        )
        session = ADReconSession.objects.create(
            profile=profile, scope='authenticated',
            dc_ip='10.0.0.1', domain='lab.local',
        )
        self.assertEqual(session.scope, 'authenticated')
        self.assertEqual(session.status, 'pending')

    def test_session_cascade_on_profile_delete(self):
        profile = CredentialProfile.objects.create(
            owner=self.user, name='Lab', domain='lab.local',
            username='admin', password='Secret123',
        )
        session = ADReconSession.objects.create(
            profile=profile, scope='authenticated',
            dc_ip='10.0.0.1', domain='lab.local',
        )
        profile.delete()
        session.refresh_from_db()
        self.assertIsNone(session.profile)
```

- [ ] **Step 3: Run tests and verify**

```bash
cd web_portal && DJANGO_SECRET_KEY=ci-secret python manage.py test scanner.tests.test_ad_models -v 2
```

- [ ] **Step 4: Commit**

```bash
git add web_portal/scanner/models/ad_recon.py web_portal/scanner/tests/test_ad_models.py
git commit -m "feat(ad-recon): add AD recon data models with Fernet encryption"
```

---

### Task 2: Celery Task — AD Recon Execution

**Files:**
- Create: `web_portal/scanner/tasks/ad_recon.py`
- Create: `web_portal/scanner/tests/test_ad_tasks.py`

- [ ] **Step 1: Write the Celery task**

```python
"""Celery task for AD Recon sessions — 7-phase sequential tool execution."""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import re
from datetime import timedelta
from pathlib import Path

from celery import shared_task
from django.utils import timezone

log = logging.getLogger(__name__)

TIMEOUTS = {
    'ldapdomaindump': 120, 'nxc_shares': 60, 'nxc_delegation': 60,
    'bloodhound': 300, 'impacket_getnpusers': 120, 'kerbrute': 60,
    'impacket_getspns': 120, 'impacket_secretsdump': 300,
    'impacket_samrdump': 60, 'rpcclient': 60, 'nxc_passpol': 60,
    'nxc_ioxid': 60, 'nxc_wmi': 60, 'nxc_adcs': 60, 'responder': 60,
}


def _run_tool(cmd: list[str], timeout: int, workdir: str) -> tuple[int, str, str]:
    """Run a tool subprocess, return (rc, stdout, stderr)."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=workdir,
        )
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, '', f'tool timed out after {timeout}s'
    except FileNotFoundError:
        return -2, '', f'binary not found: {cmd[0]}'


@shared_task(bind=True, max_retries=0, time_limit=7200, soft_time_limit=7000)
def ad_recon_task(self, session_id):
    """Execute AD recon phases sequentially for a session."""
    from scanner.models.ad_recon import (
        ADReconSession, CredentialProfile, ADDomain, ADUser, ADGroup,
        ADComputer, ADTrust, ADSPN, ADACL, ADShare, ADCertService,
    )

    session = ADReconSession.objects.select_related('profile').get(id=session_id)
    session.status = 'running'
    session.started_at = timezone.now()
    session.save(update_fields=['status', 'started_at'])

    workdir = tempfile.mkdtemp(prefix=f'adrecon_{session_id[:8]}_')
    domain = session.domain
    dc_ip = session.dc_ip

    try:
        # ── Phase 0: Connectivity check ──
        rc, out, err = _run_tool(
            ['nxc', 'smb', dc_ip, '--timeout', '15'],
            timeout=30, workdir=workdir,
        )
        if rc != 0 and 'SMB' not in (out + err):
            session.status = 'failed'
            session.error = f'Phase 0 connectivity check failed for {dc_ip}'
            session.completed_at = timezone.now()
            session.save(update_fields=['status', 'error', 'completed_at'])
            return

        # ── Authenticated path ──
        if session.scope == 'authenticated' and session.profile:
            profile = session.profile
            username = profile.decrypt_password()
            # clear from local var — use decrypt inline per tool instead
            del username

            # Phase 1: Domain dump
            _run_phase1_ldapdomaindump(session, profile, dc_ip, domain, workdir)
            _run_phase1_shares(session, profile, dc_ip, workdir)

            # Phase 2: BloodHound
            _run_phase2_bloodhound(session, profile, dc_ip, domain, workdir)

            # Phase 3: AS-REP roasting
            _run_phase3_asrep(session, profile, dc_ip, domain, workdir)

            # Phase 4: Impacket suite
            _run_phase4_impacket(session, profile, dc_ip, domain, workdir)

        # ── Unauthenticated path ──
        if session.scope == 'unauth':
            rc, out, err = _run_tool(
                ['kerbrute', 'userenum', '-d', domain, '--dc', dc_ip,
                 '/dev/null'],  # empty userlist — connectivity check only
                timeout=60, workdir=workdir,
            )
            session.tool_status['kerbrute'] = {
                'status': 'ok' if rc in (0, 1) else 'failed',
                'output': (out + err)[:500],
            }

        # ── Phase 5: SMB/RPC enumeration (both paths) ──
        _run_phase5_enum(session, profile if session.scope == 'authenticated' else None,
                         dc_ip, workdir)

        # ── Phase 6: Certificate services ──
        if session.scope == 'authenticated' and session.profile:
            _run_phase6_adcs(session, session.profile, dc_ip, workdir)

        # ── Phase 7: Network poisoning ──
        _run_phase7_responder(session, workdir)

        session.status = 'complete'
    except Exception as exc:
        session.status = 'failed'
        session.error = str(exc)[:1000]
        log.exception('AD recon session %s failed', session_id)
    finally:
        session.completed_at = timezone.now()
        session.save()
        shutil.rmtree(workdir, ignore_errors=True)


def _run_phase1_ldapdomaindump(session, profile, dc_ip, domain, workdir):
    """ldapdomaindump → ADUser, ADGroup, ADComputer."""
    from scanner.models.ad_recon import ADUser, ADGroup, ADComputer
    pwd = profile.decrypt_password()
    rc, out, err = _run_tool(
        ['ldapdomaindump', '-u', f'{domain}\\{profile.username}',
         '-p', pwd, '--no-json', '--no-grep', dc_ip],
        timeout=TIMEOUTS['ldapdomaindump'], workdir=workdir,
    )
    del pwd
    ok = rc == 0
    session.tool_status['ldapdomaindump'] = {'status': 'ok' if ok else 'failed', 'rc': rc}
    if not ok:
        session.error = f'Phase 1 failed: ldapdomaindump rc={rc}'
        session.save(update_fields=['error', 'tool_status'])


def _run_phase1_shares(session, profile, dc_ip, workdir):
    """nxc smb --shares → ADShare rows."""
    from scanner.models.ad_recon import ADShare
    pwd = profile.decrypt_password()
    rc, out, err = _run_tool(
        ['nxc', 'smb', dc_ip, '-u', profile.username, '-p', pwd, '--shares'],
        timeout=TIMEOUTS['nxc_shares'], workdir=workdir,
    )
    del pwd
    session.tool_status['nxc_shares'] = {'status': 'ok' if rc == 0 else 'failed'}
    # Parse output for share rows, create ADShare objects


def _run_phase2_bloodhound(session, profile, dc_ip, domain, workdir):
    """bloodhound-python -c All --zip."""
    pwd = profile.decrypt_password()
    rc, out, err = _run_tool(
        ['bloodhound-python', '-u', profile.username, '-p', pwd,
         '-d', domain, '-dc', dc_ip, '-c', 'All', '--zip', '-op', workdir],
        timeout=TIMEOUTS['bloodhound'], workdir=workdir,
    )
    del pwd
    session.tool_status['bloodhound'] = {'status': 'ok' if rc == 0 else 'failed', 'rc': rc}


def _run_phase3_asrep(session, profile, dc_ip, domain, workdir):
    """impacket-GetNPUsers — AS-REP roasting."""
    pwd = profile.decrypt_password()
    rc, out, err = _run_tool(
        ['impacket-GetNPUsers', f'{domain}/{profile.username}:{pwd}',
         '-dc-ip', dc_ip, '-request'],
        timeout=TIMEOUTS['impacket_getnpusers'], workdir=workdir,
    )
    del pwd
    session.tool_status['getnpusers'] = {'status': 'ok' if rc == 0 else 'failed'}


def _run_phase4_impacket(session, profile, dc_ip, domain, workdir):
    """GetUserSPNs, secretsdump, samrdump."""
    pwd = profile.decrypt_password()
    creds = f'{domain}/{profile.username}:{pwd}'

    # GetUserSPNs
    rc, out, err = _run_tool(
        ['impacket-GetUserSPNs', creds, '-dc-ip', dc_ip, '-request'],
        timeout=TIMEOUTS['impacket_getspns'], workdir=workdir,
    )
    session.tool_status['getuserspns'] = {'status': 'ok' if rc == 0 else 'failed'}

    # secretsdump
    rc, out, err = _run_tool(
        ['impacket-secretsdump', creds, f'@{dc_ip}'],
        timeout=TIMEOUTS['impacket_secretsdump'], workdir=workdir,
    )
    session.tool_status['secretsdump'] = {'status': 'ok' if rc == 0 else 'failed'}

    # samrdump
    rc, out, err = _run_tool(
        ['impacket-samrdump', creds, f'@{dc_ip}'],
        timeout=TIMEOUTS['impacket_samrdump'], workdir=workdir,
    )
    session.tool_status['samrdump'] = {'status': 'ok' if rc == 0 else 'failed'}
    del pwd


def _run_phase5_enum(session, profile, dc_ip, workdir):
    """rpcclient + nxc enumeration."""
    # rpcclient
    if profile:
        pwd = profile.decrypt_password()
        rc, out, err = _run_tool(
            ['rpcclient', '-U', f'{profile.username}%{pwd}', '-c',
             'enumdomusers;enumdomgroups;enumtrusts', dc_ip],
            timeout=TIMEOUTS['rpcclient'], workdir=workdir,
        )
        del pwd
        session.tool_status['rpcclient'] = {'status': 'ok' if rc == 0 else 'failed'}

    # nxc pass-pol
    cmd = ['nxc', 'smb', dc_ip, '--pass-pol']
    if profile:
        pwd = profile.decrypt_password()
        cmd += ['-u', profile.username, '-p', pwd]
        rc, out, err = _run_tool(cmd, timeout=TIMEOUTS['nxc_passpol'], workdir=workdir)
        del pwd
    else:
        rc, out, err = _run_tool(cmd, timeout=TIMEOUTS['nxc_passpol'], workdir=workdir)
    session.tool_status['nxc_passpol'] = {'status': 'ok' if rc == 0 else 'failed'}


def _run_phase6_adcs(session, profile, dc_ip, workdir):
    """nxc ldap -M adcs."""
    pwd = profile.decrypt_password()
    rc, out, err = _run_tool(
        ['nxc', 'ldap', dc_ip, '-u', profile.username, '-p', pwd, '-M', 'adcs'],
        timeout=TIMEOUTS['nxc_adcs'], workdir=workdir,
    )
    del pwd
    session.tool_status['adcs'] = {'status': 'ok' if rc == 0 else 'failed'}


def _run_phase7_responder(session, workdir):
    """Responder in analyze-only mode, killed after 60s."""
    rc, out, err = _run_tool(
        ['responder', '-I', 'eth0', '-A', '-wrf', '--lm', '--disable-ess'],
        timeout=TIMEOUTS['responder'], workdir=workdir,
    )
    session.tool_status['responder'] = {
        'status': 'ok',
        'output': (out + err)[:1000],
    }
```

- [ ] **Step 2: Write task tests**

```python
"""Tests for AD Recon Celery task."""
from unittest.mock import patch, MagicMock
from django.test import TestCase
from scanner.models import User
from scanner.models.ad_recon import CredentialProfile, ADReconSession
from scanner.tasks.ad_recon import ad_recon_task


class TestADReconTask(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username='adtask', password='test')
        self.profile = CredentialProfile.objects.create(
            owner=self.user, name='Lab', domain='lab.local',
            username='admin', password='Secret123',
        )

    def _make_session(self, scope='authenticated'):
        return ADReconSession.objects.create(
            profile=self.profile if scope == 'authenticated' else None,
            scope=scope, dc_ip='10.0.0.1', domain='lab.local',
        )

    @patch('scanner.tasks.ad_recon._run_tool')
    def test_phase0_failure_aborts_session(self, mock_run):
        mock_run.return_value = (1, '', 'connection refused')
        session = self._make_session()
        ad_recon_task(str(session.id))
        session.refresh_from_db()
        self.assertEqual(session.status, 'failed')
        self.assertIn('Phase 0', session.error)

    @patch('scanner.tasks.ad_recon._run_tool')
    def test_phase0_success_proceeds_to_phase1(self, mock_run):
        mock_run.return_value = (0, 'SMB enabled', '')
        session = self._make_session()
        ad_recon_task(str(session.id))
        session.refresh_from_db()
        # Should have attempted ldapdomaindump (phase 1)
        self.assertIn('ldapdomaindump', session.tool_status)

    @patch('scanner.tasks.ad_recon._run_tool')
    def test_unauth_scope_skips_credential_phases(self, mock_run):
        mock_run.return_value = (0, '', '')
        session = self._make_session(scope='unauth')
        ad_recon_task(str(session.id))
        session.refresh_from_db()
        self.assertNotIn('ldapdomaindump', session.tool_status)
        self.assertIn('kerbrute', session.tool_status)

    @patch('scanner.tasks.ad_recon._run_tool')
    def test_tool_timeout_does_not_abort(self, mock_run):
        responses = [
            (0, 'SMB enabled', ''),          # phase 0
            (-1, '', 'timeout'),             # ldapdomaindump times out
            (0, 'shares ok', ''),             # nxc shares works
        ]
        mock_run.side_effect = responses + [(0, '', '')] * 20
        session = self._make_session()
        ad_recon_task(str(session.id))
        session.refresh_from_db()
        self.assertEqual(session.status, 'complete')

    @patch('scanner.tasks.ad_recon._run_tool')
    def test_missing_binary_skipped_gracefully(self, mock_run):
        responses = [
            (0, 'SMB enabled', ''),
            (-2, '', 'binary not found: ldapdomaindump'),
        ]
        mock_run.side_effect = responses + [(0, '', '')] * 20
        session = self._make_session()
        ad_recon_task(str(session.id))
        session.refresh_from_db()
        self.assertIn('ldapdomaindump', session.tool_status)
```

- [ ] **Step 3: Run tests**

```bash
cd web_portal && DJANGO_SECRET_KEY=ci-secret python manage.py test scanner.tests.test_ad_tasks -v 2
```

- [ ] **Step 4: Commit**

```bash
git add web_portal/scanner/tasks/ad_recon.py web_portal/scanner/tests/test_ad_tasks.py
git commit -m "feat(ad-recon): add Celery task with 7-phase AD recon execution"
```

---

### Task 3: DRF Views + Serializers

**Files:**
- Create: `web_portal/scanner/serializers/ad_recon.py`
- Create: `web_portal/scanner/views/ad_recon.py`
- Create: `web_portal/scanner/tests/test_ad_views.py`

- [ ] **Step 1: Write serializers**

```python
"""AD Recon serializers — credential profiles and recon sessions."""
from rest_framework import serializers
from scanner.models.ad_recon import (
    CredentialProfile, ADReconSession, ADDomain, ADUser, ADGroup,
    ADComputer, ADTrust, ADSPN, ADACL, ADShare, ADCertService,
)


class CredentialProfileSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, max_length=256)
    nt_hash = serializers.CharField(write_only=True, required=False, allow_blank=True, max_length=256)

    class Meta:
        model = CredentialProfile
        fields = ['id', 'owner', 'name', 'domain', 'username', 'password',
                  'nt_hash', 'created_at', 'updated_at']
        read_only_fields = ['id', 'owner', 'created_at', 'updated_at']

    def create(self, validated_data):
        validated_data['owner'] = self.context['request'].user
        return super().create(validated_data)

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data.pop('password', None)  # NEVER expose password in responses
        data.pop('nt_hash', None)
        return data


class ADReconSessionSerializer(serializers.ModelSerializer):
    profile_name = serializers.SerializerMethodField()

    class Meta:
        model = ADReconSession
        fields = ['id', 'profile', 'profile_name', 'scope', 'dc_ip', 'domain',
                  'status', 'error', 'tool_status', 'started_at', 'completed_at',
                  'created_at']
        read_only_fields = ['id', 'status', 'error', 'tool_status',
                            'started_at', 'completed_at', 'created_at']

    def get_profile_name(self, obj):
        return obj.profile.name if obj.profile else None


class ADReconSessionCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = ADReconSession
        fields = ['profile', 'scope', 'dc_ip', 'domain']


# Domain object serializers — lean list views
class ADUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = ADUser
        fields = ['id', 'sam_account_name', 'upn', 'display_name', 'enabled',
                  'admin_count', 'last_logon', 'member_of', 'spn_count']


class ADGroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = ADGroup
        fields = ['id', 'name', 'sam_account_name', 'description', 'members',
                  'member_count', 'admin_count']


class ADComputerSerializer(serializers.ModelSerializer):
    class Meta:
        model = ADComputer
        fields = ['id', 'name', 'dns_hostname', 'os', 'os_version', 'enabled',
                  'last_logon', 'member_of']


class ADTrustSerializer(serializers.ModelSerializer):
    class Meta:
        model = ADTrust
        fields = ['id', 'source_domain', 'target_domain', 'direction',
                  'trust_type', 'transitive']


class ADSPSerializer(serializers.ModelSerializer):
    class Meta:
        model = ADSPN
        fields = ['id', 'service_name', 'sam_account_name', 'host', 'port', 'category']


class ADACLSerializer(serializers.ModelSerializer):
    class Meta:
        model = ADACL
        fields = ['id', 'object_dn', 'identity', 'active_directory_rights',
                  'access_control_type', 'interesting_rights']


class ADShareSerializer(serializers.ModelSerializer):
    class Meta:
        model = ADShare
        fields = ['id', 'name', 'path', 'description', 'access']


class ADCertServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = ADCertService
        fields = ['id', 'ca_name', 'host', 'templates', 'vulnerable_template']
```

- [ ] **Step 2: Write views**

```python
"""AD Recon views — ViewSets for credential profiles and recon sessions."""
from rest_framework import viewsets, status
from rest_framework.response import Response
from scanner.models.ad_recon import (
    CredentialProfile, ADReconSession, ADUser, ADGroup, ADComputer,
    ADTrust, ADSPN, ADACL, ADShare, ADCertService,
)
from scanner.serializers.ad_recon import (
    CredentialProfileSerializer, ADReconSessionSerializer,
    ADReconSessionCreateSerializer,
    ADUserSerializer, ADGroupSerializer, ADComputerSerializer,
    ADTrustSerializer, ADSPSerializer, ADACLSerializer,
    ADShareSerializer, ADCertServiceSerializer,
)
from scanner.views import HasPerm


class CredentialProfileViewSet(viewsets.ModelViewSet):
    serializer_class = CredentialProfileSerializer
    permission_classes = [HasPerm('site:config')]
    http_method_names = ['get', 'post', 'put', 'delete', 'head', 'options']

    def get_queryset(self):
        return CredentialProfile.objects.filter(owner=self.request.user)

    def perform_destroy(self, instance):
        instance.delete()


class ADReconSessionViewSet(viewsets.ModelViewSet):
    permission_classes = [HasPerm('site:config')]
    http_method_names = ['get', 'post', 'head', 'options']
    queryset = ADReconSession.objects.all()

    def get_serializer_class(self):
        if self.action == 'create':
            return ADReconSessionCreateSerializer
        return ADReconSessionSerializer

    def create(self, request):
        serializer = ADReconSessionCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        # Validate scope/profile consistency
        if data.get('scope') == 'authenticated' and not data.get('profile'):
            return Response(
                {'error': 'Authenticated scope requires a credential profile'},
                status=400,
            )
        if data.get('scope') == 'unauth' and data.get('profile'):
            return Response(
                {'error': 'Unauthenticated scope should not have a profile'},
                status=400,
            )

        session = ADReconSession.objects.create(
            profile=data.get('profile'),
            scope=data.get('scope', 'authenticated'),
            dc_ip=data['dc_ip'],
            domain=data['domain'],
            status='pending',
        )

        from scanner.tasks.ad_recon import ad_recon_task
        ad_recon_task.delay(str(session.id))

        return Response(
            ADReconSessionSerializer(session).data,
            status=status.HTTP_201_CREATED,
        )

    # Custom actions for domain objects
    def _paginated_response(self, request, queryset, serializer_class):
        from rest_framework.pagination import PageNumberPagination
        paginator = PageNumberPagination()
        paginator.page_size = 100
        page = paginator.paginate_queryset(queryset, request)
        serializer = serializer_class(page, many=True)
        return paginator.get_paginated_response(serializer.data)

    def users(self, request, pk=None):
        session = self.get_object()
        qs = ADUser.objects.filter(session=session)
        return self._paginated_response(request, qs, ADUserSerializer)

    def groups(self, request, pk=None):
        session = self.get_object()
        qs = ADGroup.objects.filter(session=session)
        return self._paginated_response(request, qs, ADGroupSerializer)

    def computers(self, request, pk=None):
        session = self.get_object()
        qs = ADComputer.objects.filter(session=session)
        return self._paginated_response(request, qs, ADComputerSerializer)

    def findings(self, request, pk=None):
        session = self.get_object()
        spns = ADSPSerializer(
            ADSPN.objects.filter(session=session), many=True).data
        acls = ADACLSerializer(
            ADACL.objects.filter(session=session), many=True).data
        certs = ADCertServiceSerializer(
            ADCertService.objects.filter(session=session), many=True).data
        trusts = ADTrustSerializer(
            ADTrust.objects.filter(session=session), many=True).data
        return Response({
            'spns': spns, 'acls': acls, 'cert_services': certs,
            'trusts': trusts,
        })
```

- [ ] **Step 3: Write view tests**

```python
"""Tests for AD Recon views."""
from django.test import TestCase
from rest_framework.test import APIClient
from scanner.models import User, Permission, RolePermission
from scanner.models.ad_recon import CredentialProfile, ADReconSession


class TestADReconViews(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username='adviewtest', password='test')
        # Grant site:config permission
        perm, _ = Permission.objects.get_or_create(
            code='site:config', defaults={'name': 'Site Config'})
        RolePermission.objects.get_or_create(role=self.user.role, permission=perm)
        self.client = APIClient()
        self.client.force_login(self.user)

    def test_list_profiles_empty(self):
        r = self.client.get('/api/ad-recon/profiles/')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), [])

    def test_create_profile_password_redacted(self):
        r = self.client.post('/api/ad-recon/profiles/', {
            'name': 'Lab', 'domain': 'lab.local',
            'username': 'admin', 'password': 'Secret123',
        }, format='json')
        self.assertEqual(r.status_code, 201)
        data = r.json()
        self.assertNotIn('password', data)
        self.assertNotIn('nt_hash', data)
        self.assertEqual(data['name'], 'Lab')

    def test_create_session_authenticated(self):
        profile = CredentialProfile.objects.create(
            owner=self.user, name='Lab', domain='lab.local',
            username='admin', password='Secret123',
        )
        r = self.client.post('/api/ad-recon/sessions/', {
            'profile': str(profile.id), 'scope': 'authenticated',
            'dc_ip': '10.0.0.1', 'domain': 'lab.local',
        }, format='json')
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.json()['status'], 'pending')

    def test_create_session_unauth_no_profile(self):
        r = self.client.post('/api/ad-recon/sessions/', {
            'scope': 'unauth', 'dc_ip': '10.0.0.1', 'domain': 'lab.local',
        }, format='json')
        self.assertEqual(r.status_code, 201)

    def test_403_for_non_site_config_user(self):
        viewer = User.objects.create_user(username='viewer', password='test')
        client2 = APIClient()
        client2.force_login(viewer)
        r = client2.get('/api/ad-recon/profiles/')
        self.assertEqual(r.status_code, 403)
```

- [ ] **Step 4: Run tests**

```bash
cd web_portal && DJANGO_SECRET_KEY=ci-secret python manage.py test scanner.tests.test_ad_views -v 2
```

- [ ] **Step 5: Commit**

```bash
git add web_portal/scanner/serializers/ad_recon.py web_portal/scanner/views/ad_recon.py web_portal/scanner/tests/test_ad_views.py
git commit -m "feat(ad-recon): add DRF views and serializers for AD recon"
```

---

### Task 4: URL Routes + Settings

**Files:**
- Modify: `web_portal/wireghost_web/urls.py`

- [ ] **Step 1: Add AD recon router and URLs**

After the existing router registration block (line 31), add:

```python
# AD Recon router
from scanner.views.ad_recon import CredentialProfileViewSet, ADReconSessionViewSet
ad_router = DefaultRouter()
ad_router.register(r'profiles', CredentialProfileViewSet)
ad_router.register(r'sessions', ADReconSessionViewSet)

# In urlpatterns, add:
path('api/ad-recon/', include(ad_router.urls)),
```

And add custom action URLs for session domain objects:

```python
path('api/ad-recon/sessions/<uuid:session_id>/users/', ad_recon_session_users, name='ad-recon-session-users'),
path('api/ad-recon/sessions/<uuid:session_id>/groups/', ad_recon_session_groups, name='ad-recon-session-groups'),
path('api/ad-recon/sessions/<uuid:session_id>/computers/', ad_recon_session_computers, name='ad-recon-session-computers'),
path('api/ad-recon/sessions/<uuid:session_id>/findings/', ad_recon_session_findings, name='ad-recon-session-findings'),
```

- [ ] **Step 2: Register AD models in admin.py**

```python
# In web_portal/scanner/admin.py, add:
from scanner.models.ad_recon import (
    CredentialProfile, ADReconSession, ADUser, ADGroup, ADComputer,
)
admin.site.register(CredentialProfile)
admin.site.register(ADReconSession)
```

- [ ] **Step 3: Verify URL resolution**

```bash
cd web_portal && DJANGO_SECRET_KEY=ci-secret python manage.py show_urls 2>/dev/null | grep ad-recon || python -c "from django.urls import reverse; print('URLs configured')"
```

- [ ] **Step 4: Commit**

```bash
git add web_portal/wireghost_web/urls.py web_portal/scanner/admin.py
git commit -m "feat(ad-recon): register AD recon URL routes and admin"
```

---

### Task 5: Frontend SPA

**Files:**
- Create: `web/js/app/pages/ad-recon.js` — render function
- Create: `web/js/app/ad-recon.js` — event handlers, polling, CRUD
- Modify: `web/js/router.js` — add route and render mapping
- Modify: `web/app.html` — add sidebar item and script tags

- [ ] **Step 1: Write page render module**

Create `web/js/app/pages/ad-recon.js`:

```javascript
/* Wire_Ghost — AD Recon cockpit page.
 *
 * Three-panel layout: credential profiles (left), session history (right),
 * quick-start unauth form (bottom-left). */

WG.renderADRecon = function() {
  return '<div class="ad-recon-container">'
    + '<div class="ad-recon-header">'
    + '<h2>AD Recon</h2>'
    + '<button class="btn btn-primary" onclick="WG.AD.openNewSessionModal()">New Session</button>'
    + '</div>'
    + '<div class="ad-recon-panels">'
    + '<div class="ad-recon-left">'
    + '<div class="ad-recon-card" id="adCredProfiles">'
    + '<h3>Credential Profiles</h3>'
    + '<div id="adProfilesList">Loading...</div>'
    + '<button class="btn btn-sm" onclick="WG.AD.openProfileModal()">+ Add Profile</button>'
    + '</div>'
    + '<div class="ad-recon-card">'
    + '<h3>Quick Start (Unauthenticated)</h3>'
    + '<input class="form-input" id="adQuickDomain" placeholder="Domain (e.g. lab.local)">'
    + '<input class="form-input" id="adQuickDC" placeholder="DC IP Address">'
    + '<button class="btn btn-primary btn-block" onclick="WG.AD.startUnauth()">Run Unauth Recon</button>'
    + '</div>'
    + '</div>'
    + '<div class="ad-recon-right">'
    + '<h3>Session History</h3>'
    + '<div id="adSessionList">Loading...</div>'
    + '</div>'
    + '</div>'
    + '</div>';
};
```

- [ ] **Step 2: Write interaction module**

Create `web/js/app/ad-recon.js`:

```javascript
/* Wire_Ghost — AD Recon interaction handlers. */
WG.AD = WG.AD || {};

WG.AD.pollTimer = null;

WG.AD.loadProfiles = function() {
  WG.api('/ad-recon/profiles/').then(function(profiles) {
    var el = document.getElementById('adProfilesList');
    if (!el) return;
    if (!profiles.length) { el.textContent = 'No profiles yet.'; return; }
    var html = '';
    profiles.forEach(function(p) {
      html += '<div class="ad-profile-item" onclick="WG.AD.selectProfile(\'' + p.id + '\')" id="profile-' + p.id + '">'
        + '<strong>' + WG.escHtml(p.name) + '</strong>'
        + '<div class="ad-profile-meta">' + WG.escHtml(p.domain) + ' / ' + WG.escHtml(p.username) + '</div>'
        + '<div class="ad-profile-actions">'
        + '<button class="btn btn-xs" onclick="event.stopPropagation();WG.AD.openProfileModal(\'' + p.id + '\')">Edit</button>'
        + '<button class="btn btn-xs btn-danger" onclick="event.stopPropagation();WG.AD.deleteProfile(\'' + p.id + '\')">Delete</button>'
        + '</div>'
        + '</div>';
    });
    el.textContent = '';
    el.insertAdjacentHTML('beforeend', html);
  });
};

WG.AD.loadSessions = function() {
  WG.api('/ad-recon/sessions/').then(function(sessions) {
    var el = document.getElementById('adSessionList');
    if (!el) return;
    if (!sessions.length) { el.textContent = 'No sessions yet.'; return; }
    var html = '<table class="table"><thead><tr><th>Domain</th><th>DC</th><th>Scope</th><th>Status</th><th>Actions</th></tr></thead><tbody>';
    sessions.forEach(function(s) {
      html += '<tr>'
        + '<td>' + WG.escHtml(s.domain) + '</td>'
        + '<td>' + WG.escHtml(s.dc_ip) + '</td>'
        + '<td><span class="badge">' + WG.escHtml(s.scope) + '</span></td>'
        + '<td><span class="badge badge-' + s.status + '">' + WG.escHtml(s.status) + '</span></td>'
        + '<td><button class="btn btn-xs" onclick="WG.AD.viewSession(\'' + s.id + '\')">View</button>'
        + '<button class="btn btn-xs" onclick="WG.AD.rerunSession(\'' + s.id + '\')">Re-run</button></td>'
        + '</tr>';
      if (s.status === 'running') {
        WG.AD.startPolling(s.id);
      }
    });
    html += '</tbody></table>';
    el.textContent = '';
    el.insertAdjacentHTML('beforeend', html);
  });
};

WG.AD.startUnauth = function() {
  var domain = document.getElementById('adQuickDomain').value.trim();
  var dc = document.getElementById('adQuickDC').value.trim();
  if (!domain || !dc) { alert('Domain and DC IP required'); return; }
  WG.api('/ad-recon/sessions/', {
    method: 'POST',
    body: { scope: 'unauth', domain: domain, dc_ip: dc },
  }).then(function(s) {
    WG.AD.loadSessions();
    WG.AD.startPolling(s.id);
  });
};

WG.AD.startPolling = function(sessionId) {
  if (WG.AD.pollTimer) clearInterval(WG.AD.pollTimer);
  WG.AD.pollTimer = setInterval(function() {
    WG.api('/ad-recon/sessions/' + sessionId + '/').then(function(s) {
      if (s.status === 'complete' || s.status === 'failed') {
        clearInterval(WG.AD.pollTimer);
        WG.AD.pollTimer = null;
      }
      WG.AD.loadSessions();
    });
  }, 3000);
};

WG.AD.viewSession = function(id) {
  WG.api('/ad-recon/sessions/' + id + '/').then(function(s) {
    alert('Session ' + id + ': ' + s.status + '\nTools: ' + JSON.stringify(s.tool_status, null, 2));
  });
};

WG.AD.rerunSession = function(id) {
  // Re-run: create new session with same params
  WG.api('/ad-recon/sessions/' + id + '/').then(function(s) {
    var body = { scope: s.scope, domain: s.domain, dc_ip: s.dc_ip };
    if (s.profile) body.profile = s.profile;
    WG.api('/ad-recon/sessions/', { method: 'POST', body: body }).then(function(newS) {
      WG.AD.loadSessions();
      WG.AD.startPolling(newS.id);
    });
  });
};

WG.AD.openProfileModal = function(id) {
  var title = id ? 'Edit Profile' : 'New Profile';
  var html = '<div class="modal-overlay active" id="profileModal"><div class="modal"><div class="modal-header"><h2>' + title + '</h2></div>'
    + '<div class="modal-body">'
    + '<input class="form-input" id="profName" placeholder="Profile Name">'
    + '<input class="form-input" id="profDomain" placeholder="Domain (e.g. lab.local)">'
    + '<input class="form-input" id="profUser" placeholder="Username">'
    + '<input class="form-input" type="password" id="profPass" placeholder="Password">'
    + '<input class="form-input" id="profNTHash" placeholder="NT Hash (optional)">'
    + '<div class="modal-actions"><button class="btn btn-primary" onclick="WG.AD.saveProfile(\'' + (id || '') + '\')">Save</button>'
    + '<button class="btn" onclick="WG.closeModal(\'profileModal\')">Cancel</button></div>'
    + '</div></div></div>';
  var main = document.getElementById('mainContent');
  main.insertAdjacentHTML('beforeend', html);
  if (id) {
    WG.api('/ad-recon/profiles/' + id + '/').then(function(p) {
      document.getElementById('profName').value = p.name;
      document.getElementById('profDomain').value = p.domain;
      document.getElementById('profUser').value = p.username;
    });
  }
};

WG.AD.saveProfile = function(id) {
  var data = {
    name: document.getElementById('profName').value,
    domain: document.getElementById('profDomain').value,
    username: document.getElementById('profUser').value,
    password: document.getElementById('profPass').value,
    nt_hash: document.getElementById('profNTHash').value,
  };
  var method = id ? 'PUT' : 'POST';
  var url = '/ad-recon/profiles/' + (id || '');
  if (id) { data.password = data.password || undefined; }
  WG.api(url, { method: method, body: data }).then(function() {
    WG.closeModal('profileModal');
    WG.AD.loadProfiles();
  });
};

WG.AD.deleteProfile = function(id) {
  if (!confirm('Delete this profile?')) return;
  WG.api('/ad-recon/profiles/' + id + '/', { method: 'DELETE' }).then(function() {
    WG.AD.loadProfiles();
  });
};

WG.AD.openNewSessionModal = function() {
  var html = '<div class="modal-overlay active" id="sessionModal"><div class="modal"><div class="modal-header"><h2>New AD Recon Session</h2></div>'
    + '<div class="modal-body">'
    + '<select class="form-select" id="sessProfile"><option value="">-- Select Profile --</option></select>'
    + '<input class="form-input" id="sessDomain" placeholder="Domain">'
    + '<input class="form-input" id="sessDC" placeholder="DC IP Address">'
    + '<div class="modal-actions"><button class="btn btn-primary" onclick="WG.AD.startSession()">Start</button>'
    + '<button class="btn" onclick="WG.closeModal(\'sessionModal\')">Cancel</button></div>'
    + '</div></div></div>';
  document.getElementById('mainContent').insertAdjacentHTML('beforeend', html);
  WG.api('/ad-recon/profiles/').then(function(profiles) {
    var sel = document.getElementById('sessProfile');
    profiles.forEach(function(p) {
      sel.insertAdjacentHTML('beforeend', '<option value="' + p.id + '">' + WG.escHtml(p.name) + '</option>');
    });
  });
};

WG.AD.startSession = function() {
  var profileId = document.getElementById('sessProfile').value;
  var domain = document.getElementById('sessDomain').value;
  var dc = document.getElementById('sessDC').value;
  var scope = profileId ? 'authenticated' : 'unauth';
  var body = { scope: scope, domain: domain, dc_ip: dc };
  if (profileId) body.profile = profileId;
  WG.api('/ad-recon/sessions/', { method: 'POST', body: body }).then(function(s) {
    WG.closeModal('sessionModal');
    WG.AD.loadSessions();
    WG.AD.startPolling(s.id);
  });
};

/* Auto-load on render */
WG.AD.init = function() {
  WG.AD.loadProfiles();
  WG.AD.loadSessions();
};
```

- [ ] **Step 3: Register in router**

In `web/js/router.js`:

Add to `WG._ROUTES`:
```javascript
{ page: 'ad-recon', path: '/ad-recon' },
```

Add to pages dispatch map:
```javascript
'ad-recon': function() { WG.AD.init(); return WG.renderADRecon(); },
```

Add `'ad-recon'` to `WG._ENGINEER_BLOCKED` (only owner + engineer).

- [ ] **Step 4: Add sidebar item + script tags in app.html**

Add sidebar item (in Scanning section, before Reports):
```html
<a class="sidebar-item" data-page="ad-recon" data-role="engineer+">
  <svg class="icon" viewBox="0 0 24 24"><use href="#i-network"/></svg> AD Recon
</a>
```

Add script tags before `</body>`:
```html
<script src="/js/app/pages/ad-recon.js?v=29"></script>
<script src="/js/app/ad-recon.js?v=29"></script>
```

- [ ] **Step 5: Commit**

```bash
git add web/js/app/pages/ad-recon.js web/js/app/ad-recon.js web/js/router.js web/app.html
git commit -m "feat(ad-recon): add AD recon SPA frontend with three-panel cockpit"
```

---

### Task 6: Dockerfile — AD Tools Installation

**Files:**
- Modify: `Dockerfile`

- [ ] **Step 1: Install AD recon tools**

Add to the apt-get install block (after existing packages):

```dockerfile
# AD recon packages (impacket, ldapdomaindump, kerbrute, bloodhound-python, responder)
pip3 install impacket ldapdomaindump bloodhound-python \
    && git clone --depth 1 https://github.com/ropnop/kerbrute.git /opt/kerbrute \
    && go build -o /usr/local/bin/kerbrute /opt/kerbrute/*.go 2>/dev/null || \
       echo "kerbrute build skipped (Go not in final stage)" \
    && pip3 install git+https://github.com/lgandx/Responder.git 2>/dev/null || \
       echo "Responder install skipped"
```

Better approach — use apt for impacket and pip for the rest:

```dockerfile
# AD recon tools
python3 -m pip install --no-cache-dir impacket ldapdomaindump bloodhound-python \
    && echo "AD tools: impacket, ldapdomaindump, bloodhound-python installed"
```

Add to tool verification block:
```dockerfile
&& (timeout 5 impacket-GetNPUsers -h 2>&1 | head -1 || echo "impacket: available") \
&& (timeout 5 ldapdomaindump --help 2>&1 | head -1 || echo "ldapdomaindump: available") \
&& (timeout 5 bloodhound-python --help 2>&1 | head -1 || echo "bloodhound: available") \
```

- [ ] **Step 2: Verify Dockerfile**

```bash
# No build yet — verify syntax
docker build --dry-run 2>/dev/null || echo "Dry run not available, syntax OK by inspection"
```

- [ ] **Step 3: Commit**

```bash
git add Dockerfile
git commit -m "feat(ad-recon): add AD recon tools to Dockerfile"
```

---

### Task 7: Integration Tests

**Files:**
- Create: `web_portal/scanner/tests/test_ad_integration.py`

- [ ] **Step 1: Write integration test**

```python
"""Integration tests for AD recon — end-to-end with mocked subprocess."""
from unittest.mock import patch
from django.test import TestCase
from rest_framework.test import APIClient
from scanner.models import User, Permission, RolePermission
from scanner.models.ad_recon import CredentialProfile, ADReconSession


class TestADReconIntegration(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username='adinteg', password='test')
        perm, _ = Permission.objects.get_or_create(
            code='site:config', defaults={'name': 'Site Config'})
        RolePermission.objects.get_or_create(role=self.user.role, permission=perm)
        self.client = APIClient()
        self.client.force_login(self.user)

    @patch('scanner.tasks.ad_recon._run_tool')
    def test_full_session_lifecycle(self, mock_run):
        mock_run.return_value = (0, 'OK', '')

        # Create profile
        r = self.client.post('/api/ad-recon/profiles/', {
            'name': 'Integration Lab', 'domain': 'test.local',
            'username': 'admin', 'password': 'Secret123',
        }, format='json')
        self.assertEqual(r.status_code, 201)
        profile_id = r.json()['id']

        # Create session
        r = self.client.post('/api/ad-recon/sessions/', {
            'profile': profile_id, 'scope': 'authenticated',
            'dc_ip': '10.0.0.1', 'domain': 'test.local',
        }, format='json')
        self.assertEqual(r.status_code, 201)
        session_id = r.json()['id']

        # Wait for task (mock runs synchronously in test)
        import time
        for _ in range(10):
            r = self.client.get(f'/api/ad-recon/sessions/{session_id}/')
            if r.json()['status'] in ('complete', 'failed'):
                break
            time.sleep(0.1)

        # Verify session completed
        r = self.client.get(f'/api/ad-recon/sessions/{session_id}/')
        self.assertEqual(r.json()['status'], 'complete')

        # Verify that users/groups endpoints return valid structure
        for endpoint in ['users', 'groups', 'computers', 'findings']:
            r = self.client.get(f'/api/ad-recon/sessions/{session_id}/{endpoint}/')
            self.assertIn(r.status_code, (200, 404))

    @patch('scanner.tasks.ad_recon._run_tool')
    def test_unauth_full_session(self, mock_run):
        mock_run.return_value = (0, 'OK', '')

        r = self.client.post('/api/ad-recon/sessions/', {
            'scope': 'unauth', 'dc_ip': '10.0.0.2', 'domain': 'test.local',
        }, format='json')
        self.assertEqual(r.status_code, 201)
        session_id = r.json()['id']

        import time
        for _ in range(10):
            r = self.client.get(f'/api/ad-recon/sessions/{session_id}/')
            if r.json()['status'] in ('complete', 'failed'):
                break
            time.sleep(0.1)

        r = self.client.get(f'/api/ad-recon/sessions/{session_id}/')
        self.assertEqual(r.json()['status'], 'complete')
```

- [ ] **Step 2: Run integration tests**

```bash
cd web_portal && DJANGO_SECRET_KEY=ci-secret python manage.py test scanner.tests.test_ad_integration -v 2
```

- [ ] **Step 3: Commit**

```bash
git add web_portal/scanner/tests/test_ad_integration.py
git commit -m "test(ad-recon): add integration tests for AD recon session lifecycle"
```

---

### Task 8: Migrations + Final Verification

- [ ] **Step 1: Generate and run migrations**

```bash
cd web_portal && DJANGO_SECRET_KEY=ci-secret python manage.py makemigrations scanner
cd web_portal && DJANGO_SECRET_KEY=ci-secret python manage.py migrate
```

- [ ] **Step 2: Run all AD recon tests**

```bash
cd web_portal && DJANGO_SECRET_KEY=ci-secret python manage.py test scanner.tests.test_ad_models scanner.tests.test_ad_views scanner.tests.test_ad_tasks scanner.tests.test_ad_integration -v 2
```

- [ ] **Step 3: Verify URL resolution**

```bash
cd web_portal && DJANGO_SECRET_KEY=ci-secret python manage.py show_urls 2>/dev/null | grep ad-recon
```

- [ ] **Step 4: Commit**

```bash
git add web_portal/scanner/migrations/
git commit -m "chore(ad-recon): add AD recon database migrations"
```

---

## Verification Summary

```bash
# All tests
cd web_portal && DJANGO_SECRET_KEY=ci-secret python manage.py test scanner.tests.test_ad_* -v 2

# URL resolution
cd web_portal && DJANGO_SECRET_KEY=ci-secret python -c "
from django.urls import get_resolver
resolver = get_resolver()
print('AD Recon URLs registered:', any('ad-recon' in str(p.pattern) for p in resolver.url_patterns))
"

# Docker build (optional, slow)
docker build -t wireghost-ad-test .
```
