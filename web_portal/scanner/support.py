"""Support diagnostic bundle builder.

Produces a .tar.gz archive containing recent log tails plus a system
snapshot. The Owner downloads this from Settings → Support when opening
an external support ticket.

Redaction pipeline strips known-secret patterns (auth headers, session
cookies, password fields) — IPs, usernames, file paths, stack traces are
preserved so the bundle is actually useful for debugging.
"""

from __future__ import annotations

import io
import json
import os
import re
import tarfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


# ─── REDACTION PATTERNS ──────────────────────────────────────────────────
# Each entry is a (compiled regex, replacement) pair. redact() applies them
# in order. The regex MUST match the *value* to strip, not the whole line —
# the replacement substitutes just that span so surrounding context is kept.
#
# Starter entries cover the session/auth tokens that Django + nginx logs
# routinely emit. Extend this list with patterns specific to YOUR
# deployment (customer OAuth tokens, partner API keys, webhook signatures)
# so the bundle stays safe to share with external support.
REDACTION_PATTERNS = [
    # HTTP Authorization headers — Bearer, Basic, Digest
    (re.compile(r'(?i)(Authorization\s*:\s*(?:Bearer|Basic|Digest|Token)\s+)\S+'),
     r'\1[REDACTED]'),
    # Session / CSRF / app-specific cookies seen in request logs
    (re.compile(r'(sessionid|csrftoken|wg_user_info|wg_session)=([^;\s"\'\\]+)'),
     r'\1=[REDACTED]'),
    # JSON password / token fields (setup wizard, auth endpoints)
    (re.compile(r'("(?:password|password1|password2|new_password|old_password|api_key|api_token|secret)"\s*:\s*)"[^"]*"'),
     r'\1"[REDACTED]"'),
    # x-api-key / x-auth-token style headers
    (re.compile(r'(?i)(X-(?:API-Key|Auth-Token|Session|CSRF-Token)\s*:\s*)\S+'),
     r'\1[REDACTED]'),
    # DSN-style credentials in URLs:  proto://user:pass@host
    (re.compile(r'([a-zA-Z][a-zA-Z0-9+.-]*://[^:\s/]+):([^@\s/]+)@'),
     r'\1:[REDACTED]@'),
    # ────────────────────────────────────────────────────────────────────
    # TODO(operator): add entries for tokens specific to your deployment —
    # internal service keys, customer OAuth tokens, anything an attacker
    # or support engineer must not see in plaintext. 3–6 extra entries
    # is plenty. Each regex is ~one line.
    #
    # Example shape:
    #   (re.compile(r'(my-token=)[A-Za-z0-9_-]+'), r'\1[REDACTED]'),
    # ────────────────────────────────────────────────────────────────────
]


def redact(text: str) -> str:
    """Apply REDACTION_PATTERNS to `text`. Always returns a string."""
    if not text:
        return text
    for pattern, replacement in REDACTION_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


# ─── FILE COLLECTION ─────────────────────────────────────────────────────

_SKIP_EXTENSIONS = {'.gz', '.zip', '.tar', '.bz2', '.xz', '.pdf', '.png', '.jpg', '.jpeg', '.ico', '.woff', '.woff2'}


def _iter_log_files(log_dir: str):
    """Yield (archive_path, absolute_path) for every log file under log_dir.

    archive_path is the relative path used inside the tar (e.g.
    "logs/api/django.log"). Binary-ish extensions are skipped.
    """
    base = Path(log_dir)
    if not base.exists() or not base.is_dir():
        return
    for path in sorted(base.rglob('*')):
        if not path.is_file():
            continue
        if path.suffix.lower() in _SKIP_EXTENSIONS:
            continue
        try:
            rel = path.relative_to(base)
        except ValueError:
            continue
        yield f'logs/{rel.as_posix()}', path


def _tail_bytes(path: Path, max_bytes: int) -> bytes:
    """Return the last `max_bytes` bytes of `path`, aligned to a line boundary."""
    try:
        size = path.stat().st_size
    except OSError:
        return b''
    with path.open('rb') as f:
        if size <= max_bytes:
            return f.read()
        # Read slightly more than requested, then trim to the first newline so
        # we don't start mid-line (which would break the first redaction pass).
        f.seek(max(0, size - max_bytes))
        chunk = f.read()
        newline = chunk.find(b'\n')
        if newline != -1:
            chunk = chunk[newline + 1:]
        return chunk


# ─── SYSTEM SNAPSHOT ─────────────────────────────────────────────────────

def _system_snapshot(requested_by) -> dict:
    """Return non-sensitive state — counts, permission matrix, site config."""
    from django.conf import settings
    from scanner.models import (
        Asset, Finding, Host, RolePermission, Scan, SiteConfig, User,
    )

    # Versions
    try:
        from wireghost import __version__ as wg_version
    except Exception:
        wg_version = 'unknown'
    try:
        import django
        django_version = django.get_version()
    except Exception:
        django_version = 'unknown'

    # Permissions matrix — { role: [code, ...] }
    perms_by_role: dict = defaultdict(list)
    for rp in RolePermission.objects.select_related('permission').all():
        perms_by_role[rp.role].append(rp.permission.code)
    for role in perms_by_role:
        perms_by_role[role].sort()

    # Counts
    role_counts = {
        r: User.objects.filter(role=r).count() for r, _ in User.ROLE_CHOICES
    }
    scan_by_status = {
        status: Scan.objects.filter(status=status).count()
        for status, _ in Scan.STATUS_CHOICES
    }
    findings_by_sev = {
        sev: Finding.objects.filter(severity=sev).count()
        for sev in ('critical', 'high', 'medium', 'low', 'info')
    }

    # Site config (no branding, no logo path)
    cfg = SiteConfig.get()
    site_cfg = {
        'setup_complete': cfg.setup_complete,
        'schedule_timezone': cfg.schedule_timezone,
        'setup_completed_at': cfg.setup_completed_at.isoformat() if cfg.setup_completed_at else None,
    }

    # Env var *names* (values never included)
    env_keys = sorted(k for k in os.environ.keys() if not k.startswith('_'))

    return {
        'version': wg_version,
        'django_version': django_version,
        'exported_at': datetime.now(timezone.utc).isoformat(),
        'exported_by': {
            'id': str(requested_by.id),
            'username': requested_by.username,
            'role': requested_by.role,
        },
        'site_config': site_cfg,
        'permissions': dict(perms_by_role),
        'counts': {
            'users': role_counts,
            'scans': {
                'total': Scan.objects.count(),
                'by_status': scan_by_status,
            },
            'hosts': Host.objects.count(),
            'findings_by_severity': findings_by_sev,
            'assets': Asset.objects.count(),
        },
        'debug_mode': bool(settings.DEBUG),
        'time_zone': settings.TIME_ZONE,
        'env_keys_present': env_keys,
    }


def _user_ref(user_str: str) -> str:
    """Collapse a username to a stable opaque ref for the bundle."""
    if not user_str:
        return '[user-none]'
    import hashlib
    h = hashlib.sha256(user_str.encode('utf-8')).hexdigest()[:8]
    return f'[user-{h}]'


# ─── BUNDLE BUILDER ──────────────────────────────────────────────────────

_README = """Wire_Ghost support bundle
=========================

This archive contains diagnostic data for troubleshooting a Wire_Ghost
deployment. Hand it to support when opening a ticket.

Contents
--------
manifest.json               — what the bundle contains and when it was built
data/snapshot.json          — system snapshot (counts, permissions, versions)
data/audit-tail.json        — last 500 audit-log rows (usernames hashed)
data/permissions.json       — role → permission-code matrix
data/site-config.json       — site configuration (no branding/logo paths)
data/counts.json            — user/scan/asset counts by category
logs/api/django.log         — Django + scanner application log
logs/api/celery-worker.log  — Celery worker log
logs/api/celery-beat.log    — Celery beat scheduler log
logs/nginx/access.log       — nginx access log
logs/nginx/error.log        — nginx error log

Redaction
---------
Log content is passed through a redaction pass before being bundled.
Known-secret patterns are replaced with [REDACTED]:
  • HTTP Authorization headers (Bearer / Basic / Digest / Token)
  • Session / CSRF cookies in request logs
  • JSON password and api_key fields
  • DSN-style credentials inside URLs

IPs, usernames, file paths, stack traces are preserved so support can
actually debug. Review the archive before sending if your deployment
handles sensitive content that these patterns don't cover.
"""


def build_support_bundle(
    *,
    log_dir: str,
    requested_by,
    max_log_bytes: int = 30 * 1024 * 1024,
    max_bytes_per_file: int | None = None,
) -> bytes:
    """Return a gzipped tar bytestring containing logs + system snapshot.

    Args:
        log_dir: Host path to tail log files from (typically '/app/logs').
        requested_by: Django User instance initiating the export.
        max_log_bytes: Upper bound on total log bytes across all files.
        max_bytes_per_file: Optional per-file cap. Defaults to max_log_bytes.
    """
    snapshot = _system_snapshot(requested_by)

    # Collect log files first so we can divide max_log_bytes evenly.
    log_entries = list(_iter_log_files(log_dir))
    per_file_cap = max_bytes_per_file
    if per_file_cap is None:
        per_file_cap = (
            max_log_bytes // max(1, len(log_entries))
            if log_entries else max_log_bytes
        )

    buf = io.BytesIO()
    # Use GNU format for large files / long paths; compresslevel=6 balances
    # CPU vs. size for typical text logs.
    with tarfile.open(fileobj=buf, mode='w:gz', compresslevel=6, format=tarfile.GNU_FORMAT) as tar:
        _add_text(tar, 'README.txt', _README)

        # Manifest lists the files inside the archive with their sizes.
        manifest = {
            'bundle_version': 1,
            'generated_at': snapshot['exported_at'],
            'generated_by': snapshot['exported_by'],
            'log_files': [],
            'redacted_patterns': len(REDACTION_PATTERNS),
        }

        for archive_path, abs_path in log_entries:
            raw = _tail_bytes(abs_path, per_file_cap)
            try:
                text = raw.decode('utf-8', errors='replace')
            except Exception:
                text = ''
            text = redact(text)
            encoded = text.encode('utf-8', errors='replace')
            _add_bytes(tar, archive_path, encoded)
            manifest['log_files'].append({
                'path': archive_path,
                'bytes_in_bundle': len(encoded),
                'source_bytes': abs_path.stat().st_size if abs_path.exists() else 0,
            })

        if not log_entries:
            _add_text(
                tar,
                'logs/_EMPTY.txt',
                'No log files were present on the host log directory at export time.\n'
                f'Configured WIREGHOST_LOG_DIR mount target: {log_dir}\n',
            )

        _add_json(tar, 'data/snapshot.json', snapshot)

        # Dedicated files for easier consumption by support tooling.
        from scanner.models import AuditLog
        audit_rows = [
            {
                'timestamp': row.timestamp.isoformat(),
                'user_ref': _user_ref(row.user),
                'action': row.action,
                'type': row.type,
                'detail': redact(row.detail or ''),
                'ip': str(row.ip_address) if row.ip_address else None,
            }
            for row in AuditLog.objects.order_by('-timestamp')[:500]
        ]
        _add_json(tar, 'data/audit-tail.json', audit_rows)
        _add_json(tar, 'data/permissions.json', snapshot['permissions'])
        _add_json(tar, 'data/counts.json', snapshot['counts'])
        _add_json(tar, 'data/site-config.json', snapshot['site_config'])
        _add_json(tar, 'manifest.json', manifest)

    return buf.getvalue()


# ─── TAR HELPERS ─────────────────────────────────────────────────────────

def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mtime = int(datetime.now(timezone.utc).timestamp())
    info.mode = 0o644
    tar.addfile(info, io.BytesIO(data))


def _add_text(tar: tarfile.TarFile, name: str, text: str) -> None:
    _add_bytes(tar, name, text.encode('utf-8'))


def _add_json(tar: tarfile.TarFile, name: str, obj) -> None:
    data = json.dumps(obj, indent=2, sort_keys=True, default=str).encode('utf-8')
    _add_bytes(tar, name, data)
