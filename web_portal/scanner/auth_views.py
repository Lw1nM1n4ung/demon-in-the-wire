"""Wire_Ghost — Authentication & User Management API."""
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from django.utils import timezone
User = get_user_model()
from django.core.cache import cache
from django.middleware.csrf import get_token
from rest_framework.decorators import api_view, permission_classes, authentication_classes, throttle_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from scanner.authentication import CsrfExemptAuth

from scanner.models import SiteConfig, UserPreference, AuditLog
import re
import json
import secrets

class InputValidationError(Exception):
    """Raised when whitelist validation fails."""
    pass

# Whitelist patterns — only allow characters valid for each field type
_PATTERNS = {
    'username': re.compile(r'^[a-zA-Z0-9._@-]+$'),
    'name':     re.compile(r"^[a-zA-Z0-9 .'-]+$"),
    'email':    None,  # use Django EmailValidator
    'company':  re.compile(r"^[a-zA-Z0-9 &.,'\-()]+$"),
    'title':    re.compile(r"^[a-zA-Z0-9 &.,:'\-()]+$"),
    'color':    re.compile(r'^#[0-9a-fA-F]{6}$'),
    'text':     re.compile(r"^[a-zA-Z0-9 &.,;:'\-()@#/\n\r]+$"),
}

def _wl(value, field_type, max_len=255):
    """Whitelist validation — reject if input doesn't match allowed pattern."""
    if not value:
        return ''
    if not isinstance(value, str):
        value = str(value)
    value = value[:max_len]
    pattern = _PATTERNS.get(field_type)
    if pattern and not pattern.match(value):
        raise InputValidationError(f'Invalid characters in {field_type}')
    if field_type == 'email':
        from django.core.validators import validate_email
        validate_email(value)
    return value

_LOGIN_WINDOW = 300  # 5 minutes
_LOGIN_MAX = 10  # max attempts per window


def _serialize_user(u):
    """Serialize a Django User to dict."""
    role = getattr(u, 'role', None) or 'viewer'
    name = u.get_full_name() or u.username
    avatar = ''.join([w[0] for w in name.split()[:2]]).upper() or 'U'
    return {
        'id': str(u.id), 'username': u.username, 'name': name, 'email': u.email,
        'role': role, 'avatar': avatar, 'status': 'active' if u.is_active else 'disabled',
        'last_login': u.last_login.isoformat() if u.last_login else None,
        'created_at': u.date_joined.isoformat(),
    }


@api_view(['POST'])
@authentication_classes([CsrfExemptAuth])
@permission_classes([AllowAny])
def auth_login(request):
    """Authenticate user and create session.

    Rate limiting only counts FAILED attempts. A successful login clears the
    counter, so a legitimate user can't lock themselves (or their whole NAT
    subnet) out by logging in several times in a 5-minute window. The bucket
    key stays per-REMOTE_ADDR to cap credential-stuffing from one origin.
    """
    ip = request.META.get('REMOTE_ADDR', '')
    cache_key = f'login_attempts:{ip}'
    attempts = cache.get(cache_key, 0)
    if attempts >= _LOGIN_MAX:
        retry_after = _LOGIN_WINDOW
        resp = Response(
            {'error': 'Too many failed login attempts. Try again later.'},
            status=429,
        )
        resp['Retry-After'] = str(retry_after)
        return resp

    username = request.data.get('username', '')
    password = request.data.get('password', '')

    # Type check — reject non-string inputs
    if not isinstance(username, str) or not isinstance(password, str):
        return Response({'error': 'Invalid input type'}, status=400)

    username = username.strip()
    if not username or not password:
        return Response({'error': 'Username and password required'}, status=400)

    user = authenticate(request, username=username, password=password)
    if user is None:
        # Count the failure — only failures burn tokens.
        cache.set(cache_key, attempts + 1, _LOGIN_WINDOW)
        return Response({'error': 'Invalid credentials'}, status=401)

    if not user.is_active:
        cache.set(cache_key, attempts + 1, _LOGIN_WINDOW)
        return Response({'error': 'Account disabled'}, status=403)

    # Success: drop the bucket so this user's retries don't count against them.
    cache.delete(cache_key)

    login(request, user)
    AuditLog.log(user.get_full_name() or user.username, 'login', f'Logged in from {ip}', 'auth', ip)
    return Response(_serialize_user(user))


@api_view(['POST'])
@authentication_classes([CsrfExemptAuth])
@permission_classes([AllowAny])
def auth_logout(request):
    """Logout and clear session."""
    if request.user.is_authenticated:
        AuditLog.log(request.user.get_full_name() or request.user.username, 'logout', 'Logged out', 'auth')
    logout(request)
    return Response({'status': 'ok'})


@api_view(['GET'])
@permission_classes([AllowAny])
def auth_csrf(request):
    """Return CSRF token for session auth."""
    return Response({'csrf': get_token(request)})


@api_view(['GET'])
def auth_me(request):
    """Return current authenticated user info."""
    if not request.user.is_authenticated:
        return Response({'error': 'Not authenticated'}, status=401)
    return Response(_serialize_user(request.user))


@api_view(['GET'])
@authentication_classes([CsrfExemptAuth])
@permission_classes([AllowAny])
def auth_check(request):
    """204 if the session is authenticated, 401 otherwise.

    Consumed by nginx `auth_request` on every gated static file and SPA path,
    so it MUST stay cheap — no DB work beyond the session-middleware lookup
    that already ran for this request. No body, no audit log, no cache write.
    """
    if request.user.is_authenticated:
        return HttpResponse(status=204)
    return HttpResponse(status=401)


@api_view(['GET'])
def auth_users(request):
    """List all users. Requires user:manage permission."""
    if not request.user.has_permission('user:manage'):
        return Response({'error': 'Not authorized'}, status=403)
    users = [_serialize_user(u) for u in User.objects.all().order_by('-date_joined')]
    return Response(users)


@api_view(['POST'])
def auth_user_create(request):
    """Create a new user. Requires user:manage permission."""
    if not request.user.has_permission('user:manage'):
        return Response({'error': 'Not authorized'}, status=403)

    try:
        username = _wl(request.data.get('username', '').strip(), 'username', 150)
        email = _wl(request.data.get('email', '').strip(), 'email', 254)
        name = _wl(request.data.get('name', '').strip(), 'name', 150)
    except (InputValidationError, Exception) as e:
        return Response({'error': str(e)}, status=400)
    password = request.data.get('password', '')
    role = request.data.get('role', 'viewer')
    status = request.data.get('status', 'active')

    if not username or not password:
        return Response({'error': 'Username and password required'}, status=400)

    if User.objects.filter(username=username).exists():
        return Response({'error': 'Username already exists'}, status=400)

    from django.contrib.auth.password_validation import validate_password
    try:
        validate_password(password)
    except Exception as e:
        return Response({'error': '; '.join(e.messages)}, status=400)

    if role not in ('engineer', 'viewer'):
        return Response({'error': 'Role must be engineer or viewer. Owner is fixed to the setup account.'}, status=400)

    parts = name.split(' ', 1) if name else [username, '']
    user = User.objects.create_user(
        username=username, password=password, email=email,
        first_name=parts[0], last_name=parts[1] if len(parts) > 1 else '',
    )
    user.is_active = (status == 'active')
    user.role = role
    user.save()  # save() syncs is_superuser / is_staff to role

    return Response(_serialize_user(user), status=201)


@api_view(['PUT'])
def auth_user_update(request, user_id):
    """Update a user. Requires user:manage permission."""
    if not request.user.has_permission('user:manage'):
        return Response({'error': 'Not authorized'}, status=403)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=404)

    # Protect the Owner account from role change.
    if user.role == 'owner' and 'role' in request.data and request.data['role'] != 'owner':
        return Response({'error': "The Owner's role cannot be changed."}, status=400)

    try:
        if 'name' in request.data:
            clean_name = _wl(request.data['name'], 'name', 150)
            parts = clean_name.split(' ', 1)
            user.first_name = parts[0]
            user.last_name = parts[1] if len(parts) > 1 else ''
        if 'email' in request.data:
            user.email = _wl(request.data['email'], 'email', 254)
        if 'username' in request.data:
            new_username = _wl(request.data['username'].strip(), 'username', 150)
    except (InputValidationError, Exception) as e:
        return Response({'error': str(e)}, status=400)
    if 'username' in request.data:
        if new_username != user.username and User.objects.filter(username=new_username).exists():
            return Response({'error': 'Username already exists'}, status=400)
        user.username = new_username
    if 'password' in request.data and request.data['password']:
        from django.contrib.auth.password_validation import validate_password
        try:
            validate_password(request.data['password'], user)
        except Exception as e:
            return Response({'error': '; '.join(e.messages)}, status=400)
        user.set_password(request.data['password'])
    if 'role' in request.data:
        new_role = request.data['role']
        if new_role not in ('engineer', 'viewer'):
            return Response({'error': 'Role must be engineer or viewer. Owner is fixed.'}, status=400)
        user.role = new_role
    if 'status' in request.data:
        user.is_active = (request.data['status'] == 'active')

    user.save()
    return Response(_serialize_user(user))


@api_view(['DELETE'])
def auth_user_delete(request, user_id):
    """Delete a user. Requires user:manage permission. Cannot delete self."""
    if not request.user.has_permission('user:manage'):
        return Response({'error': 'Not authorized'}, status=403)

    if str(request.user.id) == str(user_id):
        return Response({'error': 'Cannot delete yourself'}, status=400)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=404)

    if user.role == 'owner':
        return Response({'error': 'Cannot delete the Owner account.'}, status=400)

    name = user.get_full_name() or user.username
    user.delete()
    return Response({'status': 'deleted', 'name': name})


# ═══════════════ Site Config (setup state) ═══════════════

def _serialize_site_config(config, *, include_private=False):
    data = {
        'setup_complete': config.setup_complete,
        'setup_completed_at': config.setup_completed_at.isoformat() if config.setup_completed_at else None,
        'setup_completed_by': config.setup_completed_by,
        'schedule_timezone': config.schedule_timezone,
        'default_parallelism': config.default_parallelism,
        'default_timeout': config.default_timeout,
        'default_report_formats': config.default_report_formats,
    }
    if include_private:
        # Owner-only extras for the Notifications tab; note that bot_token is
        # NEVER surfaced in full — only the tail + a has-it flag.
        tok = config.telegram_bot_token or ''
        data['telegram_shared_chat_id'] = config.telegram_shared_chat_id
    return data


@api_view(['GET'])
@permission_classes([AllowAny])
def site_config(request):
    """Get site-wide config (setup state). Public so login/setup pages can check."""
    config = SiteConfig.get()
    data = _serialize_site_config(config)
    if not request.user.is_authenticated:
        data.pop('setup_completed_by', None)
        data.pop('setup_completed_at', None)
    return Response(data)


@api_view(['PUT'])
def update_site_config(request):
    """Update site-wide config. Requires site:config permission."""
    if not request.user.has_permission('site:config'):
        return Response({'error': 'Not authorized'}, status=403)

    config = SiteConfig.get()
    changed = []

    if 'schedule_timezone' in request.data:
        from zoneinfo import available_timezones
        tz = str(request.data.get('schedule_timezone', ''))[:64]
        if tz not in available_timezones():
            return Response({'error': f'Unknown timezone: {tz}'}, status=400)
        if tz != config.schedule_timezone:
            config.schedule_timezone = tz
            changed.append(f'schedule_timezone={tz}')

    if 'default_parallelism' in request.data:
        try:
            p = int(request.data.get('default_parallelism', 10))
        except (TypeError, ValueError):
            return Response({'error': 'default_parallelism must be an integer'}, status=400)
        if not 1 <= p <= 500:
            return Response({'error': 'default_parallelism must be between 1 and 500'}, status=400)
        if p != config.default_parallelism:
            config.default_parallelism = p
            changed.append(f'default_parallelism={p}')

    if 'default_timeout' in request.data:
        try:
            t = int(request.data.get('default_timeout', 3600))
        except (TypeError, ValueError):
            return Response({'error': 'default_timeout must be an integer'}, status=400)
        if not 60 <= t <= 86400:
            return Response({'error': 'default_timeout must be between 60 and 86400 seconds'}, status=400)
        if t != config.default_timeout:
            config.default_timeout = t
            changed.append(f'default_timeout={t}')

    if 'default_report_formats' in request.data:
        v = str(request.data.get('default_report_formats', ''))[:100]
        allowed = {'dashboard', 'html', 'docx', 'xlsx'}
        parts = [s.strip() for s in v.split(',') if s.strip()]
        if not parts or any(p not in allowed for p in parts):
            return Response({'error': f'default_report_formats must be a CSV of {sorted(allowed)}'}, status=400)
        new_val = ','.join(parts)
        if new_val != config.default_report_formats:
            config.default_report_formats = new_val
            changed.append(f'default_report_formats={new_val}')

    if changed:
        config.save()
        ip = request.META.get('REMOTE_ADDR', '')
        actor = request.user.get_full_name() or request.user.username
        AuditLog.log(actor, 'siteconfig.update', '; '.join(changed), 'config', ip)

    return Response(_serialize_site_config(config))


@api_view(['GET'])
@permission_classes([AllowAny])
def check_username(request):
    """Check if a username is available.

    Pre-auth access is only allowed during initial setup (setup_complete=False)
    so the wizard can validate the first admin username. After setup completes,
    authentication is required — prevents unauthenticated username enumeration.
    """
    config = SiteConfig.get()
    if config.setup_complete and not request.user.is_authenticated:
        return Response({'error': 'Authentication required'}, status=401)

    from django.core.cache import cache
    ip = request.META.get('REMOTE_ADDR', '')
    cache_key = f'check_user:{ip}'
    attempts = cache.get(cache_key, 0)
    if attempts >= 20:
        return Response({'error': 'Too many requests'}, status=429)
    cache.set(cache_key, attempts + 1, 60)

    username = request.query_params.get('username', '').strip()
    if not username or len(username) < 2:
        return Response({'available': False, 'reason': 'Too short'})
    exists = User.objects.filter(username=username).exists()
    return Response({'available': not exists, 'reason': 'Username taken' if exists else 'Available'})


@api_view(['POST'])
@authentication_classes([CsrfExemptAuth])
@permission_classes([AllowAny])
def setup_admin(request):
    """Create the first admin account during setup. Only works once — refuses if an admin already exists (beyond the default 'admin')."""
    try:
        username = _wl(request.data.get('username', '').strip(), 'username', 150)
        email = _wl(request.data.get('email', '').strip(), 'email', 254)
        name = _wl(request.data.get('name', '').strip(), 'name', 150)
    except (InputValidationError, Exception) as e:
        return Response({'error': str(e)}, status=400)
    password = request.data.get('password', '')

    if not username or not password:
        return Response({'error': 'Username and password required'}, status=400)

    # Check if setup already completed
    config = SiteConfig.get()
    if config.setup_complete:
        return Response({'error': 'Setup already completed. Use admin panel to create users.'}, status=403)

    if User.objects.filter(username=username).exists():
        return Response({'error': 'Username already exists'}, status=400)

    from django.contrib.auth.password_validation import validate_password
    try:
        validate_password(password)
    except Exception as e:
        return Response({'error': '; '.join(e.messages)}, status=400)

    parts = name.split(' ', 1) if name else [username, '']
    user = User.objects.create_superuser(
        username=username, password=password, email=email,
        first_name=parts[0], last_name=parts[1] if len(parts) > 1 else '',
    )
    user.role = 'owner'
    user.save()

    # Atomically mark setup complete in the same transaction as admin creation
    config = SiteConfig.get()
    config.setup_complete = True
    from django.utils import timezone
    config.setup_completed_at = timezone.now()
    config.setup_completed_by = username
    config.save()

    AuditLog.log(name or username, 'user.create', f'Setup wizard created admin: {username}', 'admin')

    return Response(_serialize_user(user), status=201)


@api_view(['POST'])
def site_setup_complete(request):
    """Mark setup as complete. Requires authentication after initial setup."""
    if not request.user.is_authenticated:
        return Response({'error': 'Authentication required'}, status=403)
    config = SiteConfig.get()
    config.setup_complete = True
    from django.utils import timezone
    config.setup_completed_at = timezone.now()
    config.setup_completed_by = request.data.get('completed_by', '')
    config.save()
    return Response({'setup_complete': True})


@api_view(['POST'])
@authentication_classes([CsrfExemptAuth])
@permission_classes([AllowAny])
def setup_one_shot(request):
    """All-in-one first-install endpoint.

    Replaces the five-request wizard dance (setup-admin, login, report-config
    PUT, report-config/logo POST, site-config/setup-complete POST) with a
    single multipart POST. Everything lands atomically — either the whole
    transaction commits or none of it does, so the Owner either lands on a
    fully-configured portal or nothing sticks.

    Accepts multipart form-data:
      username, password, email, name     (Owner — required)
      company_name, report_title,
      prepared_by, brand_color            (branding — optional)
      logo                                (file — optional)

    Refuses with 409 if setup_complete is already True (one-shot; use
    reset-setup first if you need to re-run).
    """
    from django.db import transaction
    from django.contrib.auth.password_validation import validate_password
    from scanner.models import ReportConfig
    import os

    config = SiteConfig.get()
    if config.setup_complete:
        return Response({'error': 'Setup already completed. Use admin panel to create users.'}, status=409)

    # Defensive: if a prior setup flipped `setup_complete=False` via direct DB
    # edit (not via reset-setup), there could still be an Owner in place. The
    # User.save() singleton guard would raise 500 mid-transaction — catch it
    # with a clean 409 up front instead.
    if User.objects.filter(role='owner').exists():
        return Response({'error': 'Owner account already exists — run reset-setup first'}, status=409)

    data = request.data
    try:
        username = _wl(data.get('username', '').strip(), 'username', 150)
        email = _wl(data.get('email', '').strip(), 'email', 254)
        name = _wl(data.get('name', '').strip(), 'name', 150)
    except (InputValidationError, Exception) as e:
        return Response({'error': str(e)}, status=400)
    password = data.get('password', '')
    if not username or not password:
        return Response({'error': 'Username and password required'}, status=400)
    if User.objects.filter(username=username).exists():
        return Response({'error': 'Username already exists'}, status=400)
    try:
        validate_password(password)
    except Exception as e:
        return Response({'error': '; '.join(e.messages)}, status=400)

    # Branding — reuse the same regex whitelist as PUT /report-config/.
    BRAND_PATTERNS = {
        'company_name': (re.compile(r"^[a-zA-Z0-9 &.,'\-()]+$"), 255),
        'report_title': (re.compile(r"^[a-zA-Z0-9 &.,:'\-()]+$"), 255),
        'prepared_by':  (re.compile(r"^[a-zA-Z0-9 .,'\-]+$"), 255),
        'brand_color':  (re.compile(r'^#[0-9a-fA-F]{6}$'), 7),
    }
    branding = {}
    for key, (pattern, max_len) in BRAND_PATTERNS.items():
        val = (data.get(key) or '').strip()
        if not val:
            continue
        val = val[:max_len]
        if not pattern.match(val):
            return Response({'error': f'Invalid characters in {key}'}, status=400)
        branding[key] = val

    # Logo — reuse the same 7 defenses from upload_logo (file-type allowlist,
    # dangerous-ext denylist, multi-extension scan, size cap, basename, realpath).
    logo_file = request.FILES.get('logo')
    logo_path_to_save = None
    if logo_file is not None:
        from django.utils.text import get_valid_filename
        ALLOWED = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'}
        DANGEROUS = {'.php', '.py', '.sh', '.js', '.html', '.htm', '.svg', '.exe',
                     '.bat', '.cmd', '.jsp', '.asp', '.aspx', '.cgi', '.pl'}
        ext = os.path.splitext(logo_file.name)[1].lower()
        all_exts = {('.' + p.lower()) for p in logo_file.name.split('.')[1:]} if '.' in logo_file.name else set()
        if all_exts & DANGEROUS:
            return Response({'error': 'Dangerous file extension detected'}, status=400)
        if ext not in ALLOWED:
            return Response({'error': f'File type {ext} not allowed'}, status=400)
        if logo_file.size > 2 * 1024 * 1024:
            return Response({'error': 'Logo too large (max 2MB)'}, status=400)
        logo_dir = '/data/assets/logos'
        os.makedirs(logo_dir, exist_ok=True)
        safe_name = get_valid_filename(os.path.basename(logo_file.name))
        if not safe_name:
            return Response({'error': 'Invalid logo filename'}, status=400)
        logo_path_to_save = os.path.join(logo_dir, safe_name)
        if not os.path.realpath(logo_path_to_save).startswith(os.path.realpath(logo_dir)):
            return Response({'error': 'Invalid logo path'}, status=400)

    # All validation passed — commit atomically. Owner creation + config flip
    # + branding save happen in one transaction; partial failure rolls back.
    with transaction.atomic():
        parts = name.split(' ', 1) if name else [username, '']
        user = User.objects.create_superuser(
            username=username, password=password, email=email,
            first_name=parts[0], last_name=parts[1] if len(parts) > 1 else '',
        )
        user.role = 'owner'
        user.save()

        # Mark setup complete in the same txn as Owner creation.
        config = SiteConfig.get()
        config.setup_complete = True
        config.setup_completed_at = timezone.now()
        config.setup_completed_by = username
        config.save()

        # Branding (inside txn so a regex failure would have rolled back
        # everything above — but we already validated, so this is just writes).
        if branding:
            rc = ReportConfig.get()
            for k, v in branding.items():
                setattr(rc, k, v)
            rc.save()

        # Logo write happens AFTER the DB commit so a later I/O error doesn't
        # leave an orphaned row; but we save the path on ReportConfig inside
        # the txn so the record is consistent.
        if logo_file is not None and logo_path_to_save:
            rc = ReportConfig.get()
            rc.logo_path = logo_path_to_save
            rc.save()

    # Write the logo bytes to disk post-commit — if this fails, the portal
    # is already fully set up; at worst the user re-uploads from Settings.
    if logo_file is not None and logo_path_to_save:
        try:
            with open(logo_path_to_save, 'wb+') as f:
                for chunk in logo_file.chunks():
                    f.write(chunk)
        except OSError:
            pass

    # Auto-login the new Owner so the browser lands on /dashboard with a
    # live session. Since the endpoint is CsrfExempt + AllowAny, we attach
    # the session cookie directly via django.contrib.auth.login.
    login(request, user)

    AuditLog.log(name or username, 'user.create', f'One-shot setup created Owner: {username}', 'admin')

    payload = _serialize_user(user)
    payload['setup_complete'] = True
    return Response(payload, status=201)


@api_view(['POST'])
def reset_setup(request):
    """Tear the portal back down to first-run state. Owner only.

    Deletes every user (including the caller) and flips
    SiteConfig.setup_complete back to False so the setup wizard is
    re-served on the next request. The caller's session is killed
    as a side-effect of their own user row being deleted.
    """
    if not request.user.is_authenticated:
        return Response({'error': 'Authentication required'}, status=403)
    if not request.user.has_permission('site:reset'):
        return Response({'error': 'Not authorized'}, status=403)

    actor = request.user.get_full_name() or request.user.username
    ip = request.META.get('REMOTE_ADDR', '')

    user_count = User.objects.count()
    User.objects.all().delete()

    config = SiteConfig.get()
    config.setup_complete = False
    config.setup_completed_at = None
    config.setup_completed_by = ''
    config.save()

    # Caller's session row is gone with the user delete; drop any
    # lingering perm cache so a fresh first-run Owner starts clean.
    try:
        from scanner.models import User as _U
        _U.invalidate_perm_cache()
    except Exception:
        pass

    AuditLog.log(actor, 'site.reset',
                 f'Deleted {user_count} users; setup marked incomplete',
                 'admin', ip)
    return Response({'setup_complete': False, 'users_deleted': user_count})


# ═══════════════ User Preferences ═══════════════

_CHAT_ID_RE_STR = r'^-?\d+$|^@[\w]{5,}$'


def _serialize_prefs(prefs):
    return {
        'theme_mode': prefs.theme_mode,
        'accent_color': prefs.accent_color,
        'font_size': prefs.font_size,
        'notifications': {
            'scanComplete': prefs.notif_scan_complete,
            'scanFailed': prefs.notif_scan_failed,
            'criticalFinding': prefs.notif_critical_finding,
            'reportReady': prefs.notif_report_ready,
            'weeklyDigest': prefs.notif_weekly_digest,
            'email': prefs.notif_email,
        },
        'telegram': {
            'enabled': prefs.telegram_enabled,
            'chat_id': prefs.telegram_chat_id,
        },
    }


@api_view(['GET', 'PUT'])
def user_preferences(request):
    """Get or update current user's preferences (theme, notifications, telegram DM)."""
    if not request.user.is_authenticated:
        return Response({'error': 'Not authenticated'}, status=401)

    prefs = UserPreference.for_user(request.user)

    if request.method == 'GET':
        return Response(_serialize_prefs(prefs))

    # PUT — update preferences (validate types and values)
    data = request.data
    VALID_THEMES = {'dark', 'light', 'cyberpunk'}
    VALID_ACCENTS = {'blue', 'green', 'purple', 'red', 'orange', 'cyan', 'rose'}
    VALID_SIZES = {'small', 'default', 'large', 'xlarge'}

    if 'theme_mode' in data:
        val = str(data['theme_mode'])[:20]
        prefs.theme_mode = val if val in VALID_THEMES else 'dark'
    if 'accent_color' in data:
        val = str(data['accent_color'])[:20]
        prefs.accent_color = val if val in VALID_ACCENTS else 'blue'
    if 'font_size' in data:
        val = str(data['font_size'])[:20]
        prefs.font_size = val if val in VALID_SIZES else 'default'
    if 'notifications' in data:
        n = data['notifications']
        if 'scanComplete' in n: prefs.notif_scan_complete = bool(n['scanComplete'])
        if 'scanFailed' in n: prefs.notif_scan_failed = bool(n['scanFailed'])
        if 'criticalFinding' in n: prefs.notif_critical_finding = bool(n['criticalFinding'])
        if 'reportReady' in n: prefs.notif_report_ready = bool(n['reportReady'])
        if 'weeklyDigest' in n: prefs.notif_weekly_digest = bool(n['weeklyDigest'])
        if 'email' in n: prefs.notif_email = bool(n['email'])
    if 'telegram' in data:
        t = data['telegram']
        if 'chat_id' in t:
            cid = str(t.get('chat_id') or '').strip()[:64]
            if cid and not re.match(_CHAT_ID_RE_STR, cid):
                return Response(
                    {'error': 'telegram.chat_id must be a numeric ID or @username (min 5 chars)'},
                    status=400,
                )
            prefs.telegram_chat_id = cid
        if 'enabled' in t:
            prefs.telegram_enabled = bool(t['enabled'])
    prefs.save()

    return Response(_serialize_prefs(prefs))


# ═══════════════ Active Sessions ═══════════════

@api_view(['GET'])
def list_sessions(request):
    """List active sessions for current user."""
    from django.contrib.sessions.models import Session
    from django.utils import timezone

    current_session_key = request.session.session_key
    sessions = []
    for s in Session.objects.filter(expire_date__gte=timezone.now()):
        data = s.get_decoded()
        if str(data.get('_auth_user_id')) == str(request.user.id):
            sessions.append({
                'id': s.session_key[:8],
                'session_key': s.session_key,
                'current': s.session_key == current_session_key,
                'expires': s.expire_date.isoformat(),
                'ip': data.get('_ip', 'Unknown'),
                'user_agent': data.get('_ua', 'Unknown'),
            })
    return Response(sessions)


@api_view(['POST'])
def revoke_session(request):
    """Revoke a specific session."""
    from django.contrib.sessions.models import Session
    session_key = request.data.get('session_key', '')
    if session_key == request.session.session_key:
        return Response({'error': 'Cannot revoke current session'}, status=400)
    try:
        session = Session.objects.get(session_key=session_key)
        # Verify session belongs to requesting user (prevents IDOR)
        data = session.get_decoded()
        if str(data.get('_auth_user_id')) != str(request.user.id):
            return Response({'error': 'Session not found'}, status=404)
        session.delete()
        AuditLog.log(request.user.get_full_name() or request.user.username, 'session.revoke', f'Revoked session {session_key[:8]}', 'auth')
        return Response({'status': 'revoked'})
    except Session.DoesNotExist:
        return Response({'error': 'Session not found'}, status=404)


@api_view(['POST'])
def revoke_all_sessions(request):
    """Revoke all sessions except current."""
    from django.contrib.sessions.models import Session
    from django.utils import timezone
    current = request.session.session_key
    count = 0
    for s in Session.objects.filter(expire_date__gte=timezone.now()):
        data = s.get_decoded()
        if str(data.get('_auth_user_id')) == str(request.user.id) and s.session_key != current:
            s.delete()
            count += 1
    AuditLog.log(request.user.get_full_name() or request.user.username, 'session.revoke_all', f'Revoked {count} sessions', 'auth')
    return Response({'status': 'ok', 'revoked': count})


# ═══════════════ Audit Log ═══════════════

@api_view(['GET'])
def audit_log(request):
    """List audit log entries. Requires audit:view permission."""
    if not request.user.has_permission('audit:view'):
        return Response({'error': 'Not authorized'}, status=403)

    log_type = request.query_params.get('type', '')
    try:
        limit = min(int(request.query_params.get('limit', 50)), 200)
    except (ValueError, TypeError):
        limit = 50

    qs = AuditLog.objects.all()
    if log_type:
        qs = qs.filter(type=log_type)

    entries = [{
        'id': str(e.id), 'user': e.user, 'action': e.action,
        'detail': e.detail, 'type': e.type,
        'ip_address': e.ip_address,
        'timestamp': e.timestamp.isoformat(),
    } for e in qs[:limit]]

    return Response(entries)


# ═══════════════ Personal API Tokens ═══════════════

def _serialize_token(t, *, include_raw=None):
    data = {
        'id': str(t.id),
        'name': t.name,
        'prefix': t.prefix,
        'created_at': t.created_at.isoformat(),
        'last_used_at': t.last_used_at.isoformat() if t.last_used_at else None,
        'revoked_at': t.revoked_at.isoformat() if t.revoked_at else None,
    }
    if include_raw is not None:
        data['token'] = include_raw  # only present on creation response
    return data


@api_view(['GET', 'POST'])
def tokens_list_or_create(request):
    """List the caller's tokens (GET) or mint a new one (POST).

    The plaintext token is included in the POST response ONLY — it's never
    returned again after that. POST body: ``{"name": "<80 chars max>"}``.
    Enforces a per-user active-token cap of ``ApiToken.MAX_PER_USER``.
    """
    if not request.user.is_authenticated:
        return Response({'error': 'Authentication required'}, status=401)

    from scanner.models import ApiToken

    if request.method == 'GET':
        qs = ApiToken.objects.filter(user=request.user).order_by('-created_at')
        return Response([_serialize_token(t) for t in qs])

    # POST
    name = str(request.data.get('name', '')).strip()
    if not name:
        return Response({'error': 'name is required'}, status=400)
    if len(name) > 80:
        return Response({'error': 'name too long (max 80)'}, status=400)

    active_count = ApiToken.objects.filter(user=request.user, revoked_at__isnull=True).count()
    if active_count >= ApiToken.MAX_PER_USER:
        return Response(
            {'error': f'Token limit reached ({ApiToken.MAX_PER_USER} active per user). '
                      'Revoke an existing token before creating another.'},
            status=400,
        )

    tok, raw = ApiToken.mint(request.user, name)
    actor = request.user.get_full_name() or request.user.username
    ip = request.META.get('REMOTE_ADDR', '')
    AuditLog.log(actor, 'token.create', f'{tok.prefix} ({name})', 'admin', ip)

    return Response(_serialize_token(tok, include_raw=raw), status=201)


@api_view(['POST'])
def tokens_revoke(request, token_id):
    """Revoke a token the caller owns. 404 (not 403) if the token belongs to
    another user — never leak token-existence across accounts.
    """
    if not request.user.is_authenticated:
        return Response({'error': 'Authentication required'}, status=401)

    from scanner.models import ApiToken
    try:
        tok = ApiToken.objects.get(id=token_id, user=request.user)
    except ApiToken.DoesNotExist:
        return Response({'error': 'Not found'}, status=404)

    if tok.revoked_at is None:
        tok.revoked_at = timezone.now()
        tok.save(update_fields=['revoked_at'])
        actor = request.user.get_full_name() or request.user.username
        ip = request.META.get('REMOTE_ADDR', '')
        AuditLog.log(actor, 'token.revoke', f'{tok.prefix} ({tok.name})', 'admin', ip)

    return Response(_serialize_token(tok))


# ═══════════════ Telegram notifications ═══════════════

@api_view(['GET', 'PUT'])
def notifications_config(request):
    """Site-wide Telegram config.

    GET: everyone sees ``{has_token}``; Owner also sees ``{token_tail, shared_chat_id}``.
    PUT: Owner only. Fields: ``bot_token``, ``shared_chat_id`` (both optional).
    Empty string clears. Bot token is never returned raw once saved.
    """
    if not request.user.is_authenticated:
        return Response({'error': 'Authentication required'}, status=401)

    is_owner = request.user.has_permission('site:config')
    cfg = SiteConfig.get()
    tok = cfg.telegram_bot_token or ''

    if request.method == 'GET':
        body = {'has_token': bool(tok)}
        if is_owner:
            body['token_tail'] = ('...' + tok[-6:]) if tok else ''
            body['shared_chat_id'] = cfg.telegram_shared_chat_id
        return Response(body)

    # PUT
    if not is_owner:
        return Response({'error': 'Not authorized'}, status=403)

    changed = []
    if 'bot_token' in request.data:
        new_tok = str(request.data.get('bot_token') or '').strip()[:128]
        if new_tok != cfg.telegram_bot_token:
            cfg.telegram_bot_token = new_tok
            changed.append('bot_token=' + ('<set>' if new_tok else '<cleared>'))
    if 'shared_chat_id' in request.data:
        cid = str(request.data.get('shared_chat_id') or '').strip()[:64]
        if cid and not re.match(_CHAT_ID_RE_STR, cid):
            return Response(
                {'error': 'shared_chat_id must be a numeric ID or @channelname (min 5 chars)'},
                status=400,
            )
        if cid != cfg.telegram_shared_chat_id:
            cfg.telegram_shared_chat_id = cid
            changed.append(f'shared_chat_id={cid or "<cleared>"}')

    if changed:
        cfg.save()
        ip = request.META.get('REMOTE_ADDR', '')
        actor = request.user.get_full_name() or request.user.username
        AuditLog.log(actor, 'telegram.config', '; '.join(changed), 'config', ip)

    return Response({
        'has_token': bool(cfg.telegram_bot_token),
        'token_tail': ('...' + cfg.telegram_bot_token[-6:]) if cfg.telegram_bot_token else '',
        'shared_chat_id': cfg.telegram_shared_chat_id,
    })


@api_view(['POST'])
def notifications_test(request):
    """Send a test Telegram message. Body: ``{"target": "shared"|"self"}``.

    Returns 200 with ``{ok: true}`` if Telegram accepted the send, 400 with
    ``{error}`` otherwise (propagates Telegram's error description so the
    user sees "chat not found" / "bot was blocked by the user" directly).
    """
    if not request.user.is_authenticated:
        return Response({'error': 'Authentication required'}, status=401)

    target = str(request.data.get('target', 'self')).strip().lower()
    if target not in ('shared', 'self'):
        return Response({'error': 'target must be "shared" or "self"'}, status=400)

    cfg = SiteConfig.get()
    if not cfg.telegram_bot_token:
        return Response({'error': 'Telegram bot token not configured.'}, status=400)

    if target == 'shared':
        chat_id = cfg.telegram_shared_chat_id
        if not chat_id:
            return Response({'error': 'Shared channel ID not configured.'}, status=400)
    else:  # self
        prefs = UserPreference.for_user(request.user)
        chat_id = prefs.telegram_chat_id
        if not chat_id:
            return Response({'error': 'Set your personal chat_id first.'}, status=400)

    from scanner.notifications import send_telegram, NotificationError
    actor = request.user.get_full_name() or request.user.username
    text = f'✅ Wire_Ghost test message from @{actor}'
    try:
        result = send_telegram(chat_id, text, bot_token=cfg.telegram_bot_token)
    except NotificationError as e:
        return Response({'error': str(e)}, status=400)
    if result.get('ok'):
        return Response({'ok': True})
    return Response({'error': result.get('error') or 'Telegram API rejected the send'}, status=400)


@api_view(['GET'])
def tools_health(request):
    """Live probe of external scan tools. Auth'd users only (no sensitive data,
    but the list reveals what pipeline components are present — keep behind auth).
    """
    if not request.user.is_authenticated:
        return Response({'error': 'Authentication required'}, status=401)
    from scanner.tools_health import probe_all
    refresh = str(request.query_params.get('refresh', '')).lower() in ('1', 'true', 'yes')
    return Response(probe_all(refresh=refresh))


from rest_framework.throttling import UserRateThrottle


class StatsThrottle(UserRateThrottle):
    rate = '60/min'
    scope = 'system_stats'

    def get_cache_key(self, request, view):
        if request.user.is_authenticated:
            return self.cache_format % {'scope': self.scope, 'ident': request.user.pk}
        ident = self.get_ident(request)
        return self.cache_format % {'scope': self.scope, 'ident': ident}


@api_view(['GET'])
@throttle_classes([StatsThrottle])
def system_stats(request):
    """Real-time container resource usage (CPU / memory / disk / network).

    Polled every ~1.5s by the System Monitor SPA page. Returns container-
    scoped (cgroup) numbers — no /proc or /sys host mounts in compose, so
    numbers reflect what the api container sees, which is what operators
    actually care about for capacity planning. No AuditLog write because
    this is a high-frequency polling endpoint; logging every tick would
    drown the audit trail in noise. IsAuthenticated is the only gate.
    """
    if not request.user.is_authenticated:
        return Response({'error': 'Authentication required'}, status=401)
    import time
    import psutil
    # cpu_percent(interval=None) returns the delta since the previous call
    # (or since boot on the first call). First call in a fresh process
    # returns 0.0 — fine; the client's sparkline settles within a tick.
    vm = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    net = psutil.net_io_counters()
    return Response({
        'cpu': {
            'percent': psutil.cpu_percent(interval=None),
            'count': psutil.cpu_count() or 0,
        },
        'memory': {
            'percent': vm.percent,
            'used': vm.used,
            'total': vm.total,
        },
        'disk': {
            'percent': disk.percent,
            'used': disk.used,
            'total': disk.total,
        },
        'net': {
            'bytes_sent': net.bytes_sent,
            'bytes_recv': net.bytes_recv,
        },
        'uptime': int(time.time() - psutil.boot_time()),
        'ts': int(time.time() * 1000),
    })


@api_view(['POST'])
def telegram_link_code(request):
    """Generate a 6-digit one-time code for Telegram account linking."""
    user_key = f'tg:linkgen:{request.user.id}'
    gen_count = cache.get(user_key) or 0
    if gen_count >= 3:
        return Response({'error': 'Too many code requests. Try again in 5 minutes.'}, status=429)

    reverse_key = f'tg:linkuser:{request.user.id}'
    old_code = cache.get(reverse_key)
    if old_code:
        cache.delete(f'tg:link:{old_code}')
        cache.delete(reverse_key)

    code = str(secrets.randbelow(900000) + 100000)
    cache.set(f'tg:link:{code}', json.dumps({'user_id': str(request.user.id)}), 300)
    cache.set(reverse_key, code, 300)
    cache.set(user_key, gen_count + 1, 300)

    return Response({'code': code, 'expires_in': 300})
