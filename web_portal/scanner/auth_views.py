"""Wire_Ghost — Authentication & User Management API."""
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth import get_user_model
User = get_user_model()
from django.core.cache import cache
from django.middleware.csrf import get_token
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from scanner.authentication import CsrfExemptAuth

from scanner.models import SiteConfig, UserPreference, ApiKey, AuditLog
import re
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
    'key_name': re.compile(r'^[a-zA-Z0-9 _\-]+$'),
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
    role = 'admin' if u.is_superuser else ('analyst' if u.is_staff else 'viewer')
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
    """Authenticate user and create session."""
    # Rate limiting via Django cache — use REMOTE_ADDR only (not spoofable via headers)
    ip = request.META.get('REMOTE_ADDR', '')
    cache_key = f'login_attempts:{ip}'
    attempts = cache.get(cache_key, 0)
    if attempts >= _LOGIN_MAX:
        return Response({'error': 'Too many login attempts. Try again later.'}, status=429)
    cache.set(cache_key, attempts + 1, _LOGIN_WINDOW)

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
        return Response({'error': 'Invalid credentials'}, status=401)

    if not user.is_active:
        return Response({'error': 'Account disabled'}, status=403)

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
def auth_users(request):
    """List all users (admin only)."""
    if not request.user.is_superuser:
        return Response({'error': 'Admin only'}, status=403)
    users = [_serialize_user(u) for u in User.objects.all().order_by('-date_joined')]
    return Response(users)


@api_view(['POST'])
def auth_user_create(request):
    """Create a new user (admin only)."""
    if not request.user.is_superuser:
        return Response({'error': 'Admin only'}, status=403)

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

    parts = name.split(' ', 1) if name else [username, '']
    user = User.objects.create_user(
        username=username, password=password, email=email,
        first_name=parts[0], last_name=parts[1] if len(parts) > 1 else '',
    )
    user.is_active = (status == 'active')
    user.is_superuser = (role == 'admin')
    user.is_staff = (role in ('admin', 'analyst'))
    user.save()

    return Response(_serialize_user(user), status=201)


@api_view(['PUT'])
def auth_user_update(request, user_id):
    """Update a user (admin only)."""
    if not request.user.is_superuser:
        return Response({'error': 'Admin only'}, status=403)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=404)

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
        role = request.data['role']
        user.is_superuser = (role == 'admin')
        user.is_staff = (role in ('admin', 'analyst'))
    if 'status' in request.data:
        user.is_active = (request.data['status'] == 'active')

    user.save()
    return Response(_serialize_user(user))


@api_view(['DELETE'])
def auth_user_delete(request, user_id):
    """Delete a user (admin only, cannot delete self)."""
    if not request.user.is_superuser:
        return Response({'error': 'Admin only'}, status=403)

    if str(request.user.id) == str(user_id):
        return Response({'error': 'Cannot delete yourself'}, status=400)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=404)

    name = user.get_full_name() or user.username
    user.delete()
    return Response({'status': 'deleted', 'name': name})


# ═══════════════ Site Config (setup state) ═══════════════

@api_view(['GET'])
@permission_classes([AllowAny])
def site_config(request):
    """Get site-wide config (setup state). Public so login/setup pages can check."""
    config = SiteConfig.get()
    return Response({
        'setup_complete': config.setup_complete,
        'setup_completed_at': config.setup_completed_at.isoformat() if config.setup_completed_at else None,
        'setup_completed_by': config.setup_completed_by,
    })


@api_view(['GET'])
@permission_classes([AllowAny])
def check_username(request):
    """Check if a username is available (rate-limited to prevent enumeration)."""
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


# ═══════════════ User Preferences ═══════════════

@api_view(['GET', 'PUT'])
def user_preferences(request):
    """Get or update current user's preferences (theme, notifications)."""
    if not request.user.is_authenticated:
        return Response({'error': 'Not authenticated'}, status=401)

    prefs = UserPreference.for_user(request.user)

    if request.method == 'GET':
        return Response({
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
        })

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
        if 'scanComplete' in n: prefs.notif_scan_complete = n['scanComplete']
        if 'scanFailed' in n: prefs.notif_scan_failed = n['scanFailed']
        if 'criticalFinding' in n: prefs.notif_critical_finding = n['criticalFinding']
        if 'reportReady' in n: prefs.notif_report_ready = n['reportReady']
        if 'weeklyDigest' in n: prefs.notif_weekly_digest = n['weeklyDigest']
        if 'email' in n: prefs.notif_email = n['email']
    prefs.save()

    return Response({
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
    })


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


# ═══════════════ API Keys ═══════════════

@api_view(['GET'])
def list_api_keys(request):
    """List API keys for current user (admin sees all)."""
    if request.user.is_superuser:
        keys = ApiKey.objects.all()
    else:
        keys = ApiKey.objects.filter(user=request.user)
    return Response([{
        'id': str(k.id), 'name': k.name,
        'key': k.key[:10] + '...' + k.key[-4:],  # masked
        'scopes': k.scopes,
        'last_used': k.last_used.isoformat() if k.last_used else None,
        'created_at': k.created_at.isoformat(),
        'user': k.user.username,
    } for k in keys])


@api_view(['POST'])
def create_api_key(request):
    """Generate a new API key."""
    try:
        name = _wl(request.data.get('name', '').strip(), 'key_name', 100)
    except InputValidationError as e:
        return Response({'error': str(e)}, status=400)
    if not name:
        return Response({'error': 'Name required'}, status=400)
    VALID_SCOPES = {'scans:read', 'scans:write', 'findings:read', 'hosts:read', 'dashboard:read', 'reports:read'}
    raw_scopes = request.data.get('scopes', 'scans:read,findings:read')
    scopes = ','.join(s for s in raw_scopes.split(',') if s.strip() in VALID_SCOPES) or 'scans:read,findings:read'
    key = 'wg_sk_' + secrets.token_hex(24)
    api_key = ApiKey.objects.create(user=request.user, name=name, key=key, scopes=scopes)
    AuditLog.log(request.user.get_full_name() or request.user.username, 'apikey.create', f'Created API key: {name}', 'admin')
    return Response({
        'id': str(api_key.id), 'name': name, 'key': key,  # show full key only on creation
        'scopes': scopes, 'created_at': api_key.created_at.isoformat(),
    }, status=201)


@api_view(['DELETE'])
def revoke_api_key(request, key_id):
    """Revoke (delete) an API key."""
    try:
        key = ApiKey.objects.get(id=key_id)
        if not request.user.is_superuser and key.user != request.user:
            return Response({'error': 'Not authorized'}, status=403)
        name = key.name
        key.delete()
        AuditLog.log(request.user.get_full_name() or request.user.username, 'apikey.revoke', f'Revoked API key: {name}', 'admin')
        return Response({'status': 'revoked', 'name': name})
    except ApiKey.DoesNotExist:
        return Response({'error': 'Key not found'}, status=404)


# ═══════════════ Audit Log ═══════════════

@api_view(['GET'])
def audit_log(request):
    """List audit log entries (admin only)."""
    if not request.user.is_superuser:
        return Response({'error': 'Admin only'}, status=403)

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
