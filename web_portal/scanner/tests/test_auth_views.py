"""Tests for Wire_Ghost auth_views.py — authentication, user management, site config."""
import json

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ValidationError as DjangoValidationError
from django.test import Client, TestCase

from scanner.auth_views import InputValidationError, _wl
from scanner.models import Permission, RolePermission, SiteConfig

User = get_user_model()

# A strong password that passes all Django validators.
STRONG_PW = 'X#kL9$mNp!2qR'


def _seed_permissions():
    """Ensure the RBAC permission rows exist (mirrors migration 0007)."""
    PERMISSIONS = [
        ('user:manage', 'Manage users', ''),
        ('site:config', 'Site configuration', ''),
        ('audit:view', 'View audit log', ''),
        ('scan:read', 'View scans', ''),
        ('scan:write', 'Run and manage scans', ''),
        ('host:read', 'View hosts', ''),
        ('finding:read', 'View findings', ''),
        ('dashboard:view', 'View dashboard', ''),
        ('report:download', 'Download reports', ''),
        ('report:config:write', 'Edit report branding', ''),
        ('report:logo:upload', 'Upload report logo', ''),
        ('policy:read', 'View scan policies', ''),
        ('policy:write', 'Manage scan policies', ''),
        ('schedule:read', 'View scheduled scans', ''),
        ('schedule:write', 'Manage scheduled scans', ''),
        ('site:reset', 'Reset site', ''),
    ]
    ROLE_MATRIX = {
        'owner': {code for code, _, _ in PERMISSIONS},
        'engineer': {
            'scan:read', 'scan:write', 'host:read', 'finding:read',
            'dashboard:view', 'report:download', 'report:config:write',
            'report:logo:upload', 'policy:read', 'policy:write',
            'schedule:read', 'schedule:write',
        },
        'viewer': {
            'scan:read', 'host:read', 'finding:read',
            'dashboard:view', 'report:download',
        },
    }
    code_to_perm = {}
    for code, name, desc in PERMISSIONS:
        perm, _ = Permission.objects.get_or_create(
            code=code, defaults={'name': name, 'description': desc},
        )
        code_to_perm[code] = perm
    for role, codes in ROLE_MATRIX.items():
        for code in codes:
            RolePermission.objects.get_or_create(
                role=role, permission=code_to_perm[code],
            )


# ═══════════════ _wl() whitelist validation ═══════════════

class WhitelistValidationTests(TestCase):
    """Tests for the _wl() input whitelist function."""

    def test_valid_username_pattern(self):
        result = _wl('john.doe_42', 'username')
        self.assertEqual(result, 'john.doe_42')

    def test_invalid_username_special_chars(self):
        with self.assertRaises(InputValidationError):
            _wl('<script>alert(1)</script>', 'username')

    def test_valid_name_pattern(self):
        result = _wl("John O'Brien", 'name')
        self.assertEqual(result, "John O'Brien")

    def test_invalid_name_xss(self):
        with self.assertRaises(InputValidationError):
            _wl('<img src=x onerror=alert(1)>', 'name')

    def test_valid_color(self):
        result = _wl('#00FF00', 'color')
        self.assertEqual(result, '#00FF00')

    def test_invalid_color(self):
        with self.assertRaises(InputValidationError):
            _wl('red', 'color')

    def test_valid_text_pattern(self):
        result = _wl('Hello, world; test #1 @ home', 'text')
        self.assertEqual(result, 'Hello, world; test #1 @ home')

    def test_invalid_text_angle_brackets(self):
        with self.assertRaises(InputValidationError):
            _wl('Hello <b>world</b>', 'text')

    def test_empty_input_returns_empty(self):
        self.assertEqual(_wl('', 'username'), '')
        self.assertEqual(_wl(None, 'username'), '')

    def test_non_string_coerced(self):
        result = _wl(12345, 'username')
        self.assertEqual(result, '12345')

    def test_max_length_truncation(self):
        long_input = 'a' * 300
        result = _wl(long_input, 'username', max_len=10)
        self.assertEqual(len(result), 10)
        self.assertEqual(result, 'a' * 10)


# ═══════════════ auth_login ═══════════════

class AuthLoginTests(TestCase):
    """Tests for POST /api/auth/login/."""

    def setUp(self):
        cache.clear()
        _seed_permissions()
        self.user = User.objects.create_user(
            username='testuser', password=STRONG_PW, email='test@example.com',
            role='engineer',
        )
        self.client = Client()

    def test_successful_login(self):
        res = self.client.post(
            '/api/auth/login/',
            data=json.dumps({'username': 'testuser', 'password': STRONG_PW}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body['username'], 'testuser')
        self.assertIn('role', body)

    def test_invalid_credentials_401(self):
        res = self.client.post(
            '/api/auth/login/',
            data=json.dumps({'username': 'testuser', 'password': 'wrong'}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 401)
        self.assertIn('error', res.json())

    def test_missing_username_400(self):
        res = self.client.post(
            '/api/auth/login/',
            data=json.dumps({'password': STRONG_PW}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 400)

    def test_missing_password_400(self):
        res = self.client.post(
            '/api/auth/login/',
            data=json.dumps({'username': 'testuser'}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 400)

    def test_non_string_input_400(self):
        res = self.client.post(
            '/api/auth/login/',
            data=json.dumps({'username': 123, 'password': STRONG_PW}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 400)

    def test_disabled_account_rejected(self):
        """Disabled account: Django's ModelBackend rejects inactive users at
        authenticate() level, so the view returns 401 (invalid credentials)
        rather than reaching its own 403 branch. Either way the user is denied."""
        self.user.is_active = False
        self.user.save()
        res = self.client.post(
            '/api/auth/login/',
            data=json.dumps({'username': 'testuser', 'password': STRONG_PW}),
            content_type='application/json',
        )
        # ModelBackend returns None for inactive users -> 401 from the view
        self.assertIn(res.status_code, (401, 403))

    def test_rate_limiting_429(self):
        """10 failed attempts, then 11th returns 429 with Retry-After."""
        for i in range(10):
            self.client.post(
                '/api/auth/login/',
                data=json.dumps({'username': 'testuser', 'password': 'wrong'}),
                content_type='application/json',
            )
        res = self.client.post(
            '/api/auth/login/',
            data=json.dumps({'username': 'testuser', 'password': 'wrong'}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 429)
        self.assertIn('Retry-After', res)


# ═══════════════ auth_user_create ═══════════════

class AuthUserCreateTests(TestCase):
    """Tests for POST /api/auth/users/create/."""

    def setUp(self):
        cache.clear()
        _seed_permissions()
        self.owner = User.objects.create_superuser(
            username='owner', password=STRONG_PW, email='owner@example.com',
        )
        # create_superuser + save() auto-promotes to owner role
        self.client = Client()
        self.client.force_login(self.owner)

    def test_successful_creation_201(self):
        res = self.client.post(
            '/api/auth/users/create/',
            data=json.dumps({
                'username': 'newuser', 'password': STRONG_PW,
                'name': 'New User', 'email': 'new@example.com', 'role': 'viewer',
            }),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 201)
        body = res.json()
        self.assertEqual(body['username'], 'newuser')
        self.assertEqual(body['role'], 'viewer')
        self.assertTrue(User.objects.filter(username='newuser').exists())

    def test_duplicate_username_400(self):
        User.objects.create_user(username='existing', password=STRONG_PW, role='viewer')
        res = self.client.post(
            '/api/auth/users/create/',
            data=json.dumps({
                'username': 'existing', 'password': STRONG_PW, 'role': 'viewer',
            }),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn('already exists', res.json()['error'])

    def test_weak_password_rejected(self):
        res = self.client.post(
            '/api/auth/users/create/',
            data=json.dumps({
                'username': 'weakpw', 'password': '123', 'role': 'viewer',
            }),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 400)

    def test_invalid_role_400(self):
        res = self.client.post(
            '/api/auth/users/create/',
            data=json.dumps({
                'username': 'badrole', 'password': STRONG_PW, 'role': 'admin',
            }),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn('Role must be', res.json()['error'])

    def test_owner_role_blocked(self):
        res = self.client.post(
            '/api/auth/users/create/',
            data=json.dumps({
                'username': 'wannaowner', 'password': STRONG_PW, 'role': 'owner',
            }),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 400)

    def test_missing_required_fields_400(self):
        res = self.client.post(
            '/api/auth/users/create/',
            data=json.dumps({'role': 'viewer'}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 400)

    def test_xss_in_name_rejected(self):
        res = self.client.post(
            '/api/auth/users/create/',
            data=json.dumps({
                'username': 'xssuser', 'password': STRONG_PW,
                'name': '<script>alert(1)</script>', 'role': 'viewer',
            }),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn('Invalid characters', res.json()['error'])


# ═══════════════ auth_user_update ═══════════════

class AuthUserUpdateTests(TestCase):
    """Tests for PUT /api/auth/users/<uuid:user_id>/."""

    def setUp(self):
        cache.clear()
        _seed_permissions()
        self.owner = User.objects.create_superuser(
            username='owner', password=STRONG_PW, email='owner@example.com',
        )
        self.target = User.objects.create_user(
            username='target', password=STRONG_PW, email='target@example.com',
            role='viewer',
        )
        self.client = Client()
        self.client.force_login(self.owner)

    def test_successful_update(self):
        res = self.client.put(
            f'/api/auth/users/{self.target.id}/',
            data=json.dumps({'name': 'Updated Name'}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 200)
        self.target.refresh_from_db()
        self.assertEqual(self.target.first_name, 'Updated')
        self.assertEqual(self.target.last_name, 'Name')

    def test_owner_role_cannot_be_changed(self):
        res = self.client.put(
            f'/api/auth/users/{self.owner.id}/',
            data=json.dumps({'role': 'engineer'}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn('Owner', res.json()['error'])

    def test_duplicate_username_on_rename(self):
        res = self.client.put(
            f'/api/auth/users/{self.target.id}/',
            data=json.dumps({'username': 'owner'}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn('already exists', res.json()['error'])

    def test_password_validation_on_update(self):
        res = self.client.put(
            f'/api/auth/users/{self.target.id}/',
            data=json.dumps({'password': '123'}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 400)

    def test_nonexistent_user_404(self):
        import uuid
        fake_id = uuid.uuid4()
        res = self.client.put(
            f'/api/auth/users/{fake_id}/',
            data=json.dumps({'name': 'Ghost'}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 404)


# ═══════════════ auth_user_delete ═══════════════

class AuthUserDeleteTests(TestCase):
    """Tests for DELETE /api/auth/users/<uuid:user_id>/delete/."""

    def setUp(self):
        cache.clear()
        _seed_permissions()
        self.owner = User.objects.create_superuser(
            username='owner', password=STRONG_PW, email='owner@example.com',
        )
        self.target = User.objects.create_user(
            username='target', password=STRONG_PW, email='target@example.com',
            role='viewer',
        )
        self.client = Client()
        self.client.force_login(self.owner)

    def test_successful_deletion(self):
        target_id = self.target.id
        res = self.client.delete(f'/api/auth/users/{target_id}/delete/')
        self.assertEqual(res.status_code, 200)
        self.assertFalse(User.objects.filter(id=target_id).exists())

    def test_cannot_delete_self(self):
        res = self.client.delete(f'/api/auth/users/{self.owner.id}/delete/')
        self.assertEqual(res.status_code, 400)
        self.assertIn('Cannot delete yourself', res.json()['error'])

    def test_cannot_delete_owner(self):
        # Create a second owner scenario: we need another user with user:manage
        # but the owner is the only one. We test via a second client approach:
        # The endpoint checks user.role == 'owner' on the TARGET, not caller.
        # So we create an engineer with user:manage perm — but by default
        # engineers don't have user:manage. Instead, just verify that deleting
        # the owner (by the owner themselves) is blocked by the self-check first,
        # then test the owner-role guard with a different setup.
        # Actually, the owner is the only role with user:manage, so we test
        # by creating a second user and trying to delete the owner.
        # We're already logged in as owner. The self-check fires first for
        # owner deleting themselves. So let's create a scenario where a
        # non-self owner user exists... but only one owner is allowed.
        # Instead, manually grant user:manage to an engineer for this test.
        engineer = User.objects.create_user(
            username='engineer', password=STRONG_PW, role='engineer',
        )
        # Grant user:manage to engineer for this test
        perm = Permission.objects.get(code='user:manage')
        RolePermission.objects.get_or_create(role='engineer', permission=perm)
        cache.clear()  # clear cached perms
        self.client.force_login(engineer)
        res = self.client.delete(f'/api/auth/users/{self.owner.id}/delete/')
        self.assertEqual(res.status_code, 400)
        self.assertIn('Cannot delete the Owner', res.json()['error'])

    def test_nonexistent_user_404(self):
        import uuid
        fake_id = uuid.uuid4()
        res = self.client.delete(f'/api/auth/users/{fake_id}/delete/')
        self.assertEqual(res.status_code, 404)


# ═══════════════ check_username ═══════════════

class CheckUsernameTests(TestCase):
    """Tests for GET /api/auth/check-username/."""

    def setUp(self):
        cache.clear()
        _seed_permissions()
        # Ensure setup is not complete so unauthenticated access is allowed
        config = SiteConfig.get()
        config.setup_complete = False
        config.save()
        self.client = Client()

    def test_available_username(self):
        res = self.client.get('/api/auth/check-username/', {'username': 'brandnew'})
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertTrue(body['available'])
        self.assertEqual(body['reason'], 'Available')

    def test_taken_username(self):
        User.objects.create_user(username='taken', password=STRONG_PW)
        res = self.client.get('/api/auth/check-username/', {'username': 'taken'})
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertFalse(body['available'])
        self.assertEqual(body['reason'], 'Username taken')

    def test_too_short_username(self):
        res = self.client.get('/api/auth/check-username/', {'username': 'a'})
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertFalse(body['available'])
        self.assertEqual(body['reason'], 'Too short')

    def test_rate_limiting_429(self):
        """20 requests succeed, 21st returns 429."""
        for i in range(20):
            self.client.get('/api/auth/check-username/', {'username': f'user{i:03d}'})
        res = self.client.get('/api/auth/check-username/', {'username': 'onemore'})
        self.assertEqual(res.status_code, 429)


# ═══════════════ setup_admin ═══════════════

class SetupAdminTests(TestCase):
    """Tests for POST /api/auth/setup-admin/."""

    def setUp(self):
        cache.clear()
        _seed_permissions()
        # Ensure setup is not complete
        config = SiteConfig.get()
        config.setup_complete = False
        config.setup_completed_at = None
        config.setup_completed_by = ''
        config.save()
        self.client = Client()

    def test_successful_first_time_setup(self):
        res = self.client.post(
            '/api/auth/setup-admin/',
            data=json.dumps({
                'username': 'admin1', 'password': STRONG_PW,
                'name': 'Admin One', 'email': 'admin@example.com',
            }),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 201)
        body = res.json()
        self.assertEqual(body['username'], 'admin1')
        self.assertEqual(body['role'], 'owner')
        # Site config is now setup_complete=True
        config = SiteConfig.get()
        self.assertTrue(config.setup_complete)

    def test_setup_already_complete_rejected(self):
        config = SiteConfig.get()
        config.setup_complete = True
        config.save()
        res = self.client.post(
            '/api/auth/setup-admin/',
            data=json.dumps({
                'username': 'admin2', 'password': STRONG_PW,
                'name': 'Admin Two',
            }),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 403)
        self.assertIn('Setup already completed', res.json()['error'])

    def test_owner_already_exists_rejected(self):
        # Create an owner first (setup_complete stays False)
        owner = User.objects.create_superuser(
            username='firstowner', password=STRONG_PW, email='first@example.com',
        )
        # owner auto-promoted to role='owner' by save()
        res = self.client.post(
            '/api/auth/setup-admin/',
            data=json.dumps({
                'username': 'secondowner', 'password': STRONG_PW,
                'name': 'Second Owner',
            }),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 403)
        self.assertIn('owner account already exists', res.json()['error'])

    def test_weak_password_rejected(self):
        res = self.client.post(
            '/api/auth/setup-admin/',
            data=json.dumps({
                'username': 'weakadmin', 'password': '123',
                'name': 'Weak Admin',
            }),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 400)

    def test_whitelist_validation_rejection(self):
        res = self.client.post(
            '/api/auth/setup-admin/',
            data=json.dumps({
                'username': '<script>alert(1)</script>', 'password': STRONG_PW,
                'name': 'Normal Name',
            }),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn('Invalid characters', res.json()['error'])


# ═══════════════ site_config ═══════════════

class SiteConfigTests(TestCase):
    """Tests for GET /api/site-config/."""

    def setUp(self):
        cache.clear()
        _seed_permissions()
        self.owner = User.objects.create_superuser(
            username='owner', password=STRONG_PW, email='owner@example.com',
        )
        self.client = Client()

    def test_public_access_no_private_fields(self):
        """Unauthenticated users should not see setup_completed_by or setup_completed_at."""
        config = SiteConfig.get()
        config.setup_complete = True
        config.setup_completed_by = 'admin'
        config.save()
        res = self.client.get('/api/site-config/')
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertNotIn('setup_completed_by', body)
        self.assertNotIn('setup_completed_at', body)
        self.assertIn('schedule_timezone', body)

    def test_authenticated_returns_full_config(self):
        config = SiteConfig.get()
        config.setup_complete = True
        config.setup_completed_by = 'admin'
        config.save()
        self.client.force_login(self.owner)
        res = self.client.get('/api/site-config/')
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertIn('setup_completed_by', body)
        self.assertEqual(body['setup_completed_by'], 'admin')

    def test_setup_state_visible_pre_auth(self):
        config = SiteConfig.get()
        config.setup_complete = False
        config.save()
        res = self.client.get('/api/site-config/')
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertFalse(body['setup_complete'])


# ═══════════════ update_site_config ═══════════════

class UpdateSiteConfigTests(TestCase):
    """Tests for PUT /api/site-config/update/."""

    def setUp(self):
        cache.clear()
        _seed_permissions()
        self.owner = User.objects.create_superuser(
            username='owner', password=STRONG_PW, email='owner@example.com',
        )
        self.viewer = User.objects.create_user(
            username='viewer', password=STRONG_PW, email='viewer@example.com',
            role='viewer',
        )
        self.client = Client()
        self.client.force_login(self.owner)

    def test_valid_timezone_update(self):
        res = self.client.put(
            '/api/site-config/update/',
            data=json.dumps({'schedule_timezone': 'America/New_York'}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['schedule_timezone'], 'America/New_York')

    def test_invalid_timezone_rejected(self):
        res = self.client.put(
            '/api/site-config/update/',
            data=json.dumps({'schedule_timezone': 'Fake/Zone'}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 400)

    def test_parallelism_zero_invalid(self):
        res = self.client.put(
            '/api/site-config/update/',
            data=json.dumps({'default_parallelism': 0}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 400)

    def test_parallelism_501_invalid(self):
        res = self.client.put(
            '/api/site-config/update/',
            data=json.dumps({'default_parallelism': 501}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 400)

    def test_parallelism_100_valid(self):
        res = self.client.put(
            '/api/site-config/update/',
            data=json.dumps({'default_parallelism': 100}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['default_parallelism'], 100)

    def test_timeout_59_invalid(self):
        res = self.client.put(
            '/api/site-config/update/',
            data=json.dumps({'default_timeout': 59}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 400)

    def test_timeout_86401_invalid(self):
        res = self.client.put(
            '/api/site-config/update/',
            data=json.dumps({'default_timeout': 86401}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 400)

    def test_timeout_3600_valid(self):
        res = self.client.put(
            '/api/site-config/update/',
            data=json.dumps({'default_timeout': 3600}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['default_timeout'], 3600)

    def test_report_formats_valid_csv(self):
        res = self.client.put(
            '/api/site-config/update/',
            data=json.dumps({'default_report_formats': 'dashboard,html,docx'}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 200)

    def test_report_formats_invalid_format_name(self):
        res = self.client.put(
            '/api/site-config/update/',
            data=json.dumps({'default_report_formats': 'pdf,csv'}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 400)

    def test_permission_check_non_owner_rejected(self):
        self.client.force_login(self.viewer)
        res = self.client.put(
            '/api/site-config/update/',
            data=json.dumps({'schedule_timezone': 'Asia/Tokyo'}),
            content_type='application/json',
        )
        self.assertEqual(res.status_code, 403)
