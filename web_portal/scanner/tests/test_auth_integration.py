"""Integration tests — auth flows through real HTTP requests.

Covers login, logout, session handling, CSRF, setup wizard,
and password change flows.
"""

import json

from django.contrib.auth import get_user_model
from django.test import Client, TestCase

from scanner.models import Permission, RolePermission, SiteConfig

User = get_user_model()


def _seed_permissions():
    codes = [
        'scan:read', 'scan:write', 'scan:delete',
        'finding:read', 'host:read',
        'report:read', 'report:write',
        'user:read', 'user:write',
        'policy:read', 'policy:write',
        'schedule:read', 'schedule:write',
        'settings:read', 'settings:write',
        'audit:read',
    ]
    perms = {}
    for code in codes:
        p, _ = Permission.objects.get_or_create(code=code, defaults={'name': code})
        perms[code] = p
    for code in codes:
        RolePermission.objects.get_or_create(role='owner', permission=perms[code])
    for code in codes:
        if code not in ('user:write', 'settings:write', 'audit:read'):
            RolePermission.objects.get_or_create(role='engineer', permission=perms[code])
    for code in ('scan:read', 'finding:read', 'host:read', 'report:read',
                 'policy:read', 'schedule:read', 'settings:read'):
        RolePermission.objects.get_or_create(role='viewer', permission=perms[code])
    User.invalidate_perm_cache()


class LoginFlowTests(TestCase):
    def setUp(self):
        _seed_permissions()
        self.owner = User.objects.create_superuser(
            username='admin', password='Str0ng!Pass99', email='a@test.com',
        )
        self.client = Client()

    def test_login_returns_200_with_user_data(self):
        resp = self.client.post('/api/auth/login/', {
            'username': 'admin',
            'password': 'Str0ng!Pass99',
        }, content_type='application/json')
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data['username'], 'admin')
        self.assertEqual(data['role'], 'owner')

    def test_login_sets_session(self):
        resp = self.client.post('/api/auth/login/', {
            'username': 'admin',
            'password': 'Str0ng!Pass99',
        }, content_type='application/json')
        self.assertEqual(resp.status_code, 200)
        me_resp = self.client.get('/api/auth/me/')
        self.assertEqual(me_resp.status_code, 200)

    def test_invalid_credentials_401(self):
        resp = self.client.post('/api/auth/login/', {
            'username': 'admin',
            'password': 'wrong',
        }, content_type='application/json')
        self.assertEqual(resp.status_code, 401)

    def test_missing_fields_400(self):
        resp = self.client.post('/api/auth/login/', {
            'username': 'admin',
        }, content_type='application/json')
        self.assertEqual(resp.status_code, 400)


class LogoutFlowTests(TestCase):
    def setUp(self):
        _seed_permissions()
        self.owner = User.objects.create_superuser(
            username='admin', password='Str0ng!Pass99', email='a@test.com',
        )
        self.client = Client()
        self.client.force_login(self.owner)

    def test_logout_clears_session(self):
        me_before = self.client.get('/api/auth/me/')
        self.assertEqual(me_before.status_code, 200)

        self.client.post('/api/auth/logout/')

        me_after = self.client.get('/api/auth/me/')
        self.assertIn(me_after.status_code, (401, 403))


class AuthCheckTests(TestCase):
    def setUp(self):
        _seed_permissions()
        self.owner = User.objects.create_superuser(
            username='admin', password='Str0ng!Pass99', email='a@test.com',
        )
        self.client = Client()

    def test_authenticated_check_returns_success(self):
        self.client.force_login(self.owner)
        resp = self.client.get('/api/auth/check/')
        self.assertIn(resp.status_code, (200, 204))

    def test_unauthenticated_check_returns_401(self):
        resp = self.client.get('/api/auth/check/')
        self.assertEqual(resp.status_code, 401)


class CsrfTests(TestCase):
    def test_csrf_endpoint_returns_token(self):
        resp = self.client.get('/api/auth/csrf/')
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn('csrf', data)
        self.assertTrue(len(data['csrf']) > 0)


class SetupWizardTests(TestCase):
    def test_setup_creates_admin(self):
        resp = self.client.post('/api/auth/setup/', json.dumps({
            'username': 'newadmin',
            'password': 'Str0ng!Pass99',
            'email': 'new@test.com',
        }), content_type='application/json')
        self.assertIn(resp.status_code, (200, 201))
        self.assertTrue(User.objects.filter(username='newadmin').exists())
        user = User.objects.get(username='newadmin')
        self.assertEqual(user.role, 'owner')

    def test_setup_blocked_after_owner_exists(self):
        User.objects.create_superuser(
            username='existing', password='Str0ng!Pass99', email='e@test.com',
        )
        resp = self.client.post('/api/auth/setup/', json.dumps({
            'username': 'second',
            'password': 'Str0ng!Pass99',
            'email': 's@test.com',
        }), content_type='application/json')
        self.assertIn(resp.status_code, (400, 403, 409))
        self.assertFalse(User.objects.filter(username='second').exists())


class UserManagementTests(TestCase):
    def setUp(self):
        _seed_permissions()
        self.owner = User.objects.create_superuser(
            username='admin', password='Str0ng!Pass99', email='a@test.com',
        )
        self.client = Client()
        self.client.force_login(self.owner)

    def test_create_engineer_user(self):
        resp = self.client.post('/api/auth/users/create/', json.dumps({
            'username': 'eng1',
            'password': 'Str0ng!Eng99',
            'email': 'eng@test.com',
            'role': 'engineer',
        }), content_type='application/json')
        self.assertEqual(resp.status_code, 201)
        user = User.objects.get(username='eng1')
        self.assertEqual(user.role, 'engineer')

    def test_create_viewer_user(self):
        resp = self.client.post('/api/auth/users/create/', json.dumps({
            'username': 'view1',
            'password': 'Str0ng!View99',
            'email': 'view@test.com',
            'role': 'viewer',
        }), content_type='application/json')
        self.assertEqual(resp.status_code, 201)
        user = User.objects.get(username='view1')
        self.assertEqual(user.role, 'viewer')

    def test_cannot_create_second_owner(self):
        resp = self.client.post('/api/auth/users/create/', json.dumps({
            'username': 'owner2',
            'password': 'Str0ng!Own99',
            'email': 'own2@test.com',
            'role': 'owner',
        }), content_type='application/json')
        self.assertEqual(resp.status_code, 400)

    def test_list_users(self):
        resp = self.client.get('/api/auth/users/')
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreaterEqual(len(data), 1)

    def test_delete_user(self):
        viewer = User.objects.create_user(
            username='deleteme', password='Str0ng!Del99', email='d@test.com',
        )
        resp = self.client.delete(f'/api/auth/users/{viewer.id}/delete/')
        self.assertIn(resp.status_code, (200, 204))
        self.assertFalse(User.objects.filter(username='deleteme').exists())

    def test_viewer_cannot_manage_users(self):
        viewer = User.objects.create_user(
            username='sneaky', password='Str0ng!Snk99', email='s@test.com',
        )
        viewer.role = 'viewer'
        viewer.save()
        client2 = Client()
        client2.force_login(viewer)

        resp = client2.post('/api/auth/users/create/', json.dumps({
            'username': 'illegal',
            'password': 'Str0ng!Ill99',
            'email': 'i@test.com',
            'role': 'engineer',
        }), content_type='application/json')
        self.assertEqual(resp.status_code, 403)
