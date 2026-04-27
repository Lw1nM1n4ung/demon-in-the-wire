"""Tests for custom authentication classes — TokenHeaderAuth and CsrfExemptAuth."""
from hashlib import sha256
from django.contrib.auth import get_user_model
from django.test import Client, TestCase, RequestFactory
from django.utils import timezone

from scanner.authentication import CsrfExemptAuth, TokenHeaderAuth
from scanner.models import ApiToken

User = get_user_model()


class TokenHeaderAuthTests(TestCase):
    """TokenHeaderAuth: Authorization header parsing and token lookup."""

    def setUp(self):
        self.factory = RequestFactory()
        self.auth = TokenHeaderAuth()
        self.user = User.objects.create_user(
            username='tokenuser', password='pw-test-123!', email='t@test.com'
        )
        self.raw_key = 'wg_testapitoken1234567890abcdef1234567890'
        self.key_hash = sha256(self.raw_key.encode()).hexdigest()
        self.token = ApiToken.objects.create(
            user=self.user,
            name='test-token',
            key_hash=self.key_hash,
        )

    def _request(self, header=None):
        req = self.factory.get('/api/scans/')
        if header:
            req.META['HTTP_AUTHORIZATION'] = header
        return req

    def test_valid_token_returns_user(self):
        result = self.auth.authenticate(self._request(f'Token {self.raw_key}'))
        self.assertIsNotNone(result)
        self.assertEqual(result[0], self.user)
        self.assertEqual(result[1], self.token)

    def test_valid_token_updates_last_used(self):
        before = self.token.last_used_at
        self.auth.authenticate(self._request(f'Token {self.raw_key}'))
        self.token.refresh_from_db()
        self.assertIsNotNone(self.token.last_used_at)
        if before:
            self.assertGreaterEqual(self.token.last_used_at, before)

    def test_no_header_returns_none(self):
        result = self.auth.authenticate(self._request())
        self.assertIsNone(result)

    def test_wrong_scheme_returns_none(self):
        result = self.auth.authenticate(self._request(f'Bearer {self.raw_key}'))
        self.assertIsNone(result)

    def test_malformed_header_raises(self):
        from rest_framework.exceptions import AuthenticationFailed
        with self.assertRaises(AuthenticationFailed):
            self.auth.authenticate(self._request('Token'))

    def test_invalid_token_raises(self):
        from rest_framework.exceptions import AuthenticationFailed
        with self.assertRaises(AuthenticationFailed):
            self.auth.authenticate(self._request('Token wg_invalidtoken000000000000000000000000'))

    def test_revoked_token_raises(self):
        from rest_framework.exceptions import AuthenticationFailed
        self.token.revoked_at = timezone.now()
        self.token.save()
        with self.assertRaises(AuthenticationFailed):
            self.auth.authenticate(self._request(f'Token {self.raw_key}'))

    def test_authenticate_header_returns_token(self):
        req = self._request()
        self.assertEqual(self.auth.authenticate_header(req), 'Token')


class CsrfExemptAuthTests(TestCase):
    """CsrfExemptAuth: should not enforce CSRF."""

    def test_enforce_csrf_is_noop(self):
        auth = CsrfExemptAuth()
        factory = RequestFactory()
        req = factory.post('/api/auth/login/')
        result = auth.enforce_csrf(req)
        self.assertIsNone(result)


class TokenAuthIntegrationTests(TestCase):
    """End-to-end token auth via Django test client."""

    def setUp(self):
        self.user = User.objects.create_user(
            username='apiuser', password='pw-api-123!', email='api@test.com',
            role='owner',
        )
        self.raw_key = 'wg_integrationtest1234567890abcdef123456'
        self.key_hash = sha256(self.raw_key.encode()).hexdigest()
        ApiToken.objects.create(
            user=self.user,
            name='integration-token',
            key_hash=self.key_hash,
        )
        self.client = Client()

    def test_token_auth_on_api_endpoint(self):
        res = self.client.get('/api/dashboard/', HTTP_AUTHORIZATION=f'Token {self.raw_key}')
        self.assertIn(res.status_code, (200, 301))

    def test_no_auth_returns_401_or_403(self):
        res = self.client.get('/api/scans/')
        self.assertIn(res.status_code, (401, 403))
