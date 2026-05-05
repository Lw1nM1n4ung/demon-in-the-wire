"""Tests for scanner.middleware — IdleTimeoutMiddleware."""

from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase

from scanner.middleware import IDLE_TIMEOUT, IdleTimeoutMiddleware

User = get_user_model()


class TestIdleTimeoutMiddleware(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.get_response = MagicMock(return_value=MagicMock(status_code=200))
        self.middleware = IdleTimeoutMiddleware(self.get_response)
        self.user = User.objects.create_user(
            username="testuser", password="pw-test-123!", email="t@example.com"
        )

    def _request_with_session(self, last_activity=None, authenticated=True):
        request = self.factory.get("/api/scans/")
        request.session = {"_last_activity": last_activity} if last_activity else {}
        if authenticated:
            request.user = self.user
        else:
            request.user = MagicMock(is_authenticated=False)
        return request

    @patch("scanner.middleware.timezone")
    def test_active_session_passes(self, mock_tz):
        now = 1_700_000_000.0
        mock_tz.now.return_value.timestamp.return_value = now
        request = self._request_with_session(last_activity=now - 60)
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)
        self.get_response.assert_called_once_with(request)

    @patch("scanner.middleware.timezone")
    @patch("scanner.middleware.logout")
    def test_expired_session_returns_401(self, mock_logout, mock_tz):
        now = 1_700_000_000.0
        mock_tz.now.return_value.timestamp.return_value = now
        request = self._request_with_session(last_activity=now - IDLE_TIMEOUT - 1)
        response = self.middleware(request)
        self.assertEqual(response.status_code, 401)
        mock_logout.assert_called_once_with(request)

    @patch("scanner.middleware.timezone")
    def test_unauthenticated_passes_through(self, mock_tz):
        request = self._request_with_session(authenticated=False)
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)
        self.get_response.assert_called_once()

    @patch("scanner.middleware.timezone")
    def test_no_last_activity_sets_timestamp(self, mock_tz):
        now = 1_700_000_000.0
        mock_tz.now.return_value.timestamp.return_value = now
        request = self._request_with_session(last_activity=None)
        self.middleware(request)
        self.assertEqual(request.session["_last_activity"], now)

    @patch("scanner.middleware.timezone")
    def test_active_session_updates_timestamp(self, mock_tz):
        now = 1_700_000_000.0
        mock_tz.now.return_value.timestamp.return_value = now
        request = self._request_with_session(last_activity=now - 100)
        self.middleware(request)
        self.assertEqual(request.session["_last_activity"], now)

    @patch("scanner.middleware.timezone")
    @patch("scanner.middleware.logout")
    def test_exactly_at_timeout_passes(self, mock_logout, mock_tz):
        now = 1_700_000_000.0
        mock_tz.now.return_value.timestamp.return_value = now
        request = self._request_with_session(last_activity=now - IDLE_TIMEOUT)
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)
        mock_logout.assert_not_called()

    def test_timeout_constant_is_two_hours(self):
        self.assertEqual(IDLE_TIMEOUT, 7200)
