"""Custom authentication classes for Wire_Ghost."""
from rest_framework.authentication import SessionAuthentication


class CsrfExemptAuth(SessionAuthentication):
    """Session auth without CSRF enforcement.
    SameSite=Lax cookie flag provides cross-origin protection instead."""
    def enforce_csrf(self, request):
        return
