"""Custom authentication classes for Wire_Ghost."""
from django.utils import timezone
from rest_framework import authentication, exceptions
from rest_framework.authentication import SessionAuthentication


class CsrfExemptAuth(SessionAuthentication):
    """Session auth with Django's default CSRF enforcement.

    Previously stubbed out `enforce_csrf` and relied on the SameSite=Lax
    cookie flag alone — but Lax still allows top-level form-POST navigations
    and leaves browser-side behavior as the sole defense, so a state-changing
    POST with just a stolen session cookie succeeded from any origin.
    The SPA already sets `X-CSRFToken` on all mutating requests, so restoring
    full CSRF enforcement doesn't break any legitimate flow. Header-based
    token auth (`TokenHeaderAuth`) is CSRF-immune separately because browsers
    don't auto-attach `Authorization` cross-origin.

    Class name kept for settings.py compatibility; the "exempt" in the name
    is now historical, not behavioral.
    """
    pass


class TokenHeaderAuth(authentication.BaseAuthentication):
    """``Authorization: Token wg_<40>`` — per-user revocable API tokens.

    Hashes the submitted value with SHA-256 and looks up a non-revoked
    ``ApiToken`` row. Returns ``(user, token_row)`` — DRF passes the second
    tuple element to ``request.auth`` so views can attribute actions to the
    token. Doesn't enforce CSRF: header-based auth isn't CSRF-susceptible
    because a browser won't auto-attach an ``Authorization`` header from a
    cross-origin form submission.
    """
    keyword = 'Token'

    def authenticate(self, request):
        auth = (request.META.get('HTTP_AUTHORIZATION') or '').split()
        if not auth or auth[0] != self.keyword:
            return None  # defer to the next auth class (session)
        if len(auth) != 2:
            raise exceptions.AuthenticationFailed('Invalid Token header.')
        from hashlib import sha256
        from scanner.models import ApiToken
        h = sha256(auth[1].encode('utf-8')).hexdigest()
        try:
            tok = ApiToken.objects.select_related('user').get(
                key_hash=h, revoked_at__isnull=True,
            )
        except ApiToken.DoesNotExist:
            raise exceptions.AuthenticationFailed('Invalid or revoked token.')
        # Fire-and-forget last_used bump so auth stays fast on hot paths.
        ApiToken.objects.filter(pk=tok.pk).update(last_used_at=timezone.now())
        return (tok.user, tok)

    def authenticate_header(self, request):
        return 'Token'
