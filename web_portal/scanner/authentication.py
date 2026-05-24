"""Custom authentication classes for Wire_Ghost."""

from django.utils import timezone
from rest_framework import authentication, exceptions
from rest_framework.authentication import SessionAuthentication


class CsrfExemptAuth(SessionAuthentication):
    """Truly CSRF-exempt session auth — opt-in per endpoint.

    Used only on login / csrf-bootstrap / setup-admin via
    `@authentication_classes([CsrfExemptAuth])`. These endpoints are the act
    of acquiring a session, so enforcing CSRF creates a chicken-and-egg
    problem (a user with a stale session re-hitting `/login` would be
    rejected). Every other endpoint uses the default `SessionAuthentication`
    from `DEFAULT_AUTHENTICATION_CLASSES`, which enforces CSRF normally.
    """

    def enforce_csrf(self, request):
        return


class TokenHeaderAuth(authentication.BaseAuthentication):
    """``Authorization: Token wg_<40>`` — per-user revocable API tokens.

    Hashes the submitted value with SHA-256 and looks up a non-revoked
    ``ApiToken`` row. Returns ``(user, token_row)`` — DRF passes the second
    tuple element to ``request.auth`` so views can attribute actions to the
    token. Doesn't enforce CSRF: header-based auth isn't CSRF-susceptible
    because a browser won't auto-attach an ``Authorization`` header from a
    cross-origin form submission.
    """

    keyword = "Token"

    def authenticate(self, request):
        auth = (request.META.get("HTTP_AUTHORIZATION") or "").split()
        if not auth or auth[0] != self.keyword:
            return None  # defer to the next auth class (session)
        if len(auth) != 2:
            raise exceptions.AuthenticationFailed("Invalid Token header.")
        from hashlib import sha256
        from scanner.models import ApiToken

        h = sha256(auth[1].encode("utf-8")).hexdigest()
        try:
            tok = ApiToken.objects.select_related("user").get(
                key_hash=h,
                revoked_at__isnull=True,
            )
        except ApiToken.DoesNotExist:
            raise exceptions.AuthenticationFailed("Invalid or revoked token.")
        if tok.expires_at and tok.expires_at <= timezone.now():
            raise exceptions.AuthenticationFailed("Token has expired.")
        ApiToken.objects.filter(pk=tok.pk).update(last_used_at=timezone.now())
        return (tok.user, tok)

    def authenticate_header(self, request):
        return "Token"


try:
    from drf_spectacular.extensions import OpenApiAuthenticationExtension

    class TokenHeaderAuthScheme(OpenApiAuthenticationExtension):
        target_class = "scanner.authentication.TokenHeaderAuth"
        name = "TokenAuth"

        def get_security_definition(self, auto_schema):
            return {
                "type": "apiKey",
                "in": "header",
                "name": "Authorization",
                "description": "Token wg_<40-char-value>",
            }
except ImportError:
    pass
