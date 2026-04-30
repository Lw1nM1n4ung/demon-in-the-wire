from django.contrib.auth import logout
from django.http import JsonResponse
from django.utils import timezone

IDLE_TIMEOUT = 7200  # 2 hours


class IdleTimeoutMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            now = timezone.now().timestamp()
            last = request.session.get('_last_activity')
            if last and (now - last) > IDLE_TIMEOUT:
                logout(request)
                return JsonResponse(
                    {'error': 'Session expired due to inactivity'}, status=401,
                )
            request.session['_last_activity'] = now
        return self.get_response(request)
