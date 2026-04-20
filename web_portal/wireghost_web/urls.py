from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from scanner.views import (
    ScanViewSet, HostViewSet, FindingViewSet, AssetViewSet,
    ScanPolicyViewSet, ScheduledScanViewSet,
    dashboard_stats, download_report, report_config, upload_logo,
    support_bundle,
)
from scanner.auth_views import (
    auth_login, auth_logout, auth_csrf, auth_me, auth_check, auth_users,
    auth_user_create, auth_user_update, auth_user_delete,
    site_config, update_site_config, check_username, setup_admin, setup_one_shot, site_setup_complete, reset_setup, user_preferences,
    list_sessions, revoke_session, revoke_all_sessions,
    audit_log,
    tokens_list_or_create, tokens_revoke,
    notifications_config, notifications_test, tools_health, system_stats,
)

router = DefaultRouter()
router.register(r'scans', ScanViewSet)
router.register(r'hosts', HostViewSet)
router.register(r'findings', FindingViewSet)
router.register(r'assets', AssetViewSet)
router.register(r'policies', ScanPolicyViewSet)
router.register(r'schedules', ScheduledScanViewSet)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
    path('api/dashboard/', dashboard_stats, name='dashboard-stats'),
    path('api/reports/<uuid:report_id>/download/', download_report, name='download-report'),
    path('api/report-config/', report_config, name='report-config'),
    path('api/report-config/logo/', upload_logo, name='upload-logo'),
    # Auth
    path('api/auth/login/', auth_login, name='auth-login'),
    path('api/auth/logout/', auth_logout, name='auth-logout'),
    path('api/auth/csrf/', auth_csrf, name='auth-csrf'),
    path('api/auth/me/', auth_me, name='auth-me'),
    # Lightweight session-validity probe for nginx auth_request (204/401, no body).
    path('api/auth/check/', auth_check, name='auth-check'),
    path('api/auth/users/', auth_users, name='auth-users'),
    path('api/auth/users/create/', auth_user_create, name='auth-user-create'),
    path('api/auth/users/<uuid:user_id>/', auth_user_update, name='auth-user-update'),
    path('api/auth/users/<uuid:user_id>/delete/', auth_user_delete, name='auth-user-delete'),
    # Site config & user preferences
    path('api/site-config/', site_config, name='site-config'),
    path('api/site-config/update/', update_site_config, name='site-config-update'),
    path('api/auth/check-username/', check_username, name='check-username'),
    path('api/auth/setup-admin/', setup_admin, name='setup-admin'),
    # All-in-one wizard submission — multipart POST that lands Owner creation,
    # branding save, logo upload, setup_complete flip, and auto-login in a
    # single atomic request.
    path('api/auth/setup/', setup_one_shot, name='setup-one-shot'),
    path('api/site-config/setup-complete/', site_setup_complete, name='site-setup-complete'),
    path('api/site-config/reset-setup/', reset_setup, name='site-reset-setup'),
    path('api/preferences/', user_preferences, name='user-preferences'),
    # Sessions
    path('api/sessions/', list_sessions, name='list-sessions'),
    path('api/sessions/revoke/', revoke_session, name='revoke-session'),
    path('api/sessions/revoke-all/', revoke_all_sessions, name='revoke-all-sessions'),
    # Audit Log
    path('api/audit-log/', audit_log, name='audit-log'),
    # Support diagnostic bundle (Owner only)
    path('api/support-bundle/', support_bundle, name='support-bundle'),
    # Personal API tokens (Authorization: Token <wg_...>)
    path('api/auth/tokens/', tokens_list_or_create, name='auth-tokens'),
    path('api/auth/tokens/<uuid:token_id>/revoke/', tokens_revoke, name='auth-token-revoke'),
    # Telegram notifications (site-wide config + test-send)
    path('api/notifications/config/', notifications_config, name='notifications-config'),
    path('api/notifications/test/', notifications_test, name='notifications-test'),
    # Live tool presence/version probe (drives Settings → Tools tab)
    path('api/tools-health/', tools_health, name='tools-health'),
    # Real-time container resource usage (drives /system page)
    path('api/system-stats/', system_stats, name='system-stats'),
]
