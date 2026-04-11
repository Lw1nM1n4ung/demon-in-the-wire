from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from scanner.views import ScanViewSet, HostViewSet, FindingViewSet, dashboard_stats, download_report

router = DefaultRouter()
router.register(r'scans', ScanViewSet)
router.register(r'hosts', HostViewSet)
router.register(r'findings', FindingViewSet)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
    path('api/dashboard/', dashboard_stats, name='dashboard-stats'),
    path('api/reports/<int:report_id>/download/', download_report, name='download-report'),
]
