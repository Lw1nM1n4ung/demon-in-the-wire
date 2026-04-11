from django.contrib import admin
from .models import Scan, Host, Port, Finding, Technology, Report


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ['name', 'target', 'status', 'findings_count', 'created_at']
    list_filter = ['status', 'scan_type']
    search_fields = ['name', 'target']


@admin.register(Host)
class HostAdmin(admin.ModelAdmin):
    list_display = ['ip', 'hostname', 'os', 'ports_count', 'findings_count']
    search_fields = ['ip', 'hostname']


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ['severity', 'title', 'host_ip', 'port', 'source']
    list_filter = ['severity', 'source']
    search_fields = ['title', 'host_ip', 'cve']


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ['scan', 'format', 'file_size', 'created_at']


admin.site.register(Port)
admin.site.register(Technology)
