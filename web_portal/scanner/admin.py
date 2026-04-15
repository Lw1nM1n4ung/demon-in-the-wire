from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, Scan, Host, Port, Finding, Technology, Report, ReportConfig, ScanPolicy, ScheduledScan

admin.site.register(User, UserAdmin)


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


@admin.register(ReportConfig)
class ReportConfigAdmin(admin.ModelAdmin):
    list_display = ['report_title', 'company_name', 'brand_color', 'updated_at']


@admin.register(ScanPolicy)
class ScanPolicyAdmin(admin.ModelAdmin):
    list_display = ['name', 'scan_type', 'is_default', 'created_at']
    list_filter = ['scan_type', 'is_default']


@admin.register(ScheduledScan)
class ScheduledScanAdmin(admin.ModelAdmin):
    list_display = ['name', 'target', 'frequency', 'enabled', 'next_run']
    list_filter = ['frequency', 'enabled']
