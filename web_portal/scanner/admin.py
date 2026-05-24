from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import (
    User,
    Scan,
    Host,
    Port,
    Finding,
    Technology,
    Report,
    ReportConfig,
    ScanPolicy,
    ScheduledScan,
)

admin.site.register(User, UserAdmin)


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ["name", "target", "status", "findings_count", "created_at"]
    list_filter = ["status", "scan_type"]
    search_fields = ["name", "target"]


@admin.register(Host)
class HostAdmin(admin.ModelAdmin):
    list_display = ["ip", "hostname", "os", "ports_count", "findings_count"]
    search_fields = ["ip", "hostname"]


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ["severity", "title", "host_ip", "port", "source"]
    list_filter = ["severity", "source"]
    search_fields = ["title", "host_ip", "cve"]


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ["scan", "format", "file_size", "created_at"]


admin.site.register(Port)
admin.site.register(Technology)


@admin.register(ReportConfig)
class ReportConfigAdmin(admin.ModelAdmin):
    list_display = ["report_title", "company_name", "brand_color", "updated_at"]


@admin.register(ScanPolicy)
class ScanPolicyAdmin(admin.ModelAdmin):
    list_display = ["name", "scan_type", "is_default", "created_at"]
    list_filter = ["scan_type", "is_default"]


@admin.register(ScheduledScan)
class ScheduledScanAdmin(admin.ModelAdmin):
    list_display = ["name", "target", "frequency", "enabled", "next_run"]
    list_filter = ["frequency", "enabled"]


# ── AD Recon ──
from scanner.models.ad_recon import (
    CredentialProfile,
    ADReconSession,
    ADUser,
    ADGroup,
    ADComputer,
)


@admin.register(CredentialProfile)
class CredentialProfileAdmin(admin.ModelAdmin):
    list_display = ["name", "domain", "username", "owner", "created_at"]
    search_fields = ["name", "domain", "username", "owner__username"]


@admin.register(ADReconSession)
class ADReconSessionAdmin(admin.ModelAdmin):
    list_display = ["id", "domain", "scope", "status", "dc_ip", "created_at"]
    list_filter = ["scope", "status"]
    search_fields = ["domain", "dc_ip"]
    readonly_fields = ["tool_status", "error"]


@admin.register(ADUser)
class ADUserAdmin(admin.ModelAdmin):
    list_display = ["sam_account_name", "display_name", "enabled", "admin_count"]
    list_filter = ["enabled", "admin_count"]
    search_fields = ["sam_account_name", "display_name"]


@admin.register(ADGroup)
class ADGroupAdmin(admin.ModelAdmin):
    list_display = ["name", "sam_account_name", "member_count", "admin_count"]
    search_fields = ["name", "sam_account_name"]


@admin.register(ADComputer)
class ADComputerAdmin(admin.ModelAdmin):
    list_display = ["name", "dns_hostname", "os", "enabled"]
    list_filter = ["enabled", "os"]
    search_fields = ["name", "dns_hostname"]
