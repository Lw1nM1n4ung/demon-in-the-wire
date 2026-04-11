from django.db import models
from django.contrib.auth.models import User


class Scan(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    SCAN_TYPE_CHOICES = [
        ('full', 'Full Scan'),
        ('quick', 'Quick Scan'),
        ('port', 'Port Scan Only'),
        ('web', 'Web Application Scan'),
        ('service', 'Service Enumeration'),
    ]

    name = models.CharField(max_length=255)
    target = models.CharField(max_length=500)
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPE_CHOICES, default='full')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    parallelism = models.IntegerField(default=10)
    timeout = models.IntegerField(default=3600)
    report_formats = models.CharField(max_length=100, default='dashboard,html,docx,xlsx')

    # Options
    version_detect = models.BooleanField(default=True)
    os_detect = models.BooleanField(default=True)
    service_enum = models.BooleanField(default=True)
    skip_nuclei = models.BooleanField(default=False)
    skip_openvas = models.BooleanField(default=True)

    # Results
    hosts_count = models.IntegerField(default=0)
    ports_count = models.IntegerField(default=0)
    findings_count = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    info_count = models.IntegerField(default=0)

    # Timing
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration_seconds = models.IntegerField(default=0)

    # Output
    output_dir = models.CharField(max_length=500, blank=True)
    celery_task_id = models.CharField(max_length=255, blank=True)
    error_message = models.TextField(blank=True)

    # Meta
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} ({self.target})"


class Host(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='hosts')
    ip = models.GenericIPAddressField()
    hostname = models.CharField(max_length=255, blank=True)
    os = models.CharField(max_length=255, blank=True)
    status = models.CharField(max_length=20, default='up')
    ports_count = models.IntegerField(default=0)
    findings_count = models.IntegerField(default=0)

    class Meta:
        ordering = ['ip']

    def __str__(self):
        return self.ip


class Port(models.Model):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name='ports')
    number = models.IntegerField()
    protocol = models.CharField(max_length=10, default='tcp')
    state = models.CharField(max_length=20, default='open')
    service_name = models.CharField(max_length=100, blank=True)
    service_product = models.CharField(max_length=200, blank=True)
    service_version = models.CharField(max_length=200, blank=True)

    class Meta:
        ordering = ['number']


class Finding(models.Model):
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='findings')
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name='findings', null=True)
    source = models.CharField(max_length=50)  # nuclei, nmap_vuln, searchsploit, etc.
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    title = models.CharField(max_length=500)
    description = models.TextField(blank=True)
    host_ip = models.GenericIPAddressField(null=True)
    port = models.CharField(max_length=10, blank=True)
    protocol = models.CharField(max_length=10, default='tcp')
    endpoint = models.CharField(max_length=500, blank=True)
    full_url = models.CharField(max_length=1000, blank=True)
    template_id = models.CharField(max_length=200, blank=True)
    cve = models.CharField(max_length=500, blank=True)
    cwe = models.CharField(max_length=200, blank=True)
    cvss = models.CharField(max_length=200, blank=True)
    request = models.TextField(blank=True)
    response = models.TextField(blank=True)
    curl_command = models.TextField(blank=True)
    raw_output = models.TextField(blank=True)
    references = models.TextField(blank=True)  # JSON array

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-severity', '-created_at']

    def __str__(self):
        return f"[{self.severity}] {self.title}"


class Technology(models.Model):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name='technologies')
    name = models.CharField(max_length=200)
    version = models.CharField(max_length=200, blank=True)
    url = models.CharField(max_length=500, blank=True)


class Report(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='reports')
    format = models.CharField(max_length=20)  # dashboard, html, docx, xlsx
    file_path = models.CharField(max_length=500)
    file_size = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
