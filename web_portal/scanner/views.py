from django.http import FileResponse, Http404
from rest_framework import viewsets, status
from rest_framework.decorators import action, api_view
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .models import Scan, Host, Finding, Report, ReportConfig, ScanPolicy, ScheduledScan


class IsStaffOrReadOnly(IsAuthenticated):
    """Allow read for any authenticated user, write only for staff/admin."""
    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        if request.method in ('GET', 'HEAD', 'OPTIONS'):
            return True
        return request.user.is_staff or request.user.is_superuser
from .serializers import (
    ScanSerializer, ScanListSerializer, ScanCreateSerializer,
    HostSerializer, HostListSerializer,
    FindingSerializer, FindingListSerializer,
    ReportSerializer, ReportConfigSerializer,
    ScanPolicySerializer, ScheduledScanSerializer,
)


class ScanViewSet(viewsets.ModelViewSet):
    queryset = Scan.objects.all()
    permission_classes = [IsStaffOrReadOnly]
    http_method_names = ['get', 'post', 'delete', 'head', 'options']

    def get_queryset(self):
        qs = super().get_queryset()
        if not self.request.user.is_staff:
            qs = qs.filter(created_by=self.request.user)
        return qs

    def get_serializer_class(self):
        if self.action == 'list':
            return ScanListSerializer
        if self.action == 'create':
            return ScanCreateSerializer
        return ScanSerializer

    def create(self, request):
        serializer = ScanCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        import re
        raw_name = data.get('name') or f"Scan {data['target']}"
        raw_target = data['target']
        # Whitelist: scan name allows alphanumeric + common chars only
        if not re.match(r"^[a-zA-Z0-9 _./:()'\-]+$", raw_name):
            return Response({'error': 'Invalid characters in scan name'}, status=400)
        safe_name = raw_name[:255]
        safe_target = raw_target[:500]

        scan = Scan.objects.create(
            name=safe_name,
            target=safe_target,
            scan_type=data['scan_type'],
            parallelism=data['parallelism'],
            timeout=data['timeout'],
            report_formats=data['report_formats'],
            version_detect=data['version_detect'],
            os_detect=data['os_detect'],
            service_enum=data['service_enum'],
            skip_nuclei=data['skip_nuclei'],
            skip_openvas=data['skip_openvas'],
            status='pending',
        )

        # Launch Celery task
        from scanner.tasks import run_scan
        task = run_scan.delay(str(scan.id))
        scan.celery_task_id = task.id
        scan.status = 'running'
        scan.save(update_fields=['celery_task_id', 'status'])

        return Response(ScanSerializer(scan).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        scan = self.get_object()
        if scan.status == 'running':
            # Revoke Celery task
            if scan.celery_task_id:
                from wireghost_web.celery import app as celery_app
                celery_app.control.revoke(scan.celery_task_id, terminate=True)
            scan.status = 'cancelled'
            scan.save()
        return Response(ScanSerializer(scan).data)

    @action(detail=True, methods=['post'])
    def regenerate_reports(self, request, pk=None):
        """Re-generate reports with current ReportConfig branding."""
        scan = self.get_object()
        if scan.status != 'completed':
            return Response({'error': 'Scan must be completed'}, status=400)

        formats = request.data.get('formats')
        if isinstance(formats, str):
            formats = formats.split(',')

        from scanner.tasks import generate_report
        task = generate_report.delay(str(scan.id), formats=formats)
        return Response({'task_id': task.id, 'status': 'queued'})

    @action(detail=True, methods=['get'])
    def findings(self, request, pk=None):
        scan = self.get_object()
        findings = scan.findings.all()

        severity = request.query_params.get('severity')
        source = request.query_params.get('source')
        search = request.query_params.get('search')

        if severity:
            findings = findings.filter(severity=severity)
        if source:
            findings = findings.filter(source=source)
        if search:
            findings = findings.filter(title__icontains=search)

        serializer = FindingListSerializer(findings, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def hosts(self, request, pk=None):
        scan = self.get_object()
        serializer = HostListSerializer(scan.hosts.all(), many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def topology(self, request, pk=None):
        """Return topology data for D3 force-directed graph visualization."""
        import ipaddress
        scan = self.get_object()

        hosts = scan.hosts.prefetch_related('ports', 'technologies').all()
        findings = scan.findings.all()

        # Aggregate worst severity per host
        severity_rank = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        host_severity = {}
        host_finding_counts = {}
        for f in findings:
            hid = f.host_id
            if hid is None:
                continue
            sev = f.severity
            cur = host_severity.get(hid, 'info')
            if severity_rank.get(sev, 5) < severity_rank.get(cur, 5):
                host_severity[hid] = sev
            counts = host_finding_counts.setdefault(hid, {'total': 0, 'critical': 0, 'high': 0, 'medium': 0})
            counts['total'] += 1
            if sev in counts:
                counts[sev] += 1

        # Service classification by port priority
        SERVICE_PORTS = {
            'web': {80, 443, 8080, 8443, 3000, 8000, 8888, 9443},
            'database': {3306, 5432, 1433, 27017, 6379, 5984, 9200, 9300},
            'mail': {25, 110, 143, 465, 587, 993, 995},
            'file': {21, 445, 139, 873, 2049},
            'dns': {53},
            'ssh': {22},
        }
        SERVICE_PRIORITY = ['web', 'database', 'mail', 'file', 'dns', 'ssh']

        def classify_service(ports):
            port_nums = {p.number for p in ports}
            for svc in SERVICE_PRIORITY:
                if port_nums & SERVICE_PORTS[svc]:
                    return svc
            return 'other'

        # Build nodes and compute subnets
        subnet_counts = {}
        nodes = []
        for h in hosts:
            try:
                net = ipaddress.ip_network(h.ip + '/24', strict=False)
                subnet = str(net)
            except ValueError:
                subnet = 'unknown'

            subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
            fc = host_finding_counts.get(h.id, {})

            nodes.append({
                'id': h.id,
                'ip': h.ip,
                'hostname': h.hostname or '',
                'os': h.os or '',
                'subnet': subnet,
                'ports': [
                    {'number': p.number, 'protocol': p.protocol,
                     'service_name': p.service_name, 'service_product': p.service_product}
                    for p in h.ports.all()
                ],
                'technologies': [
                    f"{t.name}{(' ' + t.version) if t.version else ''}"
                    for t in h.technologies.all()
                ],
                'primary_service': classify_service(h.ports.all()),
                'worst_severity': host_severity.get(h.id, 'clean'),
                'findings_count': fc.get('total', 0),
                'critical_count': fc.get('critical', 0),
                'high_count': fc.get('high', 0),
                'medium_count': fc.get('medium', 0),
                'ports_count': h.ports_count,
            })

        subnets = [{'cidr': cidr, 'host_count': cnt} for cidr, cnt in sorted(subnet_counts.items())]

        return Response({
            'scan_id': scan.id,
            'scan_name': scan.name,
            'target': scan.target,
            'subnets': subnets,
            'nodes': nodes,
        })


class HostViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Host.objects.all()

    def get_serializer_class(self):
        if self.action == 'list':
            return HostListSerializer
        return HostSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        # Staff/admin see all, others see only their scans' hosts
        if not self.request.user.is_staff:
            qs = qs.filter(scan__created_by=self.request.user)
        return qs


class FindingViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Finding.objects.all()

    def get_serializer_class(self):
        if self.action == 'list':
            return FindingListSerializer
        return FindingSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        # Staff/admin see all, others see only their scans' findings
        if not self.request.user.is_staff:
            qs = qs.filter(scan__created_by=self.request.user)
        severity = self.request.query_params.get('severity')
        source = self.request.query_params.get('source')
        search = self.request.query_params.get('search')
        scan_id = self.request.query_params.get('scan')

        if severity:
            qs = qs.filter(severity=severity)
        if source:
            qs = qs.filter(source=source)
        if search:
            qs = qs.filter(title__icontains=search)
        if scan_id:
            qs = qs.filter(scan_id=scan_id)
        return qs


@api_view(['GET'])
def dashboard_stats(request):
    """Dashboard summary statistics."""
    from django.db.models import Count

    total_scans = Scan.objects.count()
    running_scans = Scan.objects.filter(status='running').count()
    total_hosts = Host.objects.values('ip').distinct().count()

    severity_counts = Finding.objects.values('severity').annotate(count=Count('id'))
    sev_dict = {item['severity']: item['count'] for item in severity_counts}

    source_counts = Finding.objects.values('source').annotate(count=Count('id'))
    src_dict = {item['source']: item['count'] for item in source_counts}

    recent_scans = ScanListSerializer(
        Scan.objects.all()[:10], many=True
    ).data

    return Response({
        'total_scans': total_scans,
        'running_scans': running_scans,
        'total_hosts': total_hosts,
        'total_findings': Finding.objects.count(),
        'severity': {
            'critical': sev_dict.get('critical', 0),
            'high': sev_dict.get('high', 0),
            'medium': sev_dict.get('medium', 0),
            'low': sev_dict.get('low', 0),
            'info': sev_dict.get('info', 0),
        },
        'sources': src_dict,
        'recent_scans': recent_scans,
    })


@api_view(['GET'])
def download_report(request, report_id):
    """Download a report file. Requires staff or scan ownership."""
    try:
        report = Report.objects.get(id=report_id)
    except Report.DoesNotExist:
        raise Http404

    # Authorization: admin/staff can download any, others only their own scans
    if not request.user.is_staff and report.scan.created_by != request.user:
        return Response({'error': 'Not authorized'}, status=403)

    from pathlib import Path
    path = Path(report.file_path)

    # Verify path stays within allowed directory
    allowed_dir = '/data/output'
    if not str(path.resolve()).startswith(allowed_dir):
        raise Http404

    if not path.exists():
        raise Http404

    content_types = {
        'dashboard': 'text/html',
        'html': 'text/html',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    }

    return FileResponse(
        open(path, 'rb'),
        content_type=content_types.get(report.format, 'application/octet-stream'),
        as_attachment=True,
        filename=path.name,
    )


@api_view(['GET', 'PUT'])
def report_config(request):
    """Get or update the singleton report configuration."""
    config = ReportConfig.get()
    if request.method == 'GET':
        return Response(ReportConfigSerializer(config).data)

    # PUT requires staff/admin
    if not request.user.is_staff:
        return Response({'error': 'Staff access required'}, status=403)

    # Whitelist validation per field type
    import re
    BLOCKED_FIELDS = {'logo_path'}
    FIELD_PATTERNS = {
        'report_title': (re.compile(r"^[a-zA-Z0-9 &.,:'\-()]+$"), 255),
        'company_name': (re.compile(r"^[a-zA-Z0-9 &.,'\-()]+$"), 255),
        'prepared_by':  (re.compile(r"^[a-zA-Z0-9 .,'\-]+$"), 255),
        'reviewed_by':  (re.compile(r"^[a-zA-Z0-9 .,'\-]+$"), 255),
        'approved_by':  (re.compile(r"^[a-zA-Z0-9 .,'\-]+$"), 255),
        'brand_color':  (re.compile(r'^#[0-9a-fA-F]{6}$'), 7),
        'disclaimer':   (re.compile(r"^[a-zA-Z0-9 &.,;:'\-()@#/\n\r]+$"), 1000),
        'default_formats': (re.compile(r'^[a-z,]+$'), 100),
    }
    clean_data = {}
    for key, val in request.data.items():
        if key in BLOCKED_FIELDS:
            continue
        if isinstance(val, str) and key in FIELD_PATTERNS:
            pattern, max_len = FIELD_PATTERNS[key]
            val = val[:max_len]
            if val and not pattern.match(val):
                return Response({'error': f'Invalid characters in {key}'}, status=400)
        clean_data[key] = val

    serializer = ReportConfigSerializer(config, data=clean_data, partial=True)
    serializer.is_valid(raise_exception=True)
    serializer.save()
    return Response(serializer.data)


@api_view(['POST'])
def upload_logo(request):
    """Upload a custom logo for reports. Requires staff."""
    if not request.user.is_staff:
        return Response({'error': 'Staff access required'}, status=403)
    if 'logo' not in request.FILES:
        return Response({'error': 'No file uploaded'}, status=400)

    import os
    from django.utils.text import get_valid_filename

    logo_file = request.FILES['logo']

    # Restrict to safe image types only (no SVG, PHP, etc.)
    ALLOWED_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'}
    DANGEROUS_EXTENSIONS = {'.php', '.py', '.sh', '.js', '.html', '.htm', '.svg', '.exe', '.bat', '.cmd', '.jsp', '.asp', '.aspx', '.cgi', '.pl'}
    ext = os.path.splitext(logo_file.name)[1].lower()
    # Check ALL extensions in the filename (block shell.php.png)
    all_exts = {('.' + p.lower()) for p in logo_file.name.split('.')[1:]} if '.' in logo_file.name else set()
    if all_exts & DANGEROUS_EXTENSIONS:
        return Response({'error': 'Dangerous file extension detected'}, status=400)
    if ext not in ALLOWED_EXTENSIONS:
        return Response({'error': f'File type {ext} not allowed. Use: {", ".join(ALLOWED_EXTENSIONS)}'}, status=400)

    # Limit file size (2MB)
    if logo_file.size > 2 * 1024 * 1024:
        return Response({'error': 'File too large (max 2MB)'}, status=400)

    logo_dir = '/data/assets/logos'
    os.makedirs(logo_dir, exist_ok=True)

    # Sanitize filename to prevent path traversal
    safe_name = get_valid_filename(os.path.basename(logo_file.name))
    if not safe_name:
        return Response({'error': 'Invalid filename'}, status=400)
    logo_path = os.path.join(logo_dir, safe_name)

    # Verify the resolved path stays within logo_dir
    if not os.path.realpath(logo_path).startswith(os.path.realpath(logo_dir)):
        return Response({'error': 'Invalid file path'}, status=400)

    with open(logo_path, 'wb+') as f:
        for chunk in logo_file.chunks():
            f.write(chunk)

    config = ReportConfig.get()
    config.logo_path = logo_path
    config.save()

    return Response({'logo_path': logo_path, 'filename': safe_name})


class ScanPolicyViewSet(viewsets.ModelViewSet):
    queryset = ScanPolicy.objects.all()
    serializer_class = ScanPolicySerializer
    permission_classes = [IsStaffOrReadOnly]

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    @action(detail=True, methods=['post'])
    def clone(self, request, pk=None):
        policy = self.get_object()
        clone = ScanPolicy.objects.create(
            name=f"{policy.name} (Copy)",
            description=policy.description,
            scan_type=policy.scan_type,
            parallelism=policy.parallelism,
            timeout=policy.timeout,
            port_range=policy.port_range,
            tools=policy.tools,
            version_detect=policy.version_detect,
            os_detect=policy.os_detect,
            severity_filter=policy.severity_filter,
            report_formats=policy.report_formats,
            is_default=False,
            created_by=request.user,
        )
        return Response(ScanPolicySerializer(clone).data, status=status.HTTP_201_CREATED)


class ScheduledScanViewSet(viewsets.ModelViewSet):
    queryset = ScheduledScan.objects.all()
    serializer_class = ScheduledScanSerializer
    permission_classes = [IsStaffOrReadOnly]

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    @action(detail=True, methods=['post'])
    def toggle(self, request, pk=None):
        schedule = self.get_object()
        schedule.enabled = not schedule.enabled
        schedule.save(update_fields=['enabled'])
        return Response(ScheduledScanSerializer(schedule).data)

    @action(detail=True, methods=['post'])
    def run_now(self, request, pk=None):
        """Trigger an immediate scan from this schedule."""
        schedule = self.get_object()
        scan = Scan.objects.create(
            name=f"{schedule.name} (manual)",
            target=schedule.target,
            scan_type=schedule.scan_type,
            status='pending',
            created_by=request.user,
        )
        # Apply policy settings if linked
        if schedule.policy:
            p = schedule.policy
            scan.parallelism = p.parallelism
            scan.timeout = p.timeout
            scan.report_formats = p.report_formats
            scan.version_detect = p.version_detect
            scan.os_detect = p.os_detect
            scan.save()

        from scanner.tasks import run_scan
        task = run_scan.delay(str(scan.id))
        scan.celery_task_id = task.id
        scan.status = 'running'
        scan.save(update_fields=['celery_task_id', 'status'])

        from django.utils import timezone
        schedule.last_run = timezone.now()
        schedule.save(update_fields=['last_run'])

        return Response(ScanSerializer(scan).data, status=status.HTTP_201_CREATED)
