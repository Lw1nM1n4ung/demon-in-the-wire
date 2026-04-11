from django.http import FileResponse, Http404
from rest_framework import viewsets, status
from rest_framework.decorators import action, api_view
from rest_framework.response import Response
from .models import Scan, Host, Finding, Report
from .serializers import (
    ScanSerializer, ScanListSerializer, ScanCreateSerializer,
    HostSerializer, HostListSerializer,
    FindingSerializer, FindingListSerializer,
    ReportSerializer,
)


class ScanViewSet(viewsets.ModelViewSet):
    queryset = Scan.objects.all()

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

        # Create scan record
        scan = Scan.objects.create(
            name=data.get('name') or f"Scan {data['target']}",
            target=data['target'],
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

        # TODO: Launch Celery task
        # task = run_scan_task.delay(scan.id)
        # scan.celery_task_id = task.id
        # scan.status = 'running'
        # scan.save()

        return Response(ScanSerializer(scan).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        scan = self.get_object()
        if scan.status == 'running':
            scan.status = 'cancelled'
            scan.save()
            # TODO: Revoke Celery task
        return Response(ScanSerializer(scan).data)

    @action(detail=True, methods=['get'])
    def findings(self, request, pk=None):
        scan = self.get_object()
        findings = scan.findings.all()

        # Filters
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


class HostViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Host.objects.all()

    def get_serializer_class(self):
        if self.action == 'list':
            return HostListSerializer
        return HostSerializer


class FindingViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Finding.objects.all()

    def get_serializer_class(self):
        if self.action == 'list':
            return FindingListSerializer
        return FindingSerializer

    def get_queryset(self):
        qs = super().get_queryset()
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
    from django.db.models import Count, Q

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
    """Download a report file."""
    try:
        report = Report.objects.get(id=report_id)
    except Report.DoesNotExist:
        raise Http404

    from pathlib import Path
    path = Path(report.file_path)
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
