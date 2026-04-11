from rest_framework import serializers
from .models import Scan, Host, Port, Finding, Technology, Report


class PortSerializer(serializers.ModelSerializer):
    class Meta:
        model = Port
        fields = ['id', 'number', 'protocol', 'state', 'service_name', 'service_product', 'service_version']


class TechnologySerializer(serializers.ModelSerializer):
    class Meta:
        model = Technology
        fields = ['id', 'name', 'version', 'url']


class FindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Finding
        fields = '__all__'


class FindingListSerializer(serializers.ModelSerializer):
    """Lighter serializer for list views."""
    class Meta:
        model = Finding
        fields = ['id', 'source', 'severity', 'title', 'host_ip', 'port', 'cve', 'full_url']


class HostSerializer(serializers.ModelSerializer):
    ports = PortSerializer(many=True, read_only=True)
    technologies = TechnologySerializer(many=True, read_only=True)

    class Meta:
        model = Host
        fields = ['id', 'ip', 'hostname', 'os', 'status', 'ports_count', 'findings_count', 'ports', 'technologies']


class HostListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Host
        fields = ['id', 'ip', 'hostname', 'os', 'ports_count', 'findings_count']


class ReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = Report
        fields = ['id', 'format', 'file_path', 'file_size', 'created_at']


class ScanSerializer(serializers.ModelSerializer):
    reports = ReportSerializer(many=True, read_only=True)

    class Meta:
        model = Scan
        fields = '__all__'


class ScanListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scan
        fields = ['id', 'name', 'target', 'scan_type', 'status', 'hosts_count', 'findings_count',
                  'critical_count', 'high_count', 'medium_count', 'duration_seconds', 'created_at']


class ScanCreateSerializer(serializers.Serializer):
    target = serializers.CharField(max_length=500)
    name = serializers.CharField(max_length=255, required=False, default='')
    scan_type = serializers.ChoiceField(choices=['full', 'quick', 'port', 'web', 'service'], default='full')
    parallelism = serializers.IntegerField(default=10, min_value=1, max_value=100)
    timeout = serializers.IntegerField(default=3600)
    report_formats = serializers.CharField(default='dashboard,html,docx,xlsx')
    version_detect = serializers.BooleanField(default=True)
    os_detect = serializers.BooleanField(default=True)
    service_enum = serializers.BooleanField(default=True)
    skip_nuclei = serializers.BooleanField(default=False)
    skip_openvas = serializers.BooleanField(default=True)
