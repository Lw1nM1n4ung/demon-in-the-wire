from rest_framework import serializers
from .models import Scan, Host, Port, Finding, Technology, Report, ReportConfig, ScanPolicy, ScheduledScan, Asset, Screenshot


class AssetListSerializer(serializers.ModelSerializer):
    """Lean serializer for the Asset inventory table on the dashboard."""
    class Meta:
        model = Asset
        fields = [
            'id', 'ip', 'port', 'protocol', 'hostname', 'os',
            'service_name', 'service_product', 'service_version',
            'first_seen', 'last_seen', 'status', 'risk_score',
            'findings_count', 'critical_count', 'high_count',
        ]


class AssetSerializer(AssetListSerializer):
    """Detail serializer — same fields today, reserved for future expansion."""
    class Meta(AssetListSerializer.Meta):
        pass


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


class ScreenshotSerializer(serializers.ModelSerializer):
    image_url = serializers.SerializerMethodField()

    class Meta:
        model = Screenshot
        fields = ['id', 'url', 'image_url', 'title', 'status_code', 'created_at']

    def get_image_url(self, obj):
        return f'/api/screenshots/{obj.id}/image/'


class HostSerializer(serializers.ModelSerializer):
    ports = PortSerializer(many=True, read_only=True)
    technologies = TechnologySerializer(many=True, read_only=True)
    screenshots = ScreenshotSerializer(many=True, read_only=True)

    class Meta:
        model = Host
        fields = ['id', 'ip', 'hostname', 'os', 'status', 'ports_count', 'findings_count', 'ports', 'technologies', 'screenshots']


class HostListSerializer(serializers.ModelSerializer):
    screenshot_count = serializers.IntegerField(source='screenshots.count', read_only=True)
    thumbnail_url = serializers.SerializerMethodField()

    class Meta:
        model = Host
        fields = ['id', 'ip', 'hostname', 'os', 'ports_count', 'findings_count', 'scan', 'screenshot_count', 'thumbnail_url']

    def get_thumbnail_url(self, obj):
        first = obj.screenshots.first()
        return f'/api/screenshots/{first.id}/image/' if first else None


class ReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = Report
        fields = ['id', 'format', 'file_size', 'created_at']  # file_path excluded (path disclosure)


class ScanSerializer(serializers.ModelSerializer):
    reports = ReportSerializer(many=True, read_only=True)

    class Meta:
        model = Scan
        exclude = ['celery_task_id', 'output_dir']  # hide internal fields


class ScanListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scan
        fields = ['id', 'name', 'target', 'scan_type', 'status', 'hosts_count', 'findings_count',
                  'critical_count', 'high_count', 'medium_count', 'low_count', 'info_count',
                  'duration_seconds', 'created_at']


class ScanCreateSerializer(serializers.Serializer):
    target = serializers.CharField(max_length=500)
    name = serializers.CharField(max_length=255, required=False, default='')
    scan_type = serializers.ChoiceField(choices=['full', 'quick', 'port', 'web', 'service'], default='full')
    parallelism = serializers.IntegerField(default=10, min_value=1, max_value=100)
    timeout = serializers.IntegerField(default=3600, min_value=60, max_value=86400)
    report_formats = serializers.CharField(default='dashboard,html,docx,xlsx')
    version_detect = serializers.BooleanField(default=True)
    os_detect = serializers.BooleanField(default=True)
    service_enum = serializers.BooleanField(default=True)
    skip_nuclei = serializers.BooleanField(default=False)
    skip_screenshots = serializers.BooleanField(default=False)
    skip_openvas = serializers.BooleanField(default=True)
    nuclei_templates = serializers.CharField(max_length=500, required=False, default='', allow_blank=True)
    nuclei_default_templates = serializers.BooleanField(required=False, default=True)
    # When True, hosts that don't answer ICMP are still port-scanned. Useful
    # against firewalled targets; massively expands scope on big CIDRs.
    scan_unresponsive = serializers.BooleanField(required=False, default=False)

    def validate_target(self, value):
        """Block SSRF targets: localhost, link-local, cloud metadata, non-routable."""
        import re
        import ipaddress

        value = value.strip()
        if not value:
            raise serializers.ValidationError('Target is required')

        # Must match IP, CIDR, or hostname pattern (reject encoded/special chars)
        if not re.match(r'^[\d./a-zA-Z0-9_:-]+$', value):
            raise serializers.ValidationError('Invalid target format')

        # Block alternative IP notations that bypass ipaddress checks
        if re.match(r'^0[xX][0-9a-fA-F]+$', value):
            raise serializers.ValidationError('Hex IP notation not allowed')
        if re.match(r'^\d+$', value):
            # Pure decimal — block ALL (even single digit like "0")
            raise serializers.ValidationError('Decimal IP notation not allowed — use dotted format')
        # Block octal: any octet with leading zero (127.0.0.01)
        ip_part = value.split('/')[0]
        if '.' in ip_part:
            for octet in ip_part.split('.'):
                if len(octet) > 1 and octet.startswith('0') and octet.isdigit():
                    raise serializers.ValidationError('Octal IP notation not allowed')
        # Block short-form IPs (127.1 = 127.0.0.1)
        if re.match(r'^\d+\.\d+$', ip_part) or re.match(r'^\d+\.\d+\.\d+$', ip_part):
            raise serializers.ValidationError('Short-form IP not allowed — use full dotted notation')

        # Extract IP from CIDR if present
        ip_str = value.split('/')[0]

        def _check_ip(ip):
            """Validate a single IP address against SSRF blocklist."""
            if ip.is_loopback:
                raise serializers.ValidationError('Loopback addresses not allowed')
            if ip.is_link_local:
                raise serializers.ValidationError('Link-local addresses not allowed')
            if ip.is_multicast:
                raise serializers.ValidationError('Multicast addresses not allowed')
            if ip.is_unspecified:
                raise serializers.ValidationError('Unspecified address not allowed')
            if ip.is_reserved:
                raise serializers.ValidationError('Reserved addresses not allowed')
            if ip.is_private and str(ip).startswith('169.254'):
                raise serializers.ValidationError('Cloud metadata endpoint not allowed')
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                _check_ip(ip.ipv4_mapped)

        try:
            ip = ipaddress.ip_address(ip_str)
            _check_ip(ip)
        except ValueError:
            try:
                net = ipaddress.ip_network(value, strict=False)
                _check_ip(net.network_address)
            except ValueError:
                # Hostname — validate format and blocklist
                if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$', value):
                    raise serializers.ValidationError('Invalid hostname format')
                blocked = [
                    'localhost', 'metadata.google.internal', 'metadata.google', 'instance-data',
                    'localtest.me', 'vcap.me', 'nip.io', 'xip.io', 'sslip.io',
                    'lvh.me', 'lacolhost.com', '127.0.0.1.nip.io',
                ]
                lower = value.lower()
                if lower in blocked:
                    raise serializers.ValidationError('Blocked target')
                # Block any hostname ending with known localhost-resolving domains
                for suffix in ['.nip.io', '.xip.io', '.sslip.io', '.localtest.me', '.vcap.me', '.lvh.me']:
                    if lower.endswith(suffix):
                        raise serializers.ValidationError('DNS rebinding domain not allowed')
                # Resolve hostname and check if it points to blocked IP
                import socket
                try:
                    resolved = socket.gethostbyname(value)
                    resolved_ip = ipaddress.ip_address(resolved)
                    if resolved_ip.is_loopback or resolved_ip.is_link_local or resolved_ip.is_private:
                        raise serializers.ValidationError(f'Hostname resolves to blocked IP: {resolved}')
                except socket.gaierror:
                    pass  # unresolvable hostname — let nmap handle it

        return value


class ReportConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportConfig
        exclude = ['id']


class ScanPolicySerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanPolicy
        fields = '__all__'
        read_only_fields = ['created_by', 'created_at', 'updated_at']


class ScheduledScanSerializer(serializers.ModelSerializer):
    policy_name = serializers.CharField(source='policy.name', read_only=True, default='')

    class Meta:
        model = ScheduledScan
        fields = '__all__'
        read_only_fields = ['created_by', 'created_at', 'updated_at', 'last_run']
