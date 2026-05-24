from django.db.models import Count
from django.http import FileResponse, Http404
from rest_framework import viewsets, status
from rest_framework.decorators import action, api_view
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from ..models import (
    Scan,
    Host,
    Finding,
    Report,
    ReportConfig,
    ScanPolicy,
    ScheduledScan,
    Asset,
    Technology,
    Screenshot as DBScreenshot,
    ExploitMatch,
)
from ..policy_tools import normalize_policy_tools


def HasPerm(code):
    """DRF permission factory — grants access iff request.user.has_permission(code).

    Reads from the data-driven Permission/RolePermission tables, cached per role.
    """

    class _HasPerm(IsAuthenticated):
        def has_permission(self, request, view):
            if not super().has_permission(request, view):
                return False
            return request.user.has_permission(code)

    _HasPerm.__name__ = f"HasPerm_{code}"
    return _HasPerm


def HasMethodPerm(read_code, write_code):
    """DRF permission factory that picks the permission code by HTTP method.

    Safe methods (GET/HEAD/OPTIONS) use read_code; everything else uses write_code.
    """

    class _HMP(IsAuthenticated):
        def has_permission(self, request, view):
            if not super().has_permission(request, view):
                return False
            code = read_code if request.method in ("GET", "HEAD", "OPTIONS") else write_code
            return request.user.has_permission(code)

    _HMP.__name__ = f"HasMethodPerm_{read_code}_{write_code}"
    return _HMP


class IsCreatorOrOwnerForWrite(IsAuthenticated):
    """Object-level guard for destructive/replacing actions only.

    Guards `destroy` / `update` / `partial_update` — the actions that erase
    or overwrite the target row. Engineers can still invoke team-cooperative
    custom actions (`/cancel/`, `/regenerate_reports/`, `/clone/`, `/toggle/`,
    `/run_now/`) on any peer's resource; those have their own business logic
    and don't destroy the audit trail. Owners bypass the check entirely.

    Stacked after `HasMethodPerm` so role/unauth rejection happens first.
    """

    _DESTRUCTIVE = frozenset(("destroy", "update", "partial_update"))

    def has_object_permission(self, request, view, obj):
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return True
        if getattr(view, "action", None) not in self._DESTRUCTIVE:
            return True
        if getattr(request.user, "role", "") == "owner":
            return True
        return getattr(obj, "created_by_id", None) == request.user.id


from ..serializers import (
    ScanSerializer,
    ScanListSerializer,
    ScanCreateSerializer,
    HostSerializer,
    HostListSerializer,
    FindingSerializer,
    FindingDetailSerializer,
    FindingListSerializer,
    ReportSerializer,  # noqa: F401 — re-exported for API router
    ReportConfigSerializer,
    ScanPolicySerializer,
    ScheduledScanSerializer,
    AssetSerializer,
    AssetListSerializer,
    ScreenshotSerializer,  # noqa: F401 — re-exported for API router
    ExploitMatchSerializer,
)


class ScanViewSet(viewsets.ModelViewSet):
    queryset = Scan.objects.all()
    permission_classes = [HasMethodPerm("scan:read", "scan:write"), IsCreatorOrOwnerForWrite]
    http_method_names = ["get", "post", "delete", "head", "options"]

    def get_queryset(self):
        return super().get_queryset()

    def get_serializer_class(self):
        if self.action == "list":
            return ScanListSerializer
        if self.action == "create":
            return ScanCreateSerializer
        return ScanSerializer

    MAX_CONCURRENT_SCANS = 5

    def create(self, request):
        serializer = ScanCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        running = Scan.objects.filter(
            created_by=request.user,
            status__in=("pending", "running"),
        ).count()
        if running >= self.MAX_CONCURRENT_SCANS:
            return Response(
                {"error": f"Maximum {self.MAX_CONCURRENT_SCANS} concurrent scans allowed."},
                status=429,
            )

        import re

        raw_name = data.get("name") or f"Scan {data['target']}"
        raw_target = data["target"]
        # Whitelist: scan name allows alphanumeric + common chars only
        if not re.match(r"^[a-zA-Z0-9 _./:()'\-]+$", raw_name):
            return Response({"error": "Invalid characters in scan name"}, status=400)
        safe_name = raw_name[:255]
        safe_target = raw_target[:500]

        # Fall back to SiteConfig defaults when the client didn't explicitly
        # send a value — lets Owners raise org-wide parallelism/timeout/
        # report_formats from Settings → General without touching code.
        from scanner.models import SiteConfig

        cfg = SiteConfig.get()
        parallelism = (
            data["parallelism"] if "parallelism" in request.data else cfg.default_parallelism
        )
        timeout = data["timeout"] if "timeout" in request.data else cfg.default_timeout
        report_formats = (
            data["report_formats"]
            if "report_formats" in request.data
            else cfg.default_report_formats
        )

        scan = Scan.objects.create(
            name=safe_name,
            target=safe_target,
            scan_type=data["scan_type"],
            parallelism=parallelism,
            timeout=timeout,
            report_formats=report_formats,
            version_detect=data["version_detect"],
            os_detect=data["os_detect"],
            service_enum=data["service_enum"],
            skip_nuclei=data["skip_nuclei"],
            skip_screenshots=data.get("skip_screenshots", False),
            scan_unresponsive=data.get("scan_unresponsive", False),
            enum4linux=data.get("enum4linux", True),
            skip_nikto=data.get("skip_nikto", False),
            skip_netexec=data.get("skip_netexec", False),
            status="pending",
            created_by=request.user,
        )

        # Launch Celery task
        from scanner.tasks import run_scan

        task = run_scan.delay(str(scan.id))
        scan.celery_task_id = task.id
        scan.status = "running"
        scan.save(update_fields=["celery_task_id", "status"])

        return Response(ScanSerializer(scan).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"])
    def cancel(self, request, pk=None):
        scan = self.get_object()
        if scan.status == "running":
            # Revoke Celery task
            if scan.celery_task_id:
                from wireghost_web.celery import app as celery_app

                celery_app.control.revoke(scan.celery_task_id, terminate=True)
            scan.status = "cancelled"
            scan.save()
        return Response(ScanSerializer(scan).data)

    @action(detail=True, methods=["post"])
    def regenerate_reports(self, request, pk=None):
        """Re-generate reports with current ReportConfig branding."""
        scan = self.get_object()
        if scan.status != "completed":
            return Response({"error": "Scan must be completed"}, status=400)

        formats = request.data.get("formats")
        if isinstance(formats, str):
            formats = formats.split(",")

        from scanner.tasks import generate_report

        task = generate_report.delay(str(scan.id), formats=formats)
        return Response({"task_id": task.id, "status": "queued"})

    @action(detail=True, methods=["get"])
    def findings(self, request, pk=None):
        scan = self.get_object()
        findings = scan.findings.all()

        severity = request.query_params.get("severity")
        source = request.query_params.get("source")
        search = request.query_params.get("search")

        if severity:
            findings = findings.filter(severity=severity)
        if source:
            findings = findings.filter(source=source)
        if search:
            findings = findings.filter(title__icontains=search)

        serializer = FindingListSerializer(findings, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=["get"])
    def hosts(self, request, pk=None):
        scan = self.get_object()
        qs = scan.hosts.annotate(screenshot_count=Count("screenshots")).prefetch_related(
            "screenshots"
        )
        serializer = HostListSerializer(qs, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=["get"])
    def topology(self, request, pk=None):
        """Return enriched topology data for D3 visualization."""
        import ipaddress
        from django.core.cache import cache
        from django.db.models import Q

        scan = self.get_object()

        cache_key = f"topo:{scan.id}:{scan.updated_at.timestamp()}"
        if scan.status != "running":
            cached = cache.get(cache_key)
            if cached:
                return Response(cached)

        MAX_TOPO_NODES = 500
        hosts_qs = scan.hosts.prefetch_related("ports", "technologies").all()
        total_hosts = hosts_qs.count()
        truncated = total_hosts > MAX_TOPO_NODES
        hosts = hosts_qs[:MAX_TOPO_NODES]
        findings = scan.findings.all()

        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        host_severity = {}
        host_finding_counts = {}
        for f in findings:
            hid = f.host_id
            if hid is None:
                continue
            sev = f.severity
            cur = host_severity.get(hid, "info")
            if severity_rank.get(sev, 5) < severity_rank.get(cur, 5):
                host_severity[hid] = sev
            counts = host_finding_counts.setdefault(
                hid, {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
            )
            counts["total"] += 1
            if sev in counts:
                counts[sev] += 1

        # CVEs per host
        cve_map = {}
        cve_qs = scan.findings.filter(~Q(cve=""), host_id__isnull=False).values_list(
            "host_id", "cve"
        )
        for hid, cve_str in cve_qs:
            for cve in cve_str.split(","):
                cve = cve.strip()
                if cve:
                    cve_map.setdefault(hid, set()).add(cve)
        cve_map = {k: sorted(v) for k, v in cve_map.items()}

        SERVICE_PORTS = {
            "web": {80, 443, 8080, 8443, 3000, 8000, 8888, 9443},
            "database": {3306, 5432, 1433, 27017, 6379, 5984, 9200, 9300},
            "mail": {25, 110, 143, 465, 587, 993, 995},
            "file": {21, 445, 139, 873, 2049},
            "dns": {53},
            "ssh": {22},
        }
        SERVICE_PRIORITY = ["web", "database", "mail", "file", "dns", "ssh"]

        def classify_service(ports):
            port_nums = {p.number for p in ports}
            for svc in SERVICE_PRIORITY:
                if port_nums & SERVICE_PORTS[svc]:
                    return svc
            return "other"

        subnet_counts = {}
        nodes = []
        for h in hosts:
            try:
                net = ipaddress.ip_network(h.ip + "/24", strict=False)
                subnet = str(net)
            except ValueError:
                subnet = "unknown"

            subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1
            fc = host_finding_counts.get(h.id, {})

            nodes.append(
                {
                    "id": h.id,
                    "ip": h.ip,
                    "hostname": h.hostname or "",
                    "os": h.os or "",
                    "subnet": subnet,
                    "ports": [
                        {
                            "number": p.number,
                            "protocol": p.protocol,
                            "state": p.state,
                            "service_name": p.service_name,
                            "service_product": p.service_product,
                            "service_version": p.service_version,
                            "service_source": p.service_source,
                        }
                        for p in h.ports.all()
                    ],
                    "technologies": [
                        f"{t.name}{(' ' + t.version) if t.version else ''}"
                        for t in h.technologies.all()
                    ],
                    "primary_service": classify_service(h.ports.all()),
                    "worst_severity": host_severity.get(h.id, "clean"),
                    "findings_count": fc.get("total", 0),
                    "critical_count": fc.get("critical", 0),
                    "high_count": fc.get("high", 0),
                    "medium_count": fc.get("medium", 0),
                    "low_count": fc.get("low", 0),
                    "risk_score": min(
                        100,
                        fc.get("critical", 0) * 10
                        + fc.get("high", 0) * 5
                        + fc.get("medium", 0) * 2
                        + fc.get("low", 0),
                    ),
                    "cves": cve_map.get(h.id, []),
                    "ports_count": h.ports_count,
                }
            )

        subnets = [{"cidr": cidr, "host_count": cnt} for cidr, cnt in sorted(subnet_counts.items())]

        # Inter-host edges (CVE-based + service-based, capped at 3 per host)
        cve_to_hosts = {}
        for hid, cves in cve_map.items():
            for cve in cves:
                cve_to_hosts.setdefault(cve, []).append(str(hid))

        raw_edges = {}
        for cve, hids in cve_to_hosts.items():
            for i in range(len(hids)):
                for j in range(i + 1, len(hids)):
                    key = tuple(sorted([hids[i], hids[j]]))
                    if key not in raw_edges:
                        raw_edges[key] = {"type": "cve", "label": cve}

        svc_to_hosts = {}
        for n in nodes:
            svc = n["primary_service"]
            if svc not in ("other", "network"):
                svc_to_hosts.setdefault(svc, []).append(str(n["id"]))

        for svc, hids in svc_to_hosts.items():
            if len(hids) < 2:
                continue
            for i in range(len(hids)):
                for j in range(i + 1, min(len(hids), i + 4)):
                    key = tuple(sorted([hids[i], hids[j]]))
                    if key not in raw_edges:
                        raw_edges[key] = {"type": "service", "label": svc}

        node_risk = {str(n["id"]): n.get("risk_score", 0) for n in nodes}
        edge_count = {}
        edges = []
        for (src, tgt), meta in sorted(
            raw_edges.items(),
            key=lambda x: -(node_risk.get(x[0][0], 0) + node_risk.get(x[0][1], 0)),
        ):
            if edge_count.get(src, 0) >= 3 or edge_count.get(tgt, 0) >= 3:
                continue
            edge_count[src] = edge_count.get(src, 0) + 1
            edge_count[tgt] = edge_count.get(tgt, 0) + 1
            edges.append(
                {
                    "source": src,
                    "target": tgt,
                    "type": meta["type"],
                    "label": meta["label"],
                }
            )

        result = {
            "scan_id": scan.id,
            "scan_name": scan.name,
            "scan_status": scan.status,
            "target": scan.target,
            "subnets": subnets,
            "nodes": nodes,
            "edges": edges,
            "truncated": truncated,
            "total_hosts": total_hosts,
        }

        if scan.status != "running":
            cache.set(cache_key, result, 300)

        return Response(result)


class HostViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Host.objects.all()
    permission_classes = [HasPerm("host:read")]

    def get_serializer_class(self):
        if self.action == "list":
            return HostListSerializer
        return HostSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        if self.action == "list":
            qs = qs.annotate(screenshot_count=Count("screenshots")).prefetch_related("screenshots")
        return qs


@api_view(["GET"])
def screenshot_image(request, screenshot_id):
    """Serve a screenshot PNG with auth + host:read check."""
    if not request.user.is_authenticated or not request.user.has_permission("host:read"):
        return Response({"error": "Not authorized"}, status=403)
    try:
        ss = DBScreenshot.objects.get(id=screenshot_id)
    except (DBScreenshot.DoesNotExist, ValueError):
        raise Http404

    from pathlib import Path

    scan_dir = ss.scan.output_dir
    if not scan_dir:
        raise Http404
    output_root = Path(scan_dir)
    img_path = (output_root / ss.filename).resolve()

    if not img_path.exists():
        # Backward compat: older scans have a nested target subdirectory
        # (output_dir was passed including the target, build_output_tree
        # appended it again).  Try output_root / target / filename.
        target = ss.scan.target.replace("/", "_")
        nested_root = (output_root / target).resolve()
        alt_path = (nested_root / ss.filename).resolve()
        if alt_path.is_relative_to(nested_root) and alt_path.exists():
            img_path = alt_path
            output_root = nested_root

    if not img_path.is_relative_to(output_root.resolve()):
        raise Http404
    if not img_path.exists():
        raise Http404

    return FileResponse(
        img_path.open("rb"),
        content_type="image/png",
        headers={"Cache-Control": "private, max-age=86400"},
    )


@api_view(["GET"])
def dashboard_screenshots(request):
    """Return the 20 most recent screenshots for the dashboard Web Surface panel."""
    if not request.user.is_authenticated or not request.user.has_permission("dashboard:view"):
        return Response({"error": "Not authorized"}, status=403)
    latest_scan = Scan.objects.filter(status="completed").order_by("-completed_at").first()
    if not latest_scan:
        return Response([])
    screenshots = DBScreenshot.objects.filter(scan=latest_scan).select_related("host")[:20]
    data = [
        {
            "id": str(ss.id),
            "url": ss.url,
            "title": ss.title,
            "status_code": ss.status_code,
            "image_url": f"/api/screenshots/{ss.id}/image/",
            "host_ip": ss.host.ip,
            "host_id": str(ss.host.id),
        }
        for ss in screenshots
    ]
    return Response(data)


class AssetViewSet(viewsets.ReadOnlyModelViewSet):
    """Deduped (ip, port, protocol) inventory. Feeds the ASM dashboard table."""

    queryset = Asset.objects.all()
    permission_classes = [HasPerm("host:read")]

    def get_serializer_class(self):
        if self.action == "list":
            return AssetListSerializer
        return AssetSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        params = self.request.query_params

        search = (params.get("search") or "").strip()
        if search:
            from django.db.models import Q

            qs = qs.filter(
                Q(ip__icontains=search)
                | Q(hostname__icontains=search)
                | Q(service_name__icontains=search)
                | Q(service_product__icontains=search)
            )

        status_filter = params.get("status")
        if status_filter:
            qs = qs.filter(status=status_filter)

        min_risk = params.get("min_risk")
        if min_risk:
            try:
                qs = qs.filter(risk_score__gte=int(min_risk))
            except (TypeError, ValueError):
                pass

        if (params.get("has_cve") or "").lower() in ("1", "true", "yes"):
            qs = qs.filter(findings_count__gt=0)

        first_after = params.get("first_seen_after")
        if first_after:
            qs = qs.filter(first_seen__gte=first_after)

        service = params.get("service")
        if service:
            qs = qs.filter(service_name__iexact=service)

        return qs


class FindingViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Finding.objects.all()
    permission_classes = [HasPerm("finding:read")]

    def get_serializer_class(self):
        if self.action == "list":
            return FindingListSerializer
        if self.action == "retrieve":
            return FindingDetailSerializer
        return FindingSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        severity = self.request.query_params.get("severity")
        source = self.request.query_params.get("source")
        search = self.request.query_params.get("search")
        scan_id = self.request.query_params.get("scan")

        if severity:
            qs = qs.filter(severity=severity)
        if source:
            qs = qs.filter(source=source)
        if search:
            qs = qs.filter(title__icontains=search)
        if scan_id:
            qs = qs.filter(scan_id=scan_id)
        return qs


@api_view(["GET"])
def dashboard_stats(request):
    """Attack Surface Management roll-up for the main dashboard."""
    if not request.user.is_authenticated or not request.user.has_permission("dashboard:view"):
        return Response({"error": "Not authorized"}, status=403)

    from datetime import timedelta
    from django.db.models import Avg, Count, Sum
    from django.db.models.functions import TruncDate
    from django.utils import timezone

    now = timezone.now()
    week_ago = now - timedelta(days=7)
    month_ago = now - timedelta(days=30)

    # ── KPI band ────────────────────────────────────────────────────────
    open_assets = Asset.objects.filter(status="open")
    total_assets = open_assets.count()
    critical_exposures = open_assets.aggregate(s=Sum("critical_count"))["s"] or 0
    new_assets_7d = Asset.objects.filter(first_seen__gte=week_ago).count()
    assets_with_cves = open_assets.filter(findings_count__gt=0).count()

    # Attack Surface Score: 100 = nothing exposed; 0 = saturated with criticals.
    # When no assets exist we return None rather than an inflated 100 — the UI
    # renders this as "N/A" so a fresh install doesn't look falsely "Strong".
    if total_assets == 0:
        attack_surface_score = None
    else:
        avg_risk = open_assets.aggregate(a=Avg("risk_score"))["a"] or 0
        attack_surface_score = max(0, min(100, round(100 - avg_risk)))

    # ── Severity trend: last 30 days, one bucket per day ────────────────
    trend_rows = (
        Finding.objects.filter(created_at__gte=month_ago)
        .annotate(day=TruncDate("created_at"))
        .values("day", "severity")
        .annotate(n=Count("id"))
    )
    by_day = {}
    for row in trend_rows:
        day = row["day"].isoformat()
        bucket = by_day.setdefault(
            day, {"date": day, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        )
        if row["severity"] in bucket:
            bucket[row["severity"]] = row["n"]
    severity_trend = sorted(by_day.values(), key=lambda r: r["date"])

    # ── Risk by source (donut) ──────────────────────────────────────────
    source_rows = Finding.objects.values("source").annotate(n=Count("id")).order_by("-n")
    risk_by_source = [{"source": r["source"], "count": r["n"]} for r in source_rows]

    # ── Newly discovered assets (last 7 days) ───────────────────────────
    newly_discovered = [
        {
            "ip": a.ip,
            "port": a.port,
            "protocol": a.protocol,
            "service": a.service_name,
            "product": a.service_product,
            "version": a.service_version,
            "risk_score": a.risk_score,
            "first_seen": a.first_seen.isoformat() if a.first_seen else None,
        }
        for a in Asset.objects.filter(first_seen__gte=week_ago).order_by("-first_seen")[:10]
    ]

    # ── Top exposures — highest CVSS first ──────────────────────────────
    # CVSS is a CharField in Finding; sort client-side so non-numeric strings don't crash SQL.
    raw = (
        Finding.objects.exclude(cve="")
        .exclude(cve__isnull=True)
        .values("cve", "title", "severity", "cvss")
        .annotate(affected=Count("host_ip", distinct=True))
        .order_by("-affected")[:50]
    )

    def _cvss_num(s):
        try:
            return float(str(s).split()[0]) if s else 0.0
        except (ValueError, IndexError):
            return 0.0

    top_exposures = sorted(raw, key=lambda r: (_cvss_num(r["cvss"]), r["affected"]), reverse=True)[
        :10
    ]

    # ── Top technologies across the surface ─────────────────────────────
    top_technologies = [
        {"name": r["name"], "count": r["n"]}
        for r in Technology.objects.values("name").annotate(n=Count("id")).order_by("-n")[:10]
    ]

    return Response(
        {
            "kpis": {
                "total_assets": total_assets,
                "critical_exposures": critical_exposures,
                "new_assets_7d": new_assets_7d,
                "assets_with_cves": assets_with_cves,
                "attack_surface_score": attack_surface_score,
            },
            "severity_trend": severity_trend,
            "risk_by_source": risk_by_source,
            "newly_discovered": newly_discovered,
            "top_exposures": top_exposures,
            "top_technologies": top_technologies,
        }
    )


@api_view(["GET"])
def download_report(request, report_id):
    """Download a report file. Requires staff or scan ownership."""
    try:
        report = Report.objects.get(id=report_id)
    except (Report.DoesNotExist, ValueError):
        raise Http404

    if not request.user.has_permission("report:download"):
        return Response({"error": "Not authorized"}, status=403)

    from pathlib import Path

    path = Path(report.file_path)

    # Verify path stays within allowed directory
    allowed_dir = Path("/data/output")
    if not path.resolve().is_relative_to(allowed_dir):
        raise Http404

    if not path.exists():
        raise Http404

    content_types = {
        "dashboard": "text/html",
        "html": "text/html",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }

    return FileResponse(
        path.open("rb"),
        content_type=content_types.get(report.format, "application/octet-stream"),
        as_attachment=True,
        filename=path.name,
    )


@api_view(["GET", "PUT"])
def report_config(request):
    """Get or update the singleton report configuration."""
    config = ReportConfig.get()
    if request.method == "GET":
        return Response(ReportConfigSerializer(config).data)

    if not request.user.has_permission("report:config:write"):
        return Response({"error": "Not authorized"}, status=403)

    # Whitelist validation per field type
    import re

    BLOCKED_FIELDS = {"logo_path"}
    FIELD_PATTERNS = {
        "report_title": (re.compile(r"^[a-zA-Z0-9 &.,:'\-()]+$"), 255),
        "company_name": (re.compile(r"^[a-zA-Z0-9 &.,'\-()]+$"), 255),
        "prepared_by": (re.compile(r"^[a-zA-Z0-9 .,'\-]+$"), 255),
        "reviewed_by": (re.compile(r"^[a-zA-Z0-9 .,'\-]+$"), 255),
        "approved_by": (re.compile(r"^[a-zA-Z0-9 .,'\-]+$"), 255),
        "brand_color": (re.compile(r"^#[0-9a-fA-F]{6}$"), 7),
        "disclaimer": (re.compile(r"^[a-zA-Z0-9 &.,;:'\-()@#/\n\r]+$"), 1000),
        "default_formats": (re.compile(r"^[a-z,]+$"), 100),
    }
    clean_data = {}
    for key, val in request.data.items():
        if key in BLOCKED_FIELDS:
            continue
        if isinstance(val, str) and key in FIELD_PATTERNS:
            pattern, max_len = FIELD_PATTERNS[key]
            val = val[:max_len]
            if val and not pattern.match(val):
                return Response({"error": f"Invalid characters in {key}"}, status=400)
        clean_data[key] = val

    serializer = ReportConfigSerializer(config, data=clean_data, partial=True)
    serializer.is_valid(raise_exception=True)
    serializer.save()
    return Response(serializer.data)


@api_view(["POST"])
def upload_logo(request):
    """Upload a custom logo for reports. Requires report:logo:upload permission."""
    if not request.user.has_permission("report:logo:upload"):
        return Response({"error": "Not authorized"}, status=403)
    if "logo" not in request.FILES:
        return Response({"error": "No file uploaded"}, status=400)

    import os
    from pathlib import Path
    from django.utils.text import get_valid_filename

    logo_file = request.FILES["logo"]

    # Restrict to safe image types only (no SVG, PHP, etc.)
    ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}
    DANGEROUS_EXTENSIONS = {
        ".php",
        ".py",
        ".sh",
        ".js",
        ".html",
        ".htm",
        ".svg",
        ".exe",
        ".bat",
        ".cmd",
        ".jsp",
        ".asp",
        ".aspx",
        ".cgi",
        ".pl",
    }
    ext = os.path.splitext(logo_file.name)[1].lower()
    # Check ALL extensions in the filename (block shell.php.png)
    all_exts = (
        {("." + p.lower()) for p in logo_file.name.split(".")[1:]}
        if "." in logo_file.name
        else set()
    )
    if all_exts & DANGEROUS_EXTENSIONS:
        return Response({"error": "Dangerous file extension detected"}, status=400)
    if ext not in ALLOWED_EXTENSIONS:
        return Response(
            {"error": f"File type {ext} not allowed. Use: {', '.join(ALLOWED_EXTENSIONS)}"},
            status=400,
        )

    # Limit file size (2MB)
    if logo_file.size > 2 * 1024 * 1024:
        return Response({"error": "File too large (max 2MB)"}, status=400)

    logo_dir = "/data/assets/logos"
    os.makedirs(logo_dir, exist_ok=True)

    # Sanitize filename to prevent path traversal
    safe_name = get_valid_filename(os.path.basename(logo_file.name))
    if not safe_name:
        return Response({"error": "Invalid filename"}, status=400)
    logo_path = os.path.join(logo_dir, safe_name)

    # Verify the resolved path stays within logo_dir
    if not Path(logo_path).resolve().is_relative_to(Path(logo_dir).resolve()):
        return Response({"error": "Invalid file path"}, status=400)

    with open(logo_path, "wb+") as f:
        for chunk in logo_file.chunks():
            f.write(chunk)

    config = ReportConfig.get()
    config.logo_path = logo_path
    config.save()

    return Response({"logo_path": logo_path, "filename": safe_name})


class ScanPolicyViewSet(viewsets.ModelViewSet):
    queryset = ScanPolicy.objects.all()
    serializer_class = ScanPolicySerializer
    permission_classes = [HasMethodPerm("policy:read", "policy:write"), IsCreatorOrOwnerForWrite]

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    @action(detail=True, methods=["post"])
    def clone(self, request, pk=None):
        policy = self.get_object()
        clone = ScanPolicy.objects.create(
            name=f"{policy.name} (Copy)",
            description=policy.description,
            scan_type=policy.scan_type,
            parallelism=policy.parallelism,
            timeout=policy.timeout,
            port_range=policy.port_range,
            tools=normalize_policy_tools(policy.tools),
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
    permission_classes = [
        HasMethodPerm("schedule:read", "schedule:write"),
        IsCreatorOrOwnerForWrite,
    ]

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    @action(detail=True, methods=["post"])
    def toggle(self, request, pk=None):
        schedule = self.get_object()
        schedule.enabled = not schedule.enabled
        schedule.save(update_fields=["enabled"])
        return Response(ScheduledScanSerializer(schedule).data)

    @action(detail=True, methods=["post"])
    def run_now(self, request, pk=None):
        """Trigger an immediate scan from this schedule."""
        schedule = self.get_object()
        scan = Scan.objects.create(
            name=f"{schedule.name} (manual)",
            target=schedule.target,
            scan_type=schedule.scan_type,
            status="pending",
            created_by=request.user,
        )
        # Apply policy settings if linked
        if schedule.policy:
            p = schedule.policy
            tools = normalize_policy_tools(p.tools)
            scan.parallelism = p.parallelism
            scan.timeout = p.timeout
            scan.report_formats = p.report_formats
            scan.version_detect = p.version_detect
            scan.os_detect = p.os_detect
            scan.service_enum = tools.get("service_enum", True)
            scan.skip_nuclei = not tools.get("nuclei", True)
            scan.nuclei_templates = tools.get("nuclei_templates", "")
            scan.nuclei_default_templates = tools.get("nuclei_default_templates", True)
            scan.enum4linux = tools.get("enum4linux", True)
            scan.skip_nikto = not tools.get("nikto", True)
            scan.skip_netexec = not tools.get("netexec", True)
            scan.skip_screenshots = p.skip_screenshots
            scan.save()

        from scanner.tasks import run_scan, _compute_deadline

        deadline = _compute_deadline(schedule.stop_time) if schedule.stop_time else None
        task = run_scan.delay(str(scan.id))
        scan.celery_task_id = task.id
        scan.status = "running"
        scan.deadline = deadline
        scan.save(update_fields=["celery_task_id", "status", "deadline"])

        from django.utils import timezone

        schedule.last_run = timezone.now()
        schedule.save(update_fields=["last_run"])

        return Response(ScanSerializer(scan).data, status=status.HTTP_201_CREATED)


@api_view(["POST"])
def support_bundle(request):
    """Stream a diagnostic .tar.gz bundle. Owner only (support:export perm)."""
    if not request.user.has_permission("support:export"):
        return Response({"error": "Not authorized"}, status=403)

    import os
    from django.http import HttpResponse
    from django.utils import timezone
    from scanner.models import AuditLog
    from scanner.support import build_support_bundle

    log_dir = os.environ.get("WIREGHOST_LOG_FILE_DIR", "/app/logs")
    blob = build_support_bundle(log_dir=log_dir, requested_by=request.user)

    actor = request.user.get_full_name() or request.user.username
    ip = request.META.get("REMOTE_ADDR", "")
    AuditLog.log(actor, "support.export", f"size_bytes={len(blob)}", "admin", ip)

    filename = f"wireghost-support-{timezone.now().strftime('%Y-%m-%d-%H%M')}.tar.gz"
    resp = HttpResponse(blob, content_type="application/gzip")
    resp["Content-Disposition"] = f'attachment; filename="{filename}"'
    resp["Content-Length"] = str(len(blob))
    resp["X-Content-Type-Options"] = "nosniff"
    return resp


class ExploitMatchViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ExploitMatch.objects.all()
    serializer_class = ExploitMatchSerializer
    permission_classes = [HasPerm("scan:read")]

    def get_queryset(self):
        qs = super().get_queryset()
        scan_id = self.request.query_params.get("scan")
        if scan_id:
            qs = qs.filter(scan_id=scan_id)
        host_id = self.request.query_params.get("host")
        if host_id:
            qs = qs.filter(host_id=host_id)
        confidence = self.request.query_params.get("confidence")
        if confidence:
            qs = qs.filter(confidence=confidence)
        return qs
