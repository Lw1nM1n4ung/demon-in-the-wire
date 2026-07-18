"""AD Recon views -- ViewSets for credential profiles and recon sessions."""

import csv
import io

from django.http import HttpResponse

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from django.db import models as db_models

from scanner.models.ad_recon import (
    CredentialProfile,
    ADReconSession,
    ADCSExploitSession,
    ADDomain,
    ADUser,
    ADGroup,
    ADComputer,
    ADTrust,
    ADSPN,
    ADACL,
    ADShare,
    ADCertService,
    ADSprayResult,
    CredentialFinding,
    ACLFinding,
    VulnCheck,
)
from scanner.serializers.ad_recon import (
    CredentialProfileSerializer,
    ADReconSessionSerializer,
    ADReconSessionCreateSerializer,
    ADDomainSerializer,
    ADUserSerializer,
    ADGroupSerializer,
    ADComputerSerializer,
    ADTrustSerializer,
    ADSPNSerializer,
    ADACLSerializer,
    ADShareSerializer,
    ADCertServiceSerializer,
    ADSprayResultSerializer,
    SprayRequestSerializer,
    CredentialFindingSerializer,
    ACLFindingSerializer,
    VulnCheckSerializer,
    ADCSExploitSessionSerializer,
    ADCSExploitRespondSerializer,
)
from scanner.views import HasPerm


class CredentialProfileViewSet(viewsets.ModelViewSet):
    serializer_class = CredentialProfileSerializer
    permission_classes = [HasPerm("site:config")]
    http_method_names = ["get", "post", "put", "delete", "head", "options"]

    def get_queryset(self):
        return CredentialProfile.objects.filter(owner=self.request.user)

    def perform_destroy(self, instance):
        instance.delete()


class ADReconSessionViewSet(viewsets.ModelViewSet):
    permission_classes = [HasPerm("site:config")]
    http_method_names = ["get", "post", "head", "options"]
    queryset = ADReconSession.objects.select_related("profile").all()

    def get_serializer_class(self):
        if self.action == "create":
            return ADReconSessionCreateSerializer
        return ADReconSessionSerializer

    def create(self, request):
        serializer = ADReconSessionCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        scope = data.get("scope", "authenticated")
        profile = data.get("profile")

        if scope == "authenticated" and not profile:
            return Response(
                {"error": "Authenticated scope requires a credential profile"},
                status=400,
            )
        if scope == "unauth" and profile:
            return Response(
                {"error": "Unauthenticated scope should not have a profile"},
                status=400,
            )

        session = ADReconSession.objects.create(
            profile=profile,
            scope=scope,
            dc_ip=data["dc_ip"],
            domain=data["domain"],
            status="pending",
        )

        from scanner.tasks.ad_recon import ad_recon_task

        ad_recon_task.delay(str(session.id))

        return Response(
            ADReconSessionSerializer(session).data,
            status=status.HTTP_201_CREATED,
        )

    def _paginated_response(self, request, queryset, serializer_class):
        paginator = PageNumberPagination()
        paginator.page_size = 100
        page = paginator.paginate_queryset(queryset, request)
        serializer = serializer_class(page, many=True)
        return paginator.get_paginated_response(serializer.data)

    @action(detail=True, methods=["get"])
    def users(self, request, pk=None):
        session = self.get_object()
        qs = ADUser.objects.filter(session=session)
        return self._paginated_response(request, qs, ADUserSerializer)

    @action(detail=True, methods=["get"], url_path="export/users")
    def export_users(self, request, pk=None):
        """Export all users for this session as a CSV file."""
        session = self.get_object()
        qs = ADUser.objects.filter(session=session)

        buf = io.StringIO()
        buf.write("\ufeff")  # UTF-8 BOM for Excel
        writer = csv.writer(buf)

        writer.writerow([
            "SAM Account Name", "UPN", "Display Name", "DN", "Description",
            "Enabled", "Admin Count", "Last Logon", "Password Last Set",
            "SPN Count", "Member Of",
        ])

        for user in qs.iterator(chunk_size=500):
            writer.writerow([
                user.sam_account_name or "",
                user.upn or "",
                user.display_name or "",
                user.dn or "",
                user.description or "",
                "Yes" if user.enabled else "No",
                str(user.admin_count),
                user.last_logon.isoformat() if user.last_logon else "",
                user.pwd_last_set.isoformat() if user.pwd_last_set else "",
                str(user.spn_count),
                "; ".join(user.member_of) if isinstance(user.member_of, list) else "",
            ])

        clean_domain = session.domain.replace(".", "_").replace("/", "_")
        filename = f"{clean_domain}_users.csv"

        resp = HttpResponse(buf.getvalue(), content_type="text/csv; charset=utf-8")
        resp["Content-Disposition"] = f'attachment; filename="{filename}"'
        return resp

    @action(detail=True, methods=["get"])
    def groups(self, request, pk=None):
        session = self.get_object()
        qs = ADGroup.objects.filter(session=session).order_by('-member_count', 'name')
        return self._paginated_response(request, qs, ADGroupSerializer)

    @action(detail=True, methods=["get"])
    def computers(self, request, pk=None):
        session = self.get_object()
        qs = ADComputer.objects.filter(session=session)
        return self._paginated_response(request, qs, ADComputerSerializer)

    @action(detail=True, methods=["get"])
    def domains(self, request, pk=None):
        session = self.get_object()
        qs = ADDomain.objects.filter(session=session)
        return self._paginated_response(request, qs, ADDomainSerializer)

    @action(detail=True, methods=["get"])
    def findings(self, request, pk=None):
        session = self.get_object()
        spns = ADSPNSerializer(ADSPN.objects.filter(session=session), many=True).data
        acls = ADACLSerializer(ADACL.objects.filter(session=session), many=True).data
        certs = ADCertServiceSerializer(
            ADCertService.objects.filter(session=session), many=True
        ).data
        trusts = ADTrustSerializer(ADTrust.objects.filter(session=session), many=True).data
        shares = ADShareSerializer(ADShare.objects.filter(session=session), many=True).data
        return Response(
            {
                "spns": spns,
                "acls": acls,
                "cert_services": certs,
                "trusts": trusts,
                "shares": shares,
            }
        )

    @action(detail=True, methods=["get"])
    def tree(self, request, pk=None):
        """Build an AD tree topology from the DNs of users, computers, and groups.

        Returns a nested hierarchy: domain root -> OUs -> leaf objects.
        Each node has {id, label, type, dn, children, counts}.
        type: 'domain', 'ou', 'user', 'computer', or 'group'
        """
        session = self.get_object()

        # Collect all DNs and their types
        nodes = []  # (dn, label, obj_type)
        for u in ADUser.objects.filter(session=session).values_list("dn", "display_name"):
            if u[0]:
                nodes.append((u[0], u[1] or "", "user"))
        for c in ADComputer.objects.filter(session=session).values_list("dn", "name"):
            if c[0]:
                nodes.append((c[0], c[1] or "", "computer"))
        for g in ADGroup.objects.filter(session=session).values_list("dn", "name"):
            if g[0]:
                nodes.append((g[0], g[1] or "", "group"))

        if not nodes:
            return Response({
                "id": "empty", "label": "No data", "type": "domain", "dn": "",
                "children": [], "counts": {"users": 0, "computers": 0, "groups": 0},
            })

        def parse_dn(dn):
            """Split DN into RDN components, return list (most specific first)."""
            parts = []
            current = ""
            in_quotes = False
            for ch in dn:
                if ch == '"':
                    in_quotes = not in_quotes
                    current += ch
                elif ch == "," and not in_quotes:
                    parts.append(current.strip())
                    current = ""
                else:
                    current += ch
            if current.strip():
                parts.append(current.strip())
            return parts

        # Determine canonical DC order from the longest DN
        def get_dc_parts(parts):
            return [p for p in parts if p.upper().startswith("DC=")]

        best_dc = []
        for dn, _, _ in nodes:
            dc = get_dc_parts(parse_dn(dn))
            if len(dc) > len(best_dc):
                best_dc = dc
        dc_parts = best_dc  # most specific first: [DC=asa-myanmar, DC=com]
        domain_dn = ",".join(dc_parts)
        domain_label = ".".join(p.replace("DC=", "") for p in dc_parts)

        tree_root = {
            "id": "root",
            "label": domain_label,
            "type": "domain",
            "dn": domain_dn,
            "children": [],
            "counts": {"users": 0, "computers": 0, "groups": 0},
        }
        dn_map = {domain_dn.lower(): tree_root}

        for dn, label, obj_type in nodes:
            parts = parse_dn(dn)
            # parts = [CN=user, OU=SubOU, OU=ParentOU, DC=asa-myanmar, DC=com]
            # Separate: CN (leaf name), OUs (hierarchy path), DCs (domain)
            cn_value = None
            ou_path = []  # from most specific to least specific OU
            for p in parts:
                up = p.upper()
                if up.startswith("CN="):
                    cn_value = p.split("=", 1)[1]
                elif up.startswith("OU="):
                    ou_path.append(p)
                # DC= ignored here — we already have the root

            if not cn_value:
                continue

            leaf_label = label or cn_value

            # Walk OUs in reverse (least specific first) from the domain root
            parent = tree_root
            for ou in reversed(ou_path):
                # Build the accumulated DN for this OU node
                sibling_dns = [c["dn"] for c in parent["children"] if c["type"] == "ou"]
                # Construct the correct DN: OU=...,<parent_dn>
                ou_dn_parts = [ou]
                if parent["dn"]:
                    ou_dn_parts.append(parent["dn"])
                ou_dn = ",".join(ou_dn_parts)
                ou_key = ou_dn.lower()

                if ou_key not in dn_map:
                    ou_node = {
                        "id": "ou-" + str(len(dn_map)),
                        "label": ou.split("=", 1)[1],
                        "type": "ou",
                        "dn": ou_dn,
                        "children": [],
                        "counts": {"users": 0, "computers": 0, "groups": 0},
                    }
                    dn_map[ou_key] = ou_node
                    parent["children"].append(ou_node)

                parent = dn_map[ou_key]
                parent["counts"][obj_type + "s"] = parent["counts"].get(obj_type + "s", 0) + 1

            # Create leaf node directly under parent OU
            leaf = {
                "id": "leaf-" + str(len(dn_map)),
                "label": leaf_label,
                "type": obj_type,
                "dn": dn,
            }
            dn_map[dn.lower()] = leaf
            parent["children"].append(leaf)
            parent["counts"][obj_type + "s"] = parent["counts"].get(obj_type + "s", 0) + 1

        # Root counts from totals
        tree_root["counts"]["users"] = sum(1 for _, _, t in nodes if t == "user")
        tree_root["counts"]["computers"] = sum(1 for _, _, t in nodes if t == "computer")
        tree_root["counts"]["groups"] = sum(1 for _, _, t in nodes if t == "group")

        # Sort children at each level: OUs first, then leaf objects
        def sort_tree(node):
            if node.get("children"):
                node["children"].sort(key=lambda c: (
                    0 if c["type"] == "ou" else 1,
                    c["label"].lower(),
                ))
                for child in node["children"]:
                    sort_tree(child)

        sort_tree(tree_root)
        return Response(tree_root)

    # --- Password Spray ---

    @action(detail=True, methods=["get"])
    def spray(self, request, pk=None):
        """Return all spray results for this session."""
        session = self.get_object()
        qs = ADSprayResult.objects.filter(session=session)
        return self._paginated_response(request, qs, ADSprayResultSerializer)

    @spray.mapping.post
    def run_spray(self, request, pk=None):
        """Queue a password spray against session users using nxc smb.

        Creates pending ``ADSprayResult`` rows and dispatches a Celery task.
        Returns immediately with a summary of queued passwords.
        """
        session = self.get_object()
        serializer = SprayRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        passwords = serializer.validated_data["passwords"]
        selected_users = serializer.validated_data.get("users") or None

        dc_ip = session.dc_ip
        if not dc_ip:
            return Response(
                {"error": "No DC IP configured for this session"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Resolve target usernames
        if selected_users:
            valid_users = list(
                ADUser.objects.filter(
                    session=session, sam_account_name__in=selected_users
                ).values_list("sam_account_name", flat=True)
            )
            if not valid_users:
                return Response(
                    {"error": "None of the specified users exist in this session"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            usernames = sorted(set(valid_users))
        else:
            usernames = sorted({
                u for u in ADUser.objects.filter(session=session)
                .values_list("sam_account_name", flat=True) if u
            })

        if not usernames:
            return Response(
                {"error": "No users found for this session"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Create pending spray result rows — one per user per password
        for password in passwords:
            for username in usernames:
                ADSprayResult.objects.get_or_create(
                    session=session,
                    password=password,
                    username=username,
                    defaults={"status": "pending", "output": ""},
                )

        # Dispatch the Celery task with selected usernames
        from scanner.tasks.ad_recon import run_spray_task
        task = run_spray_task.apply_async(
            args=[str(session.id)],
            kwargs={"usernames": usernames},
        )

        return Response({
            "task_id": task.id,
            "passwords_tried": len(passwords),
            "users_targeted": len(usernames),
            "message": "Spray queued. Check /spray/ for results.",
        })

    # ── ViperOne pipeline findings ──

    @action(detail=True, methods=["get"])
    def credentials(self, request, pk=None):
        """Harvested credentials (GPP, LAPS, user descriptions, etc.)."""
        session = self.get_object()
        qs = CredentialFinding.objects.filter(session=session)
        return self._paginated_response(request, qs, CredentialFindingSerializer)

    @action(detail=True, methods=["get"])
    def acl_risks(self, request, pk=None):
        """Dangerous ACL findings sorted by risk level."""
        session = self.get_object()
        qs = ACLFinding.objects.filter(session=session).order_by(
            db_models.Case(
                db_models.When(risk_level="critical", then=db_models.Value(0)),
                db_models.When(risk_level="high", then=db_models.Value(1)),
                db_models.When(risk_level="medium", then=db_models.Value(2)),
                default=db_models.Value(3),
            )
        )
        return self._paginated_response(request, qs, ACLFindingSerializer)

    @action(detail=True, methods=["get"])
    def vulnerabilities(self, request, pk=None):
        """Privilege escalation vulnerability checks (Zerologon, NoPac, etc.)."""
        session = self.get_object()
        qs = VulnCheck.objects.filter(session=session)
        return self._paginated_response(request, qs, VulnCheckSerializer)

    @action(detail=True, methods=["post"])
    def exploit(self, request, pk=None):
        """Start an interactive ADCS exploitation for a detected ESC vuln.

        Body: {"check_name": "<VulnCheck ID or check_name>",
               "template": "<optional template name override>",
               "ca": "<optional CA name override>",
               "target_upn": "<optional target UPN>",
               "relay_ip": "<optional relay IP for ESC8>"}
        """
        session = self.get_object()

        check_id_or_name = request.data.get("check_name", "")
        if not check_id_or_name:
            return Response({"error": "check_name is required"}, status=400)

        # Accept either VulnCheck UUID or check_name string
        try:
            from uuid import UUID as PyUUID
            PyUUID(check_id_or_name)
            # It's a UUID — look up by ID
            vuln = VulnCheck.objects.get(
                session=session, id=check_id_or_name,
            )
        except (ValueError, TypeError):
            # Not a UUID — look up by check_name
            try:
                vuln = VulnCheck.objects.get(
                    session=session, check_name=check_id_or_name,
                )
            except VulnCheck.DoesNotExist:
                return Response(
                    {"error": "VulnCheck %s not found" % check_id_or_name}, status=404,
                )

        if not vuln.vulnerable:
            return Response(
                {"error": "VulnCheck %s is not vulnerable" % check_id_or_name},
                status=400,
            )

        from scanner.tasks.adcs_exploit import (
            _extract_esc_type, build_exploit_session_steps,
        )

        esc_type = _extract_esc_type(vuln.check_name)
        if not esc_type:
            return Response(
                {"error": "Cannot determine ESC type from %s" % vuln.check_name},
                status=400,
            )

        override_params = {
            k: v for k, v in request.data.items()
            if k in ("template", "ca", "target_upn", "relay_ip") and v
        }
        steps = build_exploit_session_steps(esc_type, vuln, session, overrides=override_params)

        exploit_sess = ADCSExploitSession.objects.create(
            ad_session=session,
            vuln_check=vuln,
            esc_type=esc_type,
            status="running",
            current_step=0,
            total_steps=len(steps),
            steps=steps,
            overrides=override_params,
        )

        # Dispatch first step
        from scanner.tasks.adcs_exploit import adcs_exploit_step

        adcs_exploit_step.delay(str(exploit_sess.id))

        return Response(
            ADCSExploitSessionSerializer(exploit_sess).data,
            status=status.HTTP_201_CREATED,
        )


class ADCSExploitSessionViewSet(viewsets.ModelViewSet):
    """ViewSet for ADCS exploit sessions — poll and respond."""

    permission_classes = [HasPerm("site:config")]
    http_method_names = ["get", "post", "head", "options"]
    queryset = ADCSExploitSession.objects.select_related(
        "ad_session", "vuln_check",
    ).all()

    def get_serializer_class(self):
        if self.action == "respond":
            return ADCSExploitRespondSerializer
        return ADCSExploitSessionSerializer

    @action(detail=True, methods=["post"])
    def respond(self, request, pk=None):
        """Approve or reject the current pending step.

        Body: {"action": "approve"} or {"action": "reject"}
        """
        exploit = self.get_object()

        if exploit.status != "awaiting_confirm":
            return Response(
                {"error": "Session status is %s, not awaiting_confirm" % exploit.status},
                status=400,
            )

        ser = ADCSExploitRespondSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        action_val = ser.validated_data["action"]

        if action_val == "reject":
            exploit.status = "cancelled"
            exploit.save(update_fields=["status", "updated_at"])
            return Response(ADCSExploitSessionSerializer(exploit).data)

        # Approve — mark as running and dispatch next step
        exploit.status = "running"
        exploit.save(update_fields=["status", "updated_at"])

        from scanner.tasks.adcs_exploit import adcs_exploit_step

        adcs_exploit_step.delay(str(exploit.id))

        return Response(ADCSExploitSessionSerializer(exploit).data)
