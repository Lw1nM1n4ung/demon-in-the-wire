"""AD Recon views -- ViewSets for credential profiles and recon sessions."""

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response

from scanner.models.ad_recon import (
    CredentialProfile,
    ADReconSession,
    ADDomain,
    ADUser,
    ADGroup,
    ADComputer,
    ADTrust,
    ADSPN,
    ADACL,
    ADShare,
    ADCertService,
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

    @action(detail=True, methods=["get"])
    def groups(self, request, pk=None):
        session = self.get_object()
        qs = ADGroup.objects.filter(session=session)
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

        Returns a nested hierarchy: domain root -> OUs/containers -> leaf objects.
        Each node has {id, label, type, dn, children, counts}.
        type: 'domain', 'ou', 'container', or 'leaf'
        """
        session = self.get_object()

        # Collect all DNs and their types
        nodes = []  # (dn, label, obj_type)
        for u in ADUser.objects.filter(session=session).values_list("dn", "display_name"):
            if u[0]:
                nodes.append((u[0], u[1] or u[0].split(",")[0].replace("CN=", ""), "user"))
        for c in ADComputer.objects.filter(session=session).values_list("dn", "name"):
            if c[0]:
                nodes.append((c[0], c[1] or c[0].split(",")[0].replace("CN=", ""), "computer"))
        for g in ADGroup.objects.filter(session=session).values_list("dn", "name"):
            if g[0]:
                nodes.append((g[0], g[1] or g[0].split(",")[0].replace("CN=", ""), "group"))

        if not nodes:
            return Response({"id": "empty", "label": "No data", "type": "domain", "dn": "", "children": [], "counts": {"users": 0, "computers": 0, "groups": 0}})

        # Reverse DNs to build tree bottom-up
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
            return parts  # [CN=..., OU=..., OU=..., DC=..., DC=...]

        # Find the domain root
        all_parts = [parse_dn(dn) for dn, _, _ in nodes]
        # Extract DC= components from the last DN to build domain root
        dc_parts = []
        for part in reversed(all_parts[0]):
            if part.upper().startswith("DC="):
                dc_parts.insert(0, part)
            else:
                break
        domain_dn = ",".join(dc_parts)
        domain_label = ".".join(p.replace("DC=", "") for p in dc_parts)

        # Build tree: map dn_path -> node
        tree_root = {
            "id": "root",
            "label": domain_label,
            "type": "domain",
            "dn": domain_dn,
            "children": [],
            "counts": {"users": 0, "computers": 0, "groups": 0},
        }

        # Map of dn -> node reference for inserting children
        dn_map = {domain_dn.lower(): tree_root}

        for dn, label, obj_type in nodes:
            parts = parse_dn(dn)
            # Walk from domain root down, creating OU nodes as needed
            # parts go from most-specific (CN=user) to least (DC=com)
            # We need to insert from domain root downward
            reversed_parts = list(reversed(parts))  # [DC=com, DC=asa-myanmar, OU=..., CN=...]

            # Find the insertion point: skip DC components, start from OUs
            start_idx = 0
            while start_idx < len(reversed_parts) and reversed_parts[start_idx].upper().startswith("DC="):
                start_idx += 1

            parent = tree_root
            parent_dn_parts = list(dc_parts)  # ["DC=asa-myanmar", "DC=com"]

            for i in range(start_idx, len(reversed_parts)):
                part = reversed_parts[i]
                current_dn_parts = parent_dn_parts + [part]
                current_dn = ",".join(reversed(current_dn_parts))
                current_key = current_dn.lower()

                if current_key not in dn_map:
                    # Create OU/container node
                    is_ou = part.upper().startswith("OU=")
                    ou_node = {
                        "id": "ou-" + str(len(dn_map)),
                        "label": part.split("=", 1)[1] if "=" in part else part,
                        "type": "ou" if is_ou else "container",
                        "dn": current_dn,
                        "children": [],
                        "counts": {"users": 0, "computers": 0, "groups": 0},
                    }
                    dn_map[current_key] = ou_node
                    parent["children"].append(ou_node)

                parent = dn_map[current_key]
                parent_dn_parts = current_dn_parts

                # Update counts
                parent["counts"][obj_type + "s"] = parent["counts"].get(obj_type + "s", 0) + 1

            # Add the leaf node under its parent OU
            leaf = {
                "id": "leaf-" + str(len(dn_map)),
                "label": label,
                "type": obj_type,
                "dn": dn,
                "children": [],
                "counts": {},
            }
            dn_map[dn.lower()] = leaf
            parent["children"].append(leaf)

        # Update root counts
        tree_root["counts"]["users"] = sum(1 for _, _, t in nodes if t == "user")
        tree_root["counts"]["computers"] = sum(1 for _, _, t in nodes if t == "computer")
        tree_root["counts"]["groups"] = sum(1 for _, _, t in nodes if t == "group")

        # Sort children at each level: OUs first, then leaf objects
        def sort_tree(node):
            if node.get("children"):
                node["children"].sort(key=lambda c: (
                    0 if c["type"] in ("ou", "container") else 1,
                    c["label"].lower()
                ))
                for child in node["children"]:
                    sort_tree(child)

        sort_tree(tree_root)
        return Response(tree_root)
