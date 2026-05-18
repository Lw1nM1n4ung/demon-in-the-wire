"""AD Recon views -- ViewSets for credential profiles and recon sessions."""
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response

from scanner.models.ad_recon import (
    CredentialProfile, ADReconSession, ADDomain,
    ADUser, ADGroup, ADComputer,
    ADTrust, ADSPN, ADACL, ADShare, ADCertService,
)
from scanner.serializers.ad_recon import (
    CredentialProfileSerializer, ADReconSessionSerializer,
    ADReconSessionCreateSerializer,
    ADDomainSerializer, ADUserSerializer, ADGroupSerializer, ADComputerSerializer,
    ADTrustSerializer, ADSPNSerializer, ADACLSerializer,
    ADShareSerializer, ADCertServiceSerializer,
)
from scanner.views import HasPerm


class CredentialProfileViewSet(viewsets.ModelViewSet):
    serializer_class = CredentialProfileSerializer
    permission_classes = [HasPerm('site:config')]
    http_method_names = ['get', 'post', 'put', 'delete', 'head', 'options']

    def get_queryset(self):
        return CredentialProfile.objects.filter(owner=self.request.user)

    def perform_destroy(self, instance):
        instance.delete()


class ADReconSessionViewSet(viewsets.ModelViewSet):
    permission_classes = [HasPerm('site:config')]
    http_method_names = ['get', 'post', 'head', 'options']
    queryset = ADReconSession.objects.select_related('profile').all()

    def get_serializer_class(self):
        if self.action == 'create':
            return ADReconSessionCreateSerializer
        return ADReconSessionSerializer

    def create(self, request):
        serializer = ADReconSessionCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        scope = data.get('scope', 'authenticated')
        profile = data.get('profile')

        if scope == 'authenticated' and not profile:
            return Response(
                {'error': 'Authenticated scope requires a credential profile'},
                status=400,
            )
        if scope == 'unauth' and profile:
            return Response(
                {'error': 'Unauthenticated scope should not have a profile'},
                status=400,
            )

        session = ADReconSession.objects.create(
            profile=profile,
            scope=scope,
            dc_ip=data['dc_ip'],
            domain=data['domain'],
            status='pending',
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

    @action(detail=True, methods=['get'])
    def users(self, request, pk=None):
        session = self.get_object()
        qs = ADUser.objects.filter(session=session)
        return self._paginated_response(request, qs, ADUserSerializer)

    @action(detail=True, methods=['get'])
    def groups(self, request, pk=None):
        session = self.get_object()
        qs = ADGroup.objects.filter(session=session)
        return self._paginated_response(request, qs, ADGroupSerializer)

    @action(detail=True, methods=['get'])
    def computers(self, request, pk=None):
        session = self.get_object()
        qs = ADComputer.objects.filter(session=session)
        return self._paginated_response(request, qs, ADComputerSerializer)

    @action(detail=True, methods=['get'])
    def domains(self, request, pk=None):
        session = self.get_object()
        qs = ADDomain.objects.filter(session=session)
        return self._paginated_response(request, qs, ADDomainSerializer)

    @action(detail=True, methods=['get'])
    def findings(self, request, pk=None):
        session = self.get_object()
        spns = ADSPNSerializer(ADSPN.objects.filter(session=session), many=True).data
        acls = ADACLSerializer(ADACL.objects.filter(session=session), many=True).data
        certs = ADCertServiceSerializer(ADCertService.objects.filter(session=session), many=True).data
        trusts = ADTrustSerializer(ADTrust.objects.filter(session=session), many=True).data
        shares = ADShareSerializer(ADShare.objects.filter(session=session), many=True).data
        return Response({
            'spns': spns, 'acls': acls, 'cert_services': certs,
            'trusts': trusts, 'shares': shares,
        })
