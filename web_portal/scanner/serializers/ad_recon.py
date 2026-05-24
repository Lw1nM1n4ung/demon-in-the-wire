"""AD Recon serializers -- credential profiles and recon sessions."""

from rest_framework import serializers
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


class CredentialProfileSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, max_length=256)
    nt_hash = serializers.CharField(
        write_only=True, required=False, allow_blank=True, max_length=256
    )

    class Meta:
        model = CredentialProfile
        fields = [
            "id",
            "owner",
            "name",
            "domain",
            "username",
            "password",
            "nt_hash",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "owner", "created_at", "updated_at"]

    def create(self, validated_data):
        validated_data["owner"] = self.context["request"].user
        return super().create(validated_data)

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data.pop("password", None)
        data.pop("nt_hash", None)
        return data


class ADReconSessionSerializer(serializers.ModelSerializer):
    profile_name = serializers.SerializerMethodField()

    class Meta:
        model = ADReconSession
        fields = [
            "id",
            "profile",
            "profile_name",
            "scope",
            "dc_ip",
            "domain",
            "status",
            "error",
            "tool_status",
            "started_at",
            "completed_at",
            "created_at",
        ]
        read_only_fields = [
            "id",
            "status",
            "error",
            "tool_status",
            "started_at",
            "completed_at",
            "created_at",
        ]

    def get_profile_name(self, obj):
        return obj.profile.name if obj.profile else None


class ADReconSessionCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = ADReconSession
        fields = ["profile", "scope", "dc_ip", "domain"]


class ADDomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = ADDomain
        fields = ["id", "name", "netbios_name", "sid", "functional_level", "forest"]


class ADUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = ADUser
        fields = [
            "id",
            "sam_account_name",
            "upn",
            "display_name",
            "enabled",
            "admin_count",
            "last_logon",
            "member_of",
            "spn_count",
        ]


class ADGroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = ADGroup
        fields = [
            "id",
            "name",
            "sam_account_name",
            "description",
            "members",
            "member_count",
            "admin_count",
        ]


class ADComputerSerializer(serializers.ModelSerializer):
    class Meta:
        model = ADComputer
        fields = [
            "id",
            "name",
            "dns_hostname",
            "os",
            "os_version",
            "enabled",
            "last_logon",
            "member_of",
        ]


class ADTrustSerializer(serializers.ModelSerializer):
    class Meta:
        model = ADTrust
        fields = ["id", "source_domain", "target_domain", "direction", "trust_type", "transitive"]


class ADSPNSerializer(serializers.ModelSerializer):
    class Meta:
        model = ADSPN
        fields = ["id", "service_name", "sam_account_name", "host", "port", "category"]


class ADACLSerializer(serializers.ModelSerializer):
    class Meta:
        model = ADACL
        fields = [
            "id",
            "object_dn",
            "identity",
            "active_directory_rights",
            "access_control_type",
            "interesting_rights",
        ]


class ADShareSerializer(serializers.ModelSerializer):
    class Meta:
        model = ADShare
        fields = ["id", "name", "path", "description", "access"]


class ADCertServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = ADCertService
        fields = ["id", "ca_name", "host", "templates", "vulnerable_template"]
