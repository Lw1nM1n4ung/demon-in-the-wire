"""Tests for service-name routing across all pipeline modules + Port.service_name."""

from __future__ import annotations

from wireghost.models.scan import Host, Port, Service
from wireghost.pipeline.ldap_enum import _get_ldap_ports, _parse_rootdse
from wireghost.pipeline.netexec_enum import _PORT_FALLBACK, _SERVICE_PROTOS
from wireghost.pipeline.nfs_enum import _has_nfs
from wireghost.pipeline.smb_enum import _has_smb
from wireghost.pipeline.tls_audit import _get_tls_ports


# ================================================================
# Port.service_name property
# ================================================================


class TestPortServiceName:
    def test_nmap_service_name(self):
        port = Port(number=8080, service=Service(name="http"))
        assert port.service_name == "http"

    def test_well_known_port_fallback(self):
        port = Port(number=22)
        assert port.service_name == "ssh"

    def test_well_known_port_443(self):
        port = Port(number=443)
        assert port.service_name == "https"

    def test_well_known_port_445(self):
        port = Port(number=445)
        assert port.service_name == "microsoft-ds"

    def test_well_known_port_3306(self):
        port = Port(number=3306)
        assert port.service_name == "mysql"

    def test_well_known_port_3389(self):
        port = Port(number=3389)
        assert port.service_name == "ms-wbt-server"

    def test_nmap_overrides_well_known(self):
        port = Port(number=80, service=Service(name="https"))
        assert port.service_name == "https"

    def test_unknown_port_no_service(self):
        port = Port(number=54321)
        assert port.service_name == ""

    def test_empty_service_name_falls_back(self):
        port = Port(number=22, service=Service(name=""))
        assert port.service_name == "ssh"

    def test_none_service_falls_back(self):
        port = Port(number=80, service=None)
        assert port.service_name == "http"

    def test_nonstandard_port_with_service(self):
        port = Port(number=9999, service=Service(name="microsoft-ds"))
        assert port.service_name == "microsoft-ds"

    def test_nonstandard_port_no_service(self):
        port = Port(number=9999, service=None)
        assert port.service_name == ""


# ================================================================
# SMB routing: _has_smb
# ================================================================


def _host(ports: list[tuple[int, str | None]]) -> Host:
    return Host(
        ip="10.0.0.1",
        ports=[
            Port(number=n, service=Service(name=s) if s else None)
            for n, s in ports
        ],
    )


class TestHasSmb:
    def test_microsoft_ds_service(self):
        assert _has_smb(_host([(9999, "microsoft-ds")])) is True

    def test_netbios_ssn_service(self):
        assert _has_smb(_host([(12345, "netbios-ssn")])) is True

    def test_smb_service_name(self):
        assert _has_smb(_host([(445, "smb")])) is True

    def test_port_445_no_service_fallback(self):
        assert _has_smb(_host([(445, None)])) is True

    def test_port_139_no_service_fallback(self):
        assert _has_smb(_host([(139, None)])) is True

    def test_no_smb_ports(self):
        assert _has_smb(_host([(80, "http"), (22, "ssh")])) is False

    def test_unknown_port_no_service(self):
        assert _has_smb(_host([(9999, None)])) is False

    def test_empty_ports(self):
        assert _has_smb(_host([])) is False

    def test_filtered_port_excluded(self):
        h = Host(
            ip="10.0.0.1",
            ports=[Port(number=445, state="filtered", service=Service(name="microsoft-ds"))],
        )
        assert _has_smb(h) is False


# ================================================================
# NFS routing: _has_nfs
# ================================================================


class TestHasNfs:
    def test_nfs_service_name(self):
        assert _has_nfs(_host([(9999, "nfs")])) is True

    def test_rpcbind_service(self):
        assert _has_nfs(_host([(111, "rpcbind")])) is True

    def test_mountd_service(self):
        assert _has_nfs(_host([(42000, "mountd")])) is True

    def test_port_2049_fallback(self):
        assert _has_nfs(_host([(2049, None)])) is True

    def test_port_111_fallback(self):
        assert _has_nfs(_host([(111, None)])) is True

    def test_no_nfs(self):
        assert _has_nfs(_host([(80, "http")])) is False

    def test_empty_ports(self):
        assert _has_nfs(_host([])) is False

    def test_nfs_substring_match(self):
        assert _has_nfs(_host([(2049, "nfs_acl")])) is True


# ================================================================
# TLS routing: _get_tls_ports
# ================================================================


class TestGetTlsPorts:
    def test_https_service(self):
        h = _host([(9999, "https")])
        ports = _get_tls_ports(h)
        assert len(ports) == 1
        assert ports[0].number == 9999

    def test_ssl_service(self):
        h = _host([(443, "ssl/http")])
        ports = _get_tls_ports(h)
        assert len(ports) == 1

    def test_imaps_service(self):
        h = _host([(993, "imaps")])
        ports = _get_tls_ports(h)
        assert len(ports) == 1

    def test_ldaps_service(self):
        h = _host([(636, "ldaps")])
        ports = _get_tls_ports(h)
        assert len(ports) == 1

    def test_fallback_port_443_no_service(self):
        h = _host([(443, None)])
        ports = _get_tls_ports(h)
        assert len(ports) == 1

    def test_fallback_port_8443_no_service(self):
        h = _host([(8443, None)])
        ports = _get_tls_ports(h)
        assert len(ports) == 1

    def test_http_not_tls(self):
        h = _host([(80, "http")])
        ports = _get_tls_ports(h)
        assert len(ports) == 0

    def test_no_tls_ports(self):
        h = _host([(22, "ssh"), (80, "http")])
        ports = _get_tls_ports(h)
        assert len(ports) == 0

    def test_known_service_overrides_fallback_port(self):
        h = _host([(443, "http")])
        ports = _get_tls_ports(h)
        assert len(ports) == 0

    def test_tls_on_nonstandard_port(self):
        h = _host([(12345, "tls")])
        ports = _get_tls_ports(h)
        assert len(ports) == 1


# ================================================================
# LDAP routing: _get_ldap_ports
# ================================================================


class TestGetLdapPorts:
    def test_ldap_service(self):
        h = _host([(9999, "ldap")])
        ports = _get_ldap_ports(h)
        assert len(ports) == 1

    def test_ldapssl_service(self):
        h = _host([(636, "ldapssl")])
        ports = _get_ldap_ports(h)
        assert len(ports) == 1

    def test_fallback_port_389(self):
        h = _host([(389, None)])
        ports = _get_ldap_ports(h)
        assert len(ports) == 1

    def test_fallback_port_636(self):
        h = _host([(636, None)])
        ports = _get_ldap_ports(h)
        assert len(ports) == 1

    def test_fallback_port_3268(self):
        h = _host([(3268, None)])
        ports = _get_ldap_ports(h)
        assert len(ports) == 1

    def test_no_ldap(self):
        h = _host([(80, "http")])
        ports = _get_ldap_ports(h)
        assert len(ports) == 0

    def test_ldap_on_nonstandard_port(self):
        h = _host([(50000, "ldap")])
        ports = _get_ldap_ports(h)
        assert len(ports) == 1


# ================================================================
# LDAP helper: _parse_rootdse
# ================================================================


class TestParseRootdse:
    def test_basic_attributes(self):
        stdout = (
            "dn:\n"
            "namingContexts: DC=example,DC=com\n"
            "namingContexts: DC=corp,DC=local\n"
            "domainFunctionality: 7\n"
        )
        attrs = _parse_rootdse(stdout)
        assert attrs["namingContexts"] == ["DC=example,DC=com", "DC=corp,DC=local"]
        assert attrs["domainFunctionality"] == ["7"]

    def test_comments_skipped(self):
        stdout = "# search result\nnamingContexts: DC=test\n"
        attrs = _parse_rootdse(stdout)
        assert "namingContexts" in attrs

    def test_dn_skipped(self):
        stdout = "dn: \nnamingContexts: DC=test\n"
        attrs = _parse_rootdse(stdout)
        assert "dn" not in attrs

    def test_empty_output(self):
        assert _parse_rootdse("") == {}

    def test_blank_lines_skipped(self):
        stdout = "\n\n\nnamingContexts: DC=test\n\n"
        attrs = _parse_rootdse(stdout)
        assert len(attrs) == 1


# ================================================================
# NetExec routing: _SERVICE_PROTOS + _PORT_FALLBACK
# ================================================================


class TestNetexecRouting:
    def test_microsoft_ds_maps_to_smb(self):
        assert _SERVICE_PROTOS["microsoft-ds"] == "smb"

    def test_netbios_ssn_maps_to_smb(self):
        assert _SERVICE_PROTOS["netbios-ssn"] == "smb"

    def test_ftp_maps_to_ftp(self):
        assert _SERVICE_PROTOS["ftp"] == "ftp"

    def test_rdp_maps_to_rdp(self):
        assert _SERVICE_PROTOS["ms-wbt-server"] == "rdp"

    def test_mssql_maps_to_mssql(self):
        assert _SERVICE_PROTOS["ms-sql-s"] == "mssql"

    def test_unknown_service_not_in_protos(self):
        assert "http" not in _SERVICE_PROTOS
        assert "ssh" not in _SERVICE_PROTOS

    def test_port_445_fallback_smb(self):
        assert _PORT_FALLBACK[445] == "smb"

    def test_port_139_fallback_smb(self):
        assert _PORT_FALLBACK[139] == "smb"

    def test_port_21_fallback_ftp(self):
        assert _PORT_FALLBACK[21] == "ftp"

    def test_port_3389_fallback_rdp(self):
        assert _PORT_FALLBACK[3389] == "rdp"

    def test_port_1433_fallback_mssql(self):
        assert _PORT_FALLBACK[1433] == "mssql"

    def test_unknown_port_not_in_fallback(self):
        assert 80 not in _PORT_FALLBACK
        assert 22 not in _PORT_FALLBACK

    def test_service_routing_full_host(self):
        """Service-name routing should identify smb+ftp protocols."""
        h = _host([(445, "microsoft-ds"), (21, "ftp"), (80, "http")])
        protos: set[str] = set()
        for p in h.open_ports:
            svc = p.service_name
            proto = _SERVICE_PROTOS.get(svc)
            if proto:
                protos.add(proto)
            elif not svc and p.number in _PORT_FALLBACK:
                protos.add(_PORT_FALLBACK[p.number])
        assert protos == {"smb", "ftp"}

    def test_fallback_routing_no_service(self):
        """Port-number fallback should activate when service_name is empty."""
        h = _host([(3389, None), (1433, None)])
        protos: set[str] = set()
        for p in h.open_ports:
            svc = p.service_name
            proto = _SERVICE_PROTOS.get(svc)
            if proto:
                protos.add(proto)
            elif not svc and p.number in _PORT_FALLBACK:
                protos.add(_PORT_FALLBACK[p.number])
        assert protos == {"rdp", "mssql"}

    def test_service_overrides_port_fallback(self):
        """When a port has a service name, port fallback should NOT be used."""
        h = _host([(445, "http")])
        protos: set[str] = set()
        for p in h.open_ports:
            svc = p.service_name
            proto = _SERVICE_PROTOS.get(svc)
            if proto:
                protos.add(proto)
            elif not svc and p.number in _PORT_FALLBACK:
                protos.add(_PORT_FALLBACK[p.number])
        assert protos == set()

    def test_no_matching_services_or_ports(self):
        """Host with only SSH/HTTP should yield no netexec protos."""
        h = _host([(22, "ssh"), (80, "http")])
        protos: set[str] = set()
        for p in h.open_ports:
            svc = p.service_name
            proto = _SERVICE_PROTOS.get(svc)
            if proto:
                protos.add(proto)
            elif not svc and p.number in _PORT_FALLBACK:
                protos.add(_PORT_FALLBACK[p.number])
        assert protos == set()

    def test_dedup_same_proto_multiple_ports(self):
        """Two SMB ports (445 + 139) should yield only one 'smb' proto."""
        h = _host([(445, "microsoft-ds"), (139, "netbios-ssn")])
        protos: set[str] = set()
        for p in h.open_ports:
            svc = p.service_name
            proto = _SERVICE_PROTOS.get(svc)
            if proto:
                protos.add(proto)
        assert protos == {"smb"}
