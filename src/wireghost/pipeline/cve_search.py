"""Enhanced CVE search — unified version extraction across ALL pipeline tools.

Collects version data from 11 sources (nmap -sV, fingerprintx, httpx, MSF
version scanners, service banners, WPScan, enum4linux, NetExec, SNMP, TLS
audit, LDAP), converts to CPE for precise NVD matching, and queries the
NVD API 2.0 in parallel with existing searchsploit/getsploit.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from wireghost.models.finding import Finding
from wireghost.models.severity import Severity

if TYPE_CHECKING:
    import aiohttp

    from wireghost.config import ScanConfig
    from wireghost.models.scan import Host

log = logging.getLogger("wireghost")


# ---------------------------------------------------------------------------
# VersionInfo — unified version descriptor
# ---------------------------------------------------------------------------


@dataclass
class VersionInfo:
    product: str  # e.g. "OpenSSH", "Apache httpd", "WordPress"
    version: str  # e.g. "9.6p1", "2.4.49", "6.5.3"  (FULL version)
    port: str  # port number
    source: str  # "nmap", "msf", "wpscan", "service_enum", etc.
    cpe_vendor: str = ""  # e.g. "openbsd", "apache", "wordpress"
    cpe_product: str = ""  # e.g. "openssh", "http_server", "wordpress"


# ---------------------------------------------------------------------------
# CPE mapping — product name → (vendor, product) for CPE 2.3 URIs
# ---------------------------------------------------------------------------

# Keys are lowercased product names as they appear in nmap/banner output.
# Values are (cpe_vendor, cpe_product) tuples for CPE 2.3 matching.
_CPE_MAP: dict[str, tuple[str, str]] = {
    # --- Unix services ---
    "openssh": ("openbsd", "openssh"),
    "dropbear": ("dropbear_ssh_project", "dropbear_ssh"),
    "proftpd": ("proftpd", "proftpd"),
    "vsftpd": ("vsftpd", "vsftpd"),
    "pure-ftpd": ("pureftpd", "pure-ftpd"),
    "filezilla": ("filezilla-project", "filezilla_server"),
    "bind": ("isc", "bind"),
    "powerdns": ("powerdns", "powerdns"),
    "dnsmasq": ("thekelleys", "dnsmasq"),
    "exim": ("exim", "exim"),
    "postfix": ("postfix", "postfix"),
    "sendmail": ("sendmail", "sendmail"),
    "dovecot": ("dovecot", "dovecot"),
    "courier": ("courier-mta", "courier"),
    "cyrus": ("cyrus_imap", "cyrus_imapd"),
    "squid": ("squid-cache", "squid"),
    "haproxy": ("haproxy", "haproxy"),
    "varnish": ("varnish-cache", "varnish"),
    "memcached": ("memcached", "memcached"),
    "redis": ("redis", "redis"),
    "mongodb": ("mongodb", "mongodb"),
    "couchdb": ("apache", "couchdb"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "rabbitmq": ("pivotal_software", "rabbitmq"),
    "erlang": ("erlang", "erlang"),
    "node.js": ("nodejs", "node.js"),
    "nodejs": ("nodejs", "node.js"),
    # --- Databases ---
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "microsoft sql": ("microsoft", "sql_server"),
    "mssql": ("microsoft", "sql_server"),
    "oracle database": ("oracle", "database"),
    "oracle tns": ("oracle", "database"),
    "mongod": ("mongodb", "mongodb"),
    # --- Web servers ---
    "apache httpd": ("apache", "http_server"),
    "apache": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "caddy": ("caddyserver", "caddy"),
    "iis": ("microsoft", "internet_information_services"),
    "microsoft iis": ("microsoft", "internet_information_services"),
    "microsoft httpapi": ("microsoft", "httpapi"),
    "tomcat": ("apache", "tomcat"),
    "jetty": ("eclipse", "jetty"),
    "jboss": ("redhat", "jboss"),
    "wildfly": ("redhat", "wildfly"),
    "glassfish": ("oracle", "glassfish"),
    "weblogic": ("oracle", "weblogic"),
    "websphere": ("ibm", "websphere_application_server"),
    "gunicorn": ("gunicorn", "gunicorn"),
    "uwsgi": ("unbit", "uwsgi"),
    "cherrypy": ("cherrypy", "cherrypy"),
    "tornadoweb": ("tornadoweb", "tornado"),
    # --- Languages / runtimes ---
    "php": ("php", "php"),
    "python": ("python", "python"),
    "ruby": ("ruby-lang", "ruby"),
    "perl": ("perl", "perl"),
    "java": ("oracle", "jre"),
    "openjdk": ("openjdk", "openjdk"),
    "lua": ("lua", "lua"),
    "go": ("golang", "go"),
    "ruby on rails": ("rubyonrails", "rails"),
    "django": ("djangoproject", "django"),
    "flask": ("palletsprojects", "flask"),
    "laravel": ("laravel", "laravel"),
    "symfony": ("symfony", "symfony"),
    "spring": ("spring", "spring_framework"),
    "spring boot": ("spring", "spring_boot"),
    "express": ("expressjs", "express"),
    "react": ("reactjs", "react"),
    "angular": ("angularjs", "angular.js"),
    "jquery": ("jquery", "jquery"),
    "bootstrap": ("getbootstrap", "bootstrap"),
    "vue": ("vuejs", "vue.js"),
    "next.js": ("next.js", "next.js"),
    "nuxt": ("nuxt", "nuxt.js"),
    # --- CMS ---
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla"),
    "typo3": ("typo3", "typo3"),
    "magento": ("adobe", "magento"),
    "prestashop": ("prestashop", "prestashop"),
    "shopify": ("shopify", "shopify"),
    "wix": ("wix", "wix"),
    "concrete5": ("concretecms", "concrete_cms"),
    "craftcms": ("craftcms", "craft_cms"),
    "ghost": ("ghost", "ghost"),
    "strapi": ("strapi", "strapi"),
    "umbraco": ("umbraco", "umbraco_cms"),
    # --- SSL/TLS ---
    "openssl": ("openssl", "openssl"),
    "gnutls": ("gnutls", "gnutls"),
    "libressl": ("openbsd", "libressl"),
    "mbed tls": ("arm", "mbed_tls"),
    # --- Windows / AD / SMB ---
    "windows": ("microsoft", "windows"),
    "windows server": ("microsoft", "windows_server"),
    "samba": ("samba", "samba"),
    "smbd": ("samba", "samba"),
    "netbios": ("microsoft", "netbios"),
    "exchange": ("microsoft", "exchange_server"),
    "microsoft exchange": ("microsoft", "exchange_server"),
    "sharepoint": ("microsoft", "sharepoint_server"),
    "active directory": ("microsoft", "active_directory"),
    "skype": ("microsoft", "skype_for_business"),
    # --- Virtualization ---
    "vmware": ("vmware", "vcenter_server"),
    "vmware esxi": ("vmware", "esxi"),
    "esxi": ("vmware", "esxi"),
    "virtualbox": ("oracle", "vm_virtualbox"),
    "qemu": ("qemu", "qemu"),
    "xen": ("xen", "xen"),
    "kvm": ("linux-kvm", "kvm"),
    "docker": ("docker", "docker"),
    "kubernetes": ("kubernetes", "kubernetes"),
    # --- Network devices ---
    "cisco ios": ("cisco", "ios"),
    "cisco ios xe": ("cisco", "ios_xe"),
    "cisco nx-os": ("cisco", "nx-os"),
    "cisco asa": ("cisco", "adaptive_security_appliance"),
    "juniper junos": ("juniper", "junos"),
    "arubaos": ("arubanetworks", "arubaos"),
    "fortios": ("fortinet", "fortios"),
    "palo alto": ("paloaltonetworks", "pan-os"),
    "f5 big-ip": ("f5", "big-ip"),
    "citrix netscaler": ("citrix", "netscaler"),
    # --- IoT / embedded ---
    "busybox": ("busybox", "busybox"),
    "dropbear ssh": ("dropbear_ssh_project", "dropbear_ssh"),
    "miniupnpd": ("miniupnp_project", "miniupnpd"),
    "thttpd": ("acme", "thttpd"),
    "mini_httpd": ("acme", "mini_httpd"),
    "goahead": ("embedthis", "goahead"),
    "boa": ("boa", "boa"),
    "micro_httpd": ("acme", "micro_httpd"),
    # --- Other ---
    "jenkins": ("jenkins", "jenkins"),
    "gitlab": ("gitlab", "gitlab"),
    "confluence": ("atlassian", "confluence"),
    "jira": ("atlassian", "jira"),
    "bitbucket": ("atlassian", "bitbucket"),
    "artifactory": ("jfrog", "artifactory"),
    "nexus": ("sonatype", "nexus"),
    "grafana": ("grafana", "grafana"),
    "prometheus": ("prometheus", "prometheus"),
    "splunk": ("splunk", "splunk"),
    "elastic": ("elastic", "elasticsearch"),
    "kibana": ("elastic", "kibana"),
    "logstash": ("elastic", "logstash"),
    "zabbix": ("zabbix", "zabbix"),
    "nagios": ("nagios", "nagios"),
    "cacti": ("cacti", "cacti"),
    "phpmyadmin": ("phpmyadmin", "phpmyadmin"),
    "adminer": ("adminer", "adminer"),
    "roundcube": ("roundcube", "webmail"),
    "owncloud": ("owncloud", "owncloud"),
    "nextcloud": ("nextcloud", "nextcloud"),
    "vnc": ("realvnc", "vnc"),
    "tightvnc": ("tightvnc", "tightvnc"),
    "tigervnc": ("tigervnc", "tigervnc"),
    "ultravnc": ("ultravnc", "ultravnc"),
    "x11": ("x.org", "x11"),
    "xrdp": ("neutrinolabs", "xrdp"),
    "freerdp": ("freerdp", "freerdp"),
    "rdesktop": ("rdesktop", "rdesktop"),
    "telnet": ("telnetd_project", "telnetd"),
    "krb5": ("mit", "kerberos"),
    "heimdal": ("heimdal_project", "heimdal"),
    # --- FTP variants ---
    "proftp": ("proftpd", "proftpd"),
    "pureftp": ("pureftpd", "pure-ftpd"),
    "pure-ftp": ("pureftpd", "pure-ftpd"),
    "wu-ftpd": ("washington_university", "wu-ftpd"),
    "serv-u": ("solarwinds", "serv-u"),
    "cerberus ftp": ("cerberusftp", "cerberus_ftp"),
}

# Common service names that map to product names for CPE lookup
_SERVICE_TO_PRODUCT: dict[str, str] = {
    "ssh": "openssh",
    "ftp": "proftpd",
    "http": "apache httpd",
    "https": "apache httpd",
    "mysql": "mysql",
    "postgresql": "postgresql",
    "ms-sql-s": "microsoft sql",
    "redis": "redis",
    "mongodb": "mongodb",
    "smtp": "postfix",
    "pop3": "dovecot",
    "imap": "dovecot",
    "telnet": "telnet",
    "vnc": "vnc",
    "rdp": "xrdp",
    "ms-wbt-server": "xrdp",
    "domain": "bind",
    "snmp": "net-snmp",
    "ldap": "openldap",
    "nfs": "nfs-utils",
    "microsoft-ds": "samba",
    "netbios-ssn": "samba",
}


def _lookup_cpe(product: str) -> tuple[str, str]:
    """Resolve a product name to a (vendor, product) CPE pair."""
    key = product.lower().strip()
    if key in _CPE_MAP:
        return _CPE_MAP[key]
    if key in _SERVICE_TO_PRODUCT:
        mapped = _SERVICE_TO_PRODUCT[key]
        if mapped in _CPE_MAP:
            return _CPE_MAP[mapped]
    return ("", "")


# ---------------------------------------------------------------------------
# Version extraction from all pipeline sources
# ---------------------------------------------------------------------------

_SKIP_PRODUCTS = {
    "linux",
    "ubuntu",
    "debian",
    "windows",
    "http",
    "https",
    "tcp",
    "udp",
    "http-proxy",
    "unknown",
    "ppp",
    "tcpwrapped",
    "ssl/http",
    "http-alt",
    "upnp",
    "wsman",
    "ws-management",
    "rpcbind",
    "sunrpc",
    "msrpc",
    "java-rmi",
    "rmiregistry",
}

# Regex patterns for version extraction from free text
_VERSION_RE = re.compile(
    r"(?P<product>[A-Za-z][A-Za-z0-9_.\s/-]{2,40}?)\s+"
    r"(?P<version>\d+\.\d+(?:\.\d+)*(?:[a-z]\d*)?(?:\.[a-z]\d*)*)",
    re.IGNORECASE,
)

# Specific banner patterns per tool
_SSH_BANNER = re.compile(r"SSH-\d+\.\d+-([A-Za-z][\w._]+)(?:\s+|$)", re.I)
_FTP_BANNER = re.compile(r"(?:220|FTP).*?([A-Za-z][\w.]+)\s+(?:Version\s+)?(\d+\.\d[\d.]*)", re.I)
_SMTP_BANNER = re.compile(r"220\s+.*?([A-Za-z][\w.]+)\s+.*?(\d+\.\d[\d.]*)", re.I)
_WINDOWS_VER = re.compile(r"Windows\s+(?:Server\s+)?(\d[\d.]*)\s*(?:Build\s+)?(\d+)", re.I)
_SAMBA_VER = re.compile(r"(?:Samba|Server)\s+(?:version\s+)?(\d+\.\d[\d.]*)", re.I)
_CISCO_VER = re.compile(
    r"Cisco\s+(?:IOS(?:\s+XE)?|NX-OS|ASA)\s+(?:Software\s+)?(?:Version\s+)?([\d.()A-Za-z]+)", re.I
)


def _extract_versions_from_ports(host: Host) -> list[VersionInfo]:
    """Extract versions from Port.service (nmap -sV + fingerprintx)."""
    versions: list[VersionInfo] = []
    for port in host.open_ports:
        if not port.service or not port.service.product:
            continue
        product = port.service.product.strip()
        if product.lower() in _SKIP_PRODUCTS:
            continue
        version = port.service.version.strip() if port.service.version else ""
        if not version:
            # Product-only service (e.g. "redis") — still useful for CVE search
            # but less precise
            continue
        cpe_vendor, cpe_product = _lookup_cpe(product)
        versions.append(
            VersionInfo(
                product=product,
                version=version,  # FULL version string preserved
                port=str(port.number),
                source="nmap",
                cpe_vendor=cpe_vendor,
                cpe_product=cpe_product,
            )
        )
    return versions


def _extract_versions_from_technologies(host: Host) -> list[VersionInfo]:
    """Extract versions from host.technologies (httpx tech-detect)."""
    versions: list[VersionInfo] = []
    for tech in host.technologies:
        if not tech.name or tech.name.lower() in _SKIP_PRODUCTS:
            continue
        if not tech.version:
            continue
        product = tech.name.strip()
        port = ""
        if tech.url:
            m = re.search(r":(\d+)", tech.url)
            if m:
                port = m.group(1)
        cpe_vendor, cpe_product = _lookup_cpe(product)
        versions.append(
            VersionInfo(
                product=product,
                version=tech.version,
                port=port,
                source="httpx",
                cpe_vendor=cpe_vendor,
                cpe_product=cpe_product,
            )
        )
    return versions


def _extract_versions_from_findings(findings: list[Finding]) -> list[VersionInfo]:
    """Extract version data from findings produced by various tools.

    Each tool stores version info differently — MSF in structured [*] lines,
    service_enum in banner strings, WPScan with explicit version fields, etc.
    This function dispatches to tool-specific parsers based on finding.source.
    """
    versions: list[VersionInfo] = []

    for f in findings:
        if f.source == "msf_scan":
            versions.extend(_parse_msf_finding(f))
        elif f.source == "service_enum":
            versions.extend(_parse_service_enum_finding(f))
        elif f.source == "wpscan":
            versions.extend(_parse_wpscan_finding(f))
        elif f.source == "enum4linux":
            versions.extend(_parse_enum4linux_finding(f))
        elif f.source == "netexec":
            versions.extend(_parse_netexec_finding(f))
        elif f.source == "snmp_enum":
            versions.extend(_parse_snmp_finding(f))
        elif f.source == "sslscan":
            versions.extend(_parse_tls_finding(f))
        elif f.source == "ldap_enum":
            versions.extend(_parse_ldap_finding(f))

    return versions


# ---------------------------------------------------------------------------
# Tool-specific finding parsers
# ---------------------------------------------------------------------------


def _parse_msf_finding(f: Finding) -> list[VersionInfo]:
    """Extract version info from MSF scanner findings.

    MSF version scanner titles look like:
      "MSF ssh_version: SSH server version: OpenSSH 9.6p1"
      "MSF smb_version: Host is running Windows 10 Pro build 19045"
      "MSF mysql_version: 8.0.36"
    """
    title = f.title
    port = f.port or ""

    # SSH version
    m = re.search(r"SSH.*?(?:version|server)[:\s]+([A-Za-z][\w._]+)\s*[\d.]+", title, re.I)
    if not m:
        m = re.search(r"(OpenSSH[\w._]*|Dropbear[\w._]*)\s*(\d+\.\d[\d.]*)", title, re.I)
    if m:
        product = m.group(1).strip()
        ver = m.group(2) if m.lastindex is not None and m.lastindex >= 2 else ""
        ver2 = re.search(r"(\d+\.\d[\d.p]*)", title)
        if ver2 and (not ver or ver2.group(1) != ver):
            ver = ver2.group(1) if ver2 else ver
        cpe_v, cpe_p = _lookup_cpe(product)
        return [
            VersionInfo(
                product=product,
                version=ver,
                port=port,
                source="msf",
                cpe_vendor=cpe_v,
                cpe_product=cpe_p,
            )
        ]

    # SMB / Windows version
    m = re.search(r"(?:running|Host is running)\s+(.+?)(?:\s*$|\s*\[)", title, re.I)
    if m:
        os_str = m.group(1).strip()
        m2 = _WINDOWS_VER.search(os_str)
        if m2:
            ver = (
                f"{m2.group(1)}.{m2.group(2)}"
                if m2.lastindex is not None and m2.lastindex >= 2
                else m2.group(1)
            )
            cpe_v, cpe_p = _lookup_cpe("windows")
            return [
                VersionInfo(
                    product="Windows",
                    version=ver,
                    port=port,
                    source="msf",
                    cpe_vendor=cpe_v,
                    cpe_product=cpe_p,
                )
            ]
        m3 = _SAMBA_VER.search(os_str)
        if m3:
            cpe_v, cpe_p = _lookup_cpe("samba")
            return [
                VersionInfo(
                    product="Samba",
                    version=m3.group(1),
                    port=port,
                    source="msf",
                    cpe_vendor=cpe_v,
                    cpe_product=cpe_p,
                )
            ]

    # Generic version: "MSF mysql_version: 8.0.36" or "MSF ftp_version: ProFTPD 1.3.5"
    m = re.search(r":\s+(.+?)\s+(\d+\.\d[\d.]*)", title)
    if m:
        product = m.group(1).strip()
        ver = m.group(2)
        cpe_v, cpe_p = _lookup_cpe(product)
        return [
            VersionInfo(
                product=product,
                version=ver,
                port=port,
                source="msf",
                cpe_vendor=cpe_v,
                cpe_product=cpe_p,
            )
        ]

    # Bare version only: "MSF mysql_version: 8.0.36"
    m = re.search(r":\s+(\d+\.\d[\d.]*)", title)
    if m:
        ver = m.group(1)
        # Try to infer product from module path
        mod = f.template_id or ""
        product = mod.split("/")[-1].replace("_version", "").replace("_", " ")
        cpe_v, cpe_p = _lookup_cpe(product)
        return [
            VersionInfo(
                product=product,
                version=ver,
                port=port,
                source="msf",
                cpe_vendor=cpe_v,
                cpe_product=cpe_p,
            )
        ]

    return []


def _parse_service_enum_finding(f: Finding) -> list[VersionInfo]:
    """Extract version from service_enum banner findings.

    Titles look like:
      "SSH: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.15"
      "MySQL: 8.0.36-0ubuntu0.22.04.1"
      "FTP: 220 ProFTPD 1.3.5 Server"
      "SMTP: 220 mail.example.com ESMTP Postfix (Ubuntu)"
    """
    title = f.title
    port = f.port or ""

    # SSH banner: "SSH: SSH-2.0-OpenSSH_9.6p1 ..."
    m = _SSH_BANNER.search(title)
    if m:
        product = m.group(1).replace("_", " ")
        m2 = re.search(rf"{re.escape(m.group(1))}[_/\s]+(\d+\.\d[\d.p]*)", title)
        ver = m2.group(1) if m2 else ""
        cpe_v, cpe_p = _lookup_cpe(product)
        return [
            VersionInfo(
                product=product,
                version=ver,
                port=port,
                source="service_enum",
                cpe_vendor=cpe_v,
                cpe_product=cpe_p,
            )
        ]

    # FTP banner: "FTP: 220 ProFTPD 1.3.5 ..."
    m = _FTP_BANNER.search(title)
    if m:
        product = m.group(1).strip()
        ver = m.group(2)
        cpe_v, cpe_p = _lookup_cpe(product)
        return [
            VersionInfo(
                product=product,
                version=ver,
                port=port,
                source="service_enum",
                cpe_vendor=cpe_v,
                cpe_product=cpe_p,
            )
        ]

    # SMTP banner
    m = _SMTP_BANNER.search(title)
    if m:
        product = m.group(1).strip()
        ver = m.group(2)
        cpe_v, cpe_p = _lookup_cpe(product)
        return [
            VersionInfo(
                product=product,
                version=ver,
                port=port,
                source="service_enum",
                cpe_vendor=cpe_v,
                cpe_product=cpe_p,
            )
        ]

    # Generic "PRODUCT: version" pattern from service_enum titles
    m = re.match(r"([A-Za-z]+):\s+(.+?)(\d+\.\d[\d.]*)", title)
    if m:
        svc = m.group(1)
        detail = m.group(2).strip()
        ver = m.group(3)
        # Try to find product name in detail
        product = svc  # default to service name
        m2 = _VERSION_RE.search(detail + " " + ver)
        if not m2:
            # Look for known product keywords
            for known in _CPE_MAP:
                if known.lower() in detail.lower() or known.lower() in title.lower():
                    product = known
                    break
        cpe_v, cpe_p = _lookup_cpe(product)
        return [
            VersionInfo(
                product=product,
                version=ver,
                port=port,
                source="service_enum",
                cpe_vendor=cpe_v,
                cpe_product=cpe_p,
            )
        ]

    return []


def _parse_wpscan_finding(f: Finding) -> list[VersionInfo]:
    """Extract version from WPScan findings.

    Titles: "WordPress Version: 6.5.3", "WP Plugin: woocommerce 8.9.1",
    "WP Theme: twentytwentyfour", "WP Vuln: ..."
    """
    title = f.title
    port = f.port or ""

    # WordPress core version
    m = re.search(r"WordPress\s+Version:\s+(\d+\.\d[\d.]*)", title, re.I)
    if m:
        cpe_v, cpe_p = _lookup_cpe("wordpress")
        return [
            VersionInfo(
                product="WordPress",
                version=m.group(1),
                port=port,
                source="wpscan",
                cpe_vendor=cpe_v,
                cpe_product=cpe_p,
            )
        ]

    # Plugin version
    m = re.search(r"WP\s+Plugin:\s+(\S+)\s+(\d+\.\d[\d.]*)", title, re.I)
    if m:
        plugin = m.group(1)
        ver = m.group(2)
        return [
            VersionInfo(
                product=f"WordPress Plugin: {plugin}", version=ver, port=port, source="wpscan"
            )
        ]

    # Theme
    m = re.search(r"WP\s+Theme:\s+(\S+)", title, re.I)
    if m:
        theme = m.group(1)
        return [
            VersionInfo(product=f"WordPress Theme: {theme}", version="", port=port, source="wpscan")
        ]

    return []


def _parse_enum4linux_finding(f: Finding) -> list[VersionInfo]:
    """Extract OS/Samba version from enum4linux findings.

    Titles: "SMB OS Detection: Windows 10 19041"
    Description contains: "OS=[Windows 10 19041]\nSamba/Server version: Samba 4.15"
    """
    desc = f.description or ""
    title = f.title or ""

    versions: list[VersionInfo] = []
    combined = title + "\n" + desc

    # Windows version
    m = _WINDOWS_VER.search(combined)
    if m:
        ver = f"{m.group(1)}.{m.group(2)}" if m.lastindex and m.lastindex >= 2 else m.group(1)
        cpe_v, cpe_p = _lookup_cpe("windows")
        versions.append(
            VersionInfo(
                product="Windows",
                version=ver,
                port="445",
                source="enum4linux",
                cpe_vendor=cpe_v,
                cpe_product=cpe_p,
            )
        )

    # Samba version
    m = _SAMBA_VER.search(combined)
    if m:
        cpe_v, cpe_p = _lookup_cpe("samba")
        versions.append(
            VersionInfo(
                product="Samba",
                version=m.group(1),
                port="445",
                source="enum4linux",
                cpe_vendor=cpe_v,
                cpe_product=cpe_p,
            )
        )

    return versions


def _parse_netexec_finding(f: Finding) -> list[VersionInfo]:
    """Extract OS version from NetExec findings.

    Titles: "SMB OS Detection: Windows 10.0 Build 19045"
    """
    title = f.title
    m = _WINDOWS_VER.search(title)
    if m:
        ver = f"{m.group(1)}.{m.group(2)}" if m.lastindex and m.lastindex >= 2 else m.group(1)
        cpe_v, cpe_p = _lookup_cpe("windows")
        return [
            VersionInfo(
                product="Windows",
                version=ver,
                port=f.port or "445",
                source="netexec",
                cpe_vendor=cpe_v,
                cpe_product=cpe_p,
            )
        ]
    return []


def _parse_snmp_finding(f: Finding) -> list[VersionInfo]:
    """Extract device/OS version from SNMP findings.

    Titles: "SNMP sysDescr: Cisco IOS XE Software, Version 17.3.4"
    """
    title = f.title
    desc = f.description or ""
    combined = title + "\n" + desc

    # Cisco
    m = _CISCO_VER.search(combined)
    if m:
        product = "Cisco IOS"
        if "xe" in combined.lower():
            product = "Cisco IOS XE"
        elif "nx-os" in combined.lower():
            product = "Cisco NX-OS"
        elif "asa" in combined.lower():
            product = "Cisco ASA"
        cpe_v, cpe_p = _lookup_cpe(product.lower())
        return [
            VersionInfo(
                product=product,
                version=m.group(1),
                port="161",
                source="snmp",
                cpe_vendor=cpe_v,
                cpe_product=cpe_p,
            )
        ]

    # Generic: try VERSION_RE extraction
    m = _VERSION_RE.search(combined)
    if m:
        product = m.group(1).strip()
        ver = m.group(2)
        cpe_v, cpe_p = _lookup_cpe(product)
        return [
            VersionInfo(
                product=product,
                version=ver,
                port="161",
                source="snmp",
                cpe_vendor=cpe_v,
                cpe_product=cpe_p,
            )
        ]

    return []


def _parse_tls_finding(f: Finding) -> list[VersionInfo]:
    """Extract TLS-related version info.

    SSL/TLS findings typically describe protocol/cipher weakness rather than
    product versions, but certificate info may contain server software hints.
    """
    desc = f.description or ""
    # Certificate subject/issuer may hint at server software
    for known in ("nginx", "apache", "iis", "tomcat", "haproxy"):
        if known.lower() in desc.lower():
            cpe_v, cpe_p = _lookup_cpe(known)
            return [
                VersionInfo(
                    product=known,
                    version="",
                    port=f.port or "443",
                    source="sslscan",
                    cpe_vendor=cpe_v,
                    cpe_product=cpe_p,
                )
            ]
    return []


def _parse_ldap_finding(f: Finding) -> list[VersionInfo]:
    """Extract LDAP server version from findings.

    Titles: "LDAP namingContexts: DC=domain,DC=com"
    Description may contain vendorName/vendorVersion from root DSE.
    """
    desc = f.description or ""
    # rootDSE vendor info
    for known in (
        "Active Directory",
        "OpenLDAP",
        "389 Directory",
        "ApacheDS",
        "Novell",
        "eDirectory",
        "Oracle Directory",
        "Sun ONE",
    ):
        if known.lower() in desc.lower():
            cpe_v, cpe_p = _lookup_cpe(known)
            return [
                VersionInfo(
                    product=known,
                    version="",
                    port=f.port or "389",
                    source="ldap",
                    cpe_vendor=cpe_v,
                    cpe_product=cpe_p,
                )
            ]
    return []


# ---------------------------------------------------------------------------
# Unified version collection — the single entry point
# ---------------------------------------------------------------------------


def collect_all_versions(host: Host, findings: list[Finding]) -> list[VersionInfo]:
    """Collect version data from ALL pipeline sources for a single host.

    Returns a deduplicated list of VersionInfo objects sorted by product name.
    This replaces the old _collect_versions() which only tapped nmap + httpx.
    """
    all_versions: list[VersionInfo] = []

    # Structured sources (direct dataclass fields)
    all_versions.extend(_extract_versions_from_ports(host))
    all_versions.extend(_extract_versions_from_technologies(host))

    # Finding-based sources (version data in unstructured text)
    all_versions.extend(_extract_versions_from_findings(findings))

    # Deduplicate by (product, version, port)
    seen: set[str] = set()
    deduped: list[VersionInfo] = []
    for v in all_versions:
        key = f"{v.product.lower()}|{v.version}|{v.port}"
        if key not in seen:
            seen.add(key)
            deduped.append(v)

    return sorted(deduped, key=lambda v: v.product.lower())


def build_cpe_uri(v: VersionInfo) -> str:
    """Build a CPE 2.3 formatted URI string for NVD API queries.

    Format: cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*
    """
    if v.cpe_vendor and v.cpe_product:
        return f"cpe:2.3:a:{v.cpe_vendor}:{v.cpe_product}:{v.version}:*:*:*:*:*:*:*"
    return ""


# ---------------------------------------------------------------------------
# NVD API 2.0 client
# ---------------------------------------------------------------------------

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def _query_nvd_cpe(
    cpe_uri: str,
    api_key: str = "",
    session: aiohttp.ClientSession | None = None,
) -> list[dict]:
    """Query NVD API 2.0 for CVEs matching a CPE URI.

    Without an API key, the NVD rate limit is 5 requests per 30 seconds.
    With an API key, it's 50 requests per 30 seconds.
    """
    import aiohttp

    params: dict[str, str] = {
        "cpeName": cpe_uri,
        "resultsPerPage": "20",
    }
    headers: dict[str, str] = {"User-Agent": "WireGhost/2.0"}
    if api_key:
        headers["apiKey"] = api_key

    own_session = session is None
    if own_session:
        session_obj = aiohttp.ClientSession(headers=headers)
    else:
        session_obj = session

    try:
        async with session_obj.get(
            NVD_API_BASE, params=params, timeout=aiohttp.ClientTimeout(total=30)
        ) as resp:  # type: ignore[union-attr]
            if resp.status != 200:
                log.debug("NVD API returned %d for CPE %s", resp.status, cpe_uri)
                return []
            data = await resp.json()
    except Exception as exc:
        log.debug("NVD API request failed for %s: %s", cpe_uri, exc)
        return []
    finally:
        if own_session:
            await session_obj.close()

    cves: list[dict] = []
    for vuln in data.get("vulnerabilities", []):
        cve_data = vuln.get("cve", {})
        cve_id = cve_data.get("id", "")
        if not cve_id:
            continue

        # Extract CVSS v3.1 score (preferred) or v3.0 or v2.0
        metrics = cve_data.get("metrics", {})
        cvss_score = ""
        cvss_severity = ""
        cvss_vector = ""

        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = str(cvss_data.get("baseScore", ""))
                cvss_severity = cvss_data.get("baseSeverity", "")
                cvss_vector = cvss_data.get("vectorString", "")
                break

        # Extract CWE
        weaknesses = cve_data.get("weaknesses", [])
        cwe = ""
        if weaknesses:
            cwe_list = weaknesses[0].get("description", [])
            if cwe_list:
                cwe = cwe_list[0].get("value", "")

        # Description
        descriptions = cve_data.get("descriptions", [])
        desc_text = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc_text = d.get("value", "")
                break

        # Exploitability score
        exp_score = ""
        for metric_key in ("cvssMetricV31", "cvssMetricV30"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                exp_score = str(metric_list[0].get("exploitabilityScore", ""))
                break

        cves.append(
            {
                "id": cve_id,
                "description": desc_text[:500],
                "cvss_score": cvss_score,
                "cvss_severity": cvss_severity,
                "cvss_vector": cvss_vector,
                "cwe": cwe,
                "exploitability_score": exp_score,
                "published": cve_data.get("published", ""),
            }
        )

    return cves


async def _query_nvd_keyword(
    keyword: str,
    api_key: str = "",
    session: aiohttp.ClientSession | None = None,
) -> list[dict]:
    """Query NVD API 2.0 by keyword search (fallback when no CPE match)."""
    import aiohttp

    params: dict[str, str] = {
        "keywordSearch": keyword,
        "resultsPerPage": "10",
    }
    headers: dict[str, str] = {"User-Agent": "WireGhost/2.0"}
    if api_key:
        headers["apiKey"] = api_key

    own_session = session is None
    if own_session:
        session_obj = aiohttp.ClientSession(headers=headers)
    else:
        session_obj = session

    try:
        async with session_obj.get(
            NVD_API_BASE, params=params, timeout=aiohttp.ClientTimeout(total=30)
        ) as resp:  # type: ignore[union-attr]
            if resp.status != 200:
                return []
            data = await resp.json()
    except Exception as exc:
        log.debug("NVD API keyword search failed for %s: %s", keyword, exc)
        return []
    finally:
        if own_session:
            await session_obj.close()

    cves: list[dict] = []
    for vuln in data.get("vulnerabilities", []):
        cve_data = vuln.get("cve", {})
        cve_id = cve_data.get("id", "")
        if not cve_id:
            continue

        metrics = cve_data.get("metrics", {})
        cvss_score = ""
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = str(cvss_data.get("baseScore", ""))
                break

        weaknesses = cve_data.get("weaknesses", [])
        cwe = ""
        if weaknesses:
            cwe_list = weaknesses[0].get("description", [])
            if cwe_list:
                cwe = cwe_list[0].get("value", "")

        descriptions = cve_data.get("descriptions", [])
        desc_text = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc_text = d.get("value", "")
                break

        cves.append(
            {
                "id": cve_id,
                "description": desc_text[:300],
                "cvss_score": cvss_score,
                "cwe": cwe,
                "published": cve_data.get("published", ""),
            }
        )

    return cves


def _severity_from_cvss(score: str) -> Severity:
    """Convert CVSS numeric score to severity level."""
    try:
        s = float(score)
    except (ValueError, TypeError):
        return Severity.INFO
    if s >= 9.0:
        return Severity.CRITICAL
    if s >= 7.0:
        return Severity.HIGH
    if s >= 4.0:
        return Severity.MEDIUM
    if s >= 0.1:
        return Severity.LOW
    return Severity.INFO


# ---------------------------------------------------------------------------
# Main entry point — enhanced CVE search for a single host
# ---------------------------------------------------------------------------


async def scan_cve_search(
    host: Host,
    findings: list[Finding],
    config: ScanConfig,
) -> list[Finding]:
    """Run enhanced CVE search against NVD API for all detected versions.

    Collects versions from ALL pipeline tools, generates CPE queries, and
    queries the NVD API. Returns enriched Finding objects with CVSS scores,
    CWE IDs, and CVE references.

    This runs alongside (not instead of) searchsploit/getsploit — NVD provides
    comprehensive CVE data with CVSS scores, while searchsploit/getsploit
    provide exploit availability info.
    """
    api_key = config.nvd_api_key or os.environ.get("NVD_API_KEY", "")
    if not api_key:
        log.info(
            "[%s] NVD_API_KEY not set — skipping NVD CVE search "
            "(set for higher rate limits: 50 vs 5 req/30s)",
            host.ip,
        )
        # Still run without key — just slower (rate-limited to 5 req/30s)
        # We'll use keyword search only to avoid hitting rate limits on CPE queries

    versions = collect_all_versions(host, findings)
    if not versions:
        log.debug("[%s] No version data found for CVE search", host.ip)
        return []

    log.info(
        "[%s] CVE search: %d version(s) across %d source(s)",
        host.ip,
        len(versions),
        len({v.source for v in versions}),
    )

    new_findings: list[Finding] = []
    seen_cves: set[str] = set()
    sem = asyncio.Semaphore(5)  # limit concurrent NVD requests

    async def _search_version(v: VersionInfo) -> list[Finding]:
        results: list[Finding] = []

        async with sem:
            cpe = build_cpe_uri(v)
            if cpe and api_key:
                # With API key: precise CPE matching
                cve_list = await _query_nvd_cpe(cpe, api_key)
            elif cpe:
                # Without API key: try CPE but may hit rate limit quickly
                cve_list = await _query_nvd_cpe(cpe, api_key)
            else:
                cve_list = []

            # Fallback to keyword search if CPE didn't match anything
            if not cve_list:
                keyword = f"{v.product} {v.version}"
                cve_list = await _query_nvd_keyword(keyword, api_key)

            for cve_data in cve_list:
                cve_id = cve_data["id"]
                if cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)

                cvss = cve_data.get("cvss_score", "")
                severity = _severity_from_cvss(cvss)

                title = f"CVE-{cve_id.split('-', 2)[-1] if cve_id.startswith('CVE-') else cve_id}"
                if cvss:
                    title += f" (CVSS {cvss})"

                results.append(
                    Finding(
                        source="nvd",
                        host=host.ip,
                        port=v.port,
                        protocol="tcp",
                        severity=severity,
                        title=f"NVD: {v.product} {v.version} — {title}",
                        description=cve_data.get("description", ""),
                        cve=cve_id,
                        cvss=cvss,
                        cwe=cve_data.get("cwe", ""),
                        references=[
                            f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        ],
                        template_id=f"NVD-{v.source.upper()}-{v.product[:20]}",
                        tags=[v.source, "cve", "nvd"],
                    )
                )

            return results

    tasks = [_search_version(v) for v in versions]
    batch_results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in batch_results:
        if isinstance(result, list):
            new_findings.extend(result)
        elif isinstance(result, Exception):
            log.debug("[%s] CVE search task failed: %s", host.ip, result)

    log.info(
        "[%s] NVD CVE search: %d CVE(s) found across %d version(s)",
        host.ip,
        len(new_findings),
        len(versions),
    )
    return new_findings
