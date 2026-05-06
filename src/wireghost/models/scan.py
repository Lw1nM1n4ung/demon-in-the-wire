"""Core scan data models: Service, Port, Host."""

from __future__ import annotations

from dataclasses import dataclass, field

_WELL_KNOWN_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    88: "kerberos-sec",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    512: "exec",
    513: "login",
    514: "shell",
    515: "printer",
    587: "submission",
    636: "ldapssl",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1433: "ms-sql-s",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    2376: "docker",
    3268: "ldap",
    3269: "ldapssl",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5900: "vnc",
    5985: "wsman",
    5986: "wsmans",
    6379: "redis",
    6667: "irc",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}


@dataclass
class Service:
    name: str
    product: str = ""
    version: str = ""


@dataclass
class Port:
    number: int
    protocol: str = "tcp"
    state: str = "open"
    service: Service | None = None

    @property
    def service_name(self) -> str:
        """Service name from nmap -sV, falling back to well-known port heuristic."""
        if self.service and self.service.name:
            return self.service.name
        return _WELL_KNOWN_PORTS.get(self.number, "")


@dataclass
class WebTech:
    name: str       # e.g. "Apache", "nginx", "WordPress"
    version: str    # e.g. "2.4.49", "1.24"
    url: str = ""   # which endpoint detected it


@dataclass
class Screenshot:
    url: str
    filename: str
    title: str = ""
    status_code: int = 0


@dataclass
class Host:
    ip: str
    hostname: str = ""
    status: str = "up"
    mac_address: str = ""
    vendor: str = ""
    ports: list[Port] = field(default_factory=list)
    web_endpoints: list[str] = field(default_factory=list)
    web_titles: dict[str, str] = field(default_factory=dict)  # url → page title
    technologies: list[WebTech] = field(default_factory=list)
    os: str = ""  # OS detection from nmap -O (e.g. "Linux 5.15")
    screenshots: list[Screenshot] = field(default_factory=list)

    @property
    def open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.state == "open"]
