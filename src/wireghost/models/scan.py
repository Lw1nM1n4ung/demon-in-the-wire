"""Core scan data models: Service, Port, Host."""

from __future__ import annotations

from dataclasses import dataclass, field


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
    ports: list[Port] = field(default_factory=list)
    web_endpoints: list[str] = field(default_factory=list)
    web_titles: dict[str, str] = field(default_factory=dict)  # url → page title
    technologies: list[WebTech] = field(default_factory=list)
    os: str = ""  # OS detection from nmap -O (e.g. "Linux 5.15")
    screenshots: list[Screenshot] = field(default_factory=list)

    @property
    def open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.state == "open"]
