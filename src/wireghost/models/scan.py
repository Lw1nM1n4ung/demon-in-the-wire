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
class Host:
    ip: str
    hostname: str = ""
    status: str = "up"
    ports: list[Port] = field(default_factory=list)
    web_endpoints: list[str] = field(default_factory=list)

    @property
    def open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.state == "open"]
