"""Parser for naabu JSON output (JSONL: one object per line)."""

from __future__ import annotations
import json
from collections import defaultdict
from pathlib import Path
from wireghost.models.scan import Host, Port


def parse_naabu_json(json_path: Path) -> list[Host]:
    """Parse naabu JSONL output into Host objects.
    Each line: {"ip":"x.x.x.x","port":N,"protocol":"tcp"}
    Group ports by IP. Return empty list on missing/empty file.
    """
    try:
        content = json_path.read_text(encoding="utf-8").strip()
    except (FileNotFoundError, OSError):
        return []
    if not content:
        return []

    ip_ports: dict[str, list[Port]] = defaultdict(list)
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        ip = item.get("ip", "")
        port_num = item.get("port")
        protocol = item.get("protocol", "tcp")
        if not ip or port_num is None:
            continue
        ip_ports[ip].append(Port(number=int(port_num), protocol=protocol, state="open"))

    return [Host(ip=ip, ports=ports) for ip, ports in sorted(ip_ports.items())]
