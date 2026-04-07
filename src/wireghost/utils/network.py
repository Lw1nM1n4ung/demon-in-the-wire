"""Network-related utility helpers."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)


def safe_get(obj: dict[str, Any], keys: list[str], default: str = "N/A") -> Any:
    """Nested dict access following a list of keys.

    >>> safe_get({"a": {"b": 1}}, ["a", "b"])
    1
    >>> safe_get({}, ["x", "y"])
    'N/A'
    """
    current: Any = obj
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key, default)
        else:
            return default
    return current


def extract_endpoint(url: str) -> str:
    """Return the path+query portion of a URL.

    >>> extract_endpoint("https://example.com/login?next=/dash")
    '/login?next=/dash'
    """
    parsed = urlparse(url)
    endpoint = parsed.path or "/"
    if parsed.query:
        endpoint = f"{endpoint}?{parsed.query}"
    return endpoint


def is_valid_ipv4(addr: str) -> bool:
    """Check whether *addr* is a valid IPv4 address.

    >>> is_valid_ipv4("10.0.0.1")
    True
    >>> is_valid_ipv4("999.0.0.1")
    False
    """
    return bool(_IPV4_RE.match(addr))
