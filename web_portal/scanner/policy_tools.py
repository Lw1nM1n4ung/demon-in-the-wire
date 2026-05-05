"""Helpers for scan-policy tool payload normalization."""

from __future__ import annotations

from typing import Any

SUPPORTED_POLICY_BOOL_TOOLS = (
    "nmap",
    "nuclei",
    "searchsploit",
    "wpscan",
    "service_enum",
    "enum4linux",
    "nikto",
    "netexec",
)
SUPPORTED_POLICY_TEXT_TOOLS = ("nuclei_templates",)
SUPPORTED_POLICY_FLAG_TOOLS = ("nuclei_default_templates",)


def normalize_policy_tools(raw: Any) -> dict[str, Any]:
    """Return a sanitized policy tools dict with only supported keys."""
    if not isinstance(raw, dict):
        return {}

    normalized: dict[str, Any] = {}
    for key in SUPPORTED_POLICY_BOOL_TOOLS:
        if key in raw:
            normalized[key] = bool(raw[key])

    for key in SUPPORTED_POLICY_TEXT_TOOLS:
        if key in raw and raw[key] is not None:
            normalized[key] = str(raw[key]).strip()

    for key in SUPPORTED_POLICY_FLAG_TOOLS:
        if key in raw:
            normalized[key] = bool(raw[key])

    return normalized
