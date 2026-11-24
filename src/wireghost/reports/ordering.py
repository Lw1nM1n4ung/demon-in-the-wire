"""Report ordering helpers.

Assessors triage per tool, not per severity: one nuclei sweep, one MSF pass,
one searchsploit pass.  Group findings by the tool that produced them and use
severity only to order within a tool.
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

from wireghost.models.severity import SEVERITY_ORDER
from wireghost.reports.tool_output import TOOL_SPECS, _norm_source

if TYPE_CHECKING:
    from wireghost.models.finding import Finding

_LABELS: dict[str, str] = {spec["source"]: spec["label"] for spec in TOOL_SPECS}


def tool_label(source: str) -> str:
    """Human label for a Finding.source ('nuclei_external' folds into nuclei)."""
    key = _norm_source(str(source))
    return _LABELS.get(key, key)


def tool_sort_key(finding: Finding) -> tuple[str, int, str]:
    """Order by tool, then severity, then host."""
    return (
        tool_label(getattr(finding, "source", "")),
        SEVERITY_ORDER.get(finding.severity, 99),
        str(getattr(finding, "host", "")),
    )


def group_findings_by_tool(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Findings grouped under their tool label, each group severity-ordered."""
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        grouped[tool_label(getattr(finding, "source", ""))].append(finding)
    for items in grouped.values():
        items.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), str(f.host)))
    return dict(sorted(grouped.items()))
