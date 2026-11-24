"""Text helpers for report output."""

from __future__ import annotations

import re

# Characters XML 1.0 cannot store: everything below 0x20 except tab/LF/CR.
_XML_ILLEGAL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
# CSI escape sequences such as the colours emitted by enum4linux/netexec.
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def xml_safe(value: str) -> str:
    """Strip ANSI escapes and control characters that XML/Word reject.

    Scanner output routinely contains both (nxc and enum4linux colour their
    output, Metasploit spools pick up binary bytes), and a single one aborts
    DOCX/XLSX generation with "All strings must be XML compatible".
    """
    if not value:
        return value
    return _XML_ILLEGAL.sub("", _ANSI_ESCAPE.sub("", value))
