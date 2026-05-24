"""Parse sslscan --xml output into Finding objects."""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

import defusedxml.ElementTree as ET

from wireghost.models.finding import Finding
from wireghost.models.severity import Severity

log = logging.getLogger("wireghost")


_WEAK_PROTOCOLS = {"SSLv2", "SSLv3"}
_WEAK_CIPHERS = {"RC4", "DES", "NULL", "EXPORT", "RC2", "IDEA", "SEED"}


def _cipher_is_weak(cipher_name: str) -> bool:
    upper = cipher_name.upper()
    return any(w in upper for w in _WEAK_CIPHERS)


def parse_sslscan(xml_path: Path, host_ip: str, port: int) -> list[Finding]:
    """Parse sslscan XML output into Finding objects."""
    try:
        tree = ET.parse(xml_path)
    except (ET.ParseError, OSError) as exc:
        log.warning("Failed to parse sslscan XML %s: %s", xml_path, exc)
        return []

    root = tree.getroot()
    findings: list[Finding] = []
    port_str = str(port)

    for ssltest in root.iter("ssltest"):
        # --- Weak ciphers ---
        weak_ciphers: list[str] = []
        for cipher in ssltest.iter("cipher"):
            status = cipher.get("status", "")
            if status not in ("accepted", "preferred"):
                continue
            sslversion = cipher.get("sslversion", "")
            cipher_name = cipher.get("cipher", "")
            bits = cipher.get("bits", "")

            if sslversion in _WEAK_PROTOCOLS:
                weak_ciphers.append(f"{sslversion} {cipher_name} ({bits}bit)")
            elif _cipher_is_weak(cipher_name):
                weak_ciphers.append(f"{sslversion} {cipher_name} ({bits}bit)")

        if weak_ciphers:
            findings.append(
                Finding(
                    source="sslscan",
                    host=host_ip,
                    port=port_str,
                    protocol="tcp",
                    severity=Severity.HIGH,
                    title=f"Weak TLS ciphers accepted ({len(weak_ciphers)})",
                    description="Weak or deprecated ciphers:\n" + "\n".join(weak_ciphers),
                )
            )

        # --- Deprecated protocol support ---
        for protocol_tag in ("sslv2", "sslv3"):
            el = ssltest.find(protocol_tag)
            if el is not None and el.get("enabled", "0") == "1":
                proto_name = protocol_tag.upper().replace("V", "v")
                findings.append(
                    Finding(
                        source="sslscan",
                        host=host_ip,
                        port=port_str,
                        protocol="tcp",
                        severity=Severity.HIGH,
                        title=f"Deprecated protocol {proto_name} enabled",
                        description=f"{proto_name} is enabled and should be disabled.",
                    )
                )

        # --- Certificate checks ---
        for cert in ssltest.iter("certificate"):
            # Self-signed
            self_signed = cert.find("self-signed")
            if self_signed is not None and self_signed.text == "true":
                findings.append(
                    Finding(
                        source="sslscan",
                        host=host_ip,
                        port=port_str,
                        protocol="tcp",
                        severity=Severity.MEDIUM,
                        title="Self-signed TLS certificate",
                        description="The server presents a self-signed certificate.",
                    )
                )

            # Expiry
            not_after = cert.find("not-valid-after")
            if not_after is not None and not_after.text:
                try:
                    expiry = datetime.strptime(not_after.text.strip(), "%b %d %H:%M:%S %Y %Z")
                    if expiry < datetime.now():
                        findings.append(
                            Finding(
                                source="sslscan",
                                host=host_ip,
                                port=port_str,
                                protocol="tcp",
                                severity=Severity.MEDIUM,
                                title="Expired TLS certificate",
                                description=f"Certificate expired on {not_after.text.strip()}",
                            )
                        )
                except ValueError:
                    log.debug(
                        "Could not parse cert expiry date %r for %s:%d",
                        not_after.text,
                        host_ip,
                        port,
                    )

            # Weak signature
            sig_algo = cert.find("signature-algorithm")
            if sig_algo is not None and sig_algo.text:
                algo = sig_algo.text.strip().lower()
                if "md5" in algo or ("sha1" in algo and "sha1with" in algo):
                    findings.append(
                        Finding(
                            source="sslscan",
                            host=host_ip,
                            port=port_str,
                            protocol="tcp",
                            severity=Severity.MEDIUM,
                            title=f"Weak certificate signature algorithm: {sig_algo.text.strip()}",
                            description="The certificate uses a weak hash algorithm for its signature.",
                        )
                    )

        # --- Heartbleed ---
        for hb in ssltest.iter("heartbleed"):
            if hb.get("vulnerable", "0") == "1":
                sslver = hb.get("sslversion", "")
                findings.append(
                    Finding(
                        source="sslscan",
                        host=host_ip,
                        port=port_str,
                        protocol="tcp",
                        severity=Severity.CRITICAL,
                        title=f"Heartbleed vulnerability ({sslver})",
                        description="The server is vulnerable to the Heartbleed bug (CVE-2014-0160).",
                        cve="CVE-2014-0160",
                    )
                )

    return findings
