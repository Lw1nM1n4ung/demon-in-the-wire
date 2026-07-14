"""Celery task for AD Recon sessions -- 7-phase sequential tool execution."""

from __future__ import annotations

import json as json_mod
import logging
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone as dt_timezone

from celery import shared_task
from django.utils import timezone

log = logging.getLogger(__name__)


def _normalize_username(username, domain):
    """Strip the domain prefix from *username* if it already matches *domain*.

    CredentialProfile stores usernames in ``DOMAIN\\user`` format but the task
    code composes auth strings as ``domain\\user``.  If the stored value
    already has the right domain prefix we strip it to avoid a double prefix
    (e.g. ``asa-myanmar\\asa-myanmar\\vaptuser01``) which breaks NTLM auth.
    """
    if username and "\\" in username:
        parts = username.split("\\", 1)
        if parts[0].upper() == (domain or "").upper():
            return parts[1]
    return username


def _parse_ldap_timestamp(value):
    """Convert a Windows LDAP filetime (100-ns ticks since 1601-01-01) to a
    timezone-aware UTC datetime.  Returns *None* for 0, sentinel values, or
    unparseable input."""
    if not value:
        return None
    try:
        ts = int(value)
        if ts == 0 or ts == 9223372036854775807:  # never / infinity
            return None
        return datetime(1601, 1, 1, tzinfo=dt_timezone.utc) + timedelta(microseconds=ts / 10)
    except (ValueError, OverflowError, OSError):
        return None


def _get_dns_domain_from_json(tmpdir):
    """Extract the DNS domain from ldapdomaindump JSON output.

    ldapdomaindump writes JSON entries with a top-level ``dn`` field:
    ``CN=Admin,OU=Users,DC=asa-myanmar,DC=com``.  We parse the first entry
    from any JSON file and reconstruct the DNS domain from the DC= components.
    Returns ``None`` if no DNS domain can be extracted.
    """
    import re
    import json as json_mod

    dc_pat = re.compile(r"DC=([^,]+)", re.I)
    for fname in sorted(os.listdir(tmpdir)):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(tmpdir, fname)
        try:
            with open(fpath, "r") as fh:
                data = json_mod.load(fh)
        except (json_mod.JSONDecodeError, OSError):
            continue
        if not isinstance(data, list) or not data:
            continue
        # ldapdomaindump stores DN at both top-level "dn" and nested "attributes"/"distinguishedName"
        for entry in data[:5]:  # check first 5 entries in case some have no DN
            raw = str(entry.get("dn") or "")
            parts = dc_pat.findall(raw)
            if len(parts) >= 2:
                dns = ".".join(parts).lower()
                log.info("_get_dns_domain_from_json: discovered DNS domain '%s' from %s", dns, fname)
                return dns
    return None


def _first(entry, attr):
    """Return the first element of ``entry[\"attributes\"][attr]`` (ldapdomaindump stores
    most values as single-element lists), or the scalar value if it is not a list."""
    val = _attr(entry, attr)
    if isinstance(val, list):
        return val[0] if val else None
    return val


def _attr(entry, attr):
    """Return the value of ``attr`` from ldapdomaindump's nested ``attributes`` dict."""
    return (entry.get("attributes") or {}).get(attr)


def _bool_attr(entry, attr, predicate, default):
    """Evaluate *predicate* on an attributes value; return *default* if absent."""
    val = _first(entry, attr)
    if val is None:
        return default
    try:
        return predicate(val)
    except (TypeError, ValueError):
        return default


def _parse_ldapdomaindump(tmpdir, session):
    """Parse ldapdomaindump JSON output files and bulk-create AD model records.

    ldapdomaindump writes ``<domain>_users.json``, ``<domain>_groups.json``,
    ``<domain>_computers.json`` and ``<domain>_trusts.json`` into *tmpdir*.
    This function globs for those JSON files, maps field names from the
    ldapdomaindump schema onto the Django ORM, and bulk-creates the
    corresponding rows.  Idempotent: call it after every Phase-1 run.
    """
    from scanner.models.ad_recon import ADComputer, ADGroup, ADTrust, ADUser

    json_files = sorted(
        [f for f in os.listdir(tmpdir) if f.endswith(".json")]
    )
    log.info("_parse_ldapdomaindump: %d JSON files in %s", len(json_files), tmpdir)

    stats = {"users": 0, "groups": 0, "computers": 0, "trusts": 0}

    for fname in json_files:
        fpath = os.path.join(tmpdir, fname)
        try:
            with open(fpath, "r") as fh:
                data = json_mod.load(fh)
        except (json_mod.JSONDecodeError, OSError) as e:
            log.warning("_parse_ldapdomaindump: skipped %s -- %s", fname, e)
            continue

        if not isinstance(data, list) or not data:
            continue

        fl = fname.lower()

        if "_users" in fl:
            users = [
                ADUser(
                    session=session,
                    sam_account_name=str(_first(entry, "sAMAccountName") or ""),
                    upn=str(_first(entry, "userPrincipalName") or ""),
                    display_name=str(_first(entry, "displayName") or ""),
                    dn=str(entry.get("dn") or ""),
                    description=str(_first(entry, "description") or ""),
                    enabled=not _bool_attr(entry, "userAccountControl", lambda v: (int(v or 0) & 2) == 0, True),
                    admin_count=int(_first(entry, "adminCount") or 0),
                    last_logon=_parse_ldap_timestamp(_first(entry, "lastLogon")),
                    member_of=list(_attr(entry, "memberOf") or []),
                    pwd_last_set=_parse_ldap_timestamp(_first(entry, "pwdLastSet")),
                    spn_count=len(_attr(entry, "servicePrincipalName") or []),
                )
                for entry in data
            ]
            ADUser.objects.bulk_create(users, ignore_conflicts=True)
            stats["users"] = len(users)
            log.info("_parse_ldapdomaindump: bulk-created %d ADUser records", len(users))

        elif "_groups" in fl:
            groups = [
                ADGroup(
                    session=session,
                    name=str(_first(entry, "name") or ""),
                    sam_account_name=str(_first(entry, "sAMAccountName") or ""),
                    dn=str(entry.get("dn") or ""),
                    description=str(_first(entry, "description") or ""),
                    members=list(_attr(entry, "member") or []),
                    member_count=len(_attr(entry, "member") or []),
                    admin_count=int(_first(entry, "adminCount") or 0),
                )
                for entry in data
            ]
            ADGroup.objects.bulk_create(groups, ignore_conflicts=True)
            stats["groups"] = len(groups)
            log.info("_parse_ldapdomaindump: bulk-created %d ADGroup records", len(groups))

        elif "_computers" in fl:
            computers = [
                ADComputer(
                    session=session,
                    name=str(_first(entry, "sAMAccountName") or "").rstrip("$"),
                    dns_hostname=str(_first(entry, "dNSHostName") or ""),
                    os=str(_first(entry, "operatingSystem") or ""),
                    dn=str(entry.get("dn") or ""),
                    os_version=str(_first(entry, "operatingSystemVersion") or ""),
                    enabled=not _bool_attr(entry, "userAccountControl", lambda v: (int(v or 0) & 2) != 0, False),
                    last_logon=_parse_ldap_timestamp(_first(entry, "lastLogon")),
                    member_of=list(_attr(entry, "memberOf") or []),
                )
                for entry in data
            ]
            ADComputer.objects.bulk_create(computers, ignore_conflicts=True)
            stats["computers"] = len(computers)
            log.info("_parse_ldapdomaindump: bulk-created %d ADComputer records", len(computers))

        elif "_trusts" in fl:
            trusts = [
                ADTrust(
                    session=session,
                    source_domain=str(entry.get("SourceDomain", entry.get("sourceDomain", "")) or ""),
                    target_domain=str(entry.get("TargetDomain", entry.get("targetDomain", "")) or ""),
                    direction=str(entry.get("Direction", entry.get("direction", "")) or ""),
                    trust_type=str(entry.get("Type", entry.get("type", "")) or ""),
                    transitive=bool(entry.get("Transitive", entry.get("transitive", False))),
                )
                for entry in data
            ]
            ADTrust.objects.bulk_create(trusts, ignore_conflicts=True)
            stats["trusts"] = len(trusts)
            log.info("_parse_ldapdomaindump: bulk-created %d ADTrust records", len(trusts))

    return stats


TIMEOUTS = {
    "ldapdomaindump": 120,
    "nxc_shares": 60,
    "nxc_delegation": 60,
    "bloodhound": 300,
    "impacket_getnpusers": 120,
    "kerbrute": 60,
    "impacket_getspns": 120,
    "impacket_secretsdump": 300,
    "impacket_samrdump": 60,
    "rpcclient": 60,
    "nxc_passpol": 60,
    "nxc_ioxid": 60,
    "nxc_wmi": 60,
    "nxc_adcs": 60,
    "responder": 60,
}


def _run_tool(tool_name, cmd_args, timeout=60, env=None):
    """Run a single external tool, returning (rc, stdout, stderr).

    Returns (None, None, error_message) if the binary is missing, the
    invocation times out, or the OS fails to spawn the process -- never raises.
    """
    binary = shutil.which(cmd_args[0])
    if not binary:
        log.warning("_run_tool: %s -- binary not found (%s)", tool_name, cmd_args[0])
        return None, None, "%s: binary not found" % cmd_args[0]
    try:
        log.debug("_run_tool: %s -- running %s (timeout=%s)", tool_name, binary, timeout)
        proc = subprocess.run(
            [binary] + list(cmd_args[1:]),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            env=env,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        log.warning("_run_tool: %s -- timed out after %ss", tool_name, timeout)
        return None, None, "%s: timed out after %ss" % (cmd_args[0], timeout)
    except OSError as e:
        log.warning("_run_tool: %s -- failed to execute (%s)", tool_name, e)
        return None, None, "%s: failed to execute -- %s" % (cmd_args[0], e)


def _record_tool(tool_status, name, rc, err):
    """Add a tool-status entry to the mutable dict."""
    tool_status[name] = {
        "rc": rc,
        "error": (err or "")[:500],
        "ran_at": timezone.now().isoformat(),
    }


@shared_task(bind=True, max_retries=0, time_limit=7200, soft_time_limit=7000)
def ad_recon_task(self, session_id):
    """Execute AD recon session through 7 sequential phases.

    Phase 0 is the only hard gate -- if the connectivity check fails, the
    entire session is aborted with status='failed'. All other phases degrade
    gracefully: a missing binary, timeout, or non-zero exit for a tool is
    recorded in session.tool_status but does NOT abort the session.

    Credentials are decrypted from the CredentialProfile inline, held in local
    variables for the duration of the task, and explicitly cleared via ``del``
    in the ``finally`` block.
    """
    from scanner.models.ad_recon import ADReconSession

    session = ADReconSession.objects.select_related("profile").get(id=session_id)
    session.status = "running"
    session.started_at = timezone.now()
    session.tool_status = {}
    session.save(update_fields=["status", "started_at", "tool_status"])

    tmpdir = None
    password = None
    nt_hash = None

    try:
        profile = session.profile
        if profile:
            password = profile.decrypt_password()
            nt_hash = profile.decrypt_nt_hash()
        else:
            password = ""
            nt_hash = ""

        dc_ip = session.dc_ip
        domain = session.domain
        username = profile.username if profile else None
        # Normalize: stored usernames may already include the domain prefix
        if username:
            username = _normalize_username(username, domain)
        is_auth = session.scope == "authenticated" and username and (password or nt_hash)

        tmpdir = tempfile.mkdtemp(prefix="ad_recon_")
        ts = {}

        # ── Phase 0: Connectivity Check (HARD GATE) ──
        log.info("AD recon %s: Phase 0 -- connectivity check", session_id)
        rc, out, err = _run_tool(
            "nxc_connectivity", ["nxc", "smb", dc_ip, "--timeout", "15"], timeout=30
        )
        _record_tool(ts, "nxc_connectivity", rc, err)
        session.tool_status = ts
        session.save(update_fields=["tool_status"])

        if rc is None or (rc != 0 and "SMB" not in (out or "") + (err or "")):
            raise RuntimeError(
                "Phase 0 failed: DC %s unreachable via nxc smb (rc=%s, err=%s)"
                % (dc_ip, rc, err or out or "no output")
            )

        # ── Phase 1: LDAP Enumeration ──
        log.info("AD recon %s: Phase 1 -- LDAP enumeration", session_id)

        if is_auth:
            ldap_args = [
                "ldapdomaindump",
                "-u",
                "%s\\%s" % (domain, username),
                "-p",
                password,
                "-o",
                tmpdir,
                dc_ip,
            ]
        else:
            ldap_args = ["ldapdomaindump", dc_ip]
        rc, out, err = _run_tool(
            "ldapdomaindump",
            ldap_args,
            timeout=TIMEOUTS["ldapdomaindump"],
        )
        _record_tool(ts, "ldapdomaindump", rc, err)

        # Parse ldapdomaindump JSON output into AD models
        _parse_ldapdomaindump(tmpdir, session)

        # Auto-discover the real DNS domain from ldapdomaindump filenames.
        # session.domain is the NETBIOS name (e.g. "asa-myanmar"); bloodhound
        # needs the DNS domain (e.g. "asa-myanmar.com") for SRV resolution.
        dns_domain = _get_dns_domain_from_json(tmpdir) or domain
        log.info("AD recon %s: DNS domain=%s (NETBIOS=%s)", session_id, dns_domain, domain)

        shares_cmd = ["nxc", "smb", dc_ip]
        if is_auth:
            shares_cmd += ["-u", username, "-p", password]
        shares_cmd += ["--shares"]
        rc, out, err = _run_tool(
            "nxc_shares",
            shares_cmd,
            timeout=TIMEOUTS["nxc_shares"],
        )
        _record_tool(ts, "nxc_shares", rc, err)

        if is_auth:
            rc, out, err = _run_tool(
                "nxc_delegation",
                ["nxc", "ldap", dc_ip, "-u", username, "-p", password, "--trusted-for-delegation"],
                timeout=TIMEOUTS["nxc_delegation"],
            )
            _record_tool(ts, "nxc_delegation", rc, err)

        session.tool_status = ts
        session.save(update_fields=["tool_status"])

        # ── Phase 2: BloodHound ──
        log.info("AD recon %s: Phase 2 -- BloodHound", session_id)

        # bloodhound-python uses dnspython (NOT /etc/hosts) for DNS resolution.
        # -d needs the DNS domain (e.g. asa-myanmar.com, NOT the NETBIOS name).
        # -ns points at the DC as DNS server; --dns-tcp avoids UDP truncation.
        # Omit -dc to let bloodhound auto-discover the DC FQDN via SRV records.
        bh_args = [
            "bloodhound-python",
            "-c",
            "All",
            "--zip",
            "-d",
            dns_domain,
            "-ns",
            dc_ip,
            "--dns-tcp",
        ]
        if is_auth:
            bh_args += ["-u", "%s@%s" % (username, dns_domain), "-p", password]
            if nt_hash:
                bh_args += ["--hashes", ":%s" % nt_hash]
        rc, out, err = _run_tool(
            "bloodhound",
            bh_args,
            timeout=TIMEOUTS["bloodhound"],
        )
        _record_tool(ts, "bloodhound", rc, err)
        session.tool_status = ts
        session.save(update_fields=["tool_status"])

        # ── Phase 3: AS-REP Roasting / User Enumeration ──
        log.info("AD recon %s: Phase 3 -- AS-REP roasting / user enum", session_id)

        if is_auth:
            getnp_args = [
                "GetNPUsers.py",
                "%s/%s:%s" % (domain, username, password),
                "-request",
                "-dc-ip",
                dc_ip,
                "-format",
                "hashcat",
            ]
            rc, out, err = _run_tool(
                "impacket_getnpusers",
                getnp_args,
                timeout=TIMEOUTS["impacket_getnpusers"],
            )
            _record_tool(ts, "impacket_getnpusers", rc, err)
        else:
            rc, out, err = _run_tool(
                "kerbrute",
                [
                    "kerbrute",
                    "userenum",
                    "-d",
                    domain,
                    "--dc",
                    dc_ip,
                    "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt",
                ],
                timeout=TIMEOUTS["kerbrute"],
            )
            _record_tool(ts, "kerbrute", rc, err)

        session.tool_status = ts
        session.save(update_fields=["tool_status"])

        # ── Phase 4: Kerberoasting / Secrets Dump ──
        log.info("AD recon %s: Phase 4 -- Kerberoasting / secrets dump", session_id)

        if is_auth:
            getspn_args = [
                "GetUserSPNs.py",
                "%s/%s:%s" % (domain, username, password),
                "-request",
                "-dc-ip",
                dc_ip,
                "-outputfile",
                "%s/spns.txt" % tmpdir,
            ]
            rc, out, err = _run_tool(
                "impacket_getspns",
                getspn_args,
                timeout=TIMEOUTS["impacket_getspns"],
            )
            _record_tool(ts, "impacket_getspns", rc, err)

            sd_args = [
                "secretsdump.py",
                "%s/%s:%s@%s" % (domain, username, password, dc_ip),
                "-outputfile",
                "%s/secrets" % tmpdir,
            ]
            rc, out, err = _run_tool(
                "impacket_secretsdump",
                sd_args,
                timeout=TIMEOUTS["impacket_secretsdump"],
            )
            _record_tool(ts, "impacket_secretsdump", rc, err)

            samr_args = [
                "samrdump.py",
                "%s/%s:%s@%s" % (domain, username, password, dc_ip),
            ]
            rc, out, err = _run_tool(
                "impacket_samrdump",
                samr_args,
                timeout=TIMEOUTS["impacket_samrdump"],
            )
            _record_tool(ts, "impacket_samrdump", rc, err)

        session.tool_status = ts
        session.save(update_fields=["tool_status"])

        # ── Phase 5: RPC / Protocol Enumeration ──
        log.info("AD recon %s: Phase 5 -- RPC / protocol enum", session_id)

        if is_auth:
            rpc_commands = (
                "enumdomusers;enumdomgroups;"
                "enumalsgroups builtin;enumalsgroups domain;"
                "srvinfo;lsaquery"
            )
            rpc_args = [
                "rpcclient",
                "-U",
                "%s/%s%%%s" % (domain, username, password),
                dc_ip,
                "-c",
                rpc_commands,
            ]
            rc, out, err = _run_tool(
                "rpcclient",
                rpc_args,
                timeout=TIMEOUTS["rpcclient"],
            )
            _record_tool(ts, "rpcclient", rc, err)

        passpol_cmd = ["nxc", "smb", dc_ip, "--pass-pol"]
        if is_auth:
            passpol_cmd += ["-u", username, "-p", password]
        rc, out, err = _run_tool(
            "nxc_passpol",
            passpol_cmd,
            timeout=TIMEOUTS["nxc_passpol"],
        )
        _record_tool(ts, "nxc_passpol", rc, err)

        ioxid_cmd = ["nxc", "smb", dc_ip, "-M", "ioxidresolver"]
        if is_auth:
            ioxid_cmd += ["-u", username, "-p", password]
        rc, out, err = _run_tool(
            "nxc_ioxid",
            ioxid_cmd,
            timeout=TIMEOUTS["nxc_ioxid"],
        )
        _record_tool(ts, "nxc_ioxid", rc, err)

        if is_auth:
            wmi_cmd = ["nxc", "wmi", dc_ip, "-u", username, "-p", password]
            rc, out, err = _run_tool(
                "nxc_wmi",
                wmi_cmd,
                timeout=TIMEOUTS["nxc_wmi"],
            )
            _record_tool(ts, "nxc_wmi", rc, err)

        session.tool_status = ts
        session.save(update_fields=["tool_status"])

        # ── Phase 6: ADCS Enumeration (authenticated only) ──
        log.info("AD recon %s: Phase 6 -- ADCS enumeration", session_id)

        if is_auth:
            adcs_cmd = [
                "nxc",
                "ldap",
                dc_ip,
                "-u",
                username,
                "-p",
                password,
                "-M",
                "adcs",
            ]
            rc, out, err = _run_tool(
                "nxc_adcs",
                adcs_cmd,
                timeout=TIMEOUTS["nxc_adcs"],
            )
            _record_tool(ts, "nxc_adcs", rc, err)

        session.tool_status = ts
        session.save(update_fields=["tool_status"])

        # ── Phase 7: Responder (always runs, passive, 60s capture) ──
        log.info("AD recon %s: Phase 7 -- Responder passive capture", session_id)

        try:
            iface = (
                subprocess.run(
                    ["ip", "-o", "-4", "route", "show", "to", "default"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                .stdout.strip()
                .split()[4]
            )
        except Exception:
            iface = "eth0"

        responder_args = [
            "python3",
            "/opt/Responder/Responder.py",
            "-I",
            iface,
            "-A",
            "-v",
            "--lm",
            "--disable-ess",
        ]
        rc, out, err = _run_tool(
            "responder",
            responder_args,
            timeout=TIMEOUTS["responder"],
        )
        _record_tool(ts, "responder", rc, err)

        # ── Finalize ──
        session.status = "complete"
        session.completed_at = timezone.now()
        session.tool_status = dict(ts)
        session.save(update_fields=["status", "completed_at", "tool_status"])

        log.info("AD recon %s complete (%d tools)", session_id, len(ts))
        return {"session_id": str(session_id), "status": "complete", "tools_run": len(ts)}

    except Exception as e:
        log.exception("AD recon %s failed: %s", session_id, e)
        session.status = "failed"
        session.error = str(e)[:1000]
        session.completed_at = timezone.now()
        session.save(update_fields=["status", "error", "completed_at"])
        return {"session_id": str(session_id), "status": "failed", "error": str(e)[:500]}

    finally:
        if password:
            del password
        if nt_hash:
            del nt_hash
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)
