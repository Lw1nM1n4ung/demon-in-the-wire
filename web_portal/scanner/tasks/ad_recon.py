"""Celery task for AD Recon sessions -- 7-phase sequential tool execution."""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile

from celery import shared_task
from django.utils import timezone

log = logging.getLogger(__name__)

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

        bh_args = [
            "bloodhound-python",
            "-c",
            "All",
            "--zip",
            "-d",
            domain,
            "--dc",
            dc_ip,
        ]
        if is_auth:
            bh_args += ["-u", username, "-p", password]
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
                "impacket-GetNPUsers",
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
                "impacket-GetUserSPNs",
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
                "impacket-secretsdump",
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
                "impacket-samrdump",
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

        ioxid_cmd = ["nxc", "smb", dc_ip, "-M", "ioxid-resolver"]
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
            "responder",
            "-I",
            iface,
            "-A",
            "-wrf",
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
