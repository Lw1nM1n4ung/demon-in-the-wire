#!/usr/bin/env python3
"""Wire_Ghost IP reloader — update all config files and containers when the host IP changes.

Updates every reference to the old IP across:
  - .env                → WIREGHOST_HOST, CSRF_TRUSTED_ORIGINS
  - docker-compose.yml  → DJANGO_ALLOWED_HOSTS
  - nginx.conf          → server_name, HTTP→HTTPS redirect, auth gate redirect

Then recreates the API container (new env vars) and reloads nginx.

Usage:
  sudo python3 ip-reload.py <NEW_IP>
  sudo python3 ip-reload.py 192.168.49.202
"""

import sys
import re
import os
import shutil
import subprocess
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

FILES = {
    "env": os.path.join(BASE_DIR, ".env"),
    "compose": os.path.join(BASE_DIR, "docker-compose.yml"),
    "nginx": os.path.join(BASE_DIR, "nginx.conf"),
}


def fail(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def validate_ip(ip: str) -> None:
    parts = ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        fail(f"'{ip}' is not a valid IPv4 address")


def read_file(path: str) -> str:
    if not os.path.exists(path):
        fail(f"file not found: {path}")
    with open(path) as f:
        return f.read()


def write_file(path: str, content: str) -> None:
    bak = path + ".bak"
    shutil.copy2(path, bak)
    with open(path, "w") as f:
        f.write(content)
    print(f"  ✓ wrote {path}  (backup: {bak})")


def get_old_ip() -> str:
    """Read the current WIREGHOST_HOST from .env to determine the old IP."""
    try:
        with open(FILES["env"]) as f:
            for line in f:
                if line.startswith("WIREGHOST_HOST="):
                    ip = line.strip().split("=", 1)[1].strip()
                    if ip:
                        return ip
    except OSError:
        pass
    fail("could not read WIREGHOST_HOST from .env — is this a Wire_Ghost deployment?")


def update_env(old: str, new: str) -> bool:
    """Replace old IP with new IP in .env (WIREGHOST_HOST + CSRF_TRUSTED_ORIGINS)."""
    content = read_file(FILES["env"])
    updated = content
    changed = False

    # WIREGHOST_HOST=old
    old_host = f"WIREGHOST_HOST={old}"
    new_host = f"WIREGHOST_HOST={new}"
    if old_host in updated:
        updated = updated.replace(old_host, new_host)
        print(f"  .env  WIREGHOST_HOST:  {old} → {new}")
        changed = True

    # CSRF_TRUSTED_ORIGINS=https://old  (may appear multiple times)
    old_csrf = f"https://{old}"
    new_csrf = f"https://{new}"
    if old_csrf in updated:
        updated = updated.replace(old_csrf, new_csrf)
        print(f"  .env  CSRF_TRUSTED_ORIGINS:  {old} → {new}")
        changed = True

    if changed:
        write_file(FILES["env"], updated)
    else:
        print("  .env  no changes needed")
    return changed


def update_compose(old: str, new: str) -> bool:
    """Replace old IP in DJANGO_ALLOWED_HOSTS inside docker-compose.yml."""
    content = read_file(FILES["compose"])

    # Match the DJANGO_ALLOWED_HOSTS line
    pattern = r'(DJANGO_ALLOWED_HOSTS:\s*"[^"]*)'
    match = re.search(pattern, content)
    if not match:
        fail("could not find DJANGO_ALLOWED_HOSTS in docker-compose.yml")

    old_line = match.group(0)
    old_ip_pattern = re.escape(old)
    new_line = re.sub(old_ip_pattern, new, old_line)

    if old_line == new_line:
        print("  docker-compose.yml  no changes needed (IP not found in ALLOWED_HOSTS)")
        return False

    updated = content.replace(old_line, new_line)
    print(f"  docker-compose.yml  DJANGO_ALLOWED_HOSTS:  {old} → {new}")
    write_file(FILES["compose"], updated)
    return True


def update_nginx(old: str, new: str) -> bool:
    """Replace old IP in nginx.conf (server_name + return directives)."""
    content = read_file(FILES["nginx"])
    changed = False

    # 1. server_name <old>;
    old_server = f"server_name {old};"
    new_server = f"server_name {new};"
    if old_server in content:
        content = content.replace(old_server, new_server)
        print(f"  nginx.conf  server_name:  {old} → {new}")
        changed = True

    # 2. https://<old>:<port> in return directives
    #    Match both return 301 and return 302 lines
    old_url = f"https://{old}:"
    new_url = f"https://{new}:"
    if old_url in content:
        content = content.replace(old_url, new_url)
        print(f"  nginx.conf  return https://...:  {old} → {new}")
        changed = True

    if changed:
        write_file(FILES["nginx"], content)
    else:
        print("  nginx.conf  no changes needed")
    return changed


def docker_compose(*args: str) -> None:
    """Run docker compose from BASE_DIR."""
    subprocess.run(
        ["docker", "compose", "-f", FILES["compose"], *args],
        cwd=BASE_DIR, check=True, timeout=120,
    )


def docker_exec(container: str, *args: str) -> None:
    """Run a command inside a Docker container."""
    subprocess.run(
        ["docker", "exec", container, *args],
        check=True, timeout=30,
    )


def reload_containers() -> None:
    """Recreate the API container (env var changes) and reload nginx."""
    print("\nRecreating API container...")
    docker_compose("up", "-d", "api")
    print("  ✓ API container recreated")

    print("Reloading nginx in portal container...")
    docker_exec("wireghost-portal-1", "nginx", "-s", "reload")
    print("  ✓ nginx reloaded")

    # Verify
    result = subprocess.run(
        ["docker", "exec", "wireghost-api-1", "printenv"],
        capture_output=True, text=True, timeout=10,
    )
    for line in result.stdout.splitlines():
        if "DJANGO_ALLOWED_HOSTS" in line:
            print(f"  ✓ verified: {line.strip()}")


def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <NEW_IP>")
        print(f"Example: sudo python3 {sys.argv[0]} 192.168.49.202")
        sys.exit(1)

    new_ip = sys.argv[1]
    validate_ip(new_ip)

    old_ip = get_old_ip()
    if old_ip == new_ip:
        print(f"IP is already {new_ip}. Nothing to do.")
        sys.exit(0)

    print(f"Wire_Ghost IP Reloader")
    print(f"  Old IP: {old_ip}")
    print(f"  New IP: {new_ip}")
    print(f"  Time:   {datetime.now(timezone.utc).isoformat()}")
    print()

    # Phase 1 — Update config files
    print("── Phase 1: Updating config files ──")
    any_changed = False
    any_changed |= update_env(old_ip, new_ip)
    any_changed |= update_compose(old_ip, new_ip)
    any_changed |= update_nginx(old_ip, new_ip)

    if not any_changed:
        print("\nNo files needed updating.")
        sys.exit(0)

    # Phase 2 — Reload services
    print("\n── Phase 2: Reloading services ──")
    reload_containers()

    # Phase 3 — Summary
    print(f"""
╔══════════════════════════════════════════════════════╗
║  IP reload complete                                  ║
║                                                      ║
║  Portal:  https://{new_ip}                         ║
║                                                      ║
║  Backup files saved with .bak extension.             ║
║  To revert: restore .bak files and recreate api.     ║
╚══════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    main()
