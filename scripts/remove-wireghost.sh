#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
# Wire_Ghost — Complete Docker Remover
#
# Usage:
#   sudo bash remove-wireghost.sh              # Interactive — prompts before each step
#   sudo bash remove-wireghost.sh --force      # Non-interactive — removes everything
#   sudo bash remove-wireghost.sh --keep-data  # Remove containers/images but keep volumes
#
# What it removes:
#   • All Wire_Ghost containers (api, worker, beat, portal, db, redis)
#   • Docker volumes (mysql_data, scan_output, report_assets)
#   • Built Docker images (wireghost api/worker/beat)
#   • Docker network (wireghost_net)
#   • Local files (certs/, logs/, backups/, .env, nginx.conf)
#   • Host mode: systemd units, Python venv, scan data directory
#   • Optionally: the entire project directory
# ══════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

# ── Flags ────────────────────────────────────────────────────────────
FORCE=false
KEEP_DATA=false

for arg in "$@"; do
    case "$arg" in
        --force)     FORCE=true ;;
        --keep-data) KEEP_DATA=true ;;
        --help|-h)   show_help; exit 0 ;;
    esac
done

# ── Colours ──────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

info()  { printf "${CYAN}[INFO]${NC}  %s\n" "$*"; }
ok()    { printf "${GREEN}[OK]${NC}    %s\n" "$*"; }
warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$*"; }
err()   { printf "${RED}[ERR]${NC}   %s\n" "$*" >&2; }

show_help() {
    printf "\n${BOLD}remove-wireghost.sh${NC} — Complete Wire_Ghost Docker Remover\n\n"
    printf "${BOLD}Usage:${NC}\n"
    printf "  sudo bash remove-wireghost.sh              Interactive mode\n"
    printf "  sudo bash remove-wireghost.sh --force      Remove everything without prompts\n"
    printf "  sudo bash remove-wireghost.sh --keep-data  Keep database and scan volumes\n\n"
    printf "${BOLD}What gets removed:${NC}\n"
    printf "  • Docker containers   (api, worker, beat, portal, db, redis)\n"
    printf "  • Docker volumes      (mysql_data, scan_output, report_assets)\n"
    printf "  • Docker images       (wireghost, nmap, nuclei, httpx)\n"
    printf "  • Docker network      (wireghost_net)\n"
    printf "  • Local files         (certs/, logs/, backups/, .env, nginx.conf)\n"
    printf "  • Project directory   (optional, interactive only)\n\n"
}

confirm() {
    local msg="$1"
    if $FORCE; then return 0; fi
    printf "  ${YELLOW}▸${NC} %s ${DIM}[y/N]${NC} " "$msg"
    read -r ans
    [[ "$ans" =~ ^[Yy] ]]
}

# ── Root check ───────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || { err "Run as root: sudo bash remove-wireghost.sh"; exit 1; }

# ── Banner ───────────────────────────────────────────────────────────
printf "\n${BOLD}${RED}"
cat <<'ART'
 __      __ _            ___  _               _
 \ \    / /(_) _ _  ___ / __|| |_   ___  ___ | |_
  \ \/\/ / | || '_|/ -_)| (_ | ' \ / _ \(_-< |  _|
   \_/\_/  |_||_|  \___| \___||_||_|\___//__/  \__|
ART
printf "${NC}\n"
printf "  ${BOLD}${RED}Complete Remover${NC}\n\n"

# ── Detect install mode ─────────────────────────────────────────────
INSTALL_MODE="docker"
if [ -f .env ]; then
    INSTALL_MODE=$(grep '^INSTALL_MODE=' .env 2>/dev/null | cut -d= -f2 || echo "docker")
    WIREGHOST_DATA_DIR=$(grep '^WIREGHOST_DATA_DIR=' .env 2>/dev/null | cut -d= -f2 || echo "")
fi
if [ "$INSTALL_MODE" = "host" ]; then
    info "Host mode installation detected"
fi

# ── Safety confirmation ──────────────────────────────────────────────
if ! $FORCE; then
    printf "${RED}${BOLD}  ⚠  WARNING: This will permanently destroy Wire_Ghost data.${NC}\n\n"
    printf "  Type ${BOLD}REMOVE${NC} to continue: "
    read -r ANSWER
    [ "$ANSWER" = "REMOVE" ] || { info "Aborted."; exit 0; }
    printf "\n"
fi

# ── Track what we cleaned ────────────────────────────────────────────
FREED_MB=0
STEPS_DONE=0

step() {
    STEPS_DONE=$((STEPS_DONE + 1))
    printf "\n${BOLD}[${STEPS_DONE}]${NC} %s\n" "$*"
}

# ══════════════════════════════════════════════════════════════════════
# Step 0: Remove host-mode services (if applicable)
# ══════════════════════════════════════════════════════════════════════
if [ "$INSTALL_MODE" = "host" ]; then
    step "Removing host-mode services"

    for unit in wireghost-beat wireghost-worker; do
        if systemctl is-enabled "$unit" 2>/dev/null; then
            systemctl stop "$unit" 2>/dev/null || true
            systemctl disable "$unit" 2>/dev/null || true
            rm -f "/etc/systemd/system/${unit}.service"
            ok "Removed systemd unit: ${unit}"
        fi
    done
    systemctl daemon-reload 2>/dev/null || true

    if [ -d "${PROJECT_DIR}/.venv" ]; then
        VENV_SIZE=$(du -sh "${PROJECT_DIR}/.venv" 2>/dev/null | cut -f1 || echo "?")
        rm -rf "${PROJECT_DIR}/.venv"
        ok "Removed Python venv (${VENV_SIZE})"
    fi

    if [ -n "$WIREGHOST_DATA_DIR" ] && [ -d "$WIREGHOST_DATA_DIR" ]; then
        if $KEEP_DATA; then
            warn "Keeping scan data at ${WIREGHOST_DATA_DIR} (--keep-data)"
        else
            DATA_SIZE=$(du -sh "$WIREGHOST_DATA_DIR" 2>/dev/null | cut -f1 || echo "?")
            if $FORCE || confirm "Remove scan data directory (${WIREGHOST_DATA_DIR}, ${DATA_SIZE})?"; then
                rm -rf "$WIREGHOST_DATA_DIR"
                ok "Removed scan data (${DATA_SIZE})"
            fi
        fi
    fi
fi

# ══════════════════════════════════════════════════════════════════════
# Step 1: Stop all containers
# ══════════════════════════════════════════════════════════════════════
step "Stopping Wire_Ghost containers"

if [ -f docker-compose.yml ]; then
    _compose_rm() {
        if [ "$INSTALL_MODE" = "host" ] && [ -f docker-compose.host.yml ]; then
            docker compose -f docker-compose.yml -f docker-compose.host.yml "$@"
        else
            docker compose "$@"
        fi
    }
    RUNNING=$(_compose_rm ps -q 2>/dev/null | wc -l || echo 0)
    if [ "$RUNNING" -gt 0 ]; then
        _compose_rm down --timeout 30 2>/dev/null || true
        ok "Compose stack stopped"
    else
        info "No running containers"
    fi
else
    info "No docker-compose.yml found — checking for orphan containers"
    ORPHANS=$(docker ps -a --filter "label=com.docker.compose.project=demon-in-the-wire" -q 2>/dev/null || true)
    if [ -n "$ORPHANS" ]; then
        echo "$ORPHANS" | xargs docker rm -f 2>/dev/null || true
        ok "Orphan containers removed"
    fi
fi

# ══════════════════════════════════════════════════════════════════════
# Step 2: Remove Docker volumes
# ══════════════════════════════════════════════════════════════════════
step "Removing Docker volumes"

if $KEEP_DATA; then
    warn "Skipping volume removal (--keep-data)"
else
    VOLUME_PREFIX="demon-in-the-wire"
    VOLUMES=$(docker volume ls -q --filter "name=${VOLUME_PREFIX}" 2>/dev/null || true)

    if [ -n "$VOLUMES" ]; then
        for vol in $VOLUMES; do
            SIZE=$(docker system df -v 2>/dev/null | grep "$vol" | awk '{print $NF}' || echo "unknown")
            docker volume rm "$vol" 2>/dev/null && ok "Removed volume: ${vol} (${SIZE})" || warn "Could not remove: ${vol}"
        done
    else
        info "No Wire_Ghost volumes found"
    fi
fi

# ══════════════════════════════════════════════════════════════════════
# Step 3: Remove Docker images
# ══════════════════════════════════════════════════════════════════════
step "Removing Docker images"

IMAGE_PATTERNS=(
    "demon-in-the-wire-api"
    "demon-in-the-wire-worker"
    "demon-in-the-wire-beat"
    "demon-in-the-wire-wireghost"
    "callmedemon/wireghost"
)

TOOL_IMAGES=(
    "instrumentisto/nmap"
    "projectdiscovery/nuclei"
    "projectdiscovery/httpx"
)

removed_count=0
for pattern in "${IMAGE_PATTERNS[@]}"; do
    IMAGES=$(docker images --filter "reference=*${pattern}*" -q 2>/dev/null || true)
    if [ -n "$IMAGES" ]; then
        echo "$IMAGES" | xargs docker rmi -f 2>/dev/null || true
        ok "Removed image: ${pattern}"
        removed_count=$((removed_count + 1))
    fi
done

if ! $KEEP_DATA; then
    for img in "${TOOL_IMAGES[@]}"; do
        if docker images "$img" -q 2>/dev/null | grep -q .; then
            if confirm "Remove scan tool image: ${img}?"; then
                docker rmi -f "$img" 2>/dev/null || true
                ok "Removed: ${img}"
                removed_count=$((removed_count + 1))
            fi
        fi
    done
fi

# Base images (optional)
BASE_IMAGES=("mysql:8.0" "redis:7-alpine" "nginx:alpine")
for img in "${BASE_IMAGES[@]}"; do
    if docker images "$img" -q 2>/dev/null | grep -q .; then
        if $FORCE || confirm "Remove base image: ${img}? (shared with other projects)"; then
            docker rmi "$img" 2>/dev/null || true
            ok "Removed: ${img}"
            removed_count=$((removed_count + 1))
        fi
    fi
done

if [ "$removed_count" -eq 0 ]; then
    info "No Wire_Ghost images found"
else
    ok "Removed ${removed_count} images"
fi

# ══════════════════════════════════════════════════════════════════════
# Step 4: Remove Docker network
# ══════════════════════════════════════════════════════════════════════
step "Removing Docker network"

NETS=$(docker network ls --filter "name=demon-in-the-wire" -q 2>/dev/null || true)
if [ -n "$NETS" ]; then
    echo "$NETS" | xargs docker network rm 2>/dev/null || true
    ok "Network removed"
else
    info "No Wire_Ghost network found"
fi

# ══════════════════════════════════════════════════════════════════════
# Step 5: Remove local files
# ══════════════════════════════════════════════════════════════════════
step "Removing local files"

removed_files=()

for item in .env nginx.conf; do
    if [ -f "$item" ]; then
        rm -f "$item"
        removed_files+=("$item")
    fi
done

for dir in certs logs backups; do
    if [ -d "$dir" ]; then
        SIZE=$(du -sh "$dir" 2>/dev/null | cut -f1 || echo "?")
        rm -rf "$dir"
        removed_files+=("${dir}/ (${SIZE})")
    fi
done

if [ ${#removed_files[@]} -gt 0 ]; then
    ok "Removed: ${removed_files[*]}"
else
    info "No local files to remove"
fi

# ══════════════════════════════════════════════════════════════════════
# Step 6: Docker system prune
# ══════════════════════════════════════════════════════════════════════
step "Cleaning up dangling Docker resources"

DANGLING=$(docker images -f "dangling=true" -q 2>/dev/null | wc -l || echo 0)
if [ "$DANGLING" -gt 0 ]; then
    if $FORCE || confirm "Prune ${DANGLING} dangling image(s)?"; then
        docker image prune -f >/dev/null 2>&1
        ok "Pruned dangling images"
    fi
else
    info "No dangling images"
fi

# ══════════════════════════════════════════════════════════════════════
# Step 7: Remove project directory (interactive only)
# ══════════════════════════════════════════════════════════════════════
step "Project directory"

if ! $FORCE; then
    if confirm "Remove the entire project directory (${PROJECT_DIR})?"; then
        cd /
        rm -rf "$SCRIPT_DIR"
        ok "Project directory removed: ${PROJECT_DIR}"
        printf "\n${GREEN}${BOLD}Wire_Ghost completely removed.${NC}\n\n"
        exit 0
    else
        info "Project directory kept at: ${PROJECT_DIR}"
    fi
else
    info "Project source files kept (use rm -rf ${PROJECT_DIR} to remove manually)"
fi

# ══════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════
printf "\n${GREEN}══════════════════════════════════════════════════════${NC}\n"
printf "${GREEN}  Wire_Ghost removed successfully.${NC}\n"
printf "${GREEN}══════════════════════════════════════════════════════${NC}\n\n"

printf "  ${BOLD}What was removed:${NC}\n"
printf "    • Docker containers, networks\n"
$KEEP_DATA && printf "    • Docker images (volumes preserved)\n" || printf "    • Docker volumes and images\n"
printf "    • Local config (.env, nginx.conf, certs/, logs/)\n"
if [ "$INSTALL_MODE" = "host" ]; then
    printf "    • systemd units (wireghost-worker, wireghost-beat)\n"
    printf "    • Python virtual environment (.venv/)\n"
fi
printf "\n"
printf "  ${BOLD}To reinstall:${NC}\n"

if [ -f "${PROJECT_DIR}/scripts/install.sh" ]; then
    printf "    cd ${PROJECT_DIR} && sudo bash scripts/install.sh\n"
else
    printf "    curl -fsSL https://raw.githubusercontent.com/Lw1nM1n4ung/demon-in-the-wire/stable/scripts/install-wireghost.sh | sudo bash\n"
fi
printf "\n"
