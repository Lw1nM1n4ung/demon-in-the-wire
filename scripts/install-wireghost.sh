#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
# Wire_Ghost — One-Line Remote Installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Lw1nM1n4ung/demon-in-the-wire/rewrite-v2/scripts/install-wireghost.sh | sudo bash
#
# Or download-and-run:
#   wget -qO install-wireghost.sh https://raw.githubusercontent.com/Lw1nM1n4ung/demon-in-the-wire/rewrite-v2/scripts/install-wireghost.sh
#   sudo bash install-wireghost.sh
#
# What it does:
#   1. Checks prerequisites (Docker, Compose, disk, RAM)
#   2. Clones the repository (or pulls if already cloned)
#   3. Runs the built-in install.sh (secrets, TLS, nginx, stack)
# ══════════════════════════════════════════════════════════════════════
set -euo pipefail

REPO_URL="https://github.com/Lw1nM1n4ung/demon-in-the-wire.git"
BRANCH="rewrite-v2"
INSTALL_DIR="/opt/wireghost"

# ── Colours ──────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

info()  { printf "${CYAN}[INFO]${NC}  %s\n" "$*"; }
ok()    { printf "${GREEN}[OK]${NC}    %s\n" "$*"; }
warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$*"; }
die()   { printf "${RED}[FATAL]${NC} %s\n" "$*" >&2; exit 1; }

banner() {
    printf "\n${BOLD}${CYAN}"
    cat <<'ART'
 __      __ _            ___  _               _
 \ \    / /(_) _ _  ___ / __|| |_   ___  ___ | |_
  \ \/\/ / | || '_|/ -_)| (_ | ' \ / _ \(_-< |  _|
   \_/\_/  |_||_|  \___| \___||_||_|\___//__/  \__|
ART
    printf "${NC}\n"
    printf "  ${BOLD}Remote Installer${NC}\n\n"
}

# ── Progress bar ────────────────────────────────────────────────────
_TOTAL=3; _STEP=0
step() {
    _STEP=$((_STEP + 1))
    local pct=$((_STEP * 100 / _TOTAL))
    local filled=$((pct * 30 / 100))
    local empty=$((30 - filled))
    printf "\n  ${GREEN}%s${DIM}%s${NC}  ${BOLD}%d/%d${NC}  %s\n\n" \
        "$(printf '%*s' "$filled" '' | tr ' ' '█')" \
        "$(printf '%*s' "$empty" '' | tr ' ' '░')" \
        "$_STEP" "$_TOTAL" "$1"
}

# ── WSL detection ───────────────────────────────────────────────────
_IS_WSL=false
detect_wsl() {
    if grep -qi "microsoft\|wsl" /proc/version 2>/dev/null || \
       [ -n "${WSL_DISTRO_NAME:-}" ] || \
       [ -f /proc/sys/fs/binfmt_misc/WSLInterop ]; then
        _IS_WSL=true
        info "WSL environment detected"
    fi
}

# ── Root check ───────────────────────────────────────────────────────
check_root() {
    [ "$(id -u)" -eq 0 ] || die "Run as root: sudo bash install-wireghost.sh"
}

# ── Prerequisites ────────────────────────────────────────────────────
check_prereqs() {
    info "Checking prerequisites..."

    # Docker
    if ! command -v docker >/dev/null 2>&1; then
        warn "Docker not found — attempting automatic install..."
        install_docker
    fi

    DOCKER_VERSION=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "0")
    DOCKER_MAJOR=$(echo "$DOCKER_VERSION" | cut -d. -f1)
    [ "$DOCKER_MAJOR" -ge 20 ] 2>/dev/null || die "Docker >= 20.x required (found: $DOCKER_VERSION)"

    # Docker Compose
    if ! docker compose version >/dev/null 2>&1; then
        warn "Docker Compose V2 not found — attempting install..."
        install_compose
    fi

    # Git
    if ! command -v git >/dev/null 2>&1; then
        info "Installing git..."
        apt-get update -qq && apt-get install -y -qq git >/dev/null 2>&1 || \
        yum install -y -q git >/dev/null 2>&1 || \
        die "Could not install git — install it manually"
    fi

    # System resources
    TOTAL_MEM_MB=$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)
    [ "$TOTAL_MEM_MB" -lt 3500 ] && warn "System has ${TOTAL_MEM_MB}MB RAM — 4GB+ recommended"

    DISK_FREE_GB=$(df -BG "${INSTALL_DIR%/*}" 2>/dev/null | awk 'NR==2 {gsub(/G/,"",$4); print $4}' || echo 0)
    [ "$DISK_FREE_GB" -lt 15 ] && warn "Only ${DISK_FREE_GB}GB free disk — 20GB+ recommended"

    ok "Prerequisites satisfied"
}

# ── Auto-install Docker ──────────────────────────────────────────────
install_docker() {
    if [ "$_IS_WSL" = true ]; then
        warn "On WSL, Docker Desktop with WSL integration is recommended:"
        warn "  1. Install Docker Desktop for Windows"
        warn "  2. Settings → Resources → WSL Integration → enable your distro"
        if [ -t 0 ]; then
            printf "  Install Docker CE inside WSL instead? [y/N] "
            read -r _wsl_docker
            if ! [[ "$_wsl_docker" =~ ^[Yy] ]]; then
                die "Install Docker Desktop for Windows, then re-run this script"
            fi
        else
            die "Docker not available — install Docker Desktop with WSL integration"
        fi
    fi

    if [ -f /etc/debian_version ]; then
        apt-get update -qq
        apt-get install -y -qq ca-certificates curl gnupg >/dev/null 2>&1
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>/dev/null
        chmod a+r /etc/apt/keyrings/docker.gpg
        DISTRO=$(. /etc/os-release && echo "$ID")
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${DISTRO} $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
        apt-get update -qq
        apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null 2>&1
        ok "Docker installed via apt"
    elif [ -f /etc/redhat-release ]; then
        yum install -y -q yum-utils >/dev/null 2>&1
        yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo >/dev/null 2>&1
        yum install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null 2>&1
        systemctl start docker
        systemctl enable docker
        ok "Docker installed via yum"
    else
        die "Unsupported distro — install Docker manually: https://docs.docker.com/engine/install/"
    fi
}

# ── Auto-install Docker Compose ──────────────────────────────────────
install_compose() {
    if docker compose version >/dev/null 2>&1; then
        return
    fi
    COMPOSE_VERSION=$(curl -fsSL https://api.github.com/repos/docker/compose/releases/latest 2>/dev/null | grep '"tag_name"' | head -1 | cut -d'"' -f4 || echo "v2.29.1")
    ARCH=$(uname -m)
    curl -fsSL "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-linux-${ARCH}" -o /usr/local/lib/docker/cli-plugins/docker-compose 2>/dev/null || \
    curl -fsSL "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-linux-${ARCH}" -o /usr/libexec/docker/cli-plugins/docker-compose 2>/dev/null
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose 2>/dev/null || \
    chmod +x /usr/libexec/docker/cli-plugins/docker-compose 2>/dev/null
    ok "Docker Compose installed"
}

# ── Clone or update repository ───────────────────────────────────────
clone_repo() {
    if [ -d "${INSTALL_DIR}/.git" ]; then
        info "Existing installation found at ${INSTALL_DIR} — updating..."
        cd "$INSTALL_DIR"
        git fetch origin "$BRANCH" || die "git fetch failed — check network connectivity to GitHub"
        git checkout "$BRANCH" 2>/dev/null || true
        git checkout -- nginx.conf 2>/dev/null || true
        git reset HEAD nginx.conf 2>/dev/null || true
        git pull origin "$BRANCH" || die "git pull failed — check network connectivity to GitHub"
        ok "Repository updated"
    else
        info "Cloning Wire_Ghost to ${INSTALL_DIR}..."
        mkdir -p "$(dirname "$INSTALL_DIR")"
        if [ -d "$INSTALL_DIR" ] && [ "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ]; then
            die "${INSTALL_DIR} exists and is not empty. Remove it first or choose a different directory."
        fi
        git clone -b "$BRANCH" --single-branch "$REPO_URL" "$INSTALL_DIR" || \
            die "git clone failed — check network connectivity to GitHub"
        ok "Repository cloned"
    fi
    cd "$INSTALL_DIR"
}

# ── Custom install directory ─────────────────────────────────────────
prompt_install_dir() {
    if [ -t 0 ]; then
        printf "\n${BOLD}Install directory${NC} [${INSTALL_DIR}]: "
        read -r CUSTOM_DIR
        if [ -n "$CUSTOM_DIR" ]; then
            [[ "$CUSTOM_DIR" =~ ^/ ]] || die "Install directory must be an absolute path (starts with /)"
            INSTALL_DIR="$CUSTOM_DIR"
        fi
    fi
    if [ "$_IS_WSL" = true ] && [[ "$INSTALL_DIR" == /mnt/* ]]; then
        warn "Installing on a Windows mount is slow and may break file permissions"
        warn "Recommended: use a WSL-native path (e.g., /opt/wireghost)"
    fi
}

# ══════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════
banner
check_root

step "Checking system requirements"
detect_wsl
check_prereqs

step "Cloning Wire_Ghost repository"
prompt_install_dir
clone_repo

step "Launching installer"
info "Handing off to scripts/install.sh..."
printf "═══════════════════════════════════════════════════════\n\n"

bash scripts/install.sh

printf "\n"
ok "Wire_Ghost is installed at: ${INSTALL_DIR}"
printf "  ${BOLD}Management:${NC}  cd ${INSTALL_DIR} && ./scripts/wg-ctl --help\n"
printf "  ${BOLD}Remove:${NC}      sudo bash ${INSTALL_DIR}/scripts/remove-wireghost.sh\n\n"
