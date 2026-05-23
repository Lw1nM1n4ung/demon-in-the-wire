#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
# Wire_Ghost — One-Line Updater
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Lw1nM1n4ung/demon-in-the-wire/rewrite-v2/scripts/update-wireghost.sh | sudo bash
#
#   sudo bash scripts/update-wireghost.sh              # full update (self + tools + feeds)
#   sudo bash scripts/update-wireghost.sh --docker     # full update + Docker stack
#   sudo bash scripts/update-wireghost.sh --self       # self-update only
#   sudo bash scripts/update-wireghost.sh --tools      # tools only
#   sudo bash scripts/update-wireghost.sh --feeds      # feeds only
#
#   # Pass --docker via curl:
#   curl -fsSL <url> | sudo bash -s -- --docker
# ══════════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
info()  { printf "${CYAN}[INFO]${NC}  %s\n" "$*"; }
ok()    { printf "${GREEN}[OK]${NC}    %s\n" "$*"; }
warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$*"; }

# ── Find project root ──────────────────────────────────────────────────
find_root() {
    # 1. Explicit override via env var
    if [ -n "${WG_ROOT:-}" ] && [ -f "${WG_ROOT}/pyproject.toml" ]; then
        PROJECT_DIR="$WG_ROOT"
        return
    fi

    # 2. Script-relative (works when run from local clone)
    local script_dir
    script_dir="$(cd "$(dirname "$0")" 2>/dev/null && pwd)" || script_dir=""
    if [ -n "$script_dir" ] && [ "$script_dir" != "/" ] && [ "$script_dir" != "." ]; then
        local parent
        parent="$(cd "$script_dir/.." 2>/dev/null && pwd)" || parent=""
        if [ -n "$parent" ] && [ -f "${parent}/pyproject.toml" ]; then
            PROJECT_DIR="$parent"
            return
        fi
    fi

    # 3. Common install directories (searched in order)
    for candidate in \
        /opt/wireghost \
        /opt/demon-in-the-wire \
        /home/*/demon-in-the-wire \
        /root/demon-in-the-wire; do
        if [ -f "${candidate}/pyproject.toml" ]; then
            PROJECT_DIR="$candidate"
            return
        fi
    done

    # 4. Current directory
    if [ -f "$(pwd)/pyproject.toml" ]; then
        PROJECT_DIR="$(pwd)"
        return
    fi

    # 5. Last resort
    PROJECT_DIR="/opt/wireghost"
}

WITH_TOOLS=true; WITH_FEEDS=true; WITH_SELF=true; WITH_DOCKER=false
for arg in "$@"; do
    case "$arg" in
        --self)   WITH_TOOLS=false; WITH_FEEDS=false ;;
        --tools)  WITH_SELF=false; WITH_FEEDS=false ;;
        --feeds)  WITH_SELF=false; WITH_TOOLS=false ;;
        --docker) WITH_DOCKER=true; WITH_TOOLS=false; WITH_FEEDS=false ;;
        --help|-h)
            echo "Usage: sudo bash update-wireghost.sh [--self] [--tools] [--feeds] [--docker]"
            echo "  (no flags)  Full update: self + tools + feeds"
            echo "  --self      Self-update only (git pull + pip install)"
            echo "  --tools     Tools only (nuclei, httpx, naabu, apt)"
            echo "  --feeds     Feeds only (nuclei templates, searchsploit DB)"
            echo "  --docker    Docker stack update: self + build + up + migrate"
            exit 0 ;;
    esac
done

# ── Progress ───────────────────────────────────────────────────────────
_TOTAL=0; [ "$WITH_SELF" = true ] && _TOTAL=$((_TOTAL + 1)); [ "$WITH_TOOLS" = true ] && _TOTAL=$((_TOTAL + 1)); [ "$WITH_FEEDS" = true ] && _TOTAL=$((_TOTAL + 1)); [ "$WITH_DOCKER" = true ] && _TOTAL=$((_TOTAL + 1)); _STEP=0
step() {
    _STEP=$((_STEP + 1))
    printf "\n${BOLD}${CYAN}[%d/%d]${NC} %s\n\n" "$_STEP" "$_TOTAL" "$1"
}

###########################################################################
# 1. Self-update
###########################################################################
self_update() {
    step "Updating Wire_Ghost"

    if [ ! -d "$PROJECT_DIR" ]; then
        warn "Project directory ${PROJECT_DIR} not found"
        warn "Run the installer first: curl -fsSL https://raw.githubusercontent.com/Lw1nM1n4ung/demon-in-the-wire/${BRANCH:-rewrite-v2}/scripts/install-wireghost.sh | sudo bash"
        return
    fi

    cd "$PROJECT_DIR"

    if [ ! -d .git ]; then
        warn "Not a git repo at ${PROJECT_DIR} — skipping self-update"
        warn "Run the installer: curl -fsSL https://raw.githubusercontent.com/Lw1nM1n4ung/demon-in-the-wire/${BRANCH:-rewrite-v2}/scripts/install-wireghost.sh | sudo bash"
        return
    fi

    # ── Git pull ──
    local branch; branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "rewrite-v2")
    info "Pulling ${branch}..."
    git fetch origin "$branch" || warn "git fetch failed — check network"
    if ! git pull --ff-only origin "$branch" 2>&1 | tail -3; then
        warn "git pull failed — repo may have local changes"
        return
    fi
    ok "Code updated ($(git rev-parse --short HEAD))"

    # ── Find a pip backed by Python >= 3.11 ──
    _py_ok() {
        # Parse Python version from "pip -V" output, check >= 3.11 with integers
        local ver
        ver=$("$1" -V 2>/dev/null | grep -oE 'python [0-9]+\.[0-9]+' | head -1 | cut -d' ' -f2)
        [ -z "$ver" ] && return 1
        local major minor
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        [ "$major" -ge 3 ] 2>/dev/null && [ "$minor" -ge 11 ] 2>/dev/null && return 0
        return 1
    }

    local pip="" py_ver=""
    for candidate in "${PROJECT_DIR}/.venv/bin/pip" "pip3" "pip"; do
        command -v "$candidate" >/dev/null 2>&1 || continue
        py_ver=$("$candidate" -V 2>/dev/null | grep -oE 'python [0-9]+\.[0-9]+' | head -1 | cut -d' ' -f2)
        if _py_ok "$candidate"; then
            pip="$candidate"
            break
        fi
    done

    if [ -z "$pip" ]; then
        if [ -n "$py_ver" ]; then
            warn "Python ${py_ver} too old — need 3.11+; skipping pip install"
        else
            warn "pip not found — skipping Python package update"
        fi
        return
    fi

    info "Installing packages... (Python ${py_ver})"
    set +e
    "$pip" install --no-cache-dir -e "${PROJECT_DIR}" -q 2>&1 | tail -2
    if [ -f "${PROJECT_DIR}/web_portal/requirements.txt" ]; then
        "$pip" install --no-cache-dir -r "${PROJECT_DIR}/web_portal/requirements.txt" -q 2>&1 | tail -2
    fi
    set -e
}

###########################################################################
# 2. Tools
###########################################################################
tools_update() {
    step "Updating security tools"

    # ── APT tools ──
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq 2>/dev/null || true
        for tool in nmap fping masscan searchsploit; do
            if command -v "$tool" >/dev/null 2>&1; then
                info "apt upgrade ${tool}..."
                DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade "$tool" -qq 2>/dev/null && \
                    ok "$tool upgraded" || warn "$tool — already latest or failed"
            fi
        done
    fi

    # ── ProjectDiscovery tools ──
    for tool_data in "nuclei:projectdiscovery/nuclei" "httpx:projectdiscovery/httpx" "naabu:projectdiscovery/naabu"; do
        local name="${tool_data%%:*}" repo="${tool_data##*:}"
        if ! command -v "$name" >/dev/null 2>&1; then
            continue
        fi
        info "Updating ${name}..."
        local url tag
        tag=$(curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null | grep '"tag_name"' | head -1 | cut -d'"' -f4) || true
        [ -z "$tag" ] && { warn "${name} — could not fetch latest release"; continue; }
        local arch="amd64"; uname -m | grep -q "aarch64\|arm64" && arch="arm64"
        url=$(curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null | grep -o "\"browser_download_url\": *\"[^\"]*linux_${arch}.zip\"" | head -1 | cut -d'"' -f4) || true
        [ -z "$url" ] && { warn "${name} — no binary for linux_${arch}"; continue; }
        local tmp="/tmp/${name}_update.zip"
        curl -fsSL "$url" -o "$tmp" 2>/dev/null || { warn "${name} — download failed"; continue; }
        unzip -o "$tmp" "$name" -d /usr/local/bin/ >/dev/null 2>&1 || true
        chmod +x "/usr/local/bin/${name}" 2>/dev/null || true
        rm -f "$tmp"
        ok "${name} → ${tag}"
    done
}

###########################################################################
# 3. Feeds
###########################################################################
feeds_update() {
    step "Updating vulnerability feeds"

    if command -v nuclei >/dev/null 2>&1; then
        info "nuclei -update-templates..."
        nuclei -update-templates 2>&1 | tail -2 && ok "nuclei templates updated" || warn "nuclei template update failed"
    fi

    if command -v searchsploit >/dev/null 2>&1; then
        info "searchsploit -u..."
        searchsploit -u 2>&1 | tail -2 && ok "searchsploit DB updated" || warn "searchsploit update failed"
    fi
}

###########################################################################
# 4. Docker stack
###########################################################################
docker_update() {
    step "Updating Docker Compose stack"

    # Detect which compose files are in use
    local compose_files=(-f docker-compose.yml)
    if [ -f docker-compose.host.yml ] && docker compose -f docker-compose.yml -f docker-compose.host.yml ps 2>/dev/null | grep -q "Up"; then
        compose_files+=(-f docker-compose.host.yml)
        info "Detected host-mode deployment"
    elif [ -f docker-compose.dev.yml ] && docker compose -f docker-compose.yml -f docker-compose.dev.yml ps 2>/dev/null | grep -q "Up"; then
        compose_files+=(-f docker-compose.dev.yml)
        info "Detected dev-mode deployment"
    fi

    # Pull external base images (mysql, redis, nginx — not app images)
    info "Pulling external images..."
    docker compose "${compose_files[@]}" pull db redis portal 2>&1 | tail -3 || true

    # Build app images with retry (transient CDN errors are common)
    info "Building app images..."
    local build_ok=false
    for attempt in 1 2 3; do
        if docker compose "${compose_files[@]}" build --pull 2>&1 | tail -5; then
            build_ok=true; break
        fi
        warn "Build attempt ${attempt}/3 failed — retrying in 5s..."
        sleep 5
    done
    if [ "$build_ok" = false ]; then
        warn "Build failed after 3 attempts — images may be stale"
    fi

    # Recreate containers with new images
    info "Recreating containers..."
    docker compose "${compose_files[@]}" up -d --remove-orphans 2>&1 | tail -5

    # Run migrations
    info "Running Django migrations..."
    docker compose "${compose_files[@]}" exec -T api python manage.py migrate --noinput 2>&1 | tail -3 || warn "migrations may have failed — check: docker compose logs api"

    # Collect static
    info "Collecting static files..."
    docker compose "${compose_files[@]}" exec -T api python manage.py collectstatic --noinput 2>&1 | tail -2 || true

    # Prune old images
    docker image prune -f 2>/dev/null || true
    ok "Docker stack updated"
}

###########################################################################
# Main
###########################################################################
printf "\n${BOLD}${CYAN} Wire_Ghost — One-Line Updater${NC}\n\n"
find_root
info "Project: ${PROJECT_DIR}"

if [ "$WITH_SELF" = true ]; then
    self_update
fi

if [ "$WITH_TOOLS" = true ]; then
    tools_update
fi

if [ "$WITH_FEEDS" = true ]; then
    feeds_update
fi

if [ "$WITH_DOCKER" = true ]; then
    docker_update
fi

printf "\n${GREEN}${BOLD}══ Update complete ═══════════════════════════════════${NC}\n\n"
