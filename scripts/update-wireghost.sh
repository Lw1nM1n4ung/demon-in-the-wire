#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
# Wire_Ghost — One-Line Updater
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Lw1nM1n4ung/demon-in-the-wire/rewrite-v2/scripts/update-wireghost.sh | sudo bash
#
#   sudo bash scripts/update-wireghost.sh              # full update (self + tools + feeds)
#   sudo bash scripts/update-wireghost.sh --self       # self-update only
#   sudo bash scripts/update-wireghost.sh --tools      # tools only
#   sudo bash scripts/update-wireghost.sh --feeds      # feeds only
# ══════════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
info()  { printf "${CYAN}[INFO]${NC}  %s\n" "$*"; }
ok()    { printf "${GREEN}[OK]${NC}    %s\n" "$*"; }
warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$*"; }

# ── Find project root ──────────────────────────────────────────────────
find_root() {
    if [ -n "${WG_ROOT:-}" ] && [ -f "${WG_ROOT}/pyproject.toml" ]; then
        PROJECT_DIR="$WG_ROOT"
        return
    fi
    PROJECT_DIR="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)"
    if [ ! -f "${PROJECT_DIR}/pyproject.toml" ]; then
        PROJECT_DIR="$(pwd)"
        if [ ! -f "${PROJECT_DIR}/pyproject.toml" ]; then
            PROJECT_DIR="/opt/wireghost"
        fi
    fi
}

WITH_TOOLS=true; WITH_FEEDS=true; WITH_SELF=true
for arg in "$@"; do
    case "$arg" in
        --self)  WITH_TOOLS=false; WITH_FEEDS=false ;;
        --tools) WITH_SELF=false; WITH_FEEDS=false ;;
        --feeds) WITH_SELF=false; WITH_TOOLS=false ;;
        --help|-h)
            echo "Usage: sudo bash update-wireghost.sh [--self] [--tools] [--feeds]"
            echo "  (no flags)  Full update: self + tools + feeds"
            echo "  --self      Self-update only (git pull + pip install)"
            echo "  --tools     Tools only (nuclei, httpx, naabu, apt)"
            echo "  --feeds     Feeds only (nuclei templates, searchsploit DB)"
            exit 0 ;;
    esac
done

# ── Progress ───────────────────────────────────────────────────────────
_TOTAL=0; [ "$WITH_SELF" = true ] && _TOTAL=$((_TOTAL + 1)); [ "$WITH_TOOLS" = true ] && _TOTAL=$((_TOTAL + 1)); [ "$WITH_FEEDS" = true ] && _TOTAL=$((_TOTAL + 1)); _STEP=0
step() {
    _STEP=$((_STEP + 1))
    printf "\n${BOLD}${CYAN}[%d/%d]${NC} %s\n\n" "$_STEP" "$_TOTAL" "$1"
}

###########################################################################
# 1. Self-update
###########################################################################
self_update() {
    step "Updating Wire_Ghost"
    cd "$PROJECT_DIR"

    if [ ! -d .git ]; then
        warn "Not a git repo at ${PROJECT_DIR} — skipping self-update"
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

    # ── Find pip with Python >= 3.11 ──
    local pip py
    _find_pip() {
        pip=""; py=""
        # Venv pip first
        if [ -x "${PROJECT_DIR}/.venv/bin/pip" ]; then
            py=$("${PROJECT_DIR}/.venv/bin/python3" -V 2>/dev/null || "${PROJECT_DIR}/.venv/bin/python" -V 2>/dev/null) || true
            if echo "$py" | grep -qP '3\.(1[1-9]|[2-9]\d)'; then
                pip="${PROJECT_DIR}/.venv/bin/pip"; return
            fi
        fi
        # System pip3
        if command -v pip3 >/dev/null 2>&1; then
            py=$(pip3 --version 2>/dev/null | grep -oP 'python \K[\d.]+' || python3 -V 2>/dev/null) || true
            if echo "$py" | grep -qP '3\.(1[1-9]|[2-9]\d)'; then
                pip="pip3"; return
            fi
            local _old_py="$py"
        fi
        # System pip
        if command -v pip >/dev/null 2>&1; then
            py=$(pip --version 2>/dev/null | grep -oP 'python \K[\d.]+' || python -V 2>/dev/null) || true
            if echo "$py" | grep -qP '3\.(1[1-9]|[2-9]\d)'; then
                pip="pip"; return
            fi
        fi
        # Nothing suitable
        if command -v pip3 >/dev/null 2>&1; then
            warn "Python $([ -n "${_old_py:-}" ] && echo "${_old_py}" || echo "3.10") too old — need 3.11+; skipping pip install"
        else
            warn "pip not found — skipping Python package update"
        fi
    }
    _find_pip
    [ -z "$pip" ] && return

    info "Installing packages... ($py)"
    "$pip" install --no-cache-dir -e "${PROJECT_DIR}" -q 2>&1 | tail -2

    if [ -f "${PROJECT_DIR}/web_portal/requirements.txt" ]; then
        "$pip" install --no-cache-dir -r "${PROJECT_DIR}/web_portal/requirements.txt" -q 2>&1 | tail -2
    fi

    # ── Show version ──
    local ver
    ver=$("$pip" show wireghost 2>/dev/null | awk '/^Version:/{print $2}') || true
    [ -n "$ver" ] && ok "wireghost ${ver}" || ok "wireghost installed"
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

printf "\n${GREEN}${BOLD}══ Update complete ═══════════════════════════════════${NC}\n\n"
