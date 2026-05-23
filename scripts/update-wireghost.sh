#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
# Wire_Ghost — One-Line Updater
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Lw1nM1n4ung/demon-in-the-wire/rewrite-v2/scripts/update-wireghost.sh | sudo bash
#
#   sudo bash scripts/update-wireghost.sh              # full update (auto-detect Docker)
#   sudo bash scripts/update-wireghost.sh --docker     # force Docker stack rebuild
#   sudo bash scripts/update-wireghost.sh --host       # host-only (skip Docker, pip install locally)
#   sudo bash scripts/update-wireghost.sh --self       # self-update only
#   sudo bash scripts/update-wireghost.sh --tools      # tools only (install + update)
#   sudo bash scripts/update-wireghost.sh --feeds      # feeds only
#   sudo bash scripts/update-wireghost.sh --all        # everything (host tools + feeds + Docker)
#
#   # Pass flags via curl:
#   curl -fsSL <url> | sudo bash -s -- --docker
# ══════════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
info()  { printf "${CYAN}[INFO]${NC}  %s\n" "$*"; }
ok()    { printf "${GREEN}[OK]${NC}    %s\n" "$*"; }
warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$*"; }
die()   { printf "${RED}[FATAL]${NC} %s\n" "$*" >&2; exit 1; }

# ── Find project root ──────────────────────────────────────────────────
find_root() {
    if [ -n "${WG_ROOT:-}" ] && [ -f "${WG_ROOT}/pyproject.toml" ]; then
        PROJECT_DIR="$WG_ROOT"
        return
    fi

    # Script-relative (works when run from local clone)
    local script_dir parent
    script_dir="$(cd "$(dirname "$0")" 2>/dev/null && pwd)" || script_dir=""
    if [ -n "$script_dir" ] && [ "$script_dir" != "/" ] && [ "$script_dir" != "." ]; then
        parent="$(cd "$script_dir/.." 2>/dev/null && pwd)" || parent=""
        if [ -n "$parent" ] && [ -f "${parent}/pyproject.toml" ]; then
            PROJECT_DIR="$parent"
            return
        fi
    fi

    # Common install directories
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

    # Current directory
    if [ -f "$(pwd)/pyproject.toml" ]; then
        PROJECT_DIR="$(pwd)"
        return
    fi

    PROJECT_DIR="/opt/wireghost"
}

# ── Detect Docker deployment ───────────────────────────────────────────
detect_docker() {
    DOCKER_DEPLOY=false
    DOCKER_COMPOSE_FILES=(-f docker-compose.yml)

    if [ ! -d "$PROJECT_DIR" ]; then
        return
    fi

    cd "$PROJECT_DIR"

    # Check if any compose stack is running
    if [ -f docker-compose.host.yml ] && docker compose -f docker-compose.yml -f docker-compose.host.yml ps 2>/dev/null | grep -q "Up"; then
        DOCKER_DEPLOY=true
        DOCKER_COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.host.yml)
        DOCKER_MODE="host"
    elif [ -f docker-compose.dev.yml ] && docker compose -f docker-compose.yml -f docker-compose.dev.yml ps 2>/dev/null | grep -q "Up"; then
        DOCKER_DEPLOY=true
        DOCKER_COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.dev.yml)
        DOCKER_MODE="dev"
    elif docker compose ps 2>/dev/null | grep -q "Up"; then
        DOCKER_DEPLOY=true
        DOCKER_MODE="docker"
    fi

    cd - >/dev/null
}

# ── Progress ───────────────────────────────────────────────────────────
declare -a STEPS=()
step() {
    local n="${#STEPS[@]}"
    STEPS+=("$1")
    n=$((n + 1))
    printf "\n${BOLD}${CYAN}[%d/%d]${NC} %s\n\n" "$n" "${_TOTAL}" "$1"
}

###########################################################################
# 1. Self-update
###########################################################################
self_update() {
    step "Updating Wire_Ghost code"

    if [ ! -d "$PROJECT_DIR" ]; then
        warn "Project directory ${PROJECT_DIR} not found"
        warn "Run the installer: curl -fsSL ${RAW_BASE}/scripts/install-wireghost.sh | sudo bash"
        return
    fi

    cd "$PROJECT_DIR"

    if [ ! -d .git ]; then
        warn "Not a git repo at ${PROJECT_DIR} — skipping self-update"
        warn "Run the installer: curl -fsSL ${RAW_BASE}/scripts/install-wireghost.sh | sudo bash"
        return
    fi

    # ── Git pull ──
    local branch
    branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "rewrite-v2")
    info "Pulling ${branch}..."
    git fetch origin "$branch" || warn "git fetch failed — check network"
    if ! git pull --ff-only origin "$branch" 2>&1 | tail -3; then
        warn "git pull failed — repo may have local changes"
        return
    fi
    ok "Code updated ($(git rev-parse --short HEAD))"

    # ── Pip install (host mode only — Docker containers have their own Python) ──
    if [ "$WITH_HOST_PIP" = false ]; then
        info "Skipping host pip install (Docker containers handle their own dependencies)"
        return
    fi

    # Find Python >= 3.11
    _py_ok() {
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
            warn "Python ${py_ver} too old — need 3.11+; install python3.11: sudo apt-get install python3.11 python3.11-venv"
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
    ok "Python packages updated"
}

###########################################################################
# 2. Tools — install missing + update existing
###########################################################################
tools_update() {
    step "Installing & updating security tools"

    # ── APT packages ──
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq 2>/dev/null || true

        # All required APT packages (from installer + Dockerfile)
        local apt_pkgs=(
            nmap fping masscan libpcap0.8 libsnmp40
            sslscan nfs-common snmp onesixtyone
            arp-scan netdiscover
            smbclient samba-common-bin ldap-utils
            git rsync libxml2-utils
            perl libnet-ssleay-perl libio-socket-ssl-perl
            libjson-perl libxml-writer-perl libxml-libxml-perl
        )

        local to_install=()
        for pkg in "${apt_pkgs[@]}"; do
            if ! dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; then
                to_install+=("$pkg")
            fi
        done

        if [ ${#to_install[@]} -gt 0 ]; then
            info "Installing ${#to_install[@]} missing packages..."
            DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${to_install[@]}" -qq 2>&1 | tail -2
            ok "Installed: ${to_install[*]}"
        fi

        # Upgrade already-installed tools
        for tool in nmap fping masscan; do
            if command -v "$tool" >/dev/null 2>&1; then
                info "apt upgrade ${tool}..."
                DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade "$tool" -qq 2>/dev/null && \
                    ok "$tool upgraded" || true  # already latest is fine
            fi
        done
    fi

    # ── Go tools — install via 'go install' (no GitHub API needed) ──────
    local go_needed=false
    if ! command -v go >/dev/null 2>&1; then
        go_needed=true
    else
        local go_ver
        go_ver=$(go version 2>/dev/null | grep -oE 'go[0-9]+\.[0-9]+' | head -1 | cut -c3-)
        local go_major=0 go_minor=0
        go_major=$(echo "$go_ver" | cut -d. -f1 2>/dev/null || echo 0)
        go_minor=$(echo "$go_ver" | cut -d. -f2 2>/dev/null || echo 0)
        if ! { [ "$go_major" -ge 1 ] 2>/dev/null && [ "$go_minor" -ge 21 ] 2>/dev/null; }; then
            go_needed=true
        fi
    fi

    if [ "$go_needed" = true ]; then
        if command -v apt-get >/dev/null 2>&1; then
            info "Installing Go 1.21+..."
            apt-get update -qq 2>/dev/null || true
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq golang-go 2>&1 | tail -2 && \
                ok "Go installed ($(go version 2>&1 | head -1))" || \
                warn "Go install failed — try: sudo apt-get install golang-go"
        elif command -v snap >/dev/null 2>&1; then
            info "Installing Go via snap..."
            snap install go --classic 2>&1 | tail -2 && ok "Go installed" || warn "Go snap install failed"
        else
            warn "Cannot auto-install Go — no apt or snap found"
        fi
    fi

    if command -v go >/dev/null 2>&1; then
        _go_install() {
            local name="$1" module="$2"
            if command -v "$name" >/dev/null 2>&1; then
                info "go update ${name}..."
            else
                info "go install ${name}..."
            fi
            go install "${module}@latest" 2>&1 | tail -2 || { warn "${name} — go install failed"; return 1; }
            # Copy from GOPATH to /usr/local/bin
            local gopath bin_src
            gopath=$(go env GOPATH 2>/dev/null || echo "$HOME/go")
            bin_src="${gopath}/bin/${name}"
            if [ -f "$bin_src" ]; then
                cp "$bin_src" "/usr/local/bin/${name}" 2>/dev/null || true
                chmod +x "/usr/local/bin/${name}" 2>/dev/null || true
            fi
            local new_ver
            new_ver=$("$name" -version 2>&1 | head -1 || echo "installed")
            ok "${name} → ${new_ver}"
        }

        _go_install nuclei   "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
        _go_install httpx    "github.com/projectdiscovery/httpx/cmd/httpx"
        _go_install naabu    "github.com/projectdiscovery/naabu/v2/cmd/naabu"
        _go_install katana   "github.com/projectdiscovery/katana/cmd/katana"
        _go_install gowitness "github.com/sensepost/gowitness"
        _go_install kerbrute "github.com/ropnop/kerbrute"
        _go_install fingerprintx "github.com/praetorian-inc/fingerprintx/cmd/fingerprintx"
    else
        warn "Go tool binaries skipped (Go not available after install attempt)"
    fi

    # ── Git-based tools ──
    _install_git_tool() {
        local name="$1" repo="$2" dest="$3" bin_path="$4"
        if [ -x "$bin_path" ]; then
            info "${name} already installed — updating..."
            cd "$dest" && git pull --ff-only origin HEAD 2>/dev/null || true
            cd - >/dev/null
            ok "${name} updated"
        else
            info "Installing ${name}..."
            git clone --depth 1 "$repo" "$dest" 2>/dev/null || { warn "${name} — clone failed"; return; }
            chmod +x "$bin_path" 2>/dev/null || true
            ok "${name} installed"
        fi
    }

    _install_git_tool "searchsploit" "https://gitlab.com/exploit-database/exploitdb.git" "/opt/exploitdb" "/opt/exploitdb/searchsploit"
    [ -x /opt/exploitdb/searchsploit ] && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit 2>/dev/null || true
    [ -f /opt/exploitdb/.searchsploit_rc ] && cp /opt/exploitdb/.searchsploit_rc /root/ 2>/dev/null || true

    _install_git_tool "nikto" "https://github.com/sullo/nikto.git" "/opt/nikto" "/opt/nikto/program/nikto.pl"
    [ -x /opt/nikto/program/nikto.pl ] && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto 2>/dev/null || true

    _install_git_tool "enum4linux" "https://github.com/CiscoCXSecurity/enum4linux.git" "/opt/enum4linux" "/opt/enum4linux/enum4linux.pl"
    [ -x /opt/enum4linux/enum4linux.pl ] && ln -sf /opt/enum4linux/enum4linux.pl /usr/local/bin/enum4linux 2>/dev/null || true

    # ── Python tools (impacket, netexec, bloodhound, ldapdomaindump) ──
    if command -v pip3 >/dev/null 2>&1; then
        for pypkg in impacket ldapdomaindump bloodhound; do
            if pip3 show "$pypkg" >/dev/null 2>&1; then
                info "pip upgrade ${pypkg}..."
                pip3 install --upgrade "$pypkg" -q 2>&1 | tail -1 || true
            else
                info "pip install ${pypkg}..."
                pip3 install "$pypkg" -q 2>&1 | tail -1 && ok "${pypkg} installed" || warn "${pypkg} — install failed"
            fi
        done

        # NetExec (from GitHub, not PyPI)
        if pip3 show netexec >/dev/null 2>&1; then
            info "pip upgrade netexec..."
            pip3 install --upgrade netexec -q 2>&1 | tail -1 || true
        else
            info "pip install netexec..."
            pip3 install "git+https://github.com/Pennyw0rth/NetExec.git" -q 2>&1 | tail -1 && \
                ok "netexec installed" || warn "netexec — install failed (optional)"
        fi
    fi

    # ── Summary ──
    local ok_count=0 missing=0
    for cmd in nmap fping masscan nuclei httpx naabu katana gowitness sslscan searchsploit nikto enum4linux kerbrute fingerprintx; do
        if command -v "$cmd" >/dev/null 2>&1; then
            ok_count=$((ok_count + 1))
        else
            warn "  ${cmd} — not found"
            missing=$((missing + 1))
        fi
    done
    ok "Tools: ${ok_count} available, ${missing} missing"
}

###########################################################################
# 3. Feeds
###########################################################################
feeds_update() {
    step "Updating vulnerability feeds"

    # Prefer running inside worker container if Docker is up
    if [ "$DOCKER_DEPLOY" = true ] && docker compose "${DOCKER_COMPOSE_FILES[@]}" ps 2>/dev/null | grep -q "worker.*Up"; then
        info "Updating nuclei templates in worker container..."
        docker compose "${DOCKER_COMPOSE_FILES[@]}" exec -T worker nuclei -update-templates 2>&1 | tail -2 && \
            ok "nuclei templates updated (worker)" || warn "worker nuclei template update failed"

        info "Updating searchsploit DB in worker container..."
        docker compose "${DOCKER_COMPOSE_FILES[@]}" exec -T worker searchsploit -u 2>&1 | tail -2 && \
            ok "searchsploit DB updated (worker)" || warn "worker searchsploit update failed"
    fi

    # Also update on host if tools are installed
    if command -v nuclei >/dev/null 2>&1; then
        info "nuclei -update-templates (host)..."
        nuclei -update-templates 2>&1 | tail -2 && ok "nuclei templates updated (host)" || true
    fi

    if command -v searchsploit >/dev/null 2>&1; then
        info "searchsploit -u (host)..."
        searchsploit -u 2>&1 | tail -2 && ok "searchsploit DB updated (host)" || true
    fi
}

###########################################################################
# 4. Docker stack
###########################################################################
docker_update() {
    step "Rebuilding Docker Compose stack"

    cd "$PROJECT_DIR"

    info "Mode: ${DOCKER_MODE:-docker}"
    info "Compose files: ${DOCKER_COMPOSE_FILES[*]}"

    # Pull external base images
    info "Pulling external images..."
    docker compose "${DOCKER_COMPOSE_FILES[@]}" pull db redis portal 2>&1 | tail -3 || true

    # Build app images with retry
    info "Building app images..."
    local build_ok=false
    for attempt in 1 2 3; do
        if docker compose "${DOCKER_COMPOSE_FILES[@]}" build --pull 2>&1 | tail -8; then
            build_ok=true; break
        fi
        warn "Build attempt ${attempt}/3 failed — retrying in 5s..."
        sleep 5
    done
    if [ "$build_ok" = false ]; then
        warn "Build failed after 3 attempts — images may be stale"
    fi

    # Recreate containers
    info "Recreating containers..."
    docker compose "${DOCKER_COMPOSE_FILES[@]}" up -d --remove-orphans 2>&1 | tail -5
    ok "Containers recreated"

    # Wait for DB
    info "Waiting for database..."
    for i in $(seq 1 20); do
        if docker compose "${DOCKER_COMPOSE_FILES[@]}" exec -T db mysqladmin ping -h localhost --silent 2>/dev/null; then
            ok "Database ready"
            break
        fi
        [ "$i" -eq 20 ] && warn "Database not ready after 20s"
        sleep 1
    done

    # Migrations
    info "Running Django migrations..."
    docker compose "${DOCKER_COMPOSE_FILES[@]}" exec -T api python manage.py migrate --noinput 2>&1 | tail -3 || \
        warn "migrations may have failed — check: docker compose logs api"

    # Collect static
    info "Collecting static files..."
    docker compose "${DOCKER_COMPOSE_FILES[@]}" exec -T api python manage.py collectstatic --noinput 2>&1 | tail -2 || true

    # Prune old images
    docker image prune -f 2>/dev/null || true
    ok "Docker stack updated"
}

###########################################################################
# Main
###########################################################################
RAW_BASE="https://raw.githubusercontent.com/Lw1nM1n4ung/demon-in-the-wire/rewrite-v2"

# ── Parse flags ────────────────────────────────────────────────────────
WITH_SELF=true; WITH_TOOLS=true; WITH_FEEDS=true; WITH_DOCKER=false; FORCE_HOST=false; WITH_HOST_PIP=false
for arg in "$@"; do
    case "$arg" in
        --self)   WITH_TOOLS=false; WITH_FEEDS=false ;;
        --tools)  WITH_SELF=false; WITH_FEEDS=false ;;
        --feeds)  WITH_SELF=false; WITH_TOOLS=false ;;
        --docker) WITH_DOCKER=true ;;
        --host)   FORCE_HOST=true; WITH_HOST_PIP=true ;;
        --all)    WITH_DOCKER=true; WITH_HOST_PIP=true ;;  # everything including host pip
        --help|-h)
            echo "Usage: sudo bash update-wireghost.sh [flags]"
            echo "  (no flags)  Auto-detect: self + tools + feeds + Docker (if running)"
            echo "  --docker    Force Docker stack rebuild"
            echo "  --host      Host-only mode (pip install locally, skip Docker)"
            echo "  --all       Everything: host tools + pip + Docker rebuild"
            echo "  --self      Self-update only (git pull + pip install)"
            echo "  --tools     Tools only (install missing + update existing)"
            echo "  --feeds     Feeds only (nuclei templates, searchsploit DB)"
            exit 0 ;;
    esac
done

# ── Banner ─────────────────────────────────────────────────────────────
printf "\n${BOLD}${CYAN} Wire_Ghost — One-Line Updater${NC}\n\n"

find_root
detect_docker

info "Project: ${PROJECT_DIR}"
if [ "$DOCKER_DEPLOY" = true ]; then
    ok "Detected Docker deployment (${DOCKER_MODE})"
fi

# Auto-enable Docker rebuild when deployment is detected and no explicit flags override
if [ "$DOCKER_DEPLOY" = true ] && [ "$FORCE_HOST" = false ] && [ "$WITH_SELF" = true ] && [ "$WITH_TOOLS" = true ] && [ "$WITH_FEEDS" = true ] && [ "$WITH_DOCKER" = false ]; then
    WITH_DOCKER=true
    info "Auto-enabling Docker stack rebuild (use --host to skip)"
fi

# For Docker deployments, skip host pip by default unless --host or --all
if [ "$DOCKER_DEPLOY" = true ] && [ "$FORCE_HOST" = false ]; then
    WITH_HOST_PIP=false
fi

# Count steps
_TOTAL=0
[ "$WITH_SELF" = true ] && _TOTAL=$((_TOTAL + 1))
[ "$WITH_TOOLS" = true ] && _TOTAL=$((_TOTAL + 1))
[ "$WITH_FEEDS" = true ] && _TOTAL=$((_TOTAL + 1))
[ "$WITH_DOCKER" = true ] && _TOTAL=$((_TOTAL + 1))

if [ "$_TOTAL" -eq 0 ]; then
    warn "Nothing selected — run with --help for usage"
    exit 0
fi

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

if [ "$DOCKER_DEPLOY" = true ]; then
    printf "  ${BOLD}Check status:${NC}  cd ${PROJECT_DIR} && docker compose ps\n"
fi
printf "  ${BOLD}View logs:${NC}    cd ${PROJECT_DIR} && docker compose logs -f api\n\n"
