#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
# Wire_Ghost — One-Command On-Premises Installer
#
# Usage:
#   sudo bash scripts/install.sh                     # Interactive
#   sudo bash scripts/install.sh --host              # Host mode
#   sudo bash scripts/install.sh --host --with-msf   # Host mode + Metasploit
#   sudo bash scripts/install.sh --docker            # Docker-only mode
# ══════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

# ── Flags ────────────────────────────────────────────────────────────
INSTALL_MODE=""
WITH_MSF=false
for arg in "$@"; do
    case "$arg" in
        --host)     INSTALL_MODE="host" ;;
        --docker)   INSTALL_MODE="docker" ;;
        --with-msf) WITH_MSF=true ;;
        --help|-h)
            cat <<'USAGE'
Wire_Ghost Installer

Usage: sudo bash scripts/install.sh [OPTIONS]

Options:
  --host       Host mode: scan tools on host, only web/DB in Docker
  --docker     Docker mode: everything in Docker containers (default)
  --with-msf   Install Metasploit Framework (host mode, adds ~1.5GB)
  --help       Show this help
USAGE
            exit 0
            ;;
    esac
done

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
    printf "  ${BOLD}On-Premises Installer${NC}\n\n"
}

# ── Progress bar ────────────────────────────────────────────────────
_TOTAL=7; _STEP=0
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

# ── Mode selection ──────────────────────────────────────────────────
select_install_mode() {
    if [ -n "$INSTALL_MODE" ]; then
        return
    fi

    if [ ! -t 0 ]; then
        INSTALL_MODE="docker"
        return
    fi

    printf "\n${BOLD}Select Installation Mode${NC}\n\n"
    printf "  ${CYAN}1)${NC} ${BOLD}Docker${NC}   Everything in containers (~3GB worker image)\n"
    printf "  ${CYAN}2)${NC} ${BOLD}Host${NC}     Scan tools on host, only web/DB in Docker\n"
    printf "\n"
    printf "  ${DIM}Host mode is recommended for pentesting — tools run natively\n"
    printf "  with full OS access and no container overhead.${NC}\n\n"
    printf "  Choice [1]: "
    read -r _mode
    case "$_mode" in
        2|host|Host) INSTALL_MODE="host" ;;
        *)           INSTALL_MODE="docker" ;;
    esac
    printf "\n"
}

# ── Host OS detection ───────────────────────────────────────────────
check_host_os() {
    if [ ! -f /etc/os-release ]; then
        die "Cannot detect OS — /etc/os-release not found"
    fi
    # shellcheck disable=SC1091
    source /etc/os-release
    case "${ID:-}" in
        debian|ubuntu|kali)
            ok "OS: ${PRETTY_NAME} (${ID})"
            ;;
        *)
            die "Host mode requires Debian, Ubuntu, or Kali (detected: ${PRETTY_NAME:-unknown})"
            ;;
    esac
}

# ── Prerequisite checks ─────────────────────────────────────────────
check_prereqs() {
    info "Checking prerequisites..."

    [ "$(id -u)" -eq 0 ] || die "This installer must be run as root (sudo bash install.sh)"

    if ! command -v docker >/dev/null 2>&1; then
        if [ "$_IS_WSL" = true ]; then
            die "Docker not found. On WSL, install Docker Desktop and enable WSL Integration: Settings → Resources → WSL Integration"
        fi
        die "Docker is not installed. Install Docker first: https://docs.docker.com/engine/install/"
    fi

    DOCKER_VERSION=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "0")
    DOCKER_MAJOR=$(echo "$DOCKER_VERSION" | cut -d. -f1)
    [ "$DOCKER_MAJOR" -ge 20 ] 2>/dev/null || die "Docker >= 20.x required (found: $DOCKER_VERSION)"

    docker compose version >/dev/null 2>&1 || die "Docker Compose V2 plugin not found. Install: https://docs.docker.com/compose/install/"

    if [ "$INSTALL_MODE" = "host" ]; then
        for cmd in curl unzip git; do
            command -v "$cmd" >/dev/null 2>&1 || die "${cmd} is required for host mode. Install: apt-get install ${cmd}"
        done
    fi

    TOTAL_MEM_MB=$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)
    if [ "$TOTAL_MEM_MB" -lt 3500 ]; then
        warn "System has ${TOTAL_MEM_MB}MB RAM — 4GB+ recommended for stable operation"
    fi

    DISK_FREE_GB=$(df -BG "$PROJECT_DIR" | awk 'NR==2 {gsub(/G/,"",$4); print $4}' 2>/dev/null || echo 0)
    if [ "$DISK_FREE_GB" -lt 15 ]; then
        warn "Only ${DISK_FREE_GB}GB free disk — 20GB+ recommended"
    fi

    ok "Prerequisites satisfied (Docker $DOCKER_VERSION, ${TOTAL_MEM_MB}MB RAM, ${DISK_FREE_GB}GB free)"
}

# ── Generate a cryptographic random string ───────────────────────────
gen_secret() {
    openssl rand -base64 96 | tr -d '\n/+=' | head -c 64
}

# ── Prompt helper: show default, read input, keep default if empty ───
# Usage: prompt_var VARNAME "Label" "default_value"
prompt_var() {
    local varname="$1" label="$2" default="$3"
    local current="${!varname:-$default}"
    printf "  %-22s ${DIM}[%s]${NC}: " "$label" "$current"
    read -r _input
    if [ -n "$_input" ]; then
        printf -v "$varname" '%s' "$_input"
    else
        printf -v "$varname" '%s' "$current"
    fi
}

# Prompt for a secret: show truncated auto-gen value
prompt_secret() {
    local varname="$1" label="$2" default="$3"
    local current="${!varname:-$default}"
    local masked="${current:0:4}...${current: -3}"
    printf "  %-22s ${DIM}[auto: %s]${NC}: " "$label" "$masked"
    read -r _input
    if [ -n "$_input" ]; then
        printf -v "$varname" '%s' "$_input"
    else
        printf -v "$varname" '%s' "$current"
    fi
}

# Mask a secret for display: first 4 + last 3 chars
mask_secret() {
    local val="$1"
    if [ ${#val} -gt 10 ]; then
        printf "%s...%s" "${val:0:4}" "${val: -3}"
    else
        printf "********"
    fi
}

# ── Check if a port is available (returns 0=available, 1=in-use) ────
_port_available() {
    local port="$1"
    local hit
    hit=$(ss -tlnp "sport = :${port}" 2>/dev/null | grep -v "^State" | head -1) || true
    if [ -n "$hit" ] && ! echo "$hit" | grep -q "docker\|containerd"; then
        return 1
    fi
    return 0
}

# ── Prompt for a port with live availability check ─────────────────
# Re-prompts until the user picks a free port or explicitly confirms.
# Usage: prompt_port VARNAME "Label" "default"
prompt_port() {
    local varname="$1" label="$2" default="$3"
    while true; do
        prompt_var "$varname" "$label" "$default"
        local chosen="${!varname}"
        if ! [[ "$chosen" =~ ^[0-9]+$ ]] || [ "$chosen" -lt 1 ] || [ "$chosen" -gt 65535 ]; then
            warn "Invalid port number: $chosen"
            eval "$varname=\"$default\""
            continue
        fi
        if _port_available "$chosen"; then
            break
        fi
        warn "Port $chosen is already in use by another service"
        printf "  ${DIM}Keep anyway? [y/N]:${NC} "
        read -r _keep
        if [[ "$_keep" =~ ^[Yy] ]]; then
            break
        fi
    done
}

# ── Compute derived values from proto/host/port ─────────────────────
_compute_derived() {
    if [ "$WIREGHOST_PROTO" = "https" ]; then
        SESSION_COOKIE_SECURE="true"
        CSRF_COOKIE_SECURE="true"
    else
        SESSION_COOKIE_SECURE="false"
        CSRF_COOKIE_SECURE="false"
    fi

    _PORT_SUFFIX=""
    if [ "$WIREGHOST_PROTO" = "https" ] && [ "$WIREGHOST_PORT" != "443" ]; then
        _PORT_SUFFIX=":${WIREGHOST_PORT}"
    elif [ "$WIREGHOST_PROTO" = "http" ] && [ "$WIREGHOST_PORT" != "80" ]; then
        _PORT_SUFFIX=":${WIREGHOST_PORT}"
    fi
    CSRF_TRUSTED_ORIGINS="${WIREGHOST_PROTO}://${WIREGHOST_HOST}${_PORT_SUFFIX},${WIREGHOST_PROTO}://localhost${_PORT_SUFFIX},${WIREGHOST_PROTO}://127.0.0.1${_PORT_SUFFIX}"
}

# ── Collect all configuration (interactive, grouped) ────────────────
collect_all_config() {
    UPGRADE_MODE=false
    if [ -f .env ]; then
        UPGRADE_MODE=true
        warn "Existing .env found — values from .env used as defaults"
        # shellcheck disable=SC1091
        set -a; source .env; set +a
    fi

    # Pre-generate secrets so they're available as defaults
    _AUTO_DJANGO_SECRET="$(gen_secret)"
    _AUTO_MYSQL_ROOT_PW="$(gen_secret)"
    _AUTO_MYSQL_PW="$(gen_secret)"
    _AUTO_REDIS_PW="$(gen_secret)"

    # Carry forward existing secrets in upgrade mode, otherwise use auto-gen
    DJANGO_SECRET_KEY="${DJANGO_SECRET_KEY:-$_AUTO_DJANGO_SECRET}"
    MYSQL_ROOT_PASSWORD="${MYSQL_ROOT_PASSWORD:-$_AUTO_MYSQL_ROOT_PW}"
    MYSQL_PASSWORD="${MYSQL_PASSWORD:-$_AUTO_MYSQL_PW}"
    REDIS_PASSWORD="${REDIS_PASSWORD:-$_AUTO_REDIS_PW}"
    MYSQL_DATABASE="${MYSQL_DATABASE:-wireghost}"
    MYSQL_USER="${MYSQL_USER:-wireghost}"
    WIREGHOST_PROTO="${WIREGHOST_PROTO:-https}"
    WIREGHOST_LOG_DIR="${WIREGHOST_LOG_DIR:-./logs}"
    WIREGHOST_LOG_LEVEL="${WIREGHOST_LOG_LEVEL:-INFO}"

    # Auto-detect host IP as fallback default
    _DETECTED_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [ "$_IS_WSL" = true ]; then
        _DETECTED_IP="localhost"
        info "WSL: defaulting to localhost (Windows auto-forwards ports to WSL2)"
    fi
    _HOST_DEFAULT="${WIREGHOST_HOST:-}"
    if [ -z "$_HOST_DEFAULT" ] || [ "$_HOST_DEFAULT" = "localhost" ] || [ "$_HOST_DEFAULT" = "*" ]; then
        _HOST_DEFAULT="${_DETECTED_IP:-localhost}"
    fi
    WIREGHOST_HOST="$_HOST_DEFAULT"
    WIREGHOST_PORT="${WIREGHOST_PORT:-443}"
    WIREGHOST_HTTP_PORT="${WIREGHOST_HTTP_PORT:-80}"

    # ── Non-interactive mode: accept all defaults ────────────────────
    if [ ! -t 0 ]; then
        if [ "$WIREGHOST_HOST" = "localhost" ] && [ "$_IS_WSL" != true ]; then
            die "Non-interactive mode requires WIREGHOST_HOST to be set in .env or environment"
        fi
        _compute_derived
        ok "Non-interactive mode — using defaults"
        return
    fi

    # ── Interactive: grouped sections with skip option ───────────────
    printf "\n${BOLD}Configure .env — press Enter to accept defaults in [brackets]${NC}\n"
    printf "${DIM}Each section can be skipped entirely with the default 'N'.${NC}\n"

    # ── Section 1/5: Portal Access ───────────────────────────────────
    printf "\n${CYAN}── 1/5  Portal Access ──────────────────────────────${NC}\n"
    printf "  Customize? [y/N] "
    read -r _sec1
    if [[ "$_sec1" =~ ^[Yy] ]]; then
        prompt_var WIREGHOST_HOST      "WIREGHOST_HOST"      "$WIREGHOST_HOST"
        prompt_port WIREGHOST_PORT      "HTTPS Port"          "$WIREGHOST_PORT"
        prompt_port WIREGHOST_HTTP_PORT "HTTP Port (redirect)" "$WIREGHOST_HTTP_PORT"
        prompt_var WIREGHOST_PROTO     "WIREGHOST_PROTO"     "$WIREGHOST_PROTO"
    else
        printf "  ${DIM}(using defaults: %s, https=%s, http=%s, %s)${NC}\n" "$WIREGHOST_HOST" "$WIREGHOST_PORT" "$WIREGHOST_HTTP_PORT" "$WIREGHOST_PROTO"
    fi

    # ── Section 2/5: Database ────────────────────────────────────────
    printf "\n${CYAN}── 2/5  Database (MySQL) ───────────────────────────${NC}\n"
    printf "  Customize? [y/N] "
    read -r _sec2
    if [[ "$_sec2" =~ ^[Yy] ]]; then
        prompt_var    MYSQL_DATABASE      "MYSQL_DATABASE"      "$MYSQL_DATABASE"
        prompt_var    MYSQL_USER          "MYSQL_USER"          "$MYSQL_USER"
        prompt_secret MYSQL_PASSWORD      "MYSQL_PASSWORD"      "$MYSQL_PASSWORD"
        prompt_secret MYSQL_ROOT_PASSWORD "MYSQL_ROOT_PASSWORD" "$MYSQL_ROOT_PASSWORD"
    else
        printf "  ${DIM}(using defaults: db=%s, user=%s, passwords=auto)${NC}\n" "$MYSQL_DATABASE" "$MYSQL_USER"
    fi

    # ── Section 3/5: Redis ───────────────────────────────────────────
    printf "\n${CYAN}── 3/5  Redis ─────────────────────────────────────${NC}\n"
    printf "  Customize? [y/N] "
    read -r _sec3
    if [[ "$_sec3" =~ ^[Yy] ]]; then
        prompt_secret REDIS_PASSWORD "REDIS_PASSWORD" "$REDIS_PASSWORD"
    else
        printf "  ${DIM}(using default: password=auto)${NC}\n"
    fi

    # ── Section 4/5: Django ──────────────────────────────────────────
    printf "\n${CYAN}── 4/5  Django ────────────────────────────────────${NC}\n"
    printf "  Customize? [y/N] "
    read -r _sec4
    if [[ "$_sec4" =~ ^[Yy] ]]; then
        prompt_secret DJANGO_SECRET_KEY "DJANGO_SECRET_KEY" "$DJANGO_SECRET_KEY"
    else
        printf "  ${DIM}(using default: secret_key=auto)${NC}\n"
    fi

    # ── Section 5/5: Logging ─────────────────────────────────────────
    printf "\n${CYAN}── 5/5  Logging ───────────────────────────────────${NC}\n"
    printf "  Customize? [y/N] "
    read -r _sec5
    if [[ "$_sec5" =~ ^[Yy] ]]; then
        prompt_var WIREGHOST_LOG_DIR   "WIREGHOST_LOG_DIR"   "$WIREGHOST_LOG_DIR"
        prompt_var WIREGHOST_LOG_LEVEL "WIREGHOST_LOG_LEVEL" "$WIREGHOST_LOG_LEVEL"
    else
        printf "  ${DIM}(using defaults: dir=%s, level=%s)${NC}\n" "$WIREGHOST_LOG_DIR" "$WIREGHOST_LOG_LEVEL"
    fi

    _compute_derived

    # ── Confirmation summary ─────────────────────────────────────────
    printf "\n${BOLD}══ Configuration Summary ═══════════════════════════${NC}\n"
    printf "  %-24s %s\n" "INSTALL_MODE"          "$INSTALL_MODE"
    printf "  %-24s %s\n" "WIREGHOST_HOST"       "$WIREGHOST_HOST"
    printf "  %-24s %s\n" "WIREGHOST_PORT"       "$WIREGHOST_PORT"
    printf "  %-24s %s\n" "WIREGHOST_HTTP_PORT"  "$WIREGHOST_HTTP_PORT"
    printf "  %-24s %s\n" "WIREGHOST_PROTO"      "$WIREGHOST_PROTO"
    printf "  %-24s %s\n" "MYSQL_DATABASE"       "$MYSQL_DATABASE"
    printf "  %-24s %s\n" "MYSQL_USER"           "$MYSQL_USER"
    printf "  %-24s %s  ${DIM}(auto)${NC}\n" "MYSQL_PASSWORD"       "$(mask_secret "$MYSQL_PASSWORD")"
    printf "  %-24s %s  ${DIM}(auto)${NC}\n" "MYSQL_ROOT_PASSWORD"  "$(mask_secret "$MYSQL_ROOT_PASSWORD")"
    printf "  %-24s %s  ${DIM}(auto)${NC}\n" "REDIS_PASSWORD"       "$(mask_secret "$REDIS_PASSWORD")"
    printf "  %-24s %s  ${DIM}(auto)${NC}\n" "DJANGO_SECRET_KEY"    "$(mask_secret "$DJANGO_SECRET_KEY")"
    printf "  %-24s %s\n" "SESSION_COOKIE_SECURE" "$SESSION_COOKIE_SECURE"
    printf "  %-24s %s\n" "CSRF_COOKIE_SECURE"    "$CSRF_COOKIE_SECURE"
    printf "  %-24s %s\n" "WIREGHOST_LOG_DIR"     "$WIREGHOST_LOG_DIR"
    printf "  %-24s %s\n" "WIREGHOST_LOG_LEVEL"   "$WIREGHOST_LOG_LEVEL"

    printf "\n  Write .env? [Y/n] "
    read -r _confirm
    if [[ "$_confirm" =~ ^[Nn] ]]; then
        die "Aborted — .env not written"
    fi

    ok "Configuration confirmed"
}

# ══════════════════════════════════════════════════════════════════════
# HOST MODE — Tool installation functions
# ══════════════════════════════════════════════════════════════════════

install_apt_tools() {
    info "Installing system packages..."
    apt-get update -qq

    local pkgs=(
        nmap fping masscan libpcap0.8 libsnmp40
        sslscan nfs-common snmp onesixtyone
        arp-scan netdiscover
        smbclient samba-common-bin ldap-utils
        chromium chromium-driver
        perl libnet-ssleay-perl libio-socket-ssl-perl
        libjson-perl libxml-writer-perl libxml-libxml-perl
        python3-dev python3-venv gcc default-libmysqlclient-dev pkg-config
        curl unzip git rsync libxml2-utils
    )

    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${pkgs[@]}" 2>&1 | tail -3
    ok "System packages installed"
}

_install_go_zip() {
    local name="$1" repo="$2" pattern="$3"
    if command -v "$name" >/dev/null 2>&1; then
        ok "${name} already installed: $("$name" -version 2>&1 | head -1 || true)"
        return 0
    fi
    info "Downloading ${name}..."
    local url
    url=$(curl -sL "https://api.github.com/repos/${repo}/releases/latest" \
        | grep -o "\"browser_download_url\": *\"[^\"]*${pattern}\"" \
        | head -1 | cut -d'"' -f4)
    if [ -z "$url" ]; then
        warn "Could not find download URL for ${name} — skipping"
        return 1
    fi
    local tmp="/tmp/${name}_dl.zip"
    curl -sL "$url" -o "$tmp"
    unzip -o "$tmp" "$name" -d /usr/local/bin/ >/dev/null
    chmod +x "/usr/local/bin/${name}"
    rm -f "$tmp"
    ok "${name}: $(/usr/local/bin/${name} -version 2>&1 | head -1 || echo 'installed')"
}

install_go_binaries() {
    info "Installing Go-based scan tools from GitHub releases..."

    _install_go_zip nuclei  "projectdiscovery/nuclei"  "linux_amd64.zip"
    _install_go_zip httpx   "projectdiscovery/httpx"   "linux_amd64.zip"
    _install_go_zip naabu   "projectdiscovery/naabu"   "linux_amd64.zip"
    _install_go_zip katana  "projectdiscovery/katana"  "linux_amd64.zip"

    if ! command -v gowitness >/dev/null 2>&1; then
        info "Downloading gowitness..."
        local gw_url
        gw_url=$(curl -sL "https://api.github.com/repos/sensepost/gowitness/releases/latest" \
            | grep -o '"browser_download_url": *"[^"]*linux-amd64[^"]*"' \
            | head -1 | cut -d'"' -f4)
        if [ -n "$gw_url" ]; then
            curl -sL "$gw_url" -o /usr/local/bin/gowitness
            chmod +x /usr/local/bin/gowitness
            ok "gowitness: $(gowitness version 2>&1 | head -1 || echo 'installed')"
        else
            warn "Could not find gowitness download URL — skipping"
        fi
    else
        ok "gowitness already installed"
    fi

    if command -v nuclei >/dev/null 2>&1; then
        info "Updating nuclei templates..."
        nuclei -update-templates 2>&1 | tail -2 || true
    fi

    ok "Go binaries installed"
}

install_git_tools() {
    info "Installing git-based tools..."

    if [ ! -d /opt/exploitdb ]; then
        git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb
        ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
        cp /opt/exploitdb/.searchsploit_rc /root/ 2>/dev/null || true
        ok "searchsploit installed"
    else
        ok "searchsploit already installed"
    fi

    if [ ! -d /opt/nikto ]; then
        git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto
        ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto
        chmod +x /usr/local/bin/nikto
        rm -rf /opt/nikto/.git
        ok "nikto installed"
    else
        ok "nikto already installed"
    fi

    if [ ! -d /opt/enum4linux ]; then
        git clone --depth 1 https://github.com/CiscoCXSecurity/enum4linux.git /opt/enum4linux
        ln -sf /opt/enum4linux/enum4linux.pl /usr/local/bin/enum4linux
        chmod +x /opt/enum4linux/enum4linux.pl
        ok "enum4linux installed"
    else
        ok "enum4linux already installed"
    fi
}

install_python_venv() {
    VENV_DIR="${PROJECT_DIR}/.venv"
    info "Creating Python virtual environment at ${VENV_DIR}..."

    if [ ! -d "$VENV_DIR" ]; then
        python3 -m venv "$VENV_DIR"
    fi

    "$VENV_DIR/bin/pip" install --upgrade pip wheel setuptools -q

    info "Installing Python dependencies..."
    "$VENV_DIR/bin/pip" install --no-cache-dir -r web_portal/requirements.txt -q 2>&1 | tail -3

    info "Installing wireghost library..."
    "$VENV_DIR/bin/pip" install --no-cache-dir -e . -q 2>&1 | tail -2

    info "Installing NetExec..."
    "$VENV_DIR/bin/pip" install --no-cache-dir netexec -q 2>&1 | tail -2

    ok "Python venv ready ($(${VENV_DIR}/bin/python --version))"
}

install_msf() {
    if [ "$WITH_MSF" != true ]; then
        info "Metasploit skipped (use --with-msf to install)"
        return
    fi

    if command -v msfconsole >/dev/null 2>&1; then
        ok "Metasploit already installed: $(msfconsole --version 2>&1 | head -1)"
        return
    fi

    info "Installing Metasploit Framework (~1.5GB)..."
    curl -fsSL https://apt.metasploit.com/metasploit-framework.gpg.key \
        | gpg --dearmor -o /usr/share/keyrings/metasploit.gpg
    echo "deb [signed-by=/usr/share/keyrings/metasploit.gpg] https://apt.metasploit.com/ buster main" \
        > /etc/apt/sources.list.d/metasploit.list
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends metasploit-framework 2>&1 | tail -3
    rm -rf /var/lib/apt/lists/*
    ok "Metasploit installed: $(msfconsole --version 2>&1 | head -1 || echo 'done')"
}

install_host_tools() {
    step "Installing host scan tools"

    check_host_os
    install_apt_tools
    install_go_binaries
    install_git_tools
    install_python_venv
    install_msf

    info "Verifying tools..."
    local tools_ok=0 tools_fail=0
    for cmd in nmap fping masscan nuclei naabu httpx katana gowitness sslscan searchsploit nikto enum4linux; do
        if command -v "$cmd" >/dev/null 2>&1; then
            tools_ok=$((tools_ok + 1))
        else
            warn "  ${cmd} — not found"
            tools_fail=$((tools_fail + 1))
        fi
    done
    for cmd in nxc; do
        if "$VENV_DIR/bin/python" -c "import shutil; exit(0 if shutil.which('nxc') or shutil.which('netexec') else 1)" 2>/dev/null; then
            tools_ok=$((tools_ok + 1))
        else
            warn "  netexec — not in venv PATH"
            tools_fail=$((tools_fail + 1))
        fi
    done
    ok "Tools: ${tools_ok} available, ${tools_fail} missing"
}

# ══════════════════════════════════════════════════════════════════════
# Systemd unit installation (host mode)
# ══════════════════════════════════════════════════════════════════════

install_systemd_units() {
    VENV_DIR="${VENV_DIR:-${PROJECT_DIR}/.venv}"
    local log_dir
    log_dir="$(cd "$PROJECT_DIR" && readlink -f "${WIREGHOST_LOG_DIR:-./logs}")"

    info "Installing systemd units..."

    for unit in wireghost-worker wireghost-beat; do
        local src="config/${unit}.service"
        local dst="/etc/systemd/system/${unit}.service"

        if [ ! -f "$src" ]; then
            die "Template not found: ${src}"
        fi

        sed -e "s|__PROJECT_DIR__|${PROJECT_DIR}|g" \
            -e "s|__VENV_DIR__|${VENV_DIR}|g" \
            -e "s|__LOG_DIR__|${log_dir}|g" \
            "$src" > "$dst"

        chmod 644 "$dst"
        ok "Installed ${dst}"
    done

    systemctl daemon-reload
    systemctl enable wireghost-worker wireghost-beat
    ok "systemd units enabled"
}

# ══════════════════════════════════════════════════════════════════════
# TLS certificate generation
# ══════════════════════════════════════════════════════════════════════

generate_certs() {
    mkdir -p certs

    if [ -f certs/cert.pem ] && [ -f certs/key.pem ]; then
        EXISTING_CN=$(openssl x509 -in certs/cert.pem -noout -subject 2>/dev/null | sed 's/.*CN *= *//')
        EXISTING_EXPIRY=$(openssl x509 -in certs/cert.pem -noout -enddate 2>/dev/null | cut -d= -f2)
        info "Existing TLS cert found (CN=${EXISTING_CN}, expires ${EXISTING_EXPIRY})"

        if [ "$EXISTING_CN" = "$WIREGHOST_HOST" ]; then
            ok "Certificate CN matches hostname — keeping existing cert"
            return
        else
            warn "Certificate CN (${EXISTING_CN}) doesn't match hostname (${WIREGHOST_HOST})"
            if [ -t 0 ]; then
                printf "  Regenerate certificate? [Y/n] "
                read -r REGEN
                if [[ "$REGEN" =~ ^[Nn] ]]; then
                    warn "Keeping mismatched certificate"
                    return
                fi
            fi
            info "Regenerating certificate for ${WIREGHOST_HOST}..."
        fi
    fi

    info "Generating self-signed TLS certificate for ${WIREGHOST_HOST}..."

    if echo "$WIREGHOST_HOST" | grep -qP '^\d+\.\d+\.\d+\.\d+$'; then
        SAN="IP:${WIREGHOST_HOST}"
    else
        SAN="DNS:${WIREGHOST_HOST}"
    fi

    openssl req -x509 -nodes -days 3650 \
        -newkey rsa:2048 \
        -keyout certs/key.pem \
        -out certs/cert.pem \
        -subj "/CN=${WIREGHOST_HOST}/O=Wire_Ghost" \
        -addext "subjectAltName=${SAN},IP:127.0.0.1,DNS:localhost" \
        2>/dev/null

    chmod 600 certs/key.pem
    chmod 644 certs/cert.pem

    ok "Self-signed certificate generated (valid 10 years)"
    FINGERPRINT=$(openssl x509 -in certs/cert.pem -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
    info "  SHA-256: ${FINGERPRINT}"
}

# ── Render nginx config ──────────────────────────────────────────────
render_nginx() {
    if [ ! -f config/nginx.conf.tpl ]; then
        die "config/nginx.conf.tpl not found — is this the Wire_Ghost project directory?"
    fi

    sed -e "s/{{WIREGHOST_HOST}}/${WIREGHOST_HOST}/g" \
        -e "s/{{WIREGHOST_PORT}}/${WIREGHOST_PORT}/g" \
        config/nginx.conf.tpl > nginx.conf
    ok "nginx.conf rendered for ${WIREGHOST_HOST}:${WIREGHOST_PORT}"
}

# ── Write .env ───────────────────────────────────────────────────────
write_env() {
    if [ "$UPGRADE_MODE" = true ]; then
        info "Updating .env with configured values..."

        _update_env_var() {
            local key="$1" val="$2"
            if grep -q "^${key}=" .env; then
                { grep -v "^${key}=" .env || true; } > .env.tmp && mv .env.tmp .env
            fi
            printf '%s=%s\n' "$key" "$val" >> .env
        }

        _update_env_var INSTALL_MODE          "$INSTALL_MODE"
        _update_env_var WIREGHOST_HOST       "$WIREGHOST_HOST"
        _update_env_var WIREGHOST_PORT       "$WIREGHOST_PORT"
        _update_env_var WIREGHOST_HTTP_PORT  "$WIREGHOST_HTTP_PORT"
        _update_env_var WIREGHOST_PROTO      "$WIREGHOST_PROTO"
        _update_env_var SESSION_COOKIE_SECURE "$SESSION_COOKIE_SECURE"
        _update_env_var CSRF_COOKIE_SECURE   "$CSRF_COOKIE_SECURE"
        _update_env_var CSRF_TRUSTED_ORIGINS "$CSRF_TRUSTED_ORIGINS"
        _update_env_var MYSQL_DATABASE       "$MYSQL_DATABASE"
        _update_env_var MYSQL_USER           "$MYSQL_USER"
        _update_env_var MYSQL_PASSWORD       "$MYSQL_PASSWORD"
        _update_env_var MYSQL_ROOT_PASSWORD  "$MYSQL_ROOT_PASSWORD"
        _update_env_var REDIS_PASSWORD       "$REDIS_PASSWORD"
        _update_env_var DJANGO_SECRET_KEY    "$DJANGO_SECRET_KEY"
        _update_env_var WIREGHOST_LOG_DIR    "$WIREGHOST_LOG_DIR"
        _update_env_var WIREGHOST_LOG_LEVEL  "$WIREGHOST_LOG_LEVEL"

        if [ "$INSTALL_MODE" = "host" ]; then
            _update_env_var WIREGHOST_DATA_DIR   "${PROJECT_DIR}/data"
            _update_env_var MYSQL_HOST            "127.0.0.1"
            _update_env_var MYSQL_PORT            "3306"
            _update_env_var DJANGO_SETTINGS_MODULE "wireghost_web.settings"
            _update_env_var DJANGO_DEBUG          "false"
            _update_env_var WIREGHOST_OUTPUT_DIR  "${PROJECT_DIR}/data/output"
            _update_env_var CELERY_BROKER_URL     "redis://:${REDIS_PASSWORD}@127.0.0.1:6379/0"
            _update_env_var CELERY_RESULT_BACKEND "redis://:${REDIS_PASSWORD}@127.0.0.1:6379/0"
        fi

        ok ".env updated"
        return
    fi

    cat > .env <<ENVEOF
# Wire_Ghost — Generated by install.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Do not commit this file. Secrets are auto-generated.

# Install mode
INSTALL_MODE=${INSTALL_MODE}

# Django
DJANGO_SECRET_KEY=${DJANGO_SECRET_KEY}

# MySQL
MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASSWORD}
MYSQL_DATABASE=${MYSQL_DATABASE}
MYSQL_USER=${MYSQL_USER}
MYSQL_PASSWORD=${MYSQL_PASSWORD}

# Redis
REDIS_PASSWORD=${REDIS_PASSWORD}

# Portal
WIREGHOST_HOST=${WIREGHOST_HOST}
WIREGHOST_PORT=${WIREGHOST_PORT}
WIREGHOST_HTTP_PORT=${WIREGHOST_HTTP_PORT}
WIREGHOST_PROTO=${WIREGHOST_PROTO}
SESSION_COOKIE_SECURE=${SESSION_COOKIE_SECURE}
CSRF_COOKIE_SECURE=${CSRF_COOKIE_SECURE}
CSRF_TRUSTED_ORIGINS=${CSRF_TRUSTED_ORIGINS}

# Logging
WIREGHOST_LOG_DIR=${WIREGHOST_LOG_DIR}
WIREGHOST_LOG_LEVEL=${WIREGHOST_LOG_LEVEL}
ENVEOF

    if [ "$INSTALL_MODE" = "host" ]; then
        cat >> .env <<HOSTEOF

# Host mode — worker/beat connect to DB and Redis on localhost
WIREGHOST_DATA_DIR=${PROJECT_DIR}/data
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
DJANGO_SETTINGS_MODULE=wireghost_web.settings
DJANGO_DEBUG=false
WIREGHOST_OUTPUT_DIR=${PROJECT_DIR}/data/output
CELERY_BROKER_URL=redis://:${REDIS_PASSWORD}@127.0.0.1:6379/0
CELERY_RESULT_BACKEND=redis://:${REDIS_PASSWORD}@127.0.0.1:6379/0
HOSTEOF
    fi

    chmod 600 .env
    ok ".env written (chmod 600)"
}

# ── Create directories ───────────────────────────────────────────────
create_dirs() {
    mkdir -p logs/api logs/nginx certs
    chown -R 1000:1000 logs/api 2>/dev/null || true

    if [ "$INSTALL_MODE" = "host" ]; then
        mkdir -p "${PROJECT_DIR}/data/output" "${PROJECT_DIR}/data/assets"
        ok "Data directories created (data/output, data/assets)"
    fi

    ok "Log directories created"
}

# ── Docker daemon hardening ──────────────────────────────────────────
harden_docker_daemon() {
    local DAEMON_JSON="/etc/docker/daemon.json"
    if [ ! -f "$DAEMON_JSON" ]; then
        step "Hardening Docker daemon"
        cat > "$DAEMON_JSON" <<'DAEMONJSON'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "50m",
    "max-file": "3"
  },
  "live-restore": true,
  "no-new-privileges": true
}
DAEMONJSON
        systemctl reload docker 2>/dev/null || true
        ok "Created ${DAEMON_JSON} (log rotation + no-new-privileges)"
    else
        info "Docker daemon.json already exists — skipping"
    fi
}

# ══════════════════════════════════════════════════════════════════════
# Build and start — Docker mode
# ══════════════════════════════════════════════════════════════════════

build_and_start_docker() {
    step "Building containers"
    info "This may take several minutes on first run..."
    export DOCKER_CONTENT_TRUST=1
    docker compose build --pull 2>&1 | tail -5

    step "Starting services"
    info "Starting Wire_Ghost stack..."
    docker compose up -d

    ok "All services started"
}

# ══════════════════════════════════════════════════════════════════════
# Build and start — Host mode
# ══════════════════════════════════════════════════════════════════════

build_and_start_host() {
    step "Building web containers (slim image)"

    # Remove Docker-managed named volumes that conflict with host-mode bind mounts
    for vol in demon-in-the-wire_scan_output demon-in-the-wire_report_assets; do
        if docker volume inspect "$vol" >/dev/null 2>&1; then
            driver_opts=$(docker volume inspect "$vol" --format '{{.Options}}' 2>/dev/null || echo "")
            if [ "$driver_opts" = "map[]" ] || [ -z "$driver_opts" ]; then
                warn "Removing Docker-managed volume ${vol} (conflicts with host-mode bind mount)"
                docker volume rm "$vol" 2>/dev/null || true
            fi
        fi
    done

    info "Building API/portal containers only..."
    export DOCKER_CONTENT_TRUST=1
    docker compose -f docker-compose.yml -f docker-compose.host.yml build --pull api portal 2>&1 | tail -5

    step "Starting Docker services"
    info "Starting DB, Redis, API, portal..."
    docker compose -f docker-compose.yml -f docker-compose.host.yml up -d

    step "Starting host services"
    install_systemd_units

    systemctl start wireghost-worker
    systemctl start wireghost-beat
    ok "Celery worker + beat started via systemd"
}

# ══════════════════════════════════════════════════════════════════════
# Health check
# ══════════════════════════════════════════════════════════════════════

_compose_cmd() {
    if [ "$INSTALL_MODE" = "host" ]; then
        docker compose -f docker-compose.yml -f docker-compose.host.yml "$@"
    else
        docker compose "$@"
    fi
}

wait_for_health() {
    info "Waiting for services to become healthy..."

    TIMEOUT=90
    ELAPSED=0
    while [ $ELAPSED -lt $TIMEOUT ]; do
        DB_OK=$(_compose_cmd ps db --format '{{.Health}}' 2>/dev/null || echo "")
        REDIS_OK=$(_compose_cmd ps redis --format '{{.Health}}' 2>/dev/null || echo "")

        if [ "$DB_OK" = "healthy" ] && [ "$REDIS_OK" = "healthy" ]; then
            ok "Database and Redis healthy"
            break
        fi

        sleep 3
        ELAPSED=$((ELAPSED + 3))
        printf "."
    done
    printf "\n"

    if [ $ELAPSED -ge $TIMEOUT ]; then
        warn "Timed out waiting for infrastructure (${TIMEOUT}s) — check: docker compose logs db redis"
    fi

    ELAPSED=0
    TIMEOUT=60
    while [ $ELAPSED -lt $TIMEOUT ]; do
        HTTP_CODE=$(_compose_cmd exec -T api python -c "
import django, os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'wireghost_web.settings')
django.setup()
print('OK')
" 2>/dev/null || echo "")

        if [ "$HTTP_CODE" = "OK" ]; then
            ok "Django application ready"
            break
        fi

        sleep 3
        ELAPSED=$((ELAPSED + 3))
        printf "."
    done
    printf "\n"

    if [ $ELAPSED -ge $TIMEOUT ]; then
        warn "API container not responding after ${TIMEOUT}s — check: docker compose logs api"
    fi

    if [ "$INSTALL_MODE" = "host" ]; then
        sleep 3
        if systemctl is-active --quiet wireghost-worker; then
            ok "Celery worker active"
        else
            warn "Celery worker not active — check: journalctl -u wireghost-worker"
        fi
        if systemctl is-active --quiet wireghost-beat; then
            ok "Celery beat active"
        else
            warn "Celery beat not active — check: journalctl -u wireghost-beat"
        fi
    fi
}

# ── Print summary ────────────────────────────────────────────────────
print_summary() {
    SETUP_URL="${WIREGHOST_PROTO}://${WIREGHOST_HOST}"
    if { [ "$WIREGHOST_PROTO" = "https" ] && [ "$WIREGHOST_PORT" != "443" ]; } || \
       { [ "$WIREGHOST_PROTO" = "http" ] && [ "$WIREGHOST_PORT" != "80" ]; }; then
        SETUP_URL="${SETUP_URL}:${WIREGHOST_PORT}"
    fi

    printf "\n"
    printf "${GREEN}══════════════════════════════════════════════════════════════${NC}\n"
    printf "${GREEN}  Wire_Ghost installed successfully!${NC}\n"
    printf "${GREEN}══════════════════════════════════════════════════════════════${NC}\n"
    printf "\n"
    printf "  ${BOLD}Mode:${NC}       ${CYAN}%s${NC}\n" "$INSTALL_MODE"
    printf "  ${BOLD}Setup URL:${NC}  ${CYAN}${SETUP_URL}/setup${NC}\n"
    printf "  ${BOLD}Login URL:${NC}  ${CYAN}${SETUP_URL}/login${NC}\n"
    printf "\n"
    printf "  Open the Setup URL in your browser to create the admin account.\n"
    printf "  (Accept the self-signed certificate warning if prompted.)\n"
    printf "\n"
    if [ "$_IS_WSL" = true ]; then
        printf "  ${YELLOW}${BOLD}WSL:${NC} Open the URL above in your Windows browser.\n"
        printf "  Windows auto-forwards localhost ports to WSL2.\n"
        printf "  For external access, set up Windows port forwarding.\n"
        printf "\n"
    fi
    printf "  ${BOLD}Management:${NC}\n"
    printf "    ./scripts/wg-ctl status          Show service health\n"
    printf "    ./scripts/wg-ctl backup          Create full backup\n"
    printf "    ./scripts/wg-ctl logs [service]  Stream logs\n"
    printf "    ./scripts/wg-ctl --help          All commands\n"
    printf "\n"

    if [ "$INSTALL_MODE" = "host" ]; then
        printf "  ${BOLD}Host Services:${NC}\n"
        printf "    systemctl status wireghost-worker   Celery worker\n"
        printf "    systemctl status wireghost-beat     Celery beat\n"
        printf "    journalctl -fu wireghost-worker     Stream worker logs\n"
        printf "\n"
        printf "  ${BOLD}Scan Data:${NC}  ${PROJECT_DIR}/data/output\n"
    fi

    printf "  ${BOLD}Logs:${NC}      ./logs/\n"
    printf "  ${BOLD}Certs:${NC}     ./certs/\n"
    printf "  ${BOLD}Config:${NC}    ./.env\n"
    printf "\n"
}

# ══════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════
banner

detect_wsl
select_install_mode

if [ "$INSTALL_MODE" = "host" ]; then
    _TOTAL=10
else
    _TOTAL=7
fi

step "Checking prerequisites"
check_prereqs

step "Configuring environment"
collect_all_config

step "Generating TLS certificates"
generate_certs

step "Writing configuration"
render_nginx
write_env
create_dirs
harden_docker_daemon

if [ "$INSTALL_MODE" = "host" ]; then
    install_host_tools
    build_and_start_host
else
    build_and_start_docker
fi

step "Verifying health"
wait_for_health

print_summary
