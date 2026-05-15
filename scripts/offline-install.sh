#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
# Wire_Ghost — Offline Installer
#
# Run this on the air-gapped target machine to install Wire_Ghost
# without any internet access. All Docker images must be pre-loaded
# from the bundled tar file.
#
# Usage:
#   sudo bash install.sh                    # from within the bundle dir
#   sudo bash scripts/offline-install.sh    # from project root (dev)
#
# The script auto-detects whether it's running inside a bundle
# (looks for ./wireghost-images.tar) or standalone in the project.
# ══════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Auto-detect: bundle mode (install.sh lives next to images tar) vs project mode
if [ -f "$SCRIPT_DIR/wireghost-images.tar" ]; then
    # Bundle mode — install.sh is at bundle root, project in ./project/
    BUNDLE_DIR="$SCRIPT_DIR"
    PROJECT_DIR="$BUNDLE_DIR/project"
    IMAGES_TAR="$BUNDLE_DIR/wireghost-images.tar"
elif [ -f "$SCRIPT_DIR/../wireghost-images.tar" ]; then
    # Running from project/scripts/ — bundle root is parent of project/
    BUNDLE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
    PROJECT_DIR="$SCRIPT_DIR/.."
    IMAGES_TAR="$BUNDLE_DIR/wireghost-images.tar"
else
    # Standalone / dev mode — images aren't bundled, try docker compose build
    BUNDLE_DIR=""
    PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
    IMAGES_TAR=""
fi

cd "$PROJECT_DIR"

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
  \ \/\/ / | || '_|/ -_)| (_ | ' \ / _ \(-< |  _|
   \_/\_/  |_||_|  \___| \___||_||_|\___//__/ \__|
ART
    printf "${NC}\n"
    printf "  ${BOLD}Offline Installer${NC}\n\n"
}

# ── Secret generation ────────────────────────────────────────────────
gen_secret() {
    openssl rand -base64 96 | tr -d '\n/+=' | head -c 64
}

mask_secret() {
    local val="$1"
    if [ ${#val} -gt 10 ]; then
        printf "%s...%s" "${val:0:4}" "${val: -3}"
    else
        printf "********"
    fi
}

# ── Prompt helpers ───────────────────────────────────────────────────
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

_port_available() {
    local port="$1"
    local hit
    hit=$(ss -tlnp "sport = :${port}" 2>/dev/null | grep -v "^State" | head -1) || true
    if [ -n "$hit" ] && ! echo "$hit" | grep -q "docker\|containerd"; then
        return 1
    fi
    return 0
}

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

# ══════════════════════════════════════════════════════════════════════
# Step 1: Check prerequisites
# ══════════════════════════════════════════════════════════════════════

check_prereqs() {
    info "Checking prerequisites..."

    [ "$(id -u)" -eq 0 ] || die "Must run as root (sudo bash install.sh)"

    if ! command -v docker >/dev/null 2>&1; then
        die "Docker not installed. On the air-gapped machine, install Docker Engine first.
See: https://docs.docker.com/engine/install/
For Ubuntu/Debian offline: download the .deb packages on a connected machine."
    fi

    DOCKER_VERSION=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "0")
    DOCKER_MAJOR=$(echo "$DOCKER_VERSION" | cut -d. -f1)
    [ "$DOCKER_MAJOR" -ge 20 ] 2>/dev/null || die "Docker >= 20.x required (found: $DOCKER_VERSION)"

    docker compose version >/dev/null 2>&1 || die "Docker Compose V2 plugin required"

    command -v python3 >/dev/null 2>&1 || die "python3 required — install python3 on the target machine"

    TOTAL_MEM_MB=$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)
    if [ "$TOTAL_MEM_MB" -lt 3500 ]; then
        warn "System has ${TOTAL_MEM_MB}MB RAM — 4GB+ recommended"
    fi

    DISK_FREE_GB=$(df -BG "$PROJECT_DIR" | awk 'NR==2 {gsub(/G/,"",$4); print $4}' 2>/dev/null || echo 0)
    if [ "$DISK_FREE_GB" -lt 20 ]; then
        warn "Only ${DISK_FREE_GB}GB free disk — 20GB+ recommended"
    fi

    ok "Prerequisites satisfied (Docker $DOCKER_VERSION, ${TOTAL_MEM_MB}MB RAM, ${DISK_FREE_GB}GB free)"
}

# ══════════════════════════════════════════════════════════════════════
# Step 2: Load Docker images from tar
# ══════════════════════════════════════════════════════════════════════

load_images() {
    if [ -z "$IMAGES_TAR" ]; then
        info "No bundled images tar found — building from local Dockerfiles..."
        info "This requires the project source files to be present."
        docker compose -f docker-compose.yml build --pull 2>&1 | tail -10
        ok "Images built locally"
        return
    fi

    if [ ! -f "$IMAGES_TAR" ]; then
        die "Image archive not found: $IMAGES_TAR
The bundle may be incomplete. Re-run the export on an internet-connected machine."
    fi

    local tar_size
    tar_size=$(du -h "$IMAGES_TAR" | cut -f1)
    info "Loading Docker images from $(basename "$IMAGES_TAR") (${tar_size})..."
    info "This may take 5-15 minutes depending on disk speed..."

    docker load -i "$IMAGES_TAR" 2>&1 | while IFS= read -r line; do
        if [[ "$line" == *"Loaded image"* ]]; then
            printf "  ${DIM}%s${NC}\n" "$line"
        fi
    done

    ok "Docker images loaded"

    # Verify critical images
    local missing=0
    for img in callmedemon/wireghost:web callmedemon/wireghost:worker mysql:8.0 redis:7-alpine nginx:alpine tecnativa/docker-socket-proxy:latest; do
        if ! docker image inspect "$img" >/dev/null 2>&1; then
            warn "  MISSING: $img"
            missing=$((missing + 1))
        fi
    done
    [ "$missing" -eq 0 ] || die "${missing} critical image(s) missing after load"
}

# ══════════════════════════════════════════════════════════════════════
# Step 3: Configure environment
# ══════════════════════════════════════════════════════════════════════

configure_environment() {
    printf "\n${BOLD}Configure Wire_Ghost — press Enter to accept defaults in [brackets]${NC}\n\n"

    # Auto-generate secrets
    _AUTO_DJANGO_SECRET="$(gen_secret)"
    _AUTO_MYSQL_ROOT_PW="$(gen_secret)"
    _AUTO_MYSQL_PW="$(gen_secret)"
    _AUTO_REDIS_PW="$(gen_secret)"

    DJANGO_SECRET_KEY="${DJANGO_SECRET_KEY:-$_AUTO_DJANGO_SECRET}"
    MYSQL_ROOT_PASSWORD="${MYSQL_ROOT_PASSWORD:-$_AUTO_MYSQL_ROOT_PW}"
    MYSQL_PASSWORD="${MYSQL_PASSWORD:-$_AUTO_MYSQL_PW}"
    REDIS_PASSWORD="${REDIS_PASSWORD:-$_AUTO_REDIS_PW}"
    MYSQL_DATABASE="${MYSQL_DATABASE:-wireghost}"
    MYSQL_USER="${MYSQL_USER:-wireghost}"
    WIREGHOST_PROTO="${WIREGHOST_PROTO:-https}"
    WIREGHOST_LOG_DIR="${WIREGHOST_LOG_DIR:-./logs}"
    WIREGHOST_LOG_LEVEL="${WIREGHOST_LOG_LEVEL:-INFO}"

    # Auto-detect host IP
    _DETECTED_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    _HOST_DEFAULT="${WIREGHOST_HOST:-$_DETECTED_IP:-localhost}"
    WIREGHOST_HOST="$_HOST_DEFAULT"
    WIREGHOST_PORT="${WIREGHOST_PORT:-443}"
    WIREGHOST_HTTP_PORT="${WIREGHOST_HTTP_PORT:-80}"

    # Non-interactive mode: accept all defaults
    if [ ! -t 0 ]; then
        if [ "$WIREGHOST_HOST" = "localhost" ]; then
            die "Non-interactive mode requires WIREGHOST_HOST to be set in environment"
        fi
        _compute_derived
        ok "Non-interactive mode — using defaults"
        return
    fi

    # ── Section 1: Portal Access ─────────────────────────────────────
    printf "\n${CYAN}── 1/5  Portal Access ──────────────────────────────${NC}\n"
    printf "  Customize? [y/N] "
    read -r _sec1
    if [[ "$_sec1" =~ ^[Yy] ]]; then
        prompt_var  WIREGHOST_HOST      "WIREGHOST_HOST"      "$WIREGHOST_HOST"
        prompt_port WIREGHOST_PORT      "HTTPS Port"          "$WIREGHOST_PORT"
        prompt_port WIREGHOST_HTTP_PORT "HTTP Port (redirect)" "$WIREGHOST_HTTP_PORT"
        prompt_var  WIREGHOST_PROTO     "WIREGHOST_PROTO"     "$WIREGHOST_PROTO"
    fi

    # ── Section 2: Database ──────────────────────────────────────────
    printf "\n${CYAN}── 2/5  Database (MySQL) ───────────────────────────${NC}\n"
    printf "  Customize? [y/N] "
    read -r _sec2
    if [[ "$_sec2" =~ ^[Yy] ]]; then
        prompt_var    MYSQL_DATABASE      "MYSQL_DATABASE"      "$MYSQL_DATABASE"
        prompt_var    MYSQL_USER          "MYSQL_USER"          "$MYSQL_USER"
        prompt_secret MYSQL_PASSWORD      "MYSQL_PASSWORD"      "$MYSQL_PASSWORD"
        prompt_secret MYSQL_ROOT_PASSWORD "MYSQL_ROOT_PASSWORD" "$MYSQL_ROOT_PASSWORD"
    fi

    # ── Section 3: Redis ─────────────────────────────────────────────
    printf "\n${CYAN}── 3/5  Redis ─────────────────────────────────────${NC}\n"
    printf "  Customize? [y/N] "
    read -r _sec3
    if [[ "$_sec3" =~ ^[Yy] ]]; then
        prompt_secret REDIS_PASSWORD "REDIS_PASSWORD" "$REDIS_PASSWORD"
    fi

    # ── Section 4: Django ────────────────────────────────────────────
    printf "\n${CYAN}── 4/5  Django ────────────────────────────────────${NC}\n"
    printf "  Customize? [y/N] "
    read -r _sec4
    if [[ "$_sec4" =~ ^[Yy] ]]; then
        prompt_secret DJANGO_SECRET_KEY "DJANGO_SECRET_KEY" "$DJANGO_SECRET_KEY"
    fi

    # ── Section 5: Logging ───────────────────────────────────────────
    printf "\n${CYAN}── 5/5  Logging ───────────────────────────────────${NC}\n"
    printf "  Customize? [y/N] "
    read -r _sec5
    if [[ "$_sec5" =~ ^[Yy] ]]; then
        prompt_var WIREGHOST_LOG_DIR   "WIREGHOST_LOG_DIR"   "$WIREGHOST_LOG_DIR"
        prompt_var WIREGHOST_LOG_LEVEL "WIREGHOST_LOG_LEVEL" "$WIREGHOST_LOG_LEVEL"
    fi

    _compute_derived

    # ── Confirmation ─────────────────────────────────────────────────
    printf "\n${BOLD}══ Configuration Summary ═══════════════════════════${NC}\n"
    printf "  %-24s %s\n" "WIREGHOST_HOST"       "$WIREGHOST_HOST"
    printf "  %-24s %s\n" "WIREGHOST_PORT"       "$WIREGHOST_PORT"
    printf "  %-24s %s\n" "WIREGHOST_PROTO"      "$WIREGHOST_PROTO"
    printf "  %-24s %s\n" "MYSQL_DATABASE"       "$MYSQL_DATABASE"
    printf "  %-24s %s\n" "MYSQL_USER"           "$MYSQL_USER"
    printf "  %-24s %s  ${DIM}(auto)${NC}\n" "MYSQL_PASSWORD"       "$(mask_secret "$MYSQL_PASSWORD")"
    printf "  %-24s %s  ${DIM}(auto)${NC}\n" "REDIS_PASSWORD"       "$(mask_secret "$REDIS_PASSWORD")"
    printf "  %-24s %s  ${DIM}(auto)${NC}\n" "DJANGO_SECRET_KEY"    "$(mask_secret "$DJANGO_SECRET_KEY")"

    printf "\n  Write .env? [Y/n] "
    read -r _confirm
    if [[ "$_confirm" =~ ^[Nn] ]]; then
        die "Aborted — .env not written"
    fi
    ok "Configuration confirmed"
}

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

# ══════════════════════════════════════════════════════════════════════
# Step 4: Generate TLS certificates
# ══════════════════════════════════════════════════════════════════════

generate_certs() {
    mkdir -p certs

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
}

# ══════════════════════════════════════════════════════════════════════
# Step 5: Write configuration files
# ══════════════════════════════════════════════════════════════════════

render_nginx() {
    if [ ! -f config/nginx.conf.tpl ]; then
        die "config/nginx.conf.tpl not found — bundle may be incomplete"
    fi

    sed -e "s/{{WIREGHOST_HOST}}/${WIREGHOST_HOST}/g" \
        -e "s/{{WIREGHOST_PORT}}/${WIREGHOST_PORT}/g" \
        config/nginx.conf.tpl > nginx.conf
    ok "nginx.conf rendered"
}

write_env() {
    cat > .env <<ENVEOF
# Wire_Ghost — Generated by offline installer on $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Do not commit this file. Secrets are auto-generated.

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

    chmod 600 .env
    ok ".env written (chmod 600)"
}

create_dirs() {
    mkdir -p logs/api logs/nginx certs
    chown -R 1000:1000 logs/api 2>/dev/null || true
    ok "Log directories created"
}

# ══════════════════════════════════════════════════════════════════════
# Step 6: Start services (offline — no pull, no build)
# ══════════════════════════════════════════════════════════════════════

start_services() {
    info "Starting Wire_Ghost stack..."
    info "All images pre-loaded — no internet required"

    docker compose -f docker-compose.yml up -d 2>&1 | tail -5

    ok "All services started"
}

# ══════════════════════════════════════════════════════════════════════
# Step 7: Health check
# ══════════════════════════════════════════════════════════════════════

wait_for_health() {
    info "Waiting for services to become healthy..."

    TIMEOUT=90
    ELAPSED=0
    while [ $ELAPSED -lt $TIMEOUT ]; do
        DB_OK=$(docker compose ps db --format '{{.Health}}' 2>/dev/null || echo "")
        REDIS_OK=$(docker compose ps redis --format '{{.Health}}' 2>/dev/null || echo "")

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
        warn "Timed out waiting for infrastructure — check: docker compose logs db redis"
    fi

    ELAPSED=0
    TIMEOUT=60
    while [ $ELAPSED -lt $TIMEOUT ]; do
        HTTP_CODE=$(docker compose exec -T api python -c "
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
        warn "API not responding — check: docker compose logs api"
    fi
}

# ══════════════════════════════════════════════════════════════════════
# Step 8: Print summary
# ══════════════════════════════════════════════════════════════════════

print_summary() {
    SETUP_URL="${WIREGHOST_PROTO}://${WIREGHOST_HOST}"
    if { [ "$WIREGHOST_PROTO" = "https" ] && [ "$WIREGHOST_PORT" != "443" ]; } || \
       { [ "$WIREGHOST_PROTO" = "http" ] && [ "$WIREGHOST_PORT" != "80" ]; }; then
        SETUP_URL="${SETUP_URL}:${WIREGHOST_PORT}"
    fi

    printf "\n"
    printf "${GREEN}══════════════════════════════════════════════════════════════${NC}\n"
    printf "${GREEN}  Wire_Ghost installed successfully! (offline)${NC}\n"
    printf "${GREEN}══════════════════════════════════════════════════════════════${NC}\n"
    printf "\n"
    printf "  ${BOLD}Setup URL:${NC}  ${CYAN}${SETUP_URL}/setup${NC}\n"
    printf "  ${BOLD}Login URL:${NC}  ${CYAN}${SETUP_URL}/login${NC}\n"
    printf "\n"
    printf "  Open the Setup URL in your browser to create the admin account.\n"
    printf "  (Accept the self-signed certificate warning if prompted.)\n"
    printf "\n"
    printf "  ${BOLD}Management:${NC}\n"
    printf "    ./scripts/wg-ctl status          Show service health\n"
    printf "    ./scripts/wg-ctl backup          Create full backup\n"
    printf "    ./scripts/wg-ctl logs [service]  Stream logs\n"
    printf "\n"
    printf "  ${BOLD}Logs:${NC}      ./logs/\n"
    printf "  ${BOLD}Certs:${NC}     ./certs/\n"
    printf "  ${BOLD}Config:${NC}    ./.env\n"
    printf "\n"
}

# ══════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════

banner

echo "  Step 1/7  Checking prerequisites..."
check_prereqs

echo "  Step 2/7  Loading Docker images..."
load_images

echo "  Step 3/7  Configuring environment..."
configure_environment

echo "  Step 4/7  Generating TLS certificates..."
generate_certs
render_nginx

echo "  Step 5/7  Writing configuration..."
write_env
create_dirs

echo "  Step 6/7  Starting services..."
start_services

echo "  Step 7/7  Verifying health..."
wait_for_health

print_summary
