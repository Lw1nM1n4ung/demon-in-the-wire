#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
# Wire_Ghost — One-Command On-Premises Installer
# Usage:  sudo bash scripts/install.sh
# ══════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

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

# ── Prerequisite checks ─────────────────────────────────────────────
check_prereqs() {
    info "Checking prerequisites..."

    [ "$(id -u)" -eq 0 ] || die "This installer must be run as root (sudo bash install.sh)"

    command -v docker >/dev/null 2>&1 || die "Docker is not installed. Install Docker first: https://docs.docker.com/engine/install/"

    DOCKER_VERSION=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "0")
    DOCKER_MAJOR=$(echo "$DOCKER_VERSION" | cut -d. -f1)
    [ "$DOCKER_MAJOR" -ge 20 ] 2>/dev/null || die "Docker >= 20.x required (found: $DOCKER_VERSION)"

    docker compose version >/dev/null 2>&1 || die "Docker Compose V2 plugin not found. Install: https://docs.docker.com/compose/install/"

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
    openssl rand -base64 48 | tr -d '\n/+=' | head -c 64
}

# ── Prompt helper: show default, read input, keep default if empty ───
# Usage: prompt_var VARNAME "Label" "default_value"
prompt_var() {
    local varname="$1" label="$2" default="$3"
    local current="${!varname:-$default}"
    printf "  %-22s ${DIM}[%s]${NC}: " "$label" "$current"
    read -r _input
    if [ -n "$_input" ]; then
        eval "$varname=\"\$_input\""
    else
        eval "$varname=\"\$current\""
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
        eval "$varname=\"\$_input\""
    else
        eval "$varname=\"\$current\""
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

    # Warn if chosen ports are already in use (skip if our own containers hold them)
    for _p in "$WIREGHOST_PORT" "$WIREGHOST_HTTP_PORT"; do
        _pid=$(ss -tlnp "sport = :$_p" 2>/dev/null | grep -v "^State" | head -1) || true
        if [ -n "$_pid" ] && ! echo "$_pid" | grep -q "docker\|containerd"; then
            warn "Port $_p is already in use — another service may conflict"
        fi
    done
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
    _HOST_DEFAULT="${WIREGHOST_HOST:-}"
    if [ -z "$_HOST_DEFAULT" ] || [ "$_HOST_DEFAULT" = "localhost" ] || [ "$_HOST_DEFAULT" = "*" ]; then
        _HOST_DEFAULT="${_DETECTED_IP:-localhost}"
    fi
    WIREGHOST_HOST="$_HOST_DEFAULT"
    WIREGHOST_PORT="${WIREGHOST_PORT:-443}"
    WIREGHOST_HTTP_PORT="${WIREGHOST_HTTP_PORT:-80}"

    # ── Non-interactive mode: accept all defaults ────────────────────
    if [ ! -t 0 ]; then
        if [ "$WIREGHOST_HOST" = "localhost" ]; then
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
        prompt_var WIREGHOST_PORT      "HTTPS Port"          "$WIREGHOST_PORT"
        prompt_var WIREGHOST_HTTP_PORT "HTTP Port (redirect)" "$WIREGHOST_HTTP_PORT"
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

# ── TLS certificate generation ───────────────────────────────────────
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

    sed "s/{{WIREGHOST_HOST}}/${WIREGHOST_HOST}/g" config/nginx.conf.tpl > nginx.conf
    ok "nginx.conf rendered for ${WIREGHOST_HOST}"
}

# ── Write .env ───────────────────────────────────────────────────────
write_env() {
    if [ "$UPGRADE_MODE" = true ]; then
        info "Updating .env with configured values..."

        # Update every variable — sed for existing keys, append for missing
        _update_env_var() {
            local key="$1" val="$2"
            if grep -q "^${key}=" .env; then
                sed -i "s|^${key}=.*|${key}=${val}|" .env
            else
                echo "${key}=${val}" >> .env
            fi
        }

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

        ok ".env updated"
        return
    fi

    cat > .env <<ENVEOF
# Wire_Ghost — Generated by install.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
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

# ── Create directories ───────────────────────────────────────────────
create_dirs() {
    mkdir -p logs/api logs/nginx certs
    chown -R 1000:1000 logs/api 2>/dev/null || true
    ok "Log directories created"
}

# ── Build and start ──────────────────────────────────────────────────
build_and_start() {
    info "Building containers (this may take several minutes on first run)..."
    docker compose build --pull 2>&1 | tail -5

    info "Starting Wire_Ghost stack..."
    docker compose up -d

    ok "All services started"
}

# ── Health check ─────────────────────────────────────────────────────
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
        warn "Timed out waiting for infrastructure (${TIMEOUT}s) — check: docker compose logs db redis"
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
        warn "API container not responding after ${TIMEOUT}s — check: docker compose logs api"
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
    printf "    ./scripts/wg-ctl --help          All commands\n"
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
check_prereqs
collect_all_config
generate_certs
render_nginx
write_env
create_dirs
build_and_start
wait_for_health
print_summary
