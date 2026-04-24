#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
# Wire_Ghost — One-Command On-Premises Installer
# Usage:  sudo bash install.sh
# ══════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ── Colours ──────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

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

    DISK_FREE_GB=$(df -BG "$SCRIPT_DIR" | awk 'NR==2 {gsub(/G/,"",$4); print $4}' 2>/dev/null || echo 0)
    if [ "$DISK_FREE_GB" -lt 15 ]; then
        warn "Only ${DISK_FREE_GB}GB free disk — 20GB+ recommended"
    fi

    ok "Prerequisites satisfied (Docker $DOCKER_VERSION, ${TOTAL_MEM_MB}MB RAM, ${DISK_FREE_GB}GB free)"
}

# ── Generate a cryptographic random string ───────────────────────────
gen_secret() {
    openssl rand -base64 48 | tr -d '\n/+=' | head -c 64
}

# ── Interactive prompts ──────────────────────────────────────────────
collect_inputs() {
    UPGRADE_MODE=false
    if [ -f .env ]; then
        UPGRADE_MODE=true
        warn "Existing .env found — running in upgrade mode (secrets preserved)"
        # shellcheck disable=SC1091
        set -a; source .env; set +a
    fi

    if [ -t 0 ]; then
        printf "\n${BOLD}Hostname or IP${NC} that users will access this instance at.\n"
        printf "  Examples: scanner.corp.local, 10.0.1.50, wireghost.example.com\n"
        CURRENT_HOST="${WIREGHOST_HOST:-}"
        if [ -n "$CURRENT_HOST" ] && [ "$CURRENT_HOST" != "localhost" ] && [ "$CURRENT_HOST" != "*" ]; then
            printf "  Current: ${CYAN}%s${NC}\n" "$CURRENT_HOST"
            printf "  Press Enter to keep, or type a new value: "
        else
            printf "  Hostname/IP: "
        fi
        read -r INPUT_HOST
        if [ -n "$INPUT_HOST" ]; then
            WIREGHOST_HOST="$INPUT_HOST"
        elif [ -z "$CURRENT_HOST" ] || [ "$CURRENT_HOST" = "localhost" ] || [ "$CURRENT_HOST" = "*" ]; then
            DEFAULT_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
            if [ -n "$DEFAULT_IP" ]; then
                printf "  Auto-detected IP: ${CYAN}%s${NC} — use this? [Y/n] " "$DEFAULT_IP"
                read -r CONFIRM_IP
                if [ -z "$CONFIRM_IP" ] || [[ "$CONFIRM_IP" =~ ^[Yy] ]]; then
                    WIREGHOST_HOST="$DEFAULT_IP"
                else
                    die "No hostname provided. Re-run and enter a hostname."
                fi
            else
                die "Could not detect IP. Re-run and enter a hostname."
            fi
        fi

        printf "\n${BOLD}HTTPS port${NC} [443]: "
        read -r INPUT_PORT
        WIREGHOST_PORT="${INPUT_PORT:-${WIREGHOST_PORT:-443}}"
    else
        [ -n "${WIREGHOST_HOST:-}" ] && [ "$WIREGHOST_HOST" != "localhost" ] || \
            die "Non-interactive mode requires WIREGHOST_HOST to be set in .env or environment"
        WIREGHOST_PORT="${WIREGHOST_PORT:-443}"
    fi

    ok "Target: https://${WIREGHOST_HOST}:${WIREGHOST_PORT}"
}

# ── Generate secrets (fresh install only) ────────────────────────────
generate_secrets() {
    if [ "$UPGRADE_MODE" = true ]; then
        info "Preserving existing secrets from .env"
        return
    fi

    info "Generating cryptographic secrets..."
    DJANGO_SECRET_KEY="$(gen_secret)"
    MYSQL_ROOT_PASSWORD="$(gen_secret)"
    MYSQL_PASSWORD="$(gen_secret)"
    REDIS_PASSWORD="$(gen_secret)"

    MYSQL_DATABASE="${MYSQL_DATABASE:-wireghost}"
    MYSQL_USER="${MYSQL_USER:-wireghost}"
    WIREGHOST_LOG_DIR="${WIREGHOST_LOG_DIR:-./logs}"
    WIREGHOST_LOG_LEVEL="${WIREGHOST_LOG_LEVEL:-INFO}"

    ok "4 unique 64-character secrets generated"
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
    if [ ! -f nginx.conf.tpl ]; then
        die "nginx.conf.tpl not found — is this the Wire_Ghost project directory?"
    fi

    sed "s/{{WIREGHOST_HOST}}/${WIREGHOST_HOST}/g" nginx.conf.tpl > nginx.conf
    ok "nginx.conf rendered for ${WIREGHOST_HOST}"
}

# ── Write .env ───────────────────────────────────────────────────────
write_env() {
    if [ "$UPGRADE_MODE" = true ]; then
        PREV_HOST=$(grep '^WIREGHOST_HOST=' .env | cut -d= -f2-)
        PREV_PORT=$(grep '^WIREGHOST_PORT=' .env | cut -d= -f2-)

        if [ "$PREV_HOST" != "$WIREGHOST_HOST" ] || [ "$PREV_PORT" != "$WIREGHOST_PORT" ]; then
            info "Updating hostname/port in .env"
            sed -i "s|^WIREGHOST_HOST=.*|WIREGHOST_HOST=${WIREGHOST_HOST}|" .env
            sed -i "s|^WIREGHOST_PORT=.*|WIREGHOST_PORT=${WIREGHOST_PORT}|" .env
        fi

        grep -q '^WIREGHOST_PROTO=' .env || echo "WIREGHOST_PROTO=https" >> .env
        grep -q '^SESSION_COOKIE_SECURE=' .env || echo "SESSION_COOKIE_SECURE=true" >> .env
        grep -q '^CSRF_COOKIE_SECURE=' .env || echo "CSRF_COOKIE_SECURE=true" >> .env

        _CSRF_ORIGINS="https://${WIREGHOST_HOST}:${WIREGHOST_PORT},https://localhost:${WIREGHOST_PORT},https://127.0.0.1:${WIREGHOST_PORT}"
        if grep -q '^CSRF_TRUSTED_ORIGINS=' .env; then
            sed -i "s|^CSRF_TRUSTED_ORIGINS=.*|CSRF_TRUSTED_ORIGINS=${_CSRF_ORIGINS}|" .env
        else
            echo "CSRF_TRUSTED_ORIGINS=${_CSRF_ORIGINS}" >> .env
        fi

        ok ".env updated (secrets preserved)"
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
WIREGHOST_PROTO=https
SESSION_COOKIE_SECURE=true
CSRF_COOKIE_SECURE=true
CSRF_TRUSTED_ORIGINS=https://${WIREGHOST_HOST}:${WIREGHOST_PORT},https://localhost:${WIREGHOST_PORT},https://127.0.0.1:${WIREGHOST_PORT}

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
    SETUP_URL="https://${WIREGHOST_HOST}"
    if [ "$WIREGHOST_PORT" != "443" ]; then
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
    printf "    ./wg-ctl status          Show service health\n"
    printf "    ./wg-ctl backup          Create full backup\n"
    printf "    ./wg-ctl logs [service]  Stream logs\n"
    printf "    ./wg-ctl --help          All commands\n"
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
collect_inputs
generate_secrets
generate_certs
render_nginx
write_env
create_dirs
build_and_start
wait_for_health
print_summary
