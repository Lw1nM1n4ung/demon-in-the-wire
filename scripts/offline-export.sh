#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
# Wire_Ghost — Offline Distribution Builder
#
# Run on an internet-connected machine to create a self-contained
# offline installer bundle. The bundle can be transferred to an
# air-gapped machine and installed without any internet access.
#
# Usage:
#   sudo bash scripts/offline-export.sh [OUTPUT_DIR]
#
#   OUTPUT_DIR defaults to ./wireghost-offline-YYYYMMDD/
#
# What it does:
#   1. Builds custom Docker images (wireghost:web, wireghost:worker)
#   2. Pulls upstream images (mysql, redis, nginx, docker-socket-proxy)
#   3. Saves all images to a single tar archive
#   4. Bundles project files + images + installer into a distributable dir
#   5. Optionally compresses the bundle into a .tar.gz
#
# Flags:
#   --skip-compress   Don't create .tar.gz, leave as directory
#   --with-msf        Also build the standalone CLI image (Metasploit, ~2GB extra)
#   --pull-only        Pull pre-built images from Docker Hub instead of building
# ══════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

# ── Flags ────────────────────────────────────────────────────────────
SKIP_COMPRESS=false
WITH_MSF=false
PULL_ONLY=false
OUTPUT_DIR=""

for arg in "$@"; do
    case "$arg" in
        --skip-compress) SKIP_COMPRESS=true ;;
        --with-msf)      WITH_MSF=true ;;
        --pull-only)     PULL_ONLY=true ;;
        --help|-h)
            sed -n '2,30p' "$0"
            exit 0
            ;;
        *) OUTPUT_DIR="$arg" ;;
    esac
done

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_DIR="${OUTPUT_DIR:-${PROJECT_DIR}/wireghost-offline-${TIMESTAMP}}"
BUNDLE_NAME="wireghost-offline-${TIMESTAMP}"

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
  \ \/\/ / | || '_|/ -_)| (_ | ' \ / _ \(-< |  _|
   \_/\_/  |_||_|  \___| \___||_||_|\___//__/ \__|
ART
    printf "${NC}\n"
    printf "  ${BOLD}Offline Distribution Builder${NC}\n\n"
}

# ══════════════════════════════════════════════════════════════════════
# Prerequisite checks
# ══════════════════════════════════════════════════════════════════════

check_prereqs() {
    info "Checking prerequisites..."

    [ "$(id -u)" -eq 0 ] || die "Must run as root (sudo) — Docker requires root"

    command -v docker >/dev/null 2>&1 || die "Docker not installed"
    docker compose version >/dev/null 2>&1 || die "Docker Compose V2 plugin required"
    command -v rsync >/dev/null 2>&1 || die "rsync not installed (apt install rsync)"
    command -v python3 >/dev/null 2>&1 || die "python3 required for compose file processing"

    DOCKER_VERSION=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "0")
    DOCKER_MAJOR=$(echo "$DOCKER_VERSION" | cut -d. -f1)
    [ "$DOCKER_MAJOR" -ge 20 ] 2>/dev/null || die "Docker >= 20.x required (found: $DOCKER_VERSION)"

    # Disk space check — need ~15GB free for build + output
    DISK_FREE_GB=$(df -BG "$PROJECT_DIR" | awk 'NR==2 {gsub(/G/,"",$4); print $4}' 2>/dev/null || echo 0)
    if [ "$DISK_FREE_GB" -lt 20 ]; then
        warn "Only ${DISK_FREE_GB}GB free disk — 20GB+ recommended for build"
    fi

    ok "Prerequisites satisfied (Docker $DOCKER_VERSION, ${DISK_FREE_GB}GB free)"
}

# ══════════════════════════════════════════════════════════════════════
# Image names — must match docker-compose.yml exactly
# ══════════════════════════════════════════════════════════════════════

# Custom images (built from source)
IMAGE_WEB="callmedemon/wireghost:web"
IMAGE_WORKER="callmedemon/wireghost:worker"
IMAGE_CLI="callmedemon/wireghost:latest"

# Upstream images (pulled from registries)
IMAGE_MYSQL="mysql:8.0"
IMAGE_REDIS="redis:7-alpine"
IMAGE_NGINX="nginx:alpine"
IMAGE_DOCKER_PROXY="tecnativa/docker-socket-proxy:latest"

ALL_IMAGES=(
    "$IMAGE_WEB"
    "$IMAGE_WORKER"
    "$IMAGE_MYSQL"
    "$IMAGE_REDIS"
    "$IMAGE_NGINX"
    "$IMAGE_DOCKER_PROXY"
)

# ══════════════════════════════════════════════════════════════════════
# Build custom images
# ══════════════════════════════════════════════════════════════════════

build_custom_images() {
    if [ "$PULL_ONLY" = true ]; then
        info "Pull-only mode — pulling pre-built images from Docker Hub..."
        docker pull "$IMAGE_WEB"
        docker pull "$IMAGE_WORKER"
        if [ "$WITH_MSF" = true ]; then
            docker pull "$IMAGE_CLI" || warn "CLI image not found on Docker Hub — skipping"
        fi
        ok "Images pulled from Docker Hub"
        return
    fi

    info "Building wireghost:web (API/beat/bot slim image)..."
    docker build \
        -f web_portal/Dockerfile.web \
        -t "$IMAGE_WEB" \
        --build-arg BUILDKIT_INLINE_CACHE=1 \
        . 2>&1 | tail -5
    ok "wireghost:web built"

    info "Building wireghost:worker (full scan tools image — this may take 10-20 min)..."
    docker build \
        -f web_portal/Dockerfile \
        -t "$IMAGE_WORKER" \
        --build-arg BUILDKIT_INLINE_CACHE=1 \
        . 2>&1 | tail -5
    ok "wireghost:worker built"

    if [ "$WITH_MSF" = true ]; then
        info "Building wireghost:latest (standalone CLI with Metasploit — this may take 15-25 min)..."
        docker build \
            -f Dockerfile \
            -t "$IMAGE_CLI" \
            --build-arg BUILDKIT_INLINE_CACHE=1 \
            . 2>&1 | tail -5
        ALL_IMAGES+=("$IMAGE_CLI")
        ok "wireghost:latest built"
    fi
}

# ══════════════════════════════════════════════════════════════════════
# Pull upstream images
# ══════════════════════════════════════════════════════════════════════

pull_upstream_images() {
    info "Pulling upstream images..."

    docker pull "$IMAGE_MYSQL"      && ok "mysql:8.0 pulled"      || die "Failed to pull mysql:8.0"
    docker pull "$IMAGE_REDIS"      && ok "redis:7-alpine pulled"  || die "Failed to pull redis:7-alpine"
    docker pull "$IMAGE_NGINX"      && ok "nginx:alpine pulled"    || die "Failed to pull nginx:alpine"
    docker pull "$IMAGE_DOCKER_PROXY" && ok "docker-socket-proxy pulled" || die "Failed to pull docker-socket-proxy"
}

# ══════════════════════════════════════════════════════════════════════
# Verify all images exist locally
# ══════════════════════════════════════════════════════════════════════

verify_images() {
    info "Verifying images..."

    local missing=0
    for img in "${ALL_IMAGES[@]}"; do
        if docker image inspect "$img" >/dev/null 2>&1; then
            local size
            size=$(docker image inspect "$img" --format '{{.Size}}' 2>/dev/null | \
                awk '{printf "%.0f MB", $1/1024/1024}')
            ok "  ${img}  (${size})"
        else
            warn "  ${img} — MISSING"
            missing=$((missing + 1))
        fi
    done

    [ "$missing" -eq 0 ] || die "${missing} image(s) missing — cannot continue"
}

# ══════════════════════════════════════════════════════════════════════
# Save images to tar
# ══════════════════════════════════════════════════════════════════════

save_images() {
    local tar_path="$1"
    info "Saving ${#ALL_IMAGES[@]} images to $(basename "$tar_path")..."
    info "This may take several minutes..."

    docker save "${ALL_IMAGES[@]}" -o "$tar_path"

    local tar_size
    tar_size=$(du -h "$tar_path" | cut -f1)
    ok "Images saved (${tar_size})"
}

# ══════════════════════════════════════════════════════════════════════
# Prepare the offline docker-compose.yml (strip build: directives)
# ══════════════════════════════════════════════════════════════════════

prepare_compose_file() {
    local src="$1"
    local dst="$2"

    # Remove build: blocks — keeps only image: references
    # A build: block starts with "build:" and continues until the next
    # key at the same or lesser indentation.
    python3 -c "
import re, sys

with open('$src') as f:
    text = f.read()

# Remove multi-line build: blocks.
# Pattern: line starting with optional spaces + 'build:', then all indented
# continuation lines until a line with same or less indentation.
text = re.sub(r'^(\s*)build:.*\n(?:\1\s+.*\n)*', '', text, flags=re.MULTILINE)

with open('$dst', 'w') as f:
    f.write(text)
"
    ok "Offline docker-compose.yml prepared (build: directives removed)"
}

# ══════════════════════════════════════════════════════════════════════
# Collect project files for the bundle
# ══════════════════════════════════════════════════════════════════════

copy_project_files() {
    local dest="$1"

    info "Copying project files..."

    mkdir -p "$dest"

    # Directories to copy in full
    local copy_dirs=(
        "web_portal"
        "web"
        "config"
        "src"
        "templates"
        "scripts"
    )

    for dir in "${copy_dirs[@]}"; do
        if [ -d "$dir" ]; then
            # Exclude Python cache, venvs, and large git repos
            rsync -a \
                --exclude='__pycache__' \
                --exclude='*.pyc' \
                --exclude='.venv' \
                --exclude='venv' \
                --exclude='*.egg-info' \
                "$dir/" "$dest/$dir/"
        fi
    done

    # Top-level files
    local copy_files=(
        "pyproject.toml"
        "README.md"
        ".dockerignore"
    )

    for f in "${copy_files[@]}"; do
        [ -f "$f" ] && cp "$f" "$dest/"
    done

    # Copy web/.dockerignore if exists
    [ -f "web/.dockerignore" ] && cp "web/.dockerignore" "$dest/web/"

    ok "Project files copied to bundle"
}

# ══════════════════════════════════════════════════════════════════════
# Generate the offline installer script inside the bundle
# ══════════════════════════════════════════════════════════════════════

generate_offline_installer() {
    local dest="$1"

    cat > "$dest/install.sh" <<'INSTALLER'
#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
# Wire_Ghost — Offline Installer
#
# Run this on the air-gapped target machine to install Wire_Ghost
# without any internet access. All Docker images are pre-loaded from
# the bundled tar file.
#
# Usage:
#   sudo bash install.sh
# ══════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/project"
IMAGES_TAR="$SCRIPT_DIR/wireghost-images.tar"
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

    # Use the offline compose file (no build: directives)
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
INSTALLER

    chmod +x "$dest/install.sh"
    ok "Offline installer generated"
}

# ══════════════════════════════════════════════════════════════════════
# Write manifest
# ══════════════════════════════════════════════════════════════════════

write_manifest() {
    local dest="$1"

    cat > "$dest/MANIFEST.txt" <<MANIFEST
Wire_Ghost — Offline Distribution
==================================
Created: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Host:    $(hostname)
Version: $(python3 -c "from wireghost import __version__; print(__version__)" 2>/dev/null || echo "2.0.0")

Images included:
$(for img in "${ALL_IMAGES[@]}"; do
    digest=$(docker image inspect "$img" --format '{{.Id}}' 2>/dev/null || echo "unknown")
    size=$(docker image inspect "$img" --format '{{.Size}}' 2>/dev/null | awk '{printf "%.0f MB", $1/1024/1024}')
    printf "  %s  (%s)\n" "$img" "$size"
done)

Installation:
  1. Copy this directory to the air-gapped machine
  2. cd wireghost-offline-*/
  3. sudo bash install.sh
MANIFEST

    ok "MANIFEST.txt written"
}

# ══════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════

banner

# ── Phase 1: Build and pull ──────────────────────────────────────────
info "Phase 1: Building and pulling Docker images"
info "This may take 20-40 minutes on first run..."

check_prereqs
build_custom_images
pull_upstream_images
verify_images

# ── Phase 2: Save images ─────────────────────────────────────────────
info "Phase 2: Saving images to tar archive"

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

IMAGES_TAR="$OUTPUT_DIR/wireghost-images.tar"
save_images "$IMAGES_TAR"

# ── Phase 3: Create bundle ───────────────────────────────────────────
info "Phase 3: Creating offline bundle"

PROJECT_BUNDLE="$OUTPUT_DIR/project"
copy_project_files "$PROJECT_BUNDLE"

# Prepare offline docker-compose.yml
prepare_compose_file \
    "$PROJECT_DIR/docker-compose.yml" \
    "$PROJECT_BUNDLE/docker-compose.yml"

# Copy dev and host compose files too
for f in docker-compose.dev.yml docker-compose.host.yml; do
    [ -f "$f" ] && cp "$f" "$PROJECT_BUNDLE/"
done

# Copy wireghost.example.yml for config reference (lives in config/)
[ -f "config/wireghost.example.yml" ] && cp "config/wireghost.example.yml" "$PROJECT_BUNDLE/"

generate_offline_installer "$OUTPUT_DIR"
write_manifest "$OUTPUT_DIR"

# ── Phase 4: Compress (optional) ─────────────────────────────────────
if [ "$SKIP_COMPRESS" = false ]; then
    info "Phase 4: Compressing bundle..."
    ARCHIVE_NAME="${BUNDLE_NAME}.tar.gz"
    tar czf "$ARCHIVE_NAME" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")" 2>&1 | tail -3

    local archive_size
    archive_size=$(du -h "$ARCHIVE_NAME" | cut -f1)
    ok "Compressed archive created: ${ARCHIVE_NAME} (${archive_size})"

    printf "\n${GREEN}══════════════════════════════════════════════════════════════${NC}\n"
    printf "${GREEN}  Offline bundle ready!${NC}\n"
    printf "${GREEN}══════════════════════════════════════════════════════════════${NC}\n"
    printf "\n"
    printf "  ${BOLD}Archive:${NC}  ${CYAN}${ARCHIVE_NAME}${NC}  (${archive_size})\n"
    printf "  ${BOLD}Bundle:${NC}   ${CYAN}${OUTPUT_DIR}${NC}\n"
    printf "\n"
    printf "  ${BOLD}Transfer to air-gapped machine:${NC}\n"
    printf "    scp ${ARCHIVE_NAME} user@target:/opt/\n"
    printf "    # or use USB drive / external disk\n"
    printf "\n"
    printf "  ${BOLD}On the air-gapped machine:${NC}\n"
    printf "    tar xzf ${BUNDLE_NAME}.tar.gz\n"
    printf "    cd ${BUNDLE_NAME}/\n"
    printf "    sudo bash install.sh\n"
    printf "\n"
else
    printf "\n${GREEN}══════════════════════════════════════════════════════════════${NC}\n"
    printf "${GREEN}  Offline bundle ready! (uncompressed)${NC}\n"
    printf "${GREEN}══════════════════════════════════════════════════════════════${NC}\n"
    printf "\n"
    printf "  ${BOLD}Bundle:${NC}  ${CYAN}${OUTPUT_DIR}${NC}\n"
    printf "\n"
    printf "  ${BOLD}On the air-gapped machine:${NC}\n"
    printf "    cd $(basename "$OUTPUT_DIR")/\n"
    printf "    sudo bash install.sh\n"
    printf "\n"
fi
