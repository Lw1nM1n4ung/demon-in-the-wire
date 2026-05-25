#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
# Wire_Ghost — Remote Updater (for VPS with poor Docker Hub / GitHub connectivity)
#
# Runs on a host with GOOD internet. Builds images locally, transfers
# them via SCP to the VPS, and deploys there — no external pulls needed
# on the VPS side.
#
# Usage:
#   bash scripts/update-remote.sh <vps> [--full]
#
#   vps:    SSH destination (e.g., demon@linuxuat or 192.168.1.10)
#   --full: DB backup before deploy + restore after (preserves accounts)
#
# Examples:
#   bash scripts/update-remote.sh demon@152.42.160.210
#   bash scripts/update-remote.sh demon@linuxuat --full
# ══════════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()  { printf "${CYAN}[INFO]${NC}  %s\n" "$*"; }
ok()    { printf "${GREEN}[OK]${NC}    %s\n" "$*"; }
warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$*"; }
die()   { printf "${RED}[FATAL]${NC} %s\n" "$*" >&2; exit 1; }

# ── Parse args ──────────────────────────────────────────────────────────
VPS=""; WITH_BACKUP=false; PROJECT_DIR=""; _next_project_dir=false
for arg in "$@"; do
    if [ "$_next_project_dir" = true ]; then
        PROJECT_DIR="$arg"
        _next_project_dir=false
        continue
    fi
    case "$arg" in
        --full) WITH_BACKUP=true ;;
        --project-dir) _next_project_dir=true ;;
        --project-dir=*) PROJECT_DIR="${arg#*=}" ;;
        --help|-h)
            echo "Usage: bash update-remote.sh <vps> [--full] [--project-dir=<path>]"
            echo "  vps          SSH destination (required)"
            echo "  --full       DB backup + restore"
            echo "  --project-dir Path to demon-in-the-wire project (auto-detected if omitted)"
            exit 0 ;;
        *) VPS="$arg" ;;
    esac
done

[ -z "$VPS" ] && die "VPS hostname required. Usage: bash update-remote.sh <vps> [--full]"

# ── Find project root ───────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -n "$PROJECT_DIR" ]; then
    # Explicit path given
    [ -f "${PROJECT_DIR}/pyproject.toml" ] || die "pyproject.toml not found at ${PROJECT_DIR} (--project-dir)"
elif [ -f "$PWD/pyproject.toml" ]; then
    PROJECT_DIR="$PWD"
elif [ -f "${SCRIPT_DIR}/../pyproject.toml" ]; then
    PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
else
    # Search upward from PWD
    _search="$PWD"
    while [ "$_search" != "/" ]; do
        if [ -f "$_search/pyproject.toml" ]; then
            PROJECT_DIR="$_search"
            break
        fi
        _search="$(dirname "$_search")"
    done
    [ -n "$PROJECT_DIR" ] || die "Project root not found. cd to the project or use --project-dir=<path>"
fi

REMOTE_DIR="/opt/wireghost"
TMPDIR="${PROJECT_DIR}/.remote-update"
rm -rf "$TMPDIR" 2>/dev/null || true
mkdir -p "$TMPDIR"

printf "\n${BOLD}${CYAN} Wire_Ghost — Remote Updater${NC}\n"
info "VPS:     ${VPS}"
info "Project: ${PROJECT_DIR}"
echo ""

# Extract host IP from VPS argument (e.g., "demon@10.10.9.240" → "10.10.9.240")
REMOTE_HOST="${VPS##*@}"
# If it looks like an IP, use it as default WIREGHOST_HOST for the build
if echo "$REMOTE_HOST" | grep -qP '^\d+\.\d+\.\d+\.\d+$'; then
    REMOTE_HOST_IP="$REMOTE_HOST"
else
    REMOTE_HOST_IP=""
fi

###########################################################################
# 1. DB backup (from VPS)
###########################################################################
if [ "$WITH_BACKUP" = true ]; then
    info "Step 1: Backing up database from VPS..."
    BACKUP_FILE="${TMPDIR}/wireghost_backup_$(date +%Y%m%d_%H%M%S).sql.gz"

    ssh "$VPS" "cd ${REMOTE_DIR} && docker compose -f docker-compose.yml -f docker-compose.host.yml exec -T db sh -c 'mysqldump -u root -p\"\$MYSQL_ROOT_PASSWORD\" --single-transaction --routines --triggers --events wireghost' | gzip" > "$BACKUP_FILE" 2>/dev/null || {
        warn "DB backup failed — continuing without backup"
        WITH_BACKUP=false
    }

    if [ -s "$BACKUP_FILE" ]; then
        size=$(du -h "$BACKUP_FILE" | cut -f1)
        ok "DB backed up (${size}) → ${BACKUP_FILE##*/}"
    fi
else
    info "Step 1: Skipping DB backup (use --full to enable)"
fi

###########################################################################
# 2. Git pull (local — good connectivity)
###########################################################################
info "Step 2: Pulling latest code..."
cd "$PROJECT_DIR"
git pull --ff-only origin "$(git rev-parse --abbrev-ref HEAD)" 2>&1 || warn "git pull failed"
ok "Code up to date ($(git rev-parse --short HEAD))"

###########################################################################
# 3. Build images locally
###########################################################################
info "Step 3: Building Docker images (cached)..."

# Ensure .env exists with dummy values (compose needs them for interpolation
# during build). Real values come from the VPS .env at deploy time.
if [ ! -f "${PROJECT_DIR}/.env" ]; then
    warn ".env missing (fresh clone?) — creating temporary one for build"
    cat > "${PROJECT_DIR}/.env" <<'ENVEOF'
MYSQL_ROOT_PASSWORD=build_placeholder
MYSQL_PASSWORD=build_placeholder
MYSQL_USER=wireghost
MYSQL_DATABASE=wireghost
REDIS_PASSWORD=build_placeholder
DJANGO_SECRET_KEY=build_placeholder
WIREGHOST_HOST=localhost
WIREGHOST_PROTO=https
WIREGHOST_PORT=443
WIREGHOST_HTTP_BIND=127.0.0.1
WIREGHOST_HTTP_PORT=80
WIREGHOST_LOG_DIR=./logs
EMAIL_HOST=localhost
EMAIL_PORT=587
EMAIL_USE_TLS=true
EMAIL_HOST_USER=
EMAIL_HOST_PASSWORD=
DEFAULT_FROM_EMAIL=noreply@wireghost.local
CSRF_COOKIE_SECURE=true
SESSION_COOKIE_SECURE=true
CSRF_TRUSTED_ORIGINS=https://localhost
ENVEOF
    ok "Temporary .env created (not used for deploy)"
fi
cd "$PROJECT_DIR"

# Build all services — local machine has good Docker Hub / GitHub access
docker compose -f docker-compose.yml build --pull api 2>&1 || die "API image build failed"
ok "API image built"

docker compose -f docker-compose.yml build --pull worker 2>&1 || die "Worker image build failed"
ok "Worker image built"

docker compose -f docker-compose.yml build --pull portal 2>&1 || die "Portal image build failed"
ok "Portal image built"

###########################################################################
# 4. Save images → individual tarballs
###########################################################################
info "Step 4: Saving images to archive..."

# Save each image individually — portal first (smallest, ~25MB), then worker (~2GB), then web (~500MB).
# Individual files mean a partial transfer failure doesn't lose everything,
# and portal can be deployed immediately without waiting for worker/web.
_save_one() {
    local tag="$1" file="$2"
    docker save "$tag" | gzip > "$file"
}

IMAGE_DIR="${TMPDIR}/images"
mkdir -p "$IMAGE_DIR"

_save_one callmedemon/wireghost:portal  "${IMAGE_DIR}/portal.tar.gz"  &
_save_one callmedemon/wireghost:web     "${IMAGE_DIR}/web.tar.gz"     &
_save_one callmedemon/wireghost:worker  "${IMAGE_DIR}/worker.tar.gz"  &
wait

for f in portal web worker; do
    [ -s "${IMAGE_DIR}/${f}.tar.gz" ] || die "Failed to save ${f} image"
done
ok "Images saved (portal: $(du -h "${IMAGE_DIR}/portal.tar.gz" | cut -f1), web: $(du -h "${IMAGE_DIR}/web.tar.gz" | cut -f1), worker: $(du -h "${IMAGE_DIR}/worker.tar.gz" | cut -f1))"

###########################################################################
# 5. Transfer code + images to VPS
###########################################################################
info "Step 5: Transferring to VPS..."

# Code tarball (source files the containers need)
code_tar="${TMPDIR}/wireghost-code.tar.gz"
tar czf "$code_tar" \
    --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
    --exclude='node_modules' --exclude='.remote-update' \
    --exclude='logs' --exclude='backups' --exclude='data' \
    -C "$PROJECT_DIR" \
    web_portal/ src/ config/ pyproject.toml docker-compose.yml docker-compose.host.yml \
    Dockerfile templates/ scripts/docker-entrypoint.sh 2>/dev/null

info "Transferring code ($(du -h "$code_tar" | cut -f1))..."
scp "$code_tar" "${VPS}:${REMOTE_DIR}/.remote-code.tar.gz" 2>&1 || die "SCP code transfer failed"
ok "Code transferred"

# Transfer images individually — portal first (fast, gets the critical fix deployed ASAP)
_scp_img() {
    local name="$1" file="$2" remote_file="$3"
    info "Transferring ${name} ($(du -h "$file" | cut -f1))..."
    scp "$file" "${VPS}:${remote_file}" 2>&1 || {
        warn "${name} transfer failed — continuing"
        return 1
    }
    ok "${name} transferred"
}

_scp_img "portal" "${IMAGE_DIR}/portal.tar.gz"  "${REMOTE_DIR}/.remote-portal.tar.gz"
_scp_img "web"    "${IMAGE_DIR}/web.tar.gz"     "${REMOTE_DIR}/.remote-web.tar.gz"
_scp_img "worker" "${IMAGE_DIR}/worker.tar.gz"  "${REMOTE_DIR}/.remote-worker.tar.gz"

# Transfer backup file if present
REMOTE_BACKUP=""
if [ "$WITH_BACKUP" = true ] && [ -s "$BACKUP_FILE" ]; then
    REMOTE_BACKUP="${REMOTE_DIR}/.remote-backup.sql.gz"
    info "Transferring DB backup..."
    scp "$BACKUP_FILE" "${VPS}:${REMOTE_BACKUP}" 2>&1 || {
        warn "Backup transfer failed — continuing without restore"
        WITH_BACKUP=false
        REMOTE_BACKUP=""
    }
    ok "Backup transferred"
fi

###########################################################################
# 6. Deploy on VPS
###########################################################################
info "Step 6: Deploying on VPS..."

ssh "$VPS" bash -s <<'DEPLOY' -- "$REMOTE_DIR" "$WITH_BACKUP" "$REMOTE_BACKUP"
set -euo pipefail
REMOTE_DIR="$1"; WITH_BACKUP="$2"; BACKUP_FILE="$3"

echo "[VPS] Loading images..."
cd "$REMOTE_DIR"
for f in .remote-portal .remote-web .remote-worker; do
    if [ -f "${f}.tar.gz" ]; then
        echo "[VPS]   Loading ${f#.remote-}..."
        gunzip -c "${f}.tar.gz" | docker load 2>&1 | head -3
        rm -f "${f}.tar.gz"
    else
        echo "[VPS]   ${f#.remote-} image not found — skipping"
    fi
done

echo "[VPS] Extracting code..."
tar xzf .remote-code.tar.gz 2>/dev/null
rm -f .remote-code.tar.gz

echo "[VPS] Stopping stack..."
docker compose -f docker-compose.yml -f docker-compose.host.yml down --remove-orphans 2>&1 || true

echo "[VPS] Starting stack..."
docker compose -f docker-compose.yml -f docker-compose.host.yml up -d --force-recreate --remove-orphans 2>&1

echo "[VPS] Waiting for DB..."
for i in $(seq 1 30); do
    if docker compose -f docker-compose.yml -f docker-compose.host.yml exec -T db mysqladmin ping -h localhost --silent 2>/dev/null; then
        echo "[VPS] DB ready"
        break
    fi
    sleep 1
done

echo "[VPS] Running migrations..."
docker compose -f docker-compose.yml -f docker-compose.host.yml exec -T api python manage.py migrate --noinput 2>&1 || echo "[VPS] WARNING: migrate failed"

echo "[VPS] Collecting static..."
docker compose -f docker-compose.yml -f docker-compose.host.yml exec -T api python manage.py collectstatic --noinput 2>&1 || echo "[VPS] WARNING: collectstatic failed"

# DB restore
if [ "$WITH_BACKUP" = true ] && [ -n "${BACKUP_FILE:-}" ] && [ -s "$BACKUP_FILE" ]; then
    echo "[VPS] Restoring database..."
    gunzip < "$BACKUP_FILE" | docker compose -f docker-compose.yml -f docker-compose.host.yml exec -T db sh -c \
        'mysql -u root -p"$MYSQL_ROOT_PASSWORD" wireghost' 2>&1 && \
        echo "[VPS] DB restored" || echo "[VPS] WARNING: DB restore failed"
    rm -f "$BACKUP_FILE"

    echo "[VPS] Re-running migrations after restore..."
    docker compose -f docker-compose.yml -f docker-compose.host.yml exec -T api python manage.py migrate --noinput 2>&1
fi

# Restart portal to flush DNS
echo "[VPS] Restarting portal..."
docker compose -f docker-compose.yml -f docker-compose.host.yml restart portal 2>&1 || true

echo "[VPS] Done — stack is running"
DEPLOY

ok "Deployment complete"

###########################################################################
# 7. Cleanup
###########################################################################
info "Step 7: Cleaning up..."
rm -rf "$TMPDIR"
ok "Temporary files removed"

echo ""
ok "Remote update finished successfully"
echo "  Portal: https://127.0.0.1:2006 (on VPS — access via SSH tunnel)"
