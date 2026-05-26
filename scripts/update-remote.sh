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
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
info()  { printf "${CYAN}[INFO]${NC}  %s\n" "$*"; }
ok()    { printf "${GREEN}[OK]${NC}    %s\n" "$*"; }
warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$*"; }
die()   { printf "${RED}[FATAL]${NC} %s\n" "$*" >&2; exit 1; }

# ── Transfer settings ──────────────────────────────────────────────────────
TRANSFER_TIMEOUT="${TRANSFER_TIMEOUT:-600}"   # seconds per file (0 = none)
TRANSFER_RETRIES="${TRANSFER_RETRIES:-3}"      # attempts per file

# ── Parse args ──────────────────────────────────────────────────────────
VPS=""; WITH_BACKUP=false; PROJECT_DIR=""; REMOTE_DIR=""; DEBUG=false
_next_project_dir=false; _next_remote_dir=false
for arg in "$@"; do
    if [ "$_next_project_dir" = true ]; then
        PROJECT_DIR="$arg"
        _next_project_dir=false
        continue
    fi
    if [ "$_next_remote_dir" = true ]; then
        REMOTE_DIR="$arg"
        _next_remote_dir=false
        continue
    fi
    case "$arg" in
        --full) WITH_BACKUP=true ;;
        --debug|--verbose) DEBUG=true ;;
        --project-dir) _next_project_dir=true ;;
        --remote-dir) _next_remote_dir=true ;;
        --remote-dir=*) REMOTE_DIR="${arg#*=}" ;;
        --project-dir=*) PROJECT_DIR="${arg#*=}" ;;
        --help|-h)
            echo "Usage: bash update-remote.sh <vps> [--full] [--debug|--verbose] [--project-dir=<path>] [--remote-dir=<path>]"
            echo "  vps          SSH destination (required)"
            echo "  --full       DB backup + restore"
            echo "  --debug, --verbose  Show every command + full output (troubleshooting)"
            echo "  --project-dir Path to demon-in-the-wire project (auto-detected if omitted)"
            echo "  --remote-dir  Path to project on VPS (auto-detected via SSH if omitted)"
            echo ""
            echo "  Env vars: TRANSFER_TIMEOUT=N (default 600), TRANSFER_RETRIES=N (default 3)"
            exit 0 ;;
        --*)
	            echo "ERROR: Unknown flag: $arg" >&2
	            echo "Run with --help for usage." >&2
	            exit 1 ;;
        *) VPS="$arg" ;;
    esac
done

# ── Debug mode ───────────────────────────────────────────────────────────
if [ "$DEBUG" = true ]; then
    set -x
    info "DEBUG mode enabled — full command trace + output"
    echo ""
fi

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

# ── Resolve remote project directory ─────────────────────────────────────
if [ -z "$REMOTE_DIR" ]; then
    # Auto-detect via SSH — check common paths
    REMOTE_DIR=$(ssh "$VPS" 'for d in /opt/wireghost /home/demon/Tools/demon-in-the-wire /opt/demon-in-the-wire; do [ -f "$d/docker-compose.yml" ] && echo "$d" && break; done' 2>/dev/null || echo "")
    [ -z "$REMOTE_DIR" ] && REMOTE_DIR="/opt/wireghost"  # fallback
fi

TMPDIR="${PROJECT_DIR}/.remote-update"
rm -rf "$TMPDIR" 2>/dev/null || true
mkdir -p "$TMPDIR"

printf "\n${BOLD}${CYAN} Wire_Ghost — Remote Updater${NC}\n"
info "VPS:     ${VPS}"
info "Project: ${PROJECT_DIR}"
info "Remote:  ${REMOTE_DIR}"
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
#
# Transfers are time-boxed and retried. Each file gets up to
# TRANSFER_RETRIES attempts (default 3) with TRANSFER_TIMEOUT seconds
# per attempt (default 600, 0=unlimited). On slow/unstable links:
#   TRANSFER_TIMEOUT=300 bash update-remote.sh <vps>
#
# After transfer we write a manifest (.remote-manifest) listing which
# files made it. Step 6 uses the manifest to decide what to deploy.
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
    Dockerfile templates/ 2>/dev/null

# ── Transfer helper ───────────────────────────────────────────────────────
# _transfer_file <name> <local_path> <remote_path>
# Returns 0 on success, 1 on failure.
# Handles: timeout, retry with backoff, rsync fallback, skip-if-exists.
_transfer_file() {
    local label="$1" local_file="$2" remote_file="$3"
    local size; size=$(du -h "$local_file" 2>/dev/null | cut -f1 || echo "?")

    # Check if remote file already exists with matching size
    local local_bytes remote_bytes
    local_bytes=$(stat -c%s "$local_file" 2>/dev/null || echo "0")
    remote_bytes=$(ssh -o ConnectTimeout=5 "$VPS" "stat -c%s '$remote_file' 2>/dev/null || echo 0" 2>/dev/null || echo "0")
    if [ "$local_bytes" -eq "$remote_bytes" ] && [ "$local_bytes" -gt 0 ]; then
        ok "${label} (${size} — already on remote, skipping)"
        return 0
    fi

    # Build transfer commands (try scp, fall back to rsync)
    local scp_cmd="scp -o ConnectTimeout=10 '$local_file' '${VPS}:${remote_file}'"
    local rsync_cmd="rsync -avP --partial '$local_file' '${VPS}:${remote_file}'"

    local backoff=5 attempt=1
    while [ "$attempt" -le "$TRANSFER_RETRIES" ]; do
        local prefix=""
        [ "$TRANSFER_RETRIES" -gt 1 ] && prefix="[${attempt}/${TRANSFER_RETRIES}] "
        info "${prefix}${label} (${size})..."

        # Run transfer with optional timeout
        if [ "$TRANSFER_TIMEOUT" -gt 0 ] 2>/dev/null; then
            if timeout "$TRANSFER_TIMEOUT" sh -c "$scp_cmd" 2>&1; then
                ok "${label} transferred"
                return 0
            fi
        else
            if sh -c "$scp_cmd" 2>&1; then
                ok "${label} transferred"
                return 0
            fi
        fi

        if [ "$attempt" -lt "$TRANSFER_RETRIES" ]; then
            warn "${label} attempt ${attempt} failed — retrying in ${backoff}s"

            # If scp failed, try rsync next
            if command -v rsync >/dev/null 2>&1; then
                info "  trying rsync instead..."
                if [ "$TRANSFER_TIMEOUT" -gt 0 ] 2>/dev/null; then
                    timeout "$TRANSFER_TIMEOUT" sh -c "$rsync_cmd" 2>&1 && {
                        ok "${label} transferred (rsync)"
                        return 0
                    }
                else
                    sh -c "$rsync_cmd" 2>&1 && {
                        ok "${label} transferred (rsync)"
                        return 0
                    }
                fi
            fi

            sleep "$backoff"
            backoff=$((backoff * 2))
            [ "$backoff" -gt 60 ] && backoff=60
        fi
        attempt=$((attempt + 1))
    done

    warn "${label} transfer FAILED after ${TRANSFER_RETRIES} attempts — skipping"
    return 1
}

# ── Transfer code tarball (small, critical — fail hard) ───────────────────
if ! _transfer_file "code" "$code_tar" "${REMOTE_DIR}/.remote-code.tar.gz"; then
    die "Code transfer failed — cannot deploy without source files"
fi

# ── Transfer images (best-effort, track what succeeded) ───────────────────
# Always force-transfer portal (25MB) — size-based dedup is unreliable for
# small images where a config change may produce the same compressed byte count.
ssh -o ConnectTimeout=5 "$VPS" "rm -f '${REMOTE_DIR}/.remote-portal.tar.gz'" 2>/dev/null || true

REMOTE_IMAGES=""
for img in portal web worker; do
    if _transfer_file "$img" "${IMAGE_DIR}/${img}.tar.gz" "${REMOTE_DIR}/.remote-${img}.tar.gz"; then
        REMOTE_IMAGES="${REMOTE_IMAGES} ${img}"
    fi
done
REMOTE_IMAGES="${REMOTE_IMAGES# }"  # trim leading space

if [ -z "$REMOTE_IMAGES" ]; then
    die "No images transferred — nothing to deploy"
fi
info "Images available on VPS: ${REMOTE_IMAGES}"

# ── Transfer backup file if present ───────────────────────────────────────
REMOTE_BACKUP=""
if [ "$WITH_BACKUP" = true ] && [ -s "$BACKUP_FILE" ]; then
    REMOTE_BACKUP="${REMOTE_DIR}/.remote-backup.sql.gz"
    if _transfer_file "backup" "$BACKUP_FILE" "$REMOTE_BACKUP"; then
        ok "Backup transferred"
    else
        warn "Backup transfer failed — continuing without restore"
        WITH_BACKUP=false
        REMOTE_BACKUP=""
    fi
fi

###########################################################################
# 6. Deploy on VPS
###########################################################################
info "Step 6: Deploying on VPS..."

ssh "$VPS" bash -s <<'DEPLOY' -- "$REMOTE_DIR" "$WITH_BACKUP" "$REMOTE_BACKUP" "$REMOTE_IMAGES"
set -euo pipefail
REMOTE_DIR="$1"; WITH_BACKUP="$2"; BACKUP_FILE="${3:-}"; REMOTE_IMAGES="${4:-}"

echo "[VPS] Loading images..."
echo "[VPS]   REMOTE_IMAGES='${REMOTE_IMAGES}'"
cd "$REMOTE_DIR"
for img in $REMOTE_IMAGES; do
    f=".remote-${img}.tar.gz"
    if [ -f "$f" ]; then
        echo "[VPS]   Loading ${img}..."
        gunzip -c "$f" | docker load 2>&1 || { echo "[VPS]   WARNING: ${img} load failed"; continue; }
        rm -f "$f"
        echo "[VPS]   ${img} loaded"
    else
        echo "[VPS]   ${img} image file missing — will reuse existing image"
    fi
done

echo "[VPS] Extracting code..."
tar xzf .remote-code.tar.gz 2>/dev/null
rm -f .remote-code.tar.gz

# Detect install mode to select the right compose files
if grep -q '^INSTALL_MODE=host' .env 2>/dev/null; then
    COMPOSE_FILES="-f docker-compose.yml -f docker-compose.host.yml"
    echo "[VPS] Host mode detected"
else
    COMPOSE_FILES=""
    echo "[VPS] Docker mode detected"
fi

echo "[VPS] Stopping stack..."
docker compose $COMPOSE_FILES down --remove-orphans 2>&1 || true

echo "[VPS] Starting stack..."

# Build the list of services to force-recreate (only those whose images were transferred)
# Portal is always force-recreated — it's tiny (25MB) and the cost of serving
# a stale nginx config (wrong redirect IP) is worse than 2s of portal downtime.
FORCE_SVCS="portal"
for img in $REMOTE_IMAGES; do
    case "$img" in
        portal) ;;  # already in FORCE_SVCS
        web)    FORCE_SVCS="$FORCE_SVCS api beat bot" ;;
        worker) FORCE_SVCS="$FORCE_SVCS worker" ;;
    esac
done

if [ -n "$FORCE_SVCS" ]; then
    echo "[VPS]   Force-recreating:${FORCE_SVCS}"
    docker compose $COMPOSE_FILES up -d --force-recreate --remove-orphans $FORCE_SVCS 2>&1
fi

# Bring up remaining services (db, redis, proxy — unchanged but may have been stopped)
docker compose $COMPOSE_FILES up -d --remove-orphans 2>&1

echo "[VPS] Waiting for DB..."
for i in $(seq 1 30); do
    if docker compose $COMPOSE_FILES exec -T db mysqladmin ping -h localhost --silent 2>/dev/null; then
        echo "[VPS] DB ready"
        break
    fi
    sleep 1
done

echo "[VPS] Running migrations..."
docker compose $COMPOSE_FILES exec -T api python manage.py migrate --noinput 2>&1 || echo "[VPS] WARNING: migrate failed"

echo "[VPS] Collecting static..."
docker compose $COMPOSE_FILES exec -T api python manage.py collectstatic --noinput 2>&1 || echo "[VPS] WARNING: collectstatic failed"

# DB restore
if [ "$WITH_BACKUP" = true ] && [ -n "${BACKUP_FILE:-}" ] && [ -s "$BACKUP_FILE" ]; then
    echo "[VPS] Restoring database..."
    gunzip < "$BACKUP_FILE" | docker compose $COMPOSE_FILES exec -T db sh -c \
        'mysql -u root -p"$MYSQL_ROOT_PASSWORD" wireghost' 2>&1 && \
        echo "[VPS] DB restored" || echo "[VPS] WARNING: DB restore failed"
    rm -f "$BACKUP_FILE"

    echo "[VPS] Re-running migrations after restore..."
    docker compose $COMPOSE_FILES exec -T api python manage.py migrate --noinput 2>&1
fi

echo "[VPS] Done — stack is running"

# ── Quick health check ────────────────────────────────────────────────
echo "[VPS] Health check..."
sleep 2
_portal_code=$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:2006/login 2>/dev/null || echo "000")
_redirect_url=$(curl -sk -o /dev/null -w '%{redirect_url}' https://127.0.0.1:2006/ 2>/dev/null || echo "")
echo "[VPS]   /login → HTTP ${_portal_code}"
echo "[VPS]   / → ${_redirect_url}"
if [ "$_portal_code" = "200" ]; then
    echo "[VPS]   Health: PASS"
else
    echo "[VPS]   Health: FAIL (login returned ${_portal_code})"
fi
if echo "$_redirect_url" | grep -q '127.0.0.1'; then
    echo "[VPS]   Redirect: PASS (using 127.0.0.1)"
else
    echo "[VPS]   Redirect: WARN (expected 127.0.0.1, got ${_redirect_url})"
fi
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
