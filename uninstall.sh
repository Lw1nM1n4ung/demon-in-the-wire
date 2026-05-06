#!/usr/bin/env bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Wire_Ghost — Full Uninstaller
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
#  Removes all Docker resources (containers, volumes,
#  networks, images) and host-level artifacts (logs,
#  certs, .env, generated configs).
#
#  Usage:
#    ./uninstall.sh                  Interactive (prompts)
#    ./uninstall.sh --yes            Skip confirmations
#    ./uninstall.sh --keep-data      Keep DB + scan volumes
#    ./uninstall.sh --keep-images    Keep Docker images
#    ./uninstall.sh --keep-source    Don't delete source dir
#    ./uninstall.sh --dry-run        Show what would happen
#
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

set -euo pipefail

# ── Colors ──────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ── Globals ─────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
PROJECT_NAME="demon-in-the-wire"

AUTO_YES=false
KEEP_DATA=false
KEEP_IMAGES=false
KEEP_SOURCE=false
DRY_RUN=false
EXPORT_DATA=false

ERRORS=0

# ── Helpers ─────────────────────────────────────────────
log()    { printf "${GREEN}[✓]${RESET} %s\n" "$*"; }
warn()   { printf "${YELLOW}[!]${RESET} %s\n" "$*"; }
err()    { printf "${RED}[✗]${RESET} %s\n" "$*"; ERRORS=$((ERRORS + 1)); }
info()   { printf "${CYAN}[i]${RESET} %s\n" "$*"; }
header() { printf "\n${BOLD}━━ %s ━━${RESET}\n\n" "$*"; }
dim()    { printf "${DIM}    %s${RESET}\n" "$*"; }

run() {
    if $DRY_RUN; then
        dim "[dry-run] $*"
    else
        eval "$@"
    fi
}

confirm() {
    if $AUTO_YES; then
        return 0
    fi
    local prompt="$1"
    local answer
    printf "${BOLD}%s${RESET} [y/N] " "$prompt"
    read -r answer
    [[ "$answer" =~ ^[Yy]$ ]]
}

# ── Parse args ──────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes|-y)          AUTO_YES=true ;;
        --keep-data)       KEEP_DATA=true ;;
        --keep-images)     KEEP_IMAGES=true ;;
        --keep-source)     KEEP_SOURCE=true ;;
        --dry-run|-n)      DRY_RUN=true ;;
        --export)          EXPORT_DATA=true ;;
        --help|-h)
            cat <<'USAGE'
Wire_Ghost Uninstaller

Usage: ./uninstall.sh [OPTIONS]

Options:
  --yes, -y         Skip all confirmation prompts
  --keep-data       Keep database and scan output volumes
  --keep-images     Keep Docker images (callmedemon/wireghost:*)
  --keep-source     Don't remove the source directory
  --export          Export DB + scan data before removing
  --dry-run, -n     Preview actions without executing
  --help, -h        Show this help

Removal order:
  1. Stop & remove containers
  2. Remove Docker volumes (unless --keep-data)
  3. Remove Docker networks
  4. Remove Docker images (unless --keep-images)
  5. Remove host artifacts (logs, certs, .env, nginx.conf)
  6. Remove source directory (unless --keep-source)

Examples:
  ./uninstall.sh                    # Interactive full uninstall
  ./uninstall.sh --yes --keep-data  # Automated, preserve data
  ./uninstall.sh --dry-run          # See what would happen
  ./uninstall.sh --export --yes     # Export data then remove all
USAGE
            exit 0
            ;;
        *)
            err "Unknown option: $1"
            echo "Run ./uninstall.sh --help for usage"
            exit 1
            ;;
    esac
    shift
done

# ── Pre-flight checks ──────────────────────────────────
if ! command -v docker &>/dev/null; then
    err "Docker not found — nothing to uninstall."
    exit 1
fi

if ! docker info &>/dev/null; then
    err "Docker daemon not reachable. Run with sudo or check dockerd."
    exit 1
fi

# ── Banner ──────────────────────────────────────────────
printf "\n"
printf "${RED}${BOLD}"
cat <<'BANNER'
 ╦ ╦╦╦═╗╔═╗   ╔═╗╦ ╦╔═╗╔═╗╔╦╗
 ║║║║╠╦╝║╣    ║ ╦╠═╣║ ║╚═╗ ║
 ╚╩╝╩╩╚═╚═╝───╚═╝╩ ╩╚═╝╚═╝ ╩
BANNER
printf "${RESET}"
printf "${BOLD}         Full Uninstaller${RESET}\n"
printf "\n"

# ── Inventory ───────────────────────────────────────────
header "Scanning installation"

CONTAINERS=$(docker ps -a --filter "label=com.docker.compose.project=${PROJECT_NAME}" --format '{{.Names}}' 2>/dev/null || true)
RUNNING=$(docker ps --filter "label=com.docker.compose.project=${PROJECT_NAME}" --format '{{.Names}}' 2>/dev/null || true)
VOLUMES=$(docker volume ls --filter "name=${PROJECT_NAME}_" --format '{{.Name}}' 2>/dev/null || true)
NETWORKS=$(docker network ls --filter "name=${PROJECT_NAME}_" --format '{{.Name}}' 2>/dev/null || true)
IMAGES=$(docker images --filter "reference=callmedemon/wireghost" --format '{{.Repository}}:{{.Tag}}  ({{.Size}})' 2>/dev/null || true)
PULLED_IMAGES=""
for img in "mysql:8.0" "redis:7-alpine" "nginx:alpine" "tecnativa/docker-socket-proxy:latest"; do
    if docker image inspect "$img" &>/dev/null; then
        size=$(docker image inspect "$img" --format '{{.Size}}' 2>/dev/null || echo "0")
        size_mb=$(( size / 1024 / 1024 ))
        PULLED_IMAGES="${PULLED_IMAGES}${img}  (${size_mb}MB)\n"
    fi
done

HOST_ARTIFACTS=""
for item in "${SCRIPT_DIR}/logs" "${SCRIPT_DIR}/certs" "${SCRIPT_DIR}/.env" "${SCRIPT_DIR}/nginx.conf"; do
    if [[ -e "$item" ]]; then
        HOST_ARTIFACTS="${HOST_ARTIFACTS}$(basename "$item")\n"
    fi
done

# Display what was found
if [[ -n "$RUNNING" ]]; then
    info "Running containers:"
    echo "$RUNNING" | while read -r c; do dim "$c"; done
fi
if [[ -n "$CONTAINERS" ]]; then
    count=$(echo "$CONTAINERS" | wc -l)
    info "Total containers: $count"
fi
if [[ -n "$VOLUMES" ]]; then
    info "Docker volumes:"
    echo "$VOLUMES" | while read -r v; do
        size=$(docker system df -v 2>/dev/null | grep "$v" | awk '{print $NF}' || echo "?")
        dim "$v"
    done
fi
if [[ -n "$NETWORKS" ]]; then
    info "Docker networks:"
    echo "$NETWORKS" | while read -r n; do dim "$n"; done
fi
if [[ -n "$IMAGES" ]]; then
    info "Wire_Ghost images:"
    echo "$IMAGES" | while read -r i; do dim "$i"; done
fi
if [[ -n "$PULLED_IMAGES" ]]; then
    info "Pulled base images:"
    printf "$PULLED_IMAGES" | while read -r i; do [[ -n "$i" ]] && dim "$i"; done
fi
if [[ -n "$HOST_ARTIFACTS" ]]; then
    info "Host artifacts:"
    printf "$HOST_ARTIFACTS" | while read -r a; do [[ -n "$a" ]] && dim "$a"; done
fi

# Flags summary
echo ""
if $KEEP_DATA;   then warn "Flag: --keep-data    → volumes will be preserved"; fi
if $KEEP_IMAGES; then warn "Flag: --keep-images  → images will be preserved"; fi
if $KEEP_SOURCE; then warn "Flag: --keep-source  → source directory preserved"; fi
if $DRY_RUN;     then warn "Flag: --dry-run      → no changes will be made"; fi
if $EXPORT_DATA; then warn "Flag: --export       → data exported before removal"; fi
echo ""

# Nothing to do?
if [[ -z "$CONTAINERS" && -z "$VOLUMES" && -z "$NETWORKS" && -z "$IMAGES" && -z "$HOST_ARTIFACTS" ]]; then
    log "No Wire_Ghost installation found. Nothing to do."
    exit 0
fi

# ── Final confirmation ──────────────────────────────────
if ! $DRY_RUN; then
    if ! $AUTO_YES; then
        printf "${RED}${BOLD}This will permanently remove Wire_Ghost from this system.${RESET}\n"
        if ! $KEEP_DATA; then
            printf "${RED}All scan data, database records, and reports will be DELETED.${RESET}\n"
        fi
        echo ""
        if ! confirm "Proceed with uninstall?"; then
            warn "Aborted."
            exit 0
        fi
        echo ""
    fi
fi

# ── Phase 1: Export data (optional) ────────────────────
if $EXPORT_DATA; then
    header "Phase 0 — Exporting data"

    EXPORT_DIR="${SCRIPT_DIR}/wireghost-export-$(date +%Y%m%d-%H%M%S)"
    run "mkdir -p '${EXPORT_DIR}'"

    # Export MySQL database
    if docker ps --filter "name=${PROJECT_NAME}-db-1" --format '{{.Names}}' | grep -q db; then
        info "Exporting MySQL database..."
        if ! $DRY_RUN; then
            # Source .env for password
            if [[ -f "${SCRIPT_DIR}/.env" ]]; then
                set -a; source "${SCRIPT_DIR}/.env"; set +a
            fi
            docker exec "${PROJECT_NAME}-db-1" \
                mysqldump -uroot -p"${MYSQL_ROOT_PASSWORD:-}" \
                --single-transaction --routines --triggers \
                "${MYSQL_DATABASE:-wireghost}" \
                > "${EXPORT_DIR}/wireghost-db.sql" 2>/dev/null \
                && log "Database exported: $(du -sh "${EXPORT_DIR}/wireghost-db.sql" | cut -f1)" \
                || err "Database export failed"
        else
            dim "[dry-run] mysqldump → ${EXPORT_DIR}/wireghost-db.sql"
        fi
    else
        warn "Database container not running — skipping DB export"
    fi

    # Copy scan output from volume
    info "Exporting scan output volume..."
    run "docker run --rm -v ${PROJECT_NAME}_scan_output:/src -v '${EXPORT_DIR}':/dst alpine sh -c 'cp -a /src/. /dst/scan_output/ 2>/dev/null' && log 'Scan output exported' || warn 'Scan output export failed'"

    # Copy report assets from volume
    info "Exporting report assets volume..."
    run "docker run --rm -v ${PROJECT_NAME}_report_assets:/src -v '${EXPORT_DIR}':/dst alpine sh -c 'cp -a /src/. /dst/report_assets/ 2>/dev/null' && log 'Report assets exported' || warn 'Report assets export failed'"

    if ! $DRY_RUN && [[ -d "$EXPORT_DIR" ]]; then
        total=$(du -sh "$EXPORT_DIR" | cut -f1)
        log "Export complete: ${EXPORT_DIR} (${total})"
    fi
fi

# ── Phase 1: Stop & remove containers ──────────────────
header "Phase 1 — Stopping containers"

if [[ -n "$CONTAINERS" ]]; then
    if [[ -f "$COMPOSE_FILE" ]]; then
        info "Stopping via docker compose..."
        run "docker compose -f '${COMPOSE_FILE}' down --timeout 30 2>&1 | grep -v '^$' || true"
        log "Containers stopped and removed"
    else
        info "No compose file — stopping containers directly..."
        echo "$CONTAINERS" | while read -r c; do
            run "docker rm -f '$c' 2>/dev/null || true"
            dim "Removed: $c"
        done
        log "Containers removed"
    fi
else
    info "No containers to remove"
fi

# ── Phase 2: Remove volumes ────────────────────────────
header "Phase 2 — Docker volumes"

if [[ -n "$VOLUMES" ]]; then
    if $KEEP_DATA; then
        warn "Keeping volumes (--keep-data):"
        echo "$VOLUMES" | while read -r v; do dim "$v"; done
    else
        echo "$VOLUMES" | while read -r v; do
            run "docker volume rm '$v' 2>/dev/null && echo '    Removed: $v' || echo '    Failed: $v (in use?)'"
        done
        log "Volumes removed"
    fi
else
    info "No volumes to remove"
fi

# ── Phase 3: Remove networks ───────────────────────────
header "Phase 3 — Docker networks"

if [[ -n "$NETWORKS" ]]; then
    echo "$NETWORKS" | while read -r n; do
        run "docker network rm '$n' 2>/dev/null && echo '    Removed: $n' || echo '    Skipped: $n (still in use?)'"
    done
    log "Networks cleaned"
else
    info "No project networks to remove"
fi

# ── Phase 4: Remove images ─────────────────────────────
header "Phase 4 — Docker images"

if $KEEP_IMAGES; then
    warn "Keeping images (--keep-images)"
else
    # Custom images
    custom_images=$(docker images --filter "reference=callmedemon/wireghost" --format '{{.Repository}}:{{.Tag}}' 2>/dev/null || true)
    if [[ -n "$custom_images" ]]; then
        info "Removing Wire_Ghost images..."
        echo "$custom_images" | while read -r img; do
            run "docker rmi '$img' 2>/dev/null && echo '    Removed: $img' || echo '    Failed: $img (in use?)'"
        done
    fi

    # Base images (only remove if user explicitly wants full cleanup)
    if ! $AUTO_YES; then
        if confirm "Also remove base images (mysql, redis, nginx, docker-socket-proxy)?"; then
            for img in "mysql:8.0" "redis:7-alpine" "nginx:alpine" "tecnativa/docker-socket-proxy:latest"; do
                if docker image inspect "$img" &>/dev/null; then
                    run "docker rmi '$img' 2>/dev/null && echo '    Removed: $img' || echo '    Skipped: $img (used by other projects?)'"
                fi
            done
        else
            info "Keeping base images"
        fi
    else
        # With --yes, also remove base images
        for img in "mysql:8.0" "redis:7-alpine" "nginx:alpine" "tecnativa/docker-socket-proxy:latest"; do
            if docker image inspect "$img" &>/dev/null; then
                run "docker rmi '$img' 2>/dev/null && echo '    Removed: $img' || echo '    Skipped: $img (used by other projects?)'"
            fi
        done
    fi

    # Dangling images from builds
    danglers=$(docker images -f "dangling=true" -f "label=com.docker.compose.project=${PROJECT_NAME}" -q 2>/dev/null || true)
    if [[ -n "$danglers" ]]; then
        info "Removing dangling build layers..."
        run "docker rmi $danglers 2>/dev/null || true"
    fi

    log "Images cleaned"
fi

# ── Phase 5: Host artifacts ────────────────────────────
header "Phase 5 — Host artifacts"

# Logs
if [[ -d "${SCRIPT_DIR}/logs" ]]; then
    log_size=$(du -sh "${SCRIPT_DIR}/logs" 2>/dev/null | cut -f1)
    info "Removing logs/ (${log_size})..."
    run "rm -rf '${SCRIPT_DIR}/logs'"
    log "Logs removed"
else
    info "No logs directory"
fi

# TLS certs
if [[ -d "${SCRIPT_DIR}/certs" ]]; then
    info "Removing self-signed TLS certs..."
    run "rm -rf '${SCRIPT_DIR}/certs'"
    log "Certs removed"
else
    info "No certs directory"
fi

# .env (secrets)
if [[ -f "${SCRIPT_DIR}/.env" ]]; then
    info "Removing .env (contains secrets)..."
    if ! $DRY_RUN; then
        # Overwrite before delete to prevent recovery
        dd if=/dev/urandom of="${SCRIPT_DIR}/.env" bs=1024 count=1 2>/dev/null || true
        rm -f "${SCRIPT_DIR}/.env"
    else
        dim "[dry-run] shred + rm .env"
    fi
    log ".env securely removed"
else
    info "No .env file"
fi

# nginx.conf
if [[ -f "${SCRIPT_DIR}/nginx.conf" ]]; then
    info "Removing nginx.conf..."
    run "rm -f '${SCRIPT_DIR}/nginx.conf'"
    log "nginx.conf removed"
fi

# __pycache__ and .pyc
pycache_count=$(find "${SCRIPT_DIR}" -name "__pycache__" -type d 2>/dev/null | wc -l)
if [[ "$pycache_count" -gt 0 ]]; then
    info "Cleaning ${pycache_count} __pycache__ directories..."
    run "find '${SCRIPT_DIR}' -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true"
fi

# ── Phase 6: Source directory ──────────────────────────
header "Phase 6 — Source directory"

if $KEEP_SOURCE; then
    warn "Keeping source directory (--keep-source): ${SCRIPT_DIR}"
else
    if ! $DRY_RUN; then
        source_size=$(du -sh "${SCRIPT_DIR}" 2>/dev/null | cut -f1)
        if $AUTO_YES || confirm "Delete source directory ${SCRIPT_DIR} (${source_size})?"; then
            # Safety: don't delete if we're running from inside it
            cd /tmp
            rm -rf "${SCRIPT_DIR}"
            log "Source directory removed: ${SCRIPT_DIR}"
        else
            info "Source directory preserved"
        fi
    else
        dim "[dry-run] rm -rf ${SCRIPT_DIR}"
    fi
fi

# ── Phase 7: Docker system prune (optional) ────────────
if ! $DRY_RUN && ! $KEEP_IMAGES; then
    echo ""
    if $AUTO_YES || confirm "Run 'docker system prune' to reclaim dangling resources?"; then
        info "Pruning unused Docker resources..."
        docker system prune -f 2>/dev/null | grep -v "^$" || true
        log "Docker system pruned"
    fi
fi

# ── Summary ─────────────────────────────────────────────
header "Uninstall complete"

if $DRY_RUN; then
    warn "DRY RUN — no changes were made"
    echo ""
fi

if [[ $ERRORS -gt 0 ]]; then
    err "${ERRORS} error(s) occurred during uninstall"
    echo ""
    info "Some resources may still exist. Run manually:"
    dim "docker compose -f ${COMPOSE_FILE} down -v --rmi all"
    dim "docker volume rm \$(docker volume ls -q --filter name=${PROJECT_NAME})"
    echo ""
    exit 1
fi

printf "${GREEN}${BOLD}"
cat <<'DONE'

  ╦ ╦╦╦═╗╔═╗   ╔═╗╦ ╦╔═╗╔═╗╔╦╗
  ║║║║╠╦╝║╣    ║ ╦╠═╣║ ║╚═╗ ║
  ╚╩╝╩╩╚═╚═╝───╚═╝╩ ╩╚═╝╚═╝ ╩

       Successfully uninstalled.
DONE
printf "${RESET}\n"

if $EXPORT_DATA && [[ -d "${EXPORT_DIR:-/nonexistent}" ]]; then
    info "Data backup saved to: ${EXPORT_DIR}"
fi
if $KEEP_DATA; then
    info "Volumes preserved. Re-attach with: docker volume ls --filter name=${PROJECT_NAME}"
fi
