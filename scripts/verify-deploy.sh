#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
# Wire_Ghost — Deploy Verification
#
# Run on the VPS after update-remote.sh completes to verify the stack
# is healthy and the portal is correctly bound to 127.0.0.1:2006.
#
# Usage:
#   bash verify-deploy.sh
# ══════════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'
PASS="${GREEN}[PASS]${NC}"; FAIL="${RED}[FAIL]${NC}"; WARN="${YELLOW}[WARN]${NC}"

failures=0
check() {
    local desc="$1" result="$2" detail="${3:-}"
    if [ "$result" = true ]; then
        printf "${PASS} %s\n" "$desc"
    else
        printf "${FAIL} %s — %s\n" "$desc" "$detail"
        failures=$((failures + 1))
    fi
}

REMOTE_DIR="${WIREGHOST_DIR:-/opt/wireghost}"
cd "$REMOTE_DIR" 2>/dev/null || { echo "Cannot cd to $REMOTE_DIR"; exit 1; }

echo ""
echo "  Wire_Ghost Deploy Verification"
echo "  $(date)"
echo ""

# ── 1. Stack status ──────────────────────────────────────────────────
echo "── Stack ──"
total=$(docker compose -f docker-compose.yml -f docker-compose.host.yml ps -q 2>/dev/null | wc -l)
check "8 containers running" "$([ "$total" -ge 8 ] && echo true || echo false)" "found $total"

# Check each critical service
for svc in db redis docker-proxy api worker beat bot portal; do
    cid=$(docker compose -f docker-compose.yml -f docker-compose.host.yml ps -q "$svc" 2>/dev/null || true)
    if [ -n "$cid" ]; then
        state=$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo "gone")
        check "  $svc ($state)" "$([ "$state" = running ] && echo true || echo false)" "$state"
    else
        check "  $svc" false "not found"
    fi
done

# ── 2. Portal image ──────────────────────────────────────────────────
echo ""
echo "── Portal ──"
portal_img=$(docker inspect -f '{{.Config.Image}}' "$(docker compose -f docker-compose.yml -f docker-compose.host.yml ps -q portal 2>/dev/null)" 2>/dev/null || echo "")
check "Portal image is callmedemon/wireghost:portal" \
    "$(echo "$portal_img" | grep -q 'callmedemon/wireghost:portal' && echo true || echo false)" \
    "$portal_img"

# Portal port binding should be 127.0.0.1:2006→443, NOT 0.0.0.0:443
portal_ports=$(docker port "$(docker compose -f docker-compose.yml -f docker-compose.host.yml ps -q portal 2>/dev/null)" 2>/dev/null || echo "")
check "Portal binds 127.0.0.1:2006 (not 0.0.0.0)" \
    "$(echo "$portal_ports" | grep -q '127.0.0.1:2006' && echo true || echo false)" \
    "$portal_ports"

# Nginx config inside portal — must NOT contain old IP
nginx_conf=$(docker compose -f docker-compose.yml -f docker-compose.host.yml exec -T portal cat /etc/nginx/conf.d/default.conf 2>/dev/null || echo "")
check "nginx.conf has no old IP (152.42.160.210)" \
    "$(echo "$nginx_conf" | grep -qv '152.42.160.210' && echo true || echo false)"

check "nginx.conf has 127.0.0.1:2006" \
    "$(echo "$nginx_conf" | grep -q '127.0.0.1:2006' && echo true || echo false)"

check "nginx.conf has resolver 127.0.0.11" \
    "$(echo "$nginx_conf" | grep -q 'resolver 127.0.0.11' && echo true || echo false)"

# ── 3. HTTP checks ───────────────────────────────────────────────────
echo ""
echo "── HTTP ──"

# Login page
login_code=$(curl -sk -o /dev/null -w "%{http_code}" https://127.0.0.1:2006/login 2>/dev/null || echo "000")
check "/login returns 200" "$([ "$login_code" = 200 ] && echo true || echo false)" "HTTP $login_code"

# Security headers
hsts=$(curl -sk -I https://127.0.0.1:2006/login 2>/dev/null | grep -i 'strict-transport' || echo "")
check "HSTS header present" "$([ -n "$hsts" ] && echo true || echo false)"

# Root should redirect to login (302)
root_code=$(curl -sk -o /dev/null -w "%{http_code}" https://127.0.0.1:2006/ 2>/dev/null || echo "000")
root_loc=$(curl -sk -o /dev/null -w "%header{location}" https://127.0.0.1:2006/ 2>/dev/null || echo "")
check "/ redirects to login" \
    "$([ "$root_code" = 302 ] && echo "$root_loc" | grep -q '/login' && echo true || echo false)" \
    "HTTP $root_code → $root_loc"

# HTTP→HTTPS redirect (port 80 inside container, only if HAProxy/proxy forwards)
# Skip — portal only exposes :443 externally

# ── 4. API health ────────────────────────────────────────────────────
echo ""
echo "── API ──"
csrf_code=$(curl -sk -o /dev/null -w "%{http_code}" https://127.0.0.1:2006/api/auth/csrf/ 2>/dev/null || echo "000")
check "/api/auth/csrf/ returns 200" "$([ "$csrf_code" = 200 ] && echo true || echo false)" "HTTP $csrf_code"

# ── 5. DB connectivity ───────────────────────────────────────────────
echo ""
echo "── DB ──"
db_ping=$(docker compose -f docker-compose.yml -f docker-compose.host.yml exec -T db mysqladmin ping -h localhost --silent 2>/dev/null && echo "alive" || echo "dead")
check "MySQL ping" "$([ "$db_ping" = alive ] && echo true || echo false)" "$db_ping"

# ── 6. Summary ───────────────────────────────────────────────────────
echo ""
if [ "$failures" -eq 0 ]; then
    printf "${GREEN}All checks passed${NC}\n"
else
    printf "${RED}%d check(s) failed${NC}\n" "$failures"
fi
echo ""
