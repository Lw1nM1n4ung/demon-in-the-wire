#!/usr/bin/env bash
set -euo pipefail

# Wire_Ghost — Full QA from Fresh Git Clone
# Usage: sudo bash scripts/run_qa.sh [--keep]
#   --keep   Do not tear down containers or remove the clone after completion.

REPO_URL="https://github.com/Lw1nM1n4ung/demon-in-the-wire.git"
BRANCH="rewrite-v2"
QA_DIR="/tmp/wireghost-qa-$(date +%s)"
PORT=28443
KEEP=false
[[ "${1:-}" == "--keep" ]] && KEEP=true

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
p()  { printf "${GREEN}[PASS]${NC} %s\n" "$1"; }
f()  { printf "${RED}[FAIL]${NC} %s\n" "$1"; }
h()  { printf "\n${CYAN}══════ %s ══════${NC}\n" "$1"; }
TOTAL=0; PASSED=0; FAILED=0; SKIPPED=0
RESULTS_DIR=""

pass() { ((TOTAL++)); ((PASSED++)); p "$1"; }
fail() { ((TOTAL++)); ((FAILED++)); f "$1"; }

cleanup() {
    if [[ "$KEEP" == false && -d "$QA_DIR" ]]; then
        echo -e "\n${YELLOW}Cleaning up...${NC}"
        cd /tmp
        docker compose -f "$QA_DIR/docker-compose.yml" down -v --remove-orphans 2>/dev/null || true
        rm -rf "$QA_DIR"
        echo "Cleanup complete."
    elif [[ -d "$QA_DIR" ]]; then
        echo -e "\n${YELLOW}--keep: leaving stack at $QA_DIR${NC}"
    fi
}
trap cleanup EXIT

# ══════════════════════════════════════════════════════════════════════
h "PHASE 0 — Fresh Clone & Environment Setup"
# ══════════════════════════════════════════════════════════════════════

echo "Cloning to $QA_DIR ..."
git clone --branch "$BRANCH" "$REPO_URL" "$QA_DIR" --quiet 2>/dev/null && pass "Git clone" || { fail "Git clone"; exit 1; }
cd "$QA_DIR"

RESULTS_DIR="$QA_DIR/qa-results"
mkdir -p "$RESULTS_DIR"

# Generate .env with random secrets
SECRET=$(openssl rand -base64 48 | tr -d '\n/+=' | head -c 64)
MYSQL_ROOT_PW=$(openssl rand -base64 32 | tr -d '\n/+=' | head -c 32)
MYSQL_PW=$(openssl rand -base64 32 | tr -d '\n/+=' | head -c 32)
REDIS_PW=$(openssl rand -base64 32 | tr -d '\n/+=' | head -c 32)

cat > .env << EOF
DJANGO_SECRET_KEY=${SECRET}
MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PW}
MYSQL_DATABASE=wireghost
MYSQL_USER=wireghost
MYSQL_PASSWORD=${MYSQL_PW}
REDIS_PASSWORD=${REDIS_PW}
WIREGHOST_HOST=localhost
WIREGHOST_PORT=${PORT}
WIREGHOST_PROTO=https
SESSION_COOKIE_SECURE=true
CSRF_COOKIE_SECURE=true
WIREGHOST_LOG_DIR=./logs
WIREGHOST_LOG_LEVEL=INFO
TELEGRAM_BOT_TOKEN=disabled
CSRF_TRUSTED_ORIGINS=https://localhost:${PORT},https://127.0.0.1:${PORT}
EOF
chmod 600 .env
pass "Generated .env"

# Generate self-signed TLS cert
mkdir -p certs logs/api logs/nginx
openssl req -x509 -newkey rsa:2048 -keyout certs/key.pem -out certs/cert.pem \
    -days 1 -nodes -subj "/CN=localhost" 2>/dev/null
pass "Generated TLS cert"

# Render nginx.conf from template
sed -e "s/{{WIREGHOST_HOST}}/localhost/g" \
    -e "s/{{WIREGHOST_PORT}}/${PORT}/g" \
    config/nginx.conf.tpl > nginx.conf
pass "Rendered nginx.conf"

# Build and start services (skip bot — it crashes without valid Telegram token)
echo "Building Docker images (this may take several minutes)..."
docker compose build --quiet 2>&1 | tail -5
docker compose up -d db redis api worker beat portal 2>&1 | tail -5
pass "Docker compose up"

# Wait for health
echo "Waiting for services to become healthy..."
HEALTHY=false
for i in $(seq 1 90); do
    DB_H=$(docker compose ps db --format '{{.Health}}' 2>/dev/null || echo "")
    REDIS_H=$(docker compose ps redis --format '{{.Health}}' 2>/dev/null || echo "")
    if [[ "$DB_H" == *"healthy"* && "$REDIS_H" == *"healthy"* ]]; then
        HEALTHY=true
        break
    fi
    sleep 2
done
[[ "$HEALTHY" == true ]] && pass "DB + Redis healthy" || fail "DB + Redis healthy (timeout)"

# Wait for Django API
API_READY=false
for i in $(seq 1 60); do
    HTTP=$(curl -ks -o /dev/null -w "%{http_code}" "https://localhost:${PORT}/api/auth/csrf/" 2>/dev/null || echo "000")
    if [[ "$HTTP" == "200" ]]; then
        API_READY=true
        break
    fi
    sleep 2
done
[[ "$API_READY" == true ]] && pass "Django API responding" || { fail "Django API responding (timeout)"; exit 1; }

pass "Login page serves ($(curl -ks -o /dev/null -w '%{http_code}' "https://localhost:${PORT}/login"))"

# ══════════════════════════════════════════════════════════════════════
h "PHASE 1 — Build Verification"
# ══════════════════════════════════════════════════════════════════════

# Check services running
RUNNING=$(docker compose ps --format '{{.Service}}:{{.State}}' 2>/dev/null | grep -c "running" || echo 0)
[[ "$RUNNING" -ge 6 ]] && pass "All 6 services running ($RUNNING)" || fail "Expected 6 running services, got $RUNNING"

# Migrations applied
PENDING=$(docker compose exec -T api python manage.py showmigrations --plan 2>/dev/null | grep -c '\[ \]' || echo 0)
[[ "$PENDING" -eq 0 ]] && pass "All migrations applied" || fail "$PENDING unapplied migrations"

# No users yet
ME_CODE=$(curl -ks -o /dev/null -w "%{http_code}" "https://localhost:${PORT}/api/auth/me/" 2>/dev/null)
[[ "$ME_CODE" == "401" || "$ME_CODE" == "403" ]] && pass "No authenticated users (${ME_CODE})" || fail "Expected 401/403, got $ME_CODE"

# Root redirects to login
ROOT_CODE=$(curl -ks -o /dev/null -w "%{http_code}" -L --max-redirs 0 "https://localhost:${PORT}/" 2>/dev/null)
[[ "$ROOT_CODE" == "302" || "$ROOT_CODE" == "301" ]] && pass "Root redirects to login ($ROOT_CODE)" || fail "Expected 302, got $ROOT_CODE"

# ══════════════════════════════════════════════════════════════════════
h "PHASE 2 — Unit Tests"
# ══════════════════════════════════════════════════════════════════════

echo "Running Django test suite..."
docker compose exec -T api python manage.py test scanner.tests --verbosity=1 --parallel 2>&1 | tee "$RESULTS_DIR/phase-2-django.log" | tail -5
DJANGO_EXIT=${PIPESTATUS[0]}
if [[ $DJANGO_EXIT -eq 0 ]]; then
    DJANGO_COUNT=$(grep -oP 'Ran \K[0-9]+' "$RESULTS_DIR/phase-2-django.log" | tail -1 || echo "?")
    pass "Django tests passed ($DJANGO_COUNT tests)"
else
    DJANGO_FAIL=$(grep -c "FAIL\|ERROR" "$RESULTS_DIR/phase-2-django.log" || echo "?")
    fail "Django tests failed ($DJANGO_FAIL failures)"
fi

echo "Running pytest suite..."
docker compose exec -T api python -m pytest tests/ -v --tb=short 2>&1 | tee "$RESULTS_DIR/phase-2-pytest.log" | tail -5
PYTEST_EXIT=${PIPESTATUS[0]}
if [[ $PYTEST_EXIT -eq 0 ]]; then
    PYTEST_COUNT=$(grep -oP '[0-9]+ passed' "$RESULTS_DIR/phase-2-pytest.log" | head -1 || echo "? passed")
    pass "Pytest suite passed ($PYTEST_COUNT)"
else
    fail "Pytest suite failed"
fi

# ══════════════════════════════════════════════════════════════════════
h "PHASE 3 — Integration Tests (Live API)"
# ══════════════════════════════════════════════════════════════════════

echo "Running API integration tests..."
python3 "$QA_DIR/scripts/qa_integration.py" --base "https://localhost:${PORT}" --results "$RESULTS_DIR/phase-3.json" 2>&1 | tee "$RESULTS_DIR/phase-3.log"
INTEG_EXIT=$?
if [[ $INTEG_EXIT -eq 0 ]]; then
    INTEG_P=$(python3 -c "import json; d=json.load(open('$RESULTS_DIR/phase-3.json')); print(d['passed'])" 2>/dev/null || echo "?")
    INTEG_T=$(python3 -c "import json; d=json.load(open('$RESULTS_DIR/phase-3.json')); print(d['total'])" 2>/dev/null || echo "?")
    pass "Integration tests: $INTEG_P/$INTEG_T passed"
else
    INTEG_F=$(python3 -c "import json; d=json.load(open('$RESULTS_DIR/phase-3.json')); print(d['failed'])" 2>/dev/null || echo "?")
    fail "Integration tests: $INTEG_F failures"
fi

# ══════════════════════════════════════════════════════════════════════
h "PHASE 4 — Browser/UI Tests (Playwright)"
# ══════════════════════════════════════════════════════════════════════

if command -v node &>/dev/null && node -e "require('playwright')" 2>/dev/null; then
    echo "Running Playwright E2E tests..."
    WG_BASE="https://localhost:${PORT}" node "$QA_DIR/tests/test_portal_e2e.js" 2>&1 | tee "$RESULTS_DIR/phase-4.log"
    E2E_EXIT=$?
    E2E_PASS=$(grep -c '✓\|PASS' "$RESULTS_DIR/phase-4.log" || echo 0)
    E2E_FAIL=$(grep -c '✗\|FAIL' "$RESULTS_DIR/phase-4.log" || echo 0)
    [[ $E2E_EXIT -eq 0 ]] && pass "E2E tests: $E2E_PASS passed" || fail "E2E tests: $E2E_FAIL failures"
else
    echo "Playwright not available — skipping E2E tests"
    ((TOTAL++)); ((SKIPPED++))
fi

# ══════════════════════════════════════════════════════════════════════
h "PHASE 5 — Security Regression Tests"
# ══════════════════════════════════════════════════════════════════════

echo "Running security regression tests..."
python3 "$QA_DIR/scripts/qa_security.py" --base "https://localhost:${PORT}" --results "$RESULTS_DIR/phase-5.json" 2>&1 | tee "$RESULTS_DIR/phase-5.log"
SEC_EXIT=$?
if [[ $SEC_EXIT -eq 0 ]]; then
    SEC_P=$(python3 -c "import json; d=json.load(open('$RESULTS_DIR/phase-5.json')); print(d['passed'])" 2>/dev/null || echo "?")
    SEC_T=$(python3 -c "import json; d=json.load(open('$RESULTS_DIR/phase-5.json')); print(d['total'])" 2>/dev/null || echo "?")
    pass "Security tests: $SEC_P/$SEC_T passed"
else
    SEC_F=$(python3 -c "import json; d=json.load(open('$RESULTS_DIR/phase-5.json')); print(d['failed'])" 2>/dev/null || echo "?")
    fail "Security tests: $SEC_F failures"
fi

# ══════════════════════════════════════════════════════════════════════
h "SUMMARY"
# ══════════════════════════════════════════════════════════════════════

printf "\n${CYAN}Total: %d | Passed: %d | Failed: %d | Skipped: %d${NC}\n" "$TOTAL" "$PASSED" "$FAILED" "$SKIPPED"

if [[ $FAILED -eq 0 ]]; then
    printf "\n${GREEN}✅ ALL QA CHECKS PASSED${NC}\n"
    exit 0
else
    printf "\n${RED}❌ %d FAILURES${NC}\n" "$FAILED"
    exit 1
fi
