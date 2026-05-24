#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HEAD_SHA="$(git -C "$ROOT_DIR" rev-parse HEAD)"

pick_free_port() {
    python3 - <<'PYPORT'
import socket
sock = socket.socket()
sock.bind(('127.0.0.1', 0))
print(sock.getsockname()[1])
sock.close()
PYPORT
}

QA_DIR="/tmp/wireghost-qa-$(date +%s)"
RESULTS_DIR=""
PORT="${WIREGHOST_QA_PORT:-$(pick_free_port)}"
HTTP_PORT="${WIREGHOST_QA_HTTP_PORT:-$(pick_free_port)}"
while [[ "$HTTP_PORT" == "$PORT" ]]; do
    HTTP_PORT="$(pick_free_port)"
done
KEEP=false
SOURCE_MODE="current-tree"
PLAYWRIGHT_BROWSERS_PATH=""
QA_PY=""

RED='[0;31m'
GREEN='[0;32m'
YELLOW='[1;33m'
CYAN='[0;36m'
NC='[0m'

TOTAL=0
PASSED=0
FAILED=0
SKIPPED=0

p() { printf "${GREEN}[PASS]${NC} %s
" "$1"; }
f() { printf "${RED}[FAIL]${NC} %s
" "$1"; }
s() { printf "${YELLOW}[SKIP]${NC} %s
" "$1"; }
h() { printf "
${CYAN}══════ %s ══════${NC}
" "$1"; }
pass() { ((TOTAL+=1)); ((PASSED+=1)); p "$1"; }
fail() { ((TOTAL+=1)); ((FAILED+=1)); f "$1"; }
skip() { ((TOTAL+=1)); ((SKIPPED+=1)); s "$1"; }

usage() {
    cat <<USAGE
Usage: bash scripts/run_qa.sh [--fresh-clone] [--keep]
  --fresh-clone   Validate a clean clone of the current HEAD instead of the current working tree.
  --keep          Leave the disposable QA workspace and Docker stack running.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fresh-clone)
            SOURCE_MODE="fresh-clone"
            ;;
        --keep)
            KEEP=true
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
    shift
done

cleanup() {
    if [[ -d "$QA_DIR" ]]; then
        if [[ "$KEEP" == false ]]; then
            echo -e "
${YELLOW}Cleaning up disposable QA stack...${NC}"
            docker compose -f "$QA_DIR/docker-compose.yml" down -v --remove-orphans >/dev/null 2>&1 || true
            rm -rf "$QA_DIR"
        else
            echo -e "
${YELLOW}--keep enabled: leaving QA workspace at $QA_DIR${NC}"
        fi
    fi
}
trap cleanup EXIT

run_logged() {
    local logfile="$1"
    shift
    set +e
    "$@" 2>&1 | tee "$logfile"
    local rc=${PIPESTATUS[0]}
    set -e
    return "$rc"
}

playwright_install_complete() {
    find "$PLAYWRIGHT_BROWSERS_PATH" -path '*/INSTALLATION_COMPLETE' -print -quit 2>/dev/null | grep -q .
}

render_env() {
    local secret mysql_root_pw mysql_pw redis_pw
    secret="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 64)"
    mysql_root_pw="$(openssl rand -base64 32 | tr -dc 'A-Za-z0-9' | head -c 32)"
    mysql_pw="$(openssl rand -base64 32 | tr -dc 'A-Za-z0-9' | head -c 32)"
    redis_pw="$(openssl rand -base64 32 | tr -dc 'A-Za-z0-9' | head -c 32)"

    cat > "$QA_DIR/.env" <<ENV
DJANGO_SECRET_KEY=${secret}
MYSQL_ROOT_PASSWORD=${mysql_root_pw}
MYSQL_DATABASE=wireghost
MYSQL_USER=wireghost
MYSQL_PASSWORD=${mysql_pw}
REDIS_PASSWORD=${redis_pw}
WIREGHOST_HOST=localhost
WIREGHOST_PORT=${PORT}
WIREGHOST_HTTP_PORT=${HTTP_PORT}
WIREGHOST_PROTO=https
SESSION_COOKIE_SECURE=true
CSRF_COOKIE_SECURE=true
WIREGHOST_LOG_DIR=./logs
WIREGHOST_LOG_LEVEL=INFO
TELEGRAM_BOT_TOKEN=disabled
CSRF_TRUSTED_ORIGINS=https://localhost:${PORT},https://127.0.0.1:${PORT}
ENV
    chmod 600 "$QA_DIR/.env"
}

prepare_current_tree() {
    mkdir -p "$QA_DIR"
    tar         --exclude='.git'         --exclude='node_modules'         --exclude='.qa-venv'         --exclude='.playwright-browsers'         --exclude='.pytest_cache'         --exclude='__pycache__'         --exclude='qa-results'         --exclude='logs'         --exclude='certs'         --exclude='nginx.conf'         --exclude='.env'         -cf - -C "$ROOT_DIR" . | tar -xf - -C "$QA_DIR"
    pass "Copied current working tree into disposable QA workspace"
}

prepare_fresh_clone() {
    git clone --no-local "$ROOT_DIR" "$QA_DIR" --quiet
    git -C "$QA_DIR" checkout --quiet "$HEAD_SHA"
    pass "Cloned clean workspace at HEAD ${HEAD_SHA:0:12}"
}

prepare_workspace() {
    h "PHASE 0 — Candidate Workspace"
    if [[ "$SOURCE_MODE" == "fresh-clone" ]]; then
        prepare_fresh_clone
    else
        prepare_current_tree
    fi
    RESULTS_DIR="$QA_DIR/qa-results"
    mkdir -p "$RESULTS_DIR"
    echo "Workspace: $QA_DIR"
    echo "Mode: $SOURCE_MODE"
    echo "HEAD: $HEAD_SHA"
}

bootstrap_dependencies() {
    h "PHASE 1 — Toolchain Bootstrap"
    cd "$QA_DIR"

    python3 -m venv --system-site-packages .qa-venv
    QA_PY="$QA_DIR/.qa-venv/bin/python"
    "$QA_PY" -m pip install --upgrade pip setuptools wheel >/dev/null
    if run_logged "$RESULTS_DIR/bootstrap-pip.log" "$QA_PY" -m pip install -e '.[dev]' -r web_portal/requirements.txt requests; then
        pass "Python dependencies installed"
    else
        if python3 - <<'PYENV' >/dev/null 2>&1
import django
import pytest
import requests
import rest_framework
PYENV
        then
            QA_PY=python3
            pass "Using host Python environment fallback"
        else
            fail "Python dependency install failed"
            return 1
        fi
    fi

    if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
        fail "Node.js and npm are required for QA"
        return 1
    fi

    if run_logged "$RESULTS_DIR/bootstrap-npm.log" env PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm ci; then
        pass "Node dependencies installed via npm ci"
    else
        fail "npm ci failed"
        return 1
    fi

    PLAYWRIGHT_BROWSERS_PATH="${WIREGHOST_PLAYWRIGHT_BROWSERS_PATH:-$QA_DIR/.playwright-browsers}"
    mkdir -p "$PLAYWRIGHT_BROWSERS_PATH"
    if playwright_install_complete; then
        pass "Playwright Chromium already installed"
    elif [[ $(id -u) -eq 0 ]]; then
        if run_logged "$RESULTS_DIR/bootstrap-playwright.log" env PLAYWRIGHT_BROWSERS_PATH="$PLAYWRIGHT_BROWSERS_PATH" timeout 20m npx playwright install --with-deps chromium; then
            pass "Playwright Chromium installed with system dependencies"
        elif playwright_install_complete; then
            pass "Playwright Chromium installed despite installer exit issue"
        else
            fail "Playwright Chromium install failed"
            return 1
        fi
    else
        if run_logged "$RESULTS_DIR/bootstrap-playwright.log" env PLAYWRIGHT_BROWSERS_PATH="$PLAYWRIGHT_BROWSERS_PATH" timeout 20m npx playwright install chromium; then
            pass "Playwright Chromium installed"
        elif playwright_install_complete; then
            pass "Playwright Chromium installed despite installer exit issue"
        else
            fail "Playwright Chromium install failed"
            return 1
        fi
    fi
}

run_fast_gate() {
    h "PHASE 2 — Fast Non-Live Gate"
    cd "$QA_DIR"

    if run_logged "$RESULTS_DIR/phase-2-pytest.log" env WIREGHOST_AUTO_INSTALL_TOOLS=0 "$QA_PY" -m pytest tests -q; then
        pass "pytest suite passed"
    else
        fail "pytest suite failed"
    fi

    if run_logged "$RESULTS_DIR/phase-2-django.log" bash -lc "cd '$QA_DIR/web_portal' && WIREGHOST_AUTO_INSTALL_TOOLS=0 DJANGO_SECRET_KEY=wireghost-qa-test-secret '$QA_PY' manage.py test scanner --verbosity=1"; then
        pass "Django scanner suite passed"
    else
        fail "Django scanner suite failed"
    fi

    if run_logged "$RESULTS_DIR/phase-2-frontend.log" node tests/test_frontend_js.js; then
        pass "Frontend JS suite passed"
    else
        fail "Frontend JS suite failed"
    fi

    if run_logged "$RESULTS_DIR/phase-2-topology.log" node tests/test_topology_js.js; then
        pass "Topology JS suite passed"
    else
        fail "Topology JS suite failed"
    fi

    if run_logged "$RESULTS_DIR/phase-2-installers.log" bash tests/test_installers.sh; then
        pass "Installer shell tests passed"
    else
        fail "Installer shell tests failed"
    fi
}

build_stack() {
    h "PHASE 3 — Disposable Stack Build"
    cd "$QA_DIR"

    render_env
    pass "Rendered QA .env"

    mkdir -p certs logs/api logs/nginx
    if openssl req -x509 -newkey rsa:2048 -keyout certs/key.pem -out certs/cert.pem -days 1 -nodes -subj '/CN=localhost' >/dev/null 2>&1; then
        pass "Generated self-signed TLS certificate"
    else
        fail "TLS certificate generation failed"
        return 1
    fi

    if sed -e "s/{{WIREGHOST_HOST}}/localhost/g" -e "s/{{WIREGHOST_PORT}}/${PORT}/g" config/nginx.conf.tpl > nginx.conf; then
        pass "Rendered nginx.conf"
    else
        fail "nginx.conf rendering failed"
        return 1
    fi

    if run_logged "$RESULTS_DIR/phase-3-build.log" docker compose build; then
        pass "Docker images built"
    else
        fail "Docker build failed"
        return 1
    fi

    if run_logged "$RESULTS_DIR/phase-3-up.log" docker compose up -d db redis docker-proxy; then
        pass "Infrastructure services started"
    else
        fail "Infrastructure startup failed"
        return 1
    fi

    local healthy=false
    # Fresh MySQL volumes can take several minutes to initialize before the
    # health check flips green; keep the live gate tolerant of clean boot time.
    for _ in $(seq 1 300); do
        local db_h redis_h
        db_h="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}unknown{{end}}' "$(docker compose ps -q db)" 2>/dev/null || true)"
        redis_h="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}unknown{{end}}' "$(docker compose ps -q redis)" 2>/dev/null || true)"
        if [[ "$db_h" == "healthy" && "$redis_h" == "healthy" ]]; then
            healthy=true
            break
        fi
        sleep 2
    done
    if [[ "$healthy" == true ]]; then
        pass "DB and Redis reached healthy state"
    else
        fail "DB and Redis health check timed out"
        return 1
    fi

    if run_logged "$RESULTS_DIR/phase-3-up-app.log" docker compose up -d api worker beat portal; then
        pass "Application services started"
    else
        fail "Application service startup failed"
        return 1
    fi

    local api_ready=false
    # The API container performs migrations before gunicorn binds 8000, so a
    # clean disposable stack needs a wider readiness window than warm starts.
    for _ in $(seq 1 600); do
        local code
        code="$(curl -ks -o /dev/null -w '%{http_code}' "https://localhost:${PORT}/api/auth/csrf/" || true)"
        if [[ "$code" == "200" ]]; then
            api_ready=true
            break
        fi
        sleep 2
    done
    if [[ "$api_ready" == true ]]; then
        pass "Django API responded on https://localhost:${PORT}"
    else
        fail "Django API did not become ready"
        return 1
    fi
}

verify_stack() {
    h "PHASE 4 — Live Stack Verification"
    cd "$QA_DIR"

    local running
    running="$(docker compose ps --format '{{.Service}}:{{.State}}' 2>/dev/null | grep -c 'running' || true)"
    if [[ "$running" -ge 6 ]]; then
        pass "Expected services are running ($running detected)"
    else
        fail "Expected at least 6 running services, found $running"
    fi

    local pending
    pending="$(docker compose exec -T api python manage.py showmigrations --plan 2>/dev/null | grep -c '\[ \]' || true)"
    if [[ "$pending" -eq 0 ]]; then
        pass "All migrations applied"
    else
        fail "$pending migrations remain unapplied"
    fi

    local me_code
    me_code="$(curl -ks -o /dev/null -w '%{http_code}' "https://localhost:${PORT}/api/auth/me/" || true)"
    if [[ "$me_code" == "401" || "$me_code" == "403" ]]; then
        pass "Unauthenticated /api/auth/me/ is blocked"
    else
        fail "Unexpected unauthenticated /api/auth/me/ status: $me_code"
    fi

    local root_code
    root_code="$(curl -ks -o /dev/null -w '%{http_code}' -L --max-redirs 0 "https://localhost:${PORT}/" || true)"
    if [[ "$root_code" == "301" || "$root_code" == "302" ]]; then
        pass "Portal root redirects to login"
    else
        fail "Portal root returned $root_code instead of redirect"
    fi

    if run_logged "$RESULTS_DIR/phase-4-worker-tools.log" docker compose exec -T worker sh -lc 'set -e; for bin in nmap fping masscan nuclei httpx naabu gowitness searchsploit nikto nxc fingerprintx; do command -v "$bin" >/dev/null || { echo "missing $bin"; exit 1; }; done; nmap --version | head -1; nuclei -version 2>&1 | head -1; httpx -version 2>&1 | head -1; naabu -version 2>&1 | head -1; nikto -Version 2>&1 | head -1; nxc --version 2>&1 | head -1; fingerprintx -h 2>&1 | head -1'; then
        pass "Worker scanner tool probe passed"
    else
        fail "Worker scanner tool probe failed"
    fi
}

run_live_gate() {
    h "PHASE 5 — Live API Gate"
    cd "$QA_DIR"

    if run_logged "$RESULTS_DIR/phase-5-integration.log" "$QA_PY" scripts/qa_integration.py --base "https://localhost:${PORT}" --results "$RESULTS_DIR/phase-5-integration.json"; then
        pass "API integration suite passed"
    else
        fail "API integration suite failed"
    fi
}

run_browser_gate() {
    h "PHASE 6 — Browser Gate"
    cd "$QA_DIR"
    local browser_base="https://127.0.0.1:${PORT}"

    if run_logged "$RESULTS_DIR/phase-6-flush-auth-throttles.log" docker compose exec -T api python manage.py shell -c "c=__import__('django.core.cache',fromlist=['cache']).cache; r=c._cache.get_client(); [r.delete(k) for k in r.keys('*throttle*')+r.keys('*login*')]"; then
        pass "Cleared auth throttle state before browser QA"
    else
        fail "Could not clear auth throttle state before browser QA"
    fi

    if run_logged "$RESULTS_DIR/phase-6-js-regression.log" env WG_BASE="$browser_base" WG_FAIL_ON_SKIP=1 PLAYWRIGHT_BROWSERS_PATH="$PLAYWRIGHT_BROWSERS_PATH" npm run test:js-regression; then
        pass "Browser JS regression suite passed"
    else
        fail "Browser JS regression suite failed"
    fi

    if run_logged "$RESULTS_DIR/phase-6-xss-regression.log" env WG_BASE="$browser_base" WG_FAIL_ON_SKIP=1 PLAYWRIGHT_BROWSERS_PATH="$PLAYWRIGHT_BROWSERS_PATH" npm run test:xss-regression; then
        pass "Browser XSS regression suite passed"
    else
        fail "Browser XSS regression suite failed"
    fi

    if run_logged "$RESULTS_DIR/phase-6-portal-e2e.log" env WG_BASE="$browser_base" WG_FAIL_ON_SKIP=1 PLAYWRIGHT_BROWSERS_PATH="$PLAYWRIGHT_BROWSERS_PATH" npm run test:portal-e2e; then
        pass "Portal E2E suite passed"
    else
        fail "Portal E2E suite failed"
    fi
}

run_security_gate() {
    h "PHASE 7 — Security Gate"
    cd "$QA_DIR"

    if run_logged "$RESULTS_DIR/phase-7-security.log" "$QA_PY" scripts/qa_security.py --base "https://localhost:${PORT}" --results "$RESULTS_DIR/phase-7-security.json"; then
        pass "Security regression suite passed"
    else
        fail "Security regression suite failed"
    fi
}

summarize() {
    h "SUMMARY"
    printf "
${CYAN}Total: %d | Passed: %d | Failed: %d | Skipped: %d${NC}
" "$TOTAL" "$PASSED" "$FAILED" "$SKIPPED"
    echo "Logs: $RESULTS_DIR"
    if [[ "$FAILED" -eq 0 ]]; then
        printf "
${GREEN}ALL QA CHECKS PASSED${NC}
"
        return 0
    fi
    printf "
${RED}%d QA CHECK(S) FAILED${NC}
" "$FAILED"
    return 1
}

prepare_workspace
bootstrap_dependencies || { summarize; exit 1; }
run_fast_gate
build_stack || { summarize; exit 1; }
verify_stack
run_live_gate
run_browser_gate
run_security_gate
summarize
