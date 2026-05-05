#!/usr/bin/env bash
# Wire_Ghost v2.0 — SAST / SCA Security Scan
# Runs Semgrep (5 rulesets + custom), Bandit, manual greps, pip-audit, Dockerfile audit
set -euo pipefail

cd "$(dirname "$0")/.."
PROJ="$(pwd)"
OUT="$PROJ/reports/sast-results"
mkdir -p "$OUT"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; RST='\033[0m'
info()  { echo -e "${GRN}[+]${RST} $*"; }
warn()  { echo -e "${YLW}[!]${RST} $*"; }
fail()  { echo -e "${RED}[-]${RST} $*"; }

FINDINGS=0

# ── 1. Semgrep ──────────────────────────────────────────────────────
info "Running Semgrep rulesets..."

for ruleset in django python owasp-top-ten secrets xss; do
    info "  Ruleset: p/$ruleset"
    semgrep --config "p/$ruleset" \
        --json --quiet \
        web_portal/ src/ \
        > "$OUT/semgrep-${ruleset}.json" 2>/dev/null || true
    count=$(python3 -c "import json; d=json.load(open('$OUT/semgrep-${ruleset}.json')); print(len(d.get('results',[])))" 2>/dev/null || echo 0)
    if [ "$count" -gt 0 ]; then
        warn "  → $count findings"
        FINDINGS=$((FINDINGS + count))
    else
        info "  → clean"
    fi
done

# Custom DOM XSS regression rule
info "  Custom rule: DOM XSS assignment patterns"
cat > /tmp/dom-xss-rule.yml <<'YAML'
rules:
  - id: wireghost-dom-xss-assignment
    patterns:
      - pattern: $X.innerHTML = $Y
    languages: [javascript]
    message: "Direct DOM property assignment — use textContent or safe DOM API"
    severity: WARNING
    metadata:
      category: security
      subcategory: xss
YAML
semgrep --config /tmp/dom-xss-rule.yml \
    --json --quiet \
    web_portal/scanner/static/js/ \
    > "$OUT/semgrep-dom-xss.json" 2>/dev/null || true
count=$(python3 -c "import json; d=json.load(open('$OUT/semgrep-dom-xss.json')); print(len(d.get('results',[])))" 2>/dev/null || echo 0)
if [ "$count" -gt 0 ]; then
    warn "  → $count DOM XSS assignments found"
    FINDINGS=$((FINDINGS + count))
else
    info "  → clean"
fi
rm -f /tmp/dom-xss-rule.yml

# ── 2. Bandit ───────────────────────────────────────────────────────
info "Running Bandit..."
if command -v bandit &>/dev/null; then
    bandit -r web_portal/ src/ \
        -f json \
        --severity-level medium \
        --confidence-level medium \
        -o "$OUT/bandit-results.json" 2>/dev/null || true
    count=$(python3 -c "import json; d=json.load(open('$OUT/bandit-results.json')); print(len(d.get('results',[])))" 2>/dev/null || echo 0)
    if [ "$count" -gt 0 ]; then
        warn "Bandit: $count findings"
        FINDINGS=$((FINDINGS + count))
    else
        info "Bandit: clean"
    fi
else
    fail "Bandit not installed — skipping"
fi

# ── 3. Manual grep patterns ────────────────────────────────────────
info "Running manual grep patterns..."

echo "=== Raw SQL / cursor usage ===" > "$OUT/grep-raw-sql.txt"
grep -rn --include='*.py' '\.\(raw\|execute\|cursor\)(' web_portal/ src/ >> "$OUT/grep-raw-sql.txt" 2>/dev/null || true
sql_hits=$(wc -l < "$OUT/grep-raw-sql.txt" 2>/dev/null || echo 1)
sql_hits=$((sql_hits - 1))
[ "$sql_hits" -gt 0 ] && warn "  Raw SQL: $sql_hits hits" || info "  Raw SQL: clean"

echo "=== subprocess / os.system ===" > "$OUT/grep-shell-exec.txt"
grep -rn --include='*.py' 'subprocess\.\|os\.system\|os\.popen' src/ web_portal/ >> "$OUT/grep-shell-exec.txt" 2>/dev/null || true
shell_hits=$(wc -l < "$OUT/grep-shell-exec.txt" 2>/dev/null || echo 1)
shell_hits=$((shell_hits - 1))
[ "$shell_hits" -gt 0 ] && warn "  Shell exec: $shell_hits hits" || info "  Shell exec: clean"

echo "=== Unsafe deserialization ===" > "$OUT/grep-deserialize.txt"
grep -rn --include='*.py' -E 'yaml\.load\b[^_]' web_portal/ src/ >> "$OUT/grep-deserialize.txt" 2>/dev/null || true
deser_hits=$(wc -l < "$OUT/grep-deserialize.txt" 2>/dev/null || echo 1)
deser_hits=$((deser_hits - 1))
[ "$deser_hits" -gt 0 ] && warn "  Deserialization: $deser_hits hits" || info "  Deserialization: clean"

echo "=== Hardcoded secrets ===" > "$OUT/grep-secrets.txt"
grep -rn --include='*.py' -iE "(password|secret|token|api_key)\s*=\s*['\"][^'\"]{4,}" web_portal/ src/ \
    | grep -v 'test\|fixture\|mock\|example\|placeholder\|__pycache__' >> "$OUT/grep-secrets.txt" 2>/dev/null || true
secret_hits=$(wc -l < "$OUT/grep-secrets.txt" 2>/dev/null || echo 1)
secret_hits=$((secret_hits - 1))
[ "$secret_hits" -gt 0 ] && warn "  Hardcoded secrets: $secret_hits hits" || info "  Hardcoded secrets: clean"

echo "=== DOM property assignments in JS ===" > "$OUT/grep-dom-xss.txt"
grep -rn '\.innerHTML\s*=' web_portal/scanner/static/js/ >> "$OUT/grep-dom-xss.txt" 2>/dev/null || true
inner_hits=$(wc -l < "$OUT/grep-dom-xss.txt" 2>/dev/null || echo 1)
inner_hits=$((inner_hits - 1))
[ "$inner_hits" -gt 0 ] && warn "  DOM XSS patterns: $inner_hits hits" || info "  DOM XSS: clean"

echo "=== DEBUG flags ===" > "$OUT/grep-debug.txt"
grep -rn --include='*.py' 'DEBUG\s*=\s*True' web_portal/wireghost_web/ >> "$OUT/grep-debug.txt" 2>/dev/null || true
debug_hits=$(wc -l < "$OUT/grep-debug.txt" 2>/dev/null || echo 1)
debug_hits=$((debug_hits - 1))
[ "$debug_hits" -gt 0 ] && warn "  DEBUG=True: $debug_hits hits" || info "  DEBUG flags: clean"

# ── 4. pip-audit (SCA) ─────────────────────────────────────────────
info "Running pip-audit..."
if command -v pip-audit &>/dev/null; then
    pip-audit -r web_portal/requirements.txt \
        -f json \
        -o "$OUT/pip-audit-results.json" 2>/dev/null || true
    vuln_count=$(python3 -c "
import json
try:
    d=json.load(open('$OUT/pip-audit-results.json'))
    deps = d if isinstance(d,list) else d.get('dependencies',[])
    print(sum(len(x.get('vulns',[])) for x in deps))
except: print(0)
" 2>/dev/null || echo 0)
    if [ "$vuln_count" -gt 0 ]; then
        warn "pip-audit: $vuln_count vulnerable dependencies"
        FINDINGS=$((FINDINGS + vuln_count))
    else
        info "pip-audit: clean"
    fi
else
    fail "pip-audit not installed — skipping"
fi

# ── 5. Dockerfile audit ────────────────────────────────────────────
info "Auditing Dockerfiles..."
echo "=== Dockerfile Audit ===" > "$OUT/dockerfile-audit.txt"

for df in Dockerfile Dockerfile.worker docker/Dockerfile*; do
    [ -f "$df" ] || continue
    echo "--- $df ---" >> "$OUT/dockerfile-audit.txt"

    if grep -qE 'wget|curl.*-[oOL]' "$df" 2>/dev/null; then
        if ! grep -q 'sha256\|checksum\|gpg' "$df" 2>/dev/null; then
            echo "WARNING: Downloads without SHA256 verification" >> "$OUT/dockerfile-audit.txt"
            warn "  $df: downloads without SHA256 verification"
        fi
    fi

    if ! grep -q '^USER ' "$df" 2>/dev/null; then
        echo "WARNING: No USER directive (runs as root)" >> "$OUT/dockerfile-audit.txt"
        warn "  $df: no USER directive"
    fi

    if grep -qiE 'ARG.*(password|secret|token|key)' "$df" 2>/dev/null; then
        echo "WARNING: Secrets in build args" >> "$OUT/dockerfile-audit.txt"
        warn "  $df: secrets in build args"
    fi
done

# ── Summary ─────────────────────────────────────────────────────────
echo ""
info "═══════════════════════════════════════════"
info "SAST scan complete. Total findings: $FINDINGS"
info "Results in: $OUT/"
info "═══════════════════════════════════════════"
ls -la "$OUT/"
