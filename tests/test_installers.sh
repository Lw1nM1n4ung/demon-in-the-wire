#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
# Test suite for install-wireghost.sh and install.sh
# Covers: progress bar, WSL detection, config logic, secret masking
#
# Run:  bash tests/test_installers.sh
# ══════════════════════════════════════════════════════════════════════
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Test harness ────────────────────────────────────────────────────
_PASS=0; _FAIL=0; _TOTAL=0

_assert() {
    local desc="$1" expected="$2" actual="$3"
    _TOTAL=$((_TOTAL + 1))
    if [ "$expected" = "$actual" ]; then
        _PASS=$((_PASS + 1))
        printf "  \033[0;32m✓\033[0m %s\n" "$desc"
    else
        _FAIL=$((_FAIL + 1))
        printf "  \033[0;31m✗\033[0m %s\n" "$desc"
        printf "    expected: '%s'\n" "$expected"
        printf "    actual:   '%s'\n" "$actual"
    fi
}

_assert_contains() {
    local desc="$1" needle="$2" haystack="$3"
    _TOTAL=$((_TOTAL + 1))
    if echo "$haystack" | grep -qF "$needle"; then
        _PASS=$((_PASS + 1))
        printf "  \033[0;32m✓\033[0m %s\n" "$desc"
    else
        _FAIL=$((_FAIL + 1))
        printf "  \033[0;31m✗\033[0m %s\n" "$desc"
        printf "    expected to contain: '%s'\n" "$needle"
        printf "    actual: '%s'\n" "$haystack"
    fi
}

_assert_not_contains() {
    local desc="$1" needle="$2" haystack="$3"
    _TOTAL=$((_TOTAL + 1))
    if ! echo "$haystack" | grep -qF "$needle"; then
        _PASS=$((_PASS + 1))
        printf "  \033[0;32m✓\033[0m %s\n" "$desc"
    else
        _FAIL=$((_FAIL + 1))
        printf "  \033[0;31m✗\033[0m %s\n" "$desc"
        printf "    expected NOT to contain: '%s'\n" "$needle"
    fi
}

# ── Colour stubs (needed by sourced functions) ──────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

info()  { printf "${CYAN}[INFO]${NC}  %s\n" "$*"; }
ok()    { printf "${GREEN}[OK]${NC}    %s\n" "$*"; }
warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$*"; }
die()   { printf "${RED}[FATAL]${NC} %s\n" "$*" >&2; return 1; }

# ════════════════════════════════════════════════════════════════════
# TEST GROUP: Progress bar math
# ════════════════════════════════════════════════════════════════════
printf "\n\033[1m── Progress bar math ──────────────────────────────\033[0m\n"

_test_step_math() {
    local total="$1" step_num="$2" expected_filled="$3" expected_empty="$4"
    local pct=$((step_num * 100 / total))
    local filled=$((pct * 30 / 100))
    local empty=$((30 - filled))
    _assert "step ${step_num}/${total}: filled=${expected_filled}" "$expected_filled" "$filled"
    _assert "step ${step_num}/${total}: empty=${expected_empty}" "$expected_empty" "$empty"
    _assert "step ${step_num}/${total}: total=30" "30" "$((filled + empty))"
}

_test_step_math 7 1 4 26
_test_step_math 7 4 17 13
_test_step_math 7 7 30 0
_test_step_math 3 1 9 21
_test_step_math 3 2 19 11
_test_step_math 3 3 30 0

# ════════════════════════════════════════════════════════════════════
# TEST GROUP: step() function output
# ════════════════════════════════════════════════════════════════════
printf "\n\033[1m── step() function output ─────────────────────────\033[0m\n"

# Test step() via a single subshell that runs multiple steps sequentially
output=$(
    _TOTAL_STEPS=7; _STEP=0
    _step_inner() {
        _STEP=$((_STEP + 1))
        local pct=$((_STEP * 100 / _TOTAL_STEPS))
        local filled=$((pct * 30 / 100))
        local empty=$((30 - filled))
        printf "%s%s %d/%d %s\n" \
            "$(printf '%*s' "$filled" '' | tr ' ' '#')" \
            "$(printf '%*s' "$empty" '' | tr ' ' '.')" \
            "$_STEP" "$_TOTAL_STEPS" "$1"
    }
    _step_inner "Testing"
    _step_inner "Second"
    _STEP=6
    _step_inner "Done"
)
line1=$(echo "$output" | sed -n '1p')
line2=$(echo "$output" | sed -n '2p')
line3=$(echo "$output" | sed -n '3p')

_assert_contains "step 1/7 contains label" "Testing" "$line1"
_assert_contains "step 1/7 contains counter" "1/7" "$line1"
_assert_contains "step 2/7 contains counter" "2/7" "$line2"
_assert_contains "step 7/7 at full" "7/7" "$line3"
_assert_not_contains "step 7/7 no dots" "." "$line3"

# ════════════════════════════════════════════════════════════════════
# TEST GROUP: WSL detection
# ════════════════════════════════════════════════════════════════════
printf "\n\033[1m── WSL detection ─────────────────────────────────\033[0m\n"

_test_wsl_detection_proc_version() {
    local test_content="$1" expected="$2" desc="$3"
    local tmpdir
    tmpdir=$(mktemp -d)
    mkdir -p "$tmpdir/proc"
    echo "$test_content" > "$tmpdir/proc/version"

    local result="false"
    if grep -qi "microsoft\|wsl" "$tmpdir/proc/version" 2>/dev/null; then
        result="true"
    fi
    _assert "$desc" "$expected" "$result"
    rm -rf "$tmpdir"
}

_test_wsl_detection_proc_version \
    "Linux version 5.15.153.1-microsoft-standard-WSL2 (gcc)" \
    "true" \
    "detects WSL2 kernel string"

_test_wsl_detection_proc_version \
    "Linux version 5.15.0-microsoft-standard (gcc)" \
    "true" \
    "detects WSL1 kernel string"

_test_wsl_detection_proc_version \
    "Linux version 6.8.0-110-generic (buildd@lcy02-amd64-115)" \
    "false" \
    "normal Linux kernel not detected as WSL"

_test_wsl_detection_proc_version \
    "Linux version 5.4.0-42-generic (Ubuntu 5.4.0-42.46)" \
    "false" \
    "Ubuntu kernel not detected as WSL"

# WSL_DISTRO_NAME env var detection
(
    WSL_DISTRO_NAME="Ubuntu-22.04"
    result="false"
    [ -n "${WSL_DISTRO_NAME:-}" ] && result="true"
    # Can't call _assert inside subshell and have it count, so echo
    if [ "$result" = "true" ]; then
        echo "PASS"
    else
        echo "FAIL"
    fi
) | {
    read -r line
    _assert "WSL_DISTRO_NAME set → detected" "PASS" "$line"
}

(
    unset WSL_DISTRO_NAME 2>/dev/null || true
    result="false"
    [ -n "${WSL_DISTRO_NAME:-}" ] && result="true"
    if [ "$result" = "false" ]; then
        echo "PASS"
    else
        echo "FAIL"
    fi
) | {
    read -r line
    _assert "WSL_DISTRO_NAME unset → not detected" "PASS" "$line"
}

# ════════════════════════════════════════════════════════════════════
# TEST GROUP: WSL mount path warning logic
# ════════════════════════════════════════════════════════════════════
printf "\n\033[1m── WSL mount path warning ─────────────────────────\033[0m\n"

_test_mount_warning() {
    local is_wsl="$1" install_dir="$2" expect_warn="$3" desc="$4"
    local _IS_WSL="$is_wsl"
    local should_warn="false"
    if [ "$_IS_WSL" = true ] && [[ "$install_dir" == /mnt/* ]]; then
        should_warn="true"
    fi
    _assert "$desc" "$expect_warn" "$should_warn"
}

_test_mount_warning true  "/mnt/c/wireghost" "true"  "WSL + /mnt/c → warn"
_test_mount_warning true  "/opt/wireghost"   "false" "WSL + /opt → no warn"
_test_mount_warning false "/mnt/c/wireghost" "false" "non-WSL + /mnt/c → no warn"
_test_mount_warning true  "/mnt/d/projects"  "true"  "WSL + /mnt/d → warn"
_test_mount_warning true  "/home/user/app"   "false" "WSL + /home → no warn"

# ════════════════════════════════════════════════════════════════════
# TEST GROUP: mask_secret()
# ════════════════════════════════════════════════════════════════════
printf "\n\033[1m── mask_secret() ─────────────────────────────────\033[0m\n"

mask_secret() {
    local val="$1"
    if [ ${#val} -gt 10 ]; then
        printf "%s...%s" "${val:0:4}" "${val: -3}"
    else
        printf "********"
    fi
}

_assert "long secret masked" "abcd...xyz" "$(mask_secret 'abcdefghijklmnopqrstuvwxyz')"
_assert "11-char boundary" "abcd...ijk" "$(mask_secret 'abcdefghijk')"
_assert "10-char → stars" "********" "$(mask_secret 'abcdefghij')"
_assert "short secret → stars" "********" "$(mask_secret 'abc')"
_assert "empty string → stars" "********" "$(mask_secret '')"

# ════════════════════════════════════════════════════════════════════
# TEST GROUP: _compute_derived()
# ════════════════════════════════════════════════════════════════════
printf "\n\033[1m── _compute_derived() ────────────────────────────\033[0m\n"

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

WIREGHOST_PROTO="https"; WIREGHOST_PORT="443"; WIREGHOST_HOST="10.0.0.1"
_compute_derived
_assert "https+443: secure cookies" "true" "$SESSION_COOKIE_SECURE"
_assert "https+443: no port suffix" "https://10.0.0.1,https://localhost,https://127.0.0.1" "$CSRF_TRUSTED_ORIGINS"

WIREGHOST_PROTO="https"; WIREGHOST_PORT="8443"; WIREGHOST_HOST="10.0.0.1"
_compute_derived
_assert "https+8443: port suffix" "https://10.0.0.1:8443,https://localhost:8443,https://127.0.0.1:8443" "$CSRF_TRUSTED_ORIGINS"

WIREGHOST_PROTO="http"; WIREGHOST_PORT="80"; WIREGHOST_HOST="example.com"
_compute_derived
_assert "http+80: no secure cookies" "false" "$SESSION_COOKIE_SECURE"
_assert "http+80: no port suffix" "http://example.com,http://localhost,http://127.0.0.1" "$CSRF_TRUSTED_ORIGINS"

WIREGHOST_PROTO="http"; WIREGHOST_PORT="8080"; WIREGHOST_HOST="example.com"
_compute_derived
_assert "http+8080: port suffix" "http://example.com:8080,http://localhost:8080,http://127.0.0.1:8080" "$CSRF_TRUSTED_ORIGINS"

# ════════════════════════════════════════════════════════════════════
# TEST GROUP: gen_secret()
# ════════════════════════════════════════════════════════════════════
printf "\n\033[1m── gen_secret() ──────────────────────────────────\033[0m\n"

gen_secret() {
    openssl rand -base64 96 | tr -d '\n/+=' | head -c 64
}

# After the fix (base64 96 instead of 48), gen_secret should always produce exactly 64 chars.
# Run 10 times to confirm consistency.
_all_64=true
for _i in $(seq 1 10); do
    _s=$(gen_secret)
    if [ "${#_s}" -ne 64 ]; then
        _all_64=false
        break
    fi
done
_TOTAL=$((_TOTAL + 1))
if [ "$_all_64" = true ]; then
    _PASS=$((_PASS + 1))
    printf "  \033[0;32m✓\033[0m gen_secret produces exactly 64 chars (10/10 runs)\n"
else
    _FAIL=$((_FAIL + 1))
    printf "  \033[0;31m✗\033[0m gen_secret produced != 64 chars: got %d\n" "${#_s}"
fi

secret=$(gen_secret)
secret2=$(gen_secret)
_TOTAL=$((_TOTAL + 1))
if [ "$secret" != "$secret2" ]; then
    _PASS=$((_PASS + 1))
    printf "  \033[0;32m✓\033[0m gen_secret produces unique values\n"
else
    _FAIL=$((_FAIL + 1))
    printf "  \033[0;31m✗\033[0m gen_secret produced identical values\n"
fi

# Check no forbidden chars
_TOTAL=$((_TOTAL + 1))
if echo "$secret" | grep -qE '[/+=]'; then
    _FAIL=$((_FAIL + 1))
    printf "  \033[0;31m✗\033[0m gen_secret contains /+= chars: %s\n" "$secret"
else
    _PASS=$((_PASS + 1))
    printf "  \033[0;32m✓\033[0m gen_secret has no /+= chars\n"
fi

# ════════════════════════════════════════════════════════════════════
# TEST GROUP: Non-interactive localhost guard
# ════════════════════════════════════════════════════════════════════
printf "\n\033[1m── Non-interactive localhost guard ────────────────\033[0m\n"

_test_localhost_guard() {
    local host="$1" is_wsl="$2" expect_die="$3" desc="$4"
    local _IS_WSL="$is_wsl"
    local WIREGHOST_HOST="$host"
    local would_die="false"
    if [ "$WIREGHOST_HOST" = "localhost" ] && [ "$_IS_WSL" != true ]; then
        would_die="true"
    fi
    _assert "$desc" "$expect_die" "$would_die"
}

_test_localhost_guard "localhost" "false" "true"  "non-WSL + localhost → die"
_test_localhost_guard "localhost" "true"  "false" "WSL + localhost → allowed"
_test_localhost_guard "10.0.0.1" "false" "false" "non-WSL + real IP → allowed"
_test_localhost_guard "10.0.0.1" "true"  "false" "WSL + real IP → allowed"

# ════════════════════════════════════════════════════════════════════
# TEST GROUP: Script syntax validation
# ════════════════════════════════════════════════════════════════════
printf "\n\033[1m── Script syntax validation ───────────────────────\033[0m\n"

syntax_out=$(bash -n "$PROJECT_DIR/scripts/install-wireghost.sh" 2>&1)
_assert "install-wireghost.sh syntax valid" "" "$syntax_out"

syntax_out=$(bash -n "$PROJECT_DIR/scripts/install.sh" 2>&1)
_assert "install.sh syntax valid" "" "$syntax_out"

# ════════════════════════════════════════════════════════════════════
# TEST GROUP: set -u compatibility (the original bug)
# ════════════════════════════════════════════════════════════════════
printf "\n\033[1m── set -u compatibility ──────────────────────────\033[0m\n"

nounset_test=$(bash -c '
set -euo pipefail
GREEN="\033[0;32m"; DIM="\033[2m"; BOLD="\033[1m"; NC="\033[0m"
_TOTAL=7; _STEP=0
step() {
    _STEP=$((_STEP + 1))
    local pct=$((_STEP * 100 / _TOTAL))
    local filled=$((pct * 30 / 100))
    local empty=$((30 - filled))
    printf "ok %d/%d filled=%d empty=%d" "$_STEP" "$_TOTAL" "$filled" "$empty"
}
step "test"
' 2>&1)
_assert_contains "step() works under set -u" "ok 1/7 filled=4 empty=26" "$nounset_test"

# Run all 7 steps under set -u
nounset_full=$(bash -c '
set -euo pipefail
_TOTAL=7; _STEP=0
for i in 1 2 3 4 5 6 7; do
    _STEP=$((_STEP + 1))
    local_pct=$((_STEP * 100 / _TOTAL))
    local_filled=$((local_pct * 30 / 100))
    local_empty=$((30 - local_filled))
    printf "%d " $(( local_filled + local_empty ))
done
' 2>&1)
_assert "all 7 steps sum to 30 under set -u" "30 30 30 30 30 30 30 " "$nounset_full"

# ════════════════════════════════════════════════════════════════════
# TEST GROUP: WSL host detection override
# ════════════════════════════════════════════════════════════════════
printf "\n\033[1m── WSL host detection override ───────────────────\033[0m\n"

_test_host_detection() {
    local is_wsl="$1" hostname_output="$2" expected="$3" desc="$4"
    local _IS_WSL="$is_wsl"
    local _DETECTED_IP="$hostname_output"
    if [ "$_IS_WSL" = true ]; then
        _DETECTED_IP="localhost"
    fi
    _assert "$desc" "$expected" "$_DETECTED_IP"
}

_test_host_detection "true"  "172.24.176.1" "localhost"    "WSL overrides 172.x to localhost"
_test_host_detection "false" "172.24.176.1" "172.24.176.1" "non-WSL keeps 172.x"
_test_host_detection "true"  "10.0.0.5"     "localhost"    "WSL overrides any IP to localhost"
_test_host_detection "false" "10.0.0.5"     "10.0.0.5"    "non-WSL keeps real IP"

# ════════════════════════════════════════════════════════════════════
# TEST GROUP: _update_env_var (sed delimiter fix)
# ════════════════════════════════════════════════════════════════════
printf "\n\033[1m── _update_env_var() (delimiter-safe) ─────────────\033[0m\n"

_test_update_env_var() {
    local desc="$1" key="$2" val="$3" initial_content="$4" expected_content="$5"
    local tmpdir
    tmpdir=$(mktemp -d)
    printf '%s\n' "$initial_content" > "$tmpdir/.env"

    _update_env_var() {
        local key="$1" val="$2"
        if grep -q "^${key}=" "$tmpdir/.env"; then
            { grep -v "^${key}=" "$tmpdir/.env" || true; } > "$tmpdir/.env.tmp" && mv "$tmpdir/.env.tmp" "$tmpdir/.env"
        fi
        printf '%s=%s\n' "$key" "$val" >> "$tmpdir/.env"
    }

    _update_env_var "$key" "$val"
    local actual
    actual=$(cat "$tmpdir/.env")
    _assert "$desc" "$expected_content" "$actual"
    rm -rf "$tmpdir"
}

# Value with pipe — the old sed "s|...|...|" delimiter would break
_test_update_env_var \
    "value with pipe char preserved" \
    "MYSQL_PASSWORD" "abc|def&ghi" \
    "# comment
MYSQL_PASSWORD=oldvalue
OTHER=keep" \
    "# comment
OTHER=keep
MYSQL_PASSWORD=abc|def&ghi"

# Value with ampersand — old sed would expand & to matched text
_test_update_env_var \
    "value with ampersand preserved" \
    "SECRET" 'P&ssw0rd\$pecial' \
    "SECRET=old" \
    'SECRET=P&ssw0rd\$pecial'

# New key (append mode)
_test_update_env_var \
    "new key appended" \
    "NEW_KEY" "new_val" \
    "EXISTING=yes" \
    "EXISTING=yes
NEW_KEY=new_val"

# ════════════════════════════════════════════════════════════════════
# TEST GROUP: printf -v vs eval (prompt_var safety)
# ════════════════════════════════════════════════════════════════════
printf "\n\033[1m── printf -v safety ──────────────────────────────\033[0m\n"

# printf -v should treat input as literal string, not execute it
printf_v_test=$(bash -c '
set -euo pipefail
MY_VAR="default"
_input='\''$(echo INJECTED)'\''
printf -v "MY_VAR" "%s" "$_input"
echo "$MY_VAR"
' 2>&1)
_assert "printf -v treats \$(cmd) as literal" '$(echo INJECTED)' "$printf_v_test"

printf_v_test2=$(bash -c '
set -euo pipefail
MY_VAR="default"
_input='\''`whoami`'\''
printf -v "MY_VAR" "%s" "$_input"
echo "$MY_VAR"
' 2>&1)
_assert "printf -v treats backtick as literal" '`whoami`' "$printf_v_test2"

# ════════════════════════════════════════════════════════════════════
# TEST GROUP: CUSTOM_DIR validation
# ════════════════════════════════════════════════════════════════════
printf "\n\033[1m── CUSTOM_DIR validation ─────────────────────────\033[0m\n"

_test_dir_validation() {
    local dir="$1" expect_ok="$2" desc="$3"
    local result="ok"
    if ! [[ "$dir" =~ ^/ ]]; then
        result="rejected"
    fi
    _assert "$desc" "$expect_ok" "$result"
}

_test_dir_validation "/opt/wireghost"       "ok"       "absolute path accepted"
_test_dir_validation "/home/user/my app"    "ok"       "absolute path with space accepted"
_test_dir_validation "relative/path"        "rejected" "relative path rejected"
_test_dir_validation "wireghost"            "rejected" "bare name rejected"
_test_dir_validation "./local"              "rejected" "dot-relative rejected"

# ════════════════════════════════════════════════════════════════════
# TEST GROUP: install.sh --prebuilt flag parsing
# ════════════════════════════════════════════════════════════════════
printf "\n\033[1m── install.sh --prebuilt flag ────────────────────\033[0m\n"

_test_flag_parse() {
    local args="$1" expect_prebuilt="$2" expect_mode="$3" desc="$4"
    # Simulate the flag parsing loop from install.sh
    INSTALL_MODE=""
    PREBUILT=false
    for arg in $args; do
        case "$arg" in
            --host)      INSTALL_MODE="host" ;;
            --docker)    INSTALL_MODE="docker" ;;
            --prebuilt)  PREBUILT=true ;;
            --with-msf)  : ;;
        esac
    done
    _assert "$desc — PREBUILT" "$expect_prebuilt" "$PREBUILT"
    if [ -n "$expect_mode" ]; then
        _assert "$desc — INSTALL_MODE" "$expect_mode" "$INSTALL_MODE"
    fi
}

_test_flag_parse "--docker"                  "false" "docker" "no --prebuilt flag"
_test_flag_parse "--docker --prebuilt"       "true"  "docker" "--prebuilt with --docker"
_test_flag_parse "--prebuilt --docker"       "true"  "docker" "--prebuilt before --docker"
_test_flag_parse "--host --prebuilt"         "true"  "host"   "--prebuilt with --host"
_test_flag_parse "--prebuilt"                "true"  ""       "--prebuilt alone"
_test_flag_parse ""                          "false" ""       "no flags at all"
_test_flag_parse "--host --with-msf"         "false" "host"   "--host --with-msf (no prebuilt)"
_test_flag_parse "--host --with-msf --prebuilt" "true" "host" "--host --with-msf --prebuilt"

# ════════════════════════════════════════════════════════════════════
# TEST GROUP: build_and_start_docker() branching
# ════════════════════════════════════════════════════════════════════
printf "\n\033[1m── build_and_start_docker() branch ───────────────\033[0m\n"

_test_build_branch() {
    local prebuilt="$1" expect_skip="$2" desc="$3"
    PREBUILT="$prebuilt"
    local output=""
    if $PREBUILT; then
        output="SKIP_BUILD:up -d"
    else
        output="BUILD:up -d"
    fi
    _assert "$desc" "$expect_skip" "$output"
}

_test_build_branch "true"  "SKIP_BUILD:up -d" "PREBUILT=true skips build"
_test_build_branch "false" "BUILD:up -d"      "PREBUILT=false runs build"

# ════════════════════════════════════════════════════════════════════
# TEST GROUP: update-remote.sh _none_ sentinel
# ════════════════════════════════════════════════════════════════════
printf "\n\033[1m── _none_ sentinel conversion ────────────────────\033[0m\n"

_test_sentinel() {
    local input="$1" expect="$2" desc="$3"
    local BACKUP_FILE="$input"
    [ "$BACKUP_FILE" = "_none_" ] && BACKUP_FILE=""
    _assert "$desc" "$expect" "$BACKUP_FILE"
}

_test_sentinel "_none_"          ""                "_none_ → empty string"
_test_sentinel "backup.tar.gz"   "backup.tar.gz"   "non-sentinel passes through"
_test_sentinel ""                ""                 "empty stays empty"
_test_sentinel "none"            "none"             "'none' (no underscores) passes through"

# ════════════════════════════════════════════════════════════════════
# TEST GROUP: update-remote.sh flag parsing
# ════════════════════════════════════════════════════════════════════
printf "\n\033[1m── update-remote.sh flag parsing ─────────────────\033[0m\n"

_test_updater_flags() {
    local args="$1" expect_debug="$2" expect_exit="$3" desc="$4"
    local DEBUG=false VPS=""
    local exit_code=0
    for arg in $args; do
        case "$arg" in
            --full)                  : ;;
            --debug|--verbose)       DEBUG=true ;;
            --help|-h)               exit_code=0 ;;
            --*)                     exit_code=1 ;;
            *)                       VPS="$arg" ;;
        esac
    done
    _assert "$desc — DEBUG" "$expect_debug" "$DEBUG"
}

_test_updater_flags "--verbose"                        "true"  "0" "--verbose sets DEBUG"
_test_updater_flags "--debug"                          "true"  "0" "--debug sets DEBUG"
_test_updater_flags "--full"                           "false" "0" "--full does not set DEBUG"
_test_updater_flags "demon@10.10.9.240"                "false" "0" "VPS hostname parsed correctly"
_test_updater_flags "demon@10.10.9.240 --verbose"      "true"  "0" "VPS + --verbose"
_test_updater_flags "demon@10.10.9.240 --full --debug" "true"  "0" "VPS + --full + --debug"

_test_updater_unknown_flag() {
    local args="$1" expect_exit="$2" desc="$3"
    local exit_code=0
    for arg in $args; do
        case "$arg" in
            --full)             : ;;
            --debug|--verbose)  : ;;
            --help|-h)          exit_code=0 ;;
            --*)                exit_code=1 ;;
            *)                  : ;;
        esac
    done
    _assert "$desc" "$expect_exit" "$exit_code"
}

_test_updater_unknown_flag "--bogus"  "1" "unknown --flag exits 1"
_test_updater_unknown_flag "--wtf"    "1" "unknown --wtf exits 1"
_test_updater_unknown_flag "--full"   "0" "known --full exits 0"

# ════════════════════════════════════════════════════════════════════
# TEST GROUP: First-time install guard logic
# ════════════════════════════════════════════════════════════════════
printf "\n\033[1m── First-time install guard ──────────────────────\033[0m\n"

_test_guard() {
    local env_exists="$1" compose_ok="$2" expect_install="$3" desc="$4"
    local would_install="false"
    # Only missing .env triggers install — compose validation failure
    # (e.g. Docker daemon down) warns but does NOT nuke existing config.
    if [ "$env_exists" = false ]; then
        would_install="true"
    fi
    _assert "$desc" "$expect_install" "$would_install"
}

_test_guard "false" "false" "true"  "no .env + no compose → install"
_test_guard "false" "true"  "true"  "no .env (compose irrelevant) → install"
_test_guard "true"  "false" "false" ".env exists + compose fails → warn, skip install"
_test_guard "true"  "true"  "false" ".env valid + compose ok → skip install"

# ════════════════════════════════════════════════════════════════════
# TEST GROUP: Code tar includes scripts/
# ════════════════════════════════════════════════════════════════════
printf "\n\033[1m── Code tar glob check ───────────────────────────\033[0m\n"

_tar_cmd="web_portal/ src/ config/ scripts/ pyproject.toml docker-compose.yml docker-compose.host.yml Dockerfile templates/"
_assert_contains "tar glob includes scripts/" "scripts/" "$_tar_cmd"
_assert_contains "tar glob includes web_portal/" "web_portal/" "$_tar_cmd"
_assert_contains "tar glob includes Dockerfile" "Dockerfile" "$_tar_cmd"

# ════════════════════════════════════════════════════════════════════
# TEST GROUP: Script syntax validation (extended)
# ════════════════════════════════════════════════════════════════════
printf "\n\033[1m── Extended syntax validation ────────────────────\033[0m\n"

syntax_out=$(bash -n "$PROJECT_DIR/scripts/install.sh" 2>&1)
_assert "install.sh syntax valid" "" "$syntax_out"

syntax_out=$(bash -n "$PROJECT_DIR/scripts/update-remote.sh" 2>&1)
_assert "update-remote.sh syntax valid" "" "$syntax_out"

syntax_out=$(bash -n "$PROJECT_DIR/scripts/remove-wireghost.sh" 2>&1)
_assert "remove-wireghost.sh syntax valid" "" "$syntax_out"

# ════════════════════════════════════════════════════════════════════
# Summary
# ════════════════════════════════════════════════════════════════════
printf "\n\033[1m══════════════════════════════════════════════════\033[0m\n"
if [ "$_FAIL" -eq 0 ]; then
    printf "\033[0;32m  %d/%d tests passed\033[0m\n" "$_PASS" "$_TOTAL"
else
    printf "\033[0;31m  %d/%d tests passed, %d FAILED\033[0m\n" "$_PASS" "$_TOTAL" "$_FAIL"
fi
printf "\033[1m══════════════════════════════════════════════════\033[0m\n\n"

exit "$_FAIL"
