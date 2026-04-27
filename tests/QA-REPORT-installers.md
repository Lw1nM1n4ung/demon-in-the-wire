# QA Report — Installer Scripts

| Field | Value |
|---|---|
| **Targets** | `scripts/install-wireghost.sh`, `scripts/install.sh` |
| **Stack** | Bash (set -euo pipefail) |
| **Test framework** | Custom bash harness (`tests/test_installers.sh`) |
| **Date** | 2026-04-27 |

---

## Tests Written

| Group | Count | Status |
|---|---|---|
| Progress bar math (both scripts) | 18 | PASS |
| step() function output | 5 | PASS |
| WSL detection | 6 | PASS |
| WSL mount path warning | 5 | PASS |
| mask_secret() | 5 | PASS |
| _compute_derived() | 6 | PASS |
| gen_secret() (10-run consistency) | 3 | PASS |
| Non-interactive localhost guard | 4 | PASS |
| Script syntax validation | 2 | PASS |
| set -u compatibility | 2 | PASS |
| WSL host detection override | 4 | PASS |
| _update_env_var() delimiter-safe | 3 | PASS |
| printf -v injection safety | 2 | PASS |
| CUSTOM_DIR validation | 5 | PASS |
| **Total** | **68** | **68/68 PASS** |

---

## Static Review Findings — All Fixed

### FIXED — gen_secret() can produce fewer than 64 characters

**File:** `install.sh:91`
**Was:** `openssl rand -base64 48` — only 64 base64 chars before stripping `/+=`, leaving 54-63 chars.
**Fix applied:** Changed to `-base64 96` (128 base64 chars pre-strip). Now produces exactly 64 chars on 10/10 test runs.

### FIXED — sed delimiter collision in _update_env_var (upgrade mode)

**File:** `install.sh:395-400`
**Was:** `sed -i "s|...|...|"` — `|` delimiter and `&`/`\` expansion in sed replacement corrupted values.
**Fix applied:** Replaced sed with `grep -v` (delete old line) + `printf` (append new). No delimiter or metachar issues. Added `|| true` guard for single-line .env edge case.

### FIXED — eval in prompt_var / prompt_secret

**File:** `install.sh:101-105, 115-119`
**Was:** `eval "$varname=\"\$_input\""` — user input could execute subshells via `$(...)` or backticks.
**Fix applied:** Replaced with `printf -v "$varname" '%s' "$_input"` — treats all input as literal string.

### FIXED — No CUSTOM_DIR sanitization

**File:** `install-wireghost.sh:191-193`
**Was:** Accepted any string including relative paths.
**Fix applied:** Added `[[ "$CUSTOM_DIR" =~ ^/ ]]` validation — rejects non-absolute paths with clear error.

---

## Coverage

| Area | Covered | Notes |
|---|---|---|
| Progress bar math | Yes | All step/total combos for both 3-step and 7-step |
| set -u nounset compat | Yes | The original production bug |
| WSL detection (3 signals) | Yes | proc/version, env var, binfmt_misc |
| WSL behavior changes | Yes | Host override, mount warning, localhost guard |
| Secret masking | Yes | Boundary conditions |
| Config derivation | Yes | Proto/port/cookie/CSRF combos |
| Secret generation | Yes | 10-run consistency, uniqueness, charset |
| _update_env_var safety | Yes | Pipe, ampersand, backslash in values |
| printf -v injection | Yes | $(cmd) and backtick literals verified |
| CUSTOM_DIR validation | Yes | Absolute, relative, bare name, dot-relative |
| Interactive prompts | No | Requires TTY; not unit-testable |
| Docker/TLS/nginx | No | Requires Docker daemon; integration-only |
| Syntax validation | Yes | `bash -n` on both scripts |
