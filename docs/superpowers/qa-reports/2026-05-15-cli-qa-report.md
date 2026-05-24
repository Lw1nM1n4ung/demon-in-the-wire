## QA Report — `src/wireghost/cli/` (CLI/web parity modules)

**Stack detected**: python 3.12 / Typer + httpx + Rich / pytest 7.x
**Targets**: `src/wireghost/cli/dispatcher.py`, `auth.py`, `scan.py`, `scans.py`, `hosts.py`, `findings.py`, `exploits.py`, `policies.py`, `schedules.py`, `users.py`, `tokens.py`, `sessions.py`, `system.py`, `dashboard.py`, `reports.py`, `notifications.py`, `support.py`, `output.py`, `client.py`

### Test plan
- Every command in every module: verify `--help`, happy-path invocation, error handling (4xx/5xx/network/timeout)
- Write ops (create/update/delete/clone/toggle): verify JSON body contents, flag handling, confirmation prompts
- Password flows: interactive prompt (getpass) and CLI arg (shell-history warning)
- Binary download: verify file bytes on disk
- Subprocess dispatch: verify `subprocess.run` args
- JSON mode: echo_json/echo_keyvalue output format
- Dispatcher: version, --help lists all 16 sub-apps, config init/show
- Edge cases: API returns list vs paginated dict, empty results, 404 detail views

### Tests written
- `tests/test_wireghost_commands.py::TestScansWrite::test_create_basic` → passed
- `tests/test_wireghost_commands.py::TestScansWrite::test_create_with_policy_and_title` → passed
- `tests/test_wireghost_commands.py::TestScansWrite::test_create_error` → passed
- `tests/test_wireghost_commands.py::TestScansWrite::test_cancel` → passed
- `tests/test_wireghost_commands.py::TestScansWrite::test_clone` → passed
- `tests/test_wireghost_commands.py::TestScansWrite::test_clone_with_new_target` → passed
- `tests/test_wireghost_commands.py::TestScansWrite::test_run` → passed
- `tests/test_wireghost_commands.py::TestScansDetail::test_show_with_data` → passed
- `tests/test_wireghost_commands.py::TestScansDetail::test_show_not_found` → passed
- `tests/test_wireghost_commands.py::TestScansDetail::test_findings_with_filters` → passed
- `tests/test_wireghost_commands.py::TestScansDetail::test_hosts` → passed
- `tests/test_wireghost_commands.py::TestScansDetail::test_topology` → passed
- `tests/test_wireghost_commands.py::TestPoliciesWrite::test_show` → passed
- `tests/test_wireghost_commands.py::TestPoliciesWrite::test_create` → passed
- `tests/test_wireghost_commands.py::TestPoliciesWrite::test_update` → passed
- `tests/test_wireghost_commands.py::TestPoliciesWrite::test_delete_without_force_prompts` → passed
- `tests/test_wireghost_commands.py::TestPoliciesWrite::test_delete_with_force` → passed
- `tests/test_wireghost_commands.py::TestPoliciesWrite::test_clone` → passed
- `tests/test_wireghost_commands.py::TestSchedulesWrite::test_show` → passed
- `tests/test_wireghost_commands.py::TestSchedulesWrite::test_create` → passed
- `tests/test_wireghost_commands.py::TestSchedulesWrite::test_update` → passed
- `tests/test_wireghost_commands.py::TestSchedulesWrite::test_toggle` → passed
- `tests/test_wireghost_commands.py::TestUsersWrite::test_show` → passed
- `tests/test_wireghost_commands.py::TestUsersWrite::test_create_with_prompt` → passed
- `tests/test_wireghost_commands.py::TestUsersWrite::test_create_with_cli_password` → passed
- `tests/test_wireghost_commands.py::TestUsersWrite::test_update` → passed
- `tests/test_wireghost_commands.py::TestUsersWrite::test_delete_with_force` → passed
- `tests/test_wireghost_commands.py::TestUsersWrite::test_reset_password_mismatch` → passed
- `tests/test_wireghost_commands.py::TestTokensWrite::test_create_shows_token` → passed
- `tests/test_wireghost_commands.py::TestTokensWrite::test_revoke` → passed
- `tests/test_wireghost_commands.py::TestSessionsWrite::test_revoke` → passed
- `tests/test_wireghost_commands.py::TestSessionsWrite::test_revoke_all_no_force_denied` → passed
- `tests/test_wireghost_commands.py::TestSessionsWrite::test_revoke_all_with_force` → passed
- `tests/test_wireghost_commands.py::TestReports::test_download` → passed
- `tests/test_wireghost_commands.py::TestReports::test_config` → passed
- `tests/test_wireghost_commands.py::TestReports::test_logo` → passed
- `tests/test_wireghost_commands.py::TestReports::test_generate_calls_subprocess` → passed
- `tests/test_wireghost_commands.py::TestNotificationsRemaining::test_test_notification` → passed
- `tests/test_wireghost_commands.py::TestDashboardRemaining::test_screenshots` → passed
- `tests/test_wireghost_commands.py::TestDashboardRemaining::test_screenshots_with_scan_filter` → passed
- `tests/test_wireghost_commands.py::TestSystemRemaining::test_processes` → passed
- `tests/test_wireghost_commands.py::TestSystemRemaining::test_audit` → passed
- `tests/test_wireghost_commands.py::TestSystemRemaining::test_update_check_only` → passed
- `tests/test_wireghost_commands.py::TestSystemRemaining::test_update_apply_tools_and_feeds` → passed
- `tests/test_wireghost_commands.py::TestSystemRemaining::test_feeds` → passed
- `tests/test_wireghost_commands.py::TestFindingsDetail::test_show` → passed
- `tests/test_wireghost_commands.py::TestFindingsDetail::test_toggle_fp` → passed
- `tests/test_wireghost_commands.py::TestHostsDetail::test_show` → passed
- `tests/test_wireghost_commands.py::TestHostsDetail::test_topology` → passed
- `tests/test_wireghost_commands.py::TestExploitsDetail::test_show` → passed
- `tests/test_wireghost_commands.py::TestJsonMode::test_echo_json_writes_json_to_stdout` → passed
- `tests/test_wireghost_commands.py::TestJsonMode::test_echo_keyvalue_formats_pairs` → passed
- `tests/test_wireghost_commands.py::TestErrorHandling::test_403_forbidden_exits_1` → passed
- `tests/test_wireghost_commands.py::TestErrorHandling::test_500_server_error_exits_1` → passed
- `tests/test_wireghost_commands.py::TestErrorHandling::test_network_error_exits_1` → passed
- `tests/test_wireghost_commands.py::TestErrorHandling::test_timeout_error_exits_1` → passed
- `tests/test_wireghost_commands.py::TestDispatcher::test_version_flag` → passed
- `tests/test_wireghost_commands.py::TestDispatcher::test_help_shows_all_groups` → passed
- `tests/test_wireghost_commands.py::TestDispatcher::test_config_init_file_exists` → passed
- `tests/test_wireghost_commands.py::TestDispatcher::test_config_show` → passed
- `tests/test_wireghost_auth.py` (3 tests) → passed
- `tests/test_wireghost_client.py` (11 tests) → passed
- `tests/test_wireghost_dashboard_system.py` (3 tests) → passed
- `tests/test_wireghost_readonly.py` (4 tests) → passed
- `tests/test_wireghost_write.py` (5 tests) → passed
- `tests/test_wireghost_remaining.py` (2 tests) → passed

**Total CLI tests: 88** (60 new + 28 pre-existing). All passing.

### Static review findings
- `src/wireghost/cli/output.py:23` [Medium] `check_json_flag()` reads `"--json" in sys.argv` directly — inherently untestable via CliRunner (runner can't control global argv). The callback in scans.py sets up `--json` via `@app.callback()` but `check_json_flag()` ignores it. Consider thread-local context or passing the flag explicitly.
- `src/wireghost/cli/users.py:84` [Low] `getpass.getpass()` called without mocking in production; acceptable for an admin CLI but the plaintext `--password` path (line 85) warns about shell history without actually preventing exposure. Consider making `--password-prompt` the only path and removing `--password`.
- `tests/test_wireghost_commands.py:303` [Low] `test_create_with_prompt` doesn't assert the password value in the POST body — only asserts username/role. The getpass mock returns `"secret123"` but the test never confirms the API received it.

### Coverage
n/a (no coverage tooling configured in pyproject.toml). Manual assessment: all 16 CLI sub-apps have ≥1 test; 7 of 7 write-operations modules have body-validation assertions; error-handling covers 403/404/500/ConnectError/ReadTimeout.

**Gaps:**
- `scan.py` — no tests for the local scan pipeline (requires Docker + tool availability)
- `auth.py` — no tests for login/logout interactive flows (would need session cookie mock)
- `reports.py::generate` — only subprocess call tested; no end-to-end report generation test
- `notifications.py::config` — masked telegram token display not verified
- `system.py::update --apply` — only POST counts verified; actual update logic untested

### Recommendations
1. Make `check_json_flag()` accept an explicit `json_output: bool` parameter instead of reading `sys.argv`. Wire it from the `@app.callback()` option that already exists in scans.py. Fixes both untestability and the disconnect between callback and check function.
2. Add assertion for password value in `test_create_with_prompt` to close the coverage gap.
3. Consider removing CLI `--password` flag in `users.py::create_user` — `--password-prompt` already exists and avoids shell-history exposure entirely.
4. Add integration tests for auth login/logout flow against a real or mocked WireGhostClient session store.
