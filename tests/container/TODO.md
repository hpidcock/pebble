# Container integration test checklist

Each item maps to a sub-directory under `tests/container/` containing a
`Containerfile` and a `test.sh`. See `README.md` for the conventions.

## Done

- [x] **`version`** — `version_default`, `version_client_flag`, `version_json_client`, `version_yaml_client`, `version_global_flag`, `version_with_server`, `version_extra_args_error`

---

## Daemon lifecycle

- [x] **`run`** — `run_socket_appears`, `run_create_dirs`, `run_hold`, `run_http`, `run_verbose`, `run_args`

---

## Services

- [x] **`services`** — `services_empty`, `services_lists_service`, `services_shows_started`, `services_format_json`, `services_format_yaml`, `services_specific_service`
- [x] **`start`** — `start_starts_service`, `start_no_wait`, `start_unknown_service`, `start_already_started`
- [x] **`stop`** — `stop_stops_service`, `stop_no_wait`, `stop_unknown_service`, `stop_already_stopped`
- [x] **`restart`** — `restart_restarts_service`, `restart_no_wait`, `restart_unknown_service`
- [x] **`autostart`** — `autostart_starts_enabled_services`, `autostart_no_wait`, `autostart_no_enabled_services`
- [x] **`replan`** — `replan_starts_enabled_service`, `replan_no_wait`, `replan_starts_new_service`
- [x] **`signal`** — `signal_sends_sigusr1`, `signal_unknown_service`, `signal_invalid_signal`

---

## Plan / layers

- [x] **`add`** — `add_appends_layer`, `add_combine`, `add_no_label`
- [x] **`plan`** — `plan_empty`, `plan_shows_services`, `plan_reflects_added_layer`

---

## Health checks

- [x] **`checks`** — `checks_empty`, `checks_lists_check`, `checks_format_json`, `checks_format_yaml`, `checks_level_filter`
- [x] **`check`** — `check_shows_check`, `check_format_json`, `check_format_yaml`, `check_unknown`, `check_refresh`
- [x] **`health`** — `health_all_healthy`, `health_unhealthy`, `health_level_filter`, `health_no_checks`
- [x] **`start-checks`** — `start_checks_starts_check`, `start_checks_idempotent`, `start_checks_unknown`
- [x] **`stop-checks`** — `stop_checks_stops_check`, `stop_checks_idempotent`, `stop_checks_unknown`

---

## Changes & tasks

- [x] **`changes`** — `changes_lists_after_start`, `changes_format_json`, `changes_format_yaml`, `changes_empty`, `changes_abs_time`
- [x] **`tasks`** — `tasks_shows_tasks`, `tasks_format_json`, `tasks_unknown_change`, `tasks_abs_time`

---

## Notices & warnings

- [x] **`notices`** — `notices_empty`, `notices_lists_notice`, `notices_type_filter`, `notices_key_filter`, `notices_format_json`, `notices_timeout`
- [x] **`notice`** — `notice_by_id`, `notice_by_type_and_key`, `notice_unknown_id`, `notice_format_json`
- [x] **`notify`** — `notify_records_notice`, `notify_with_data`, `notify_repeat_after`, `notify_no_key`
- [x] **`okay`** — `okay_acknowledges_notices`, `okay_no_notices`, `okay_warnings_flag`, `okay_clears_warnings`
- [x] **`warnings`** — `warnings_empty`, `warnings_all_flag`, `warnings_format_json`, `warnings_format_yaml`, `warnings_verbose`, `warnings_abs_time`

---

## Identities

- [x] **`identities`** — `identities_empty`, `identities_lists`, `identities_format_json`, `identities_format_yaml`
- [x] **`identity`** — `identity_shows`, `identity_unknown`, `identity_format_json`
- [x] **`add-identities`** — `add_identities_adds`, `add_identities_multiple`, `add_identities_duplicate`, `add_identities_no_from`
- [x] **`update-identities`** — `update_identities_updates`, `update_identities_replace_adds`, `update_identities_replace_removes`, `update_identities_no_from`
- [x] **`remove-identities`** — `remove_identities_removes`, `remove_identities_unknown`, `remove_identities_no_from`

---

## File operations

- [x] **`ls`** — `ls_lists_directory`, `ls_long_format`, `ls_directory_itself`, `ls_format_json`, `ls_format_yaml`, `ls_nonexistent`, `ls_glob`
- [x] **`mkdir`** — `mkdir_creates_directory`, `mkdir_parents`, `mkdir_already_exists_fails`, `mkdir_already_exists_with_p`, `mkdir_mode`, `mkdir_user_group`
- [x] **`rm`** — `rm_removes_file`, `rm_removes_directory_recursive`, `rm_nonexistent`, `rm_directory_without_r`
- [x] **`push`** — `push_uploads_file`, `push_creates_parents`, `push_mode`, `push_nonexistent_source`, `push_user_group`
- [x] **`pull`** — `pull_downloads_file`, `pull_nonexistent_remote`, `pull_overwrites_existing`

---

## Exec

- [x] **`exec`** — `exec_runs_command`, `exec_env_var`, `exec_working_dir`, `exec_timeout`, `exec_exit_code`, `exec_with_context`, `exec_user_group`

---

## Logs

- [x] **`logs`** — `logs_shows_service_output`, `logs_n_limits_lines`, `logs_format_json`, `logs_follow`, `logs_all`, `logs_multiple_services`

---

## Enter (container entrypoint)

- [x] **`enter`** — `enter_version`, `enter_exec`, `enter_plan`, `enter_services`, `enter_ls`, `enter_run_starts_services`, `enter_hold`, `enter_unsupported_subcommand`

---

## Help

- [x] **`help`** — `help_default`, `help_all`, `help_specific_command`, `help_unknown_command`, `help_flag`, `help_command_help_flag`
