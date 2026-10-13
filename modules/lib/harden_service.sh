#!/bin/sh

# Shared service hardening engine. Item wrappers must provide fixed local unit
# names and legacy activation paths; no server-supplied command is accepted.

os_guard_service_set_error() {
    service_error_code=$1
    service_error_message=$2
    service_outcome='FAILED'
}

os_guard_service_initialize() {
    service_requested_action=${1:-}
    service_distro=${OS_GUARD_DISTRO:-unknown}
    service_version_id=${OS_GUARD_VERSION_ID:-unknown}
    service_test_root=${OS_GUARD_TEST_ROOT:-}
    service_outcome='FAILED'
    service_error_code=''
    service_error_message=''
    service_check_status='NOT_RUN'
    service_active_records=''
    service_active_count=0
    service_applied_records=''
    service_state_fingerprint=''
    service_backup_created=false
    service_backup_id=''
    service_backup_directory=''
    service_changes_applied=false
    service_validation_success=false
    service_rollback_attempted=false
    service_rollback_success=false
    service_systemctl=''
    service_sha256=''
}

os_guard_service_resolve_commands() {
    if [ -n "$service_test_root" ] && [ -n "${OS_GUARD_TEST_SYSTEMCTL_BIN:-}" ]; then
        service_systemctl=$OS_GUARD_TEST_SYSTEMCTL_BIN
    else
        service_systemctl=$(command -v systemctl 2>/dev/null || true)
    fi

    service_sha256=$(command -v sha256sum 2>/dev/null || true)
    if [ -z "$service_systemctl" ] || [ ! -x "$service_systemctl" ]; then
        os_guard_service_set_error 'SYSTEMCTL_UNAVAILABLE' 'systemctl is required for this remediation'
        return 1
    fi
    if [ -z "$service_sha256" ] || [ ! -x "$service_sha256" ]; then
        os_guard_service_set_error 'SHA256_COMMAND_UNAVAILABLE' 'sha256sum is required for approval state binding'
        return 1
    fi
}

os_guard_service_run_check() {
    if [ -n "$service_test_root" ] && [ "${OS_GUARD_TEST_CHECK_FAILURE:-false}" = 'true' ]; then
        service_check_status='ERROR'
        return 1
    fi

    service_check_output=$("$HARDEN_CHECK_SCRIPT" 2>/dev/null)
    if [ $? -ne 0 ]; then
        service_check_status='ERROR'
        return 1
    fi

    for possible_status in GOOD VULNERABLE UNCHECKABLE N/A; do
        if printf '%s\n' "$service_check_output" | grep -Eq \
            '"item_id":"'"$HARDEN_ITEM_ID"'".*"status":"'"$possible_status"'"'; then
            service_check_status=$possible_status
            return 0
        fi
    done
    if printf '%s\n' "$service_check_output" | grep -Eq \
        '"item_id":"'"$HARDEN_ITEM_ID"'".*"status":null'; then
        service_check_status='PENDING'
        return 0
    fi
    service_check_status='INVALID'
    return 1
}

os_guard_service_require_actionable_check() {
    if ! os_guard_service_run_check; then
        os_guard_service_set_error 'CHECK_EXECUTION_FAILED' 'the existing CHECK could not be evaluated'
        return 1
    fi
    case "$service_check_status" in
        GOOD|N/A)
            service_outcome='NO_CHANGE'
            return 2
            ;;
        VULNERABLE)
            return 0
            ;;
        PENDING|UNCHECKABLE)
            os_guard_service_set_error 'CHECK_STATE_NOT_ACTIONABLE' 'the CHECK result is not actionable'
            return 1
            ;;
        *)
            os_guard_service_set_error 'CHECK_RESULT_INVALID' 'the CHECK returned an invalid result'
            return 1
            ;;
    esac
}

os_guard_service_legacy_activation_is_enabled() {
    while IFS= read -r relative_path; do
        [ -n "$relative_path" ] || continue
        legacy_path="${service_test_root}${relative_path}"
        [ -r "$legacy_path" ] || continue
        if grep -Eiq "$HARDEN_LEGACY_PATTERN" "$legacy_path"; then
            return 0
        fi
    done <<EOF
$HARDEN_LEGACY_FILES
EOF
    return 1
}

os_guard_service_has_reverse_dependency() {
    dependency_unit=$1
    dependency_output=$("$service_systemctl" list-dependencies --reverse --plain --no-legend \
        "$dependency_unit" 2>/dev/null || true)

    while IFS= read -r dependency_line; do
        dependency_name=$(printf '%s\n' "$dependency_line" | \
            awk '{ value=$NF; sub(/^[^[:alnum:]_.@-]+/, "", value); print value }')
        [ -n "$dependency_name" ] || continue
        [ "$dependency_name" = "$dependency_unit" ] && continue
        return 0
    done <<EOF
$dependency_output
EOF
    return 1
}

os_guard_service_has_active_guard_unit() {
    while IFS= read -r guard_unit; do
        [ -n "$guard_unit" ] || continue
        guard_state=$("$service_systemctl" is-active "$guard_unit" 2>/dev/null || true)
        if [ "$guard_state" = 'active' ]; then
            return 0
        fi
    done <<EOF
${HARDEN_GUARD_UNITS:-}
EOF
    return 1
}

os_guard_service_append_active_record() {
    active_unit_name=$1
    active_enabled_state=$2
    active_record="$active_unit_name|$active_enabled_state"
    if [ -z "$service_active_records" ]; then
        service_active_records=$active_record
    else
        service_active_records="$service_active_records
$active_record"
    fi
    service_active_count=$((service_active_count + 1))
}

os_guard_service_collect_active_units() {
    service_active_records=''
    service_active_count=0

    while IFS= read -r unit_name; do
        [ -n "$unit_name" ] || continue
        unit_active_state=$("$service_systemctl" is-active "$unit_name" 2>/dev/null || true)
        [ "$unit_active_state" = 'active' ] || continue

        unit_enabled_state=$("$service_systemctl" is-enabled "$unit_name" 2>/dev/null || true)
        case "$unit_enabled_state" in
            enabled|enabled-runtime|disabled|static|indirect)
                ;;
            masked|masked-runtime)
                os_guard_service_set_error 'MASKED_ACTIVE_UNIT_UNSAFE' 'an active masked unit cannot be restored safely'
                return 1
                ;;
            *)
                os_guard_service_set_error 'SYSTEMD_STATE_UNRESOLVED' 'an active unit has an unsupported enablement state'
                return 1
                ;;
        esac

        if os_guard_service_has_reverse_dependency "$unit_name"; then
            os_guard_service_set_error 'ACTIVE_DEPENDENCY_REQUIRES_MANUAL_REMEDIATION' 'an active target has a reverse systemd dependency'
            return 1
        fi
        os_guard_service_append_active_record "$unit_name" "$unit_enabled_state"
    done <<EOF
$HARDEN_SYSTEMD_UNITS
EOF

    if [ "$service_active_count" -eq 0 ]; then
        os_guard_service_set_error 'ACTIVE_UNIT_NOT_RESOLVED' 'the vulnerable activation path is not a supported systemd unit'
        return 1
    fi

    service_state_fingerprint=$(printf '%s\n' "$service_active_records" | \
        "$service_sha256" | awk '{ print $1 }')
    if [ -z "$service_state_fingerprint" ]; then
        os_guard_service_set_error 'STATE_FINGERPRINT_FAILED' 'the unit state fingerprint could not be created'
        return 1
    fi
}

os_guard_service_validate_authorization() {
    if [ "${OS_GUARD_HARDEN_APPROVED:-}" != 'true' ]; then
        os_guard_service_set_error 'APPROVAL_REQUIRED' 'EXECUTE requires explicit administrator approval'
        return 1
    fi
    approved_fingerprint=${OS_GUARD_HARDEN_EXPECTED_STATE:-}
    if [ -z "$approved_fingerprint" ]; then
        os_guard_service_set_error 'EXPECTED_STATE_REQUIRED' 'EXECUTE requires the PREVIEW state fingerprint'
        return 1
    fi
    if [ "$approved_fingerprint" != "$service_state_fingerprint" ]; then
        os_guard_service_set_error 'STATE_DRIFT' 'the unit state changed after PREVIEW'
        return 1
    fi
}

os_guard_service_create_backup() {
    if [ -n "$service_test_root" ] && [ "${OS_GUARD_TEST_FAIL_STEP:-}" = 'backup' ]; then
        os_guard_service_set_error 'BACKUP_FAILED' 'unit state backup creation failed'
        return 1
    fi
    if [ -n "$service_test_root" ]; then
        default_backup_root="${service_test_root}/var/lib/os-guard-agent/backups/${HARDEN_ITEM_ID}"
        backup_root=${OS_GUARD_TEST_BACKUP_ROOT:-$default_backup_root}
    else
        backup_root="/var/lib/os-guard-agent/backups/${HARDEN_ITEM_ID}"
    fi
    if ! os_guard_harden_create_private_directory "$backup_root"; then
        os_guard_service_set_error 'BACKUP_FAILED' 'the private backup directory could not be prepared'
        return 1
    fi
    service_backup_directory=$(mktemp -d "$backup_root/backup.XXXXXX" 2>/dev/null || true)
    if [ -z "$service_backup_directory" ] || ! chmod 0700 -- "$service_backup_directory"; then
        os_guard_service_set_error 'BACKUP_FAILED' 'the private unit state backup could not be created'
        return 1
    fi
    if ! printf '%s\n' "$service_active_records" > "$service_backup_directory/unit-state" || \
        ! chmod 0600 -- "$service_backup_directory/unit-state"; then
        os_guard_service_set_error 'BACKUP_FAILED' 'the unit state backup could not be written'
        return 1
    fi
    service_backup_created=true
    service_backup_id=${service_backup_directory##*/}
}

os_guard_service_remember_applied_record() {
    applied_record=$1
    if [ -z "$service_applied_records" ]; then
        service_applied_records=$applied_record
    else
        service_applied_records="$applied_record
$service_applied_records"
    fi
}

os_guard_service_apply() {
    while IFS='|' read -r unit_name original_enabled_state; do
        [ -n "$unit_name" ] || continue
        os_guard_service_remember_applied_record "$unit_name|$original_enabled_state"
        case "$original_enabled_state" in
            enabled)
                if ! "$service_systemctl" disable "$unit_name" >/dev/null 2>&1; then
                    os_guard_service_set_error 'SERVICE_DISABLE_FAILED' 'a target unit could not be disabled'
                    return 1
                fi
                ;;
            enabled-runtime)
                if ! "$service_systemctl" disable --runtime "$unit_name" >/dev/null 2>&1; then
                    os_guard_service_set_error 'SERVICE_DISABLE_FAILED' 'a runtime-enabled target unit could not be disabled'
                    return 1
                fi
                ;;
        esac
        service_changes_applied=true
        if ! "$service_systemctl" stop "$unit_name" >/dev/null 2>&1; then
            os_guard_service_set_error 'SERVICE_STOP_FAILED' 'a target unit could not be stopped'
            return 1
        fi
    done <<EOF
$service_active_records
EOF
}

os_guard_service_validate_inactive() {
    while IFS='|' read -r unit_name original_enabled_state; do
        [ -n "$unit_name" ] || continue
        current_active_state=$("$service_systemctl" is-active "$unit_name" 2>/dev/null || true)
        if [ "$current_active_state" = 'active' ]; then
            os_guard_service_set_error 'SERVICE_VALIDATION_FAILED' 'a target unit remains active'
            return 1
        fi
    done <<EOF
$service_active_records
EOF
    service_validation_success=true
}

os_guard_service_rollback() {
    service_rollback_attempted=true
    service_rollback_success=true
    if [ -n "$service_test_root" ] && [ "${OS_GUARD_TEST_FAIL_STEP:-}" = 'rollback' ]; then
        service_rollback_success=false
        return 1
    fi

    while IFS='|' read -r unit_name original_enabled_state; do
        [ -n "$unit_name" ] || continue
        case "$original_enabled_state" in
            enabled)
                "$service_systemctl" enable "$unit_name" >/dev/null 2>&1 || service_rollback_success=false
                ;;
            enabled-runtime)
                "$service_systemctl" enable --runtime "$unit_name" >/dev/null 2>&1 || service_rollback_success=false
                ;;
        esac
        "$service_systemctl" start "$unit_name" >/dev/null 2>&1 || service_rollback_success=false
        restored_active_state=$("$service_systemctl" is-active "$unit_name" 2>/dev/null || true)
        [ "$restored_active_state" = 'active' ] || service_rollback_success=false
        restored_enabled_state=$("$service_systemctl" is-enabled "$unit_name" 2>/dev/null || true)
        [ "$restored_enabled_state" = "$original_enabled_state" ] || service_rollback_success=false
    done <<EOF
$service_applied_records
EOF
    [ "$service_rollback_success" = true ]
}

os_guard_service_execute() {
    if ! os_guard_service_validate_authorization || ! os_guard_service_create_backup; then
        return 1
    fi
    if ! os_guard_service_apply || ! os_guard_service_validate_inactive; then
        os_guard_service_rollback || true
        return 1
    fi
    if [ -n "$service_test_root" ] && [ "${OS_GUARD_TEST_FORCE_RECHECK_FAILURE:-false}" = 'true' ]; then
        service_check_status='VULNERABLE'
    elif ! os_guard_service_run_check; then
        service_check_status='ERROR'
    fi
    if [ "$service_check_status" != 'GOOD' ]; then
        os_guard_service_set_error 'RECHECK_FAILED' 'the existing CHECK did not return GOOD after remediation'
        os_guard_service_rollback || true
        return 1
    fi
    service_outcome='SUCCESS'
}

os_guard_service_build_result() {
    change_required=false
    backup_required=false
    service_stop_required=false
    if [ "$service_active_count" -gt 0 ]; then
        change_required=true
        backup_required=true
        service_stop_required=true
    fi
    active_units_json=$(printf '%s\n' "$service_active_records" | \
        awk -F'|' 'NF { print $1 }' | os_guard_json_array_from_lines)

    printf '{"item_id":'
    os_guard_json_quote "$HARDEN_ITEM_ID"
    printf ',"action":'
    os_guard_json_quote "$service_requested_action"
    printf ',"outcome":'
    os_guard_json_quote "$service_outcome"
    printf ',"preview":{"target":'
    os_guard_json_quote "$HARDEN_TARGET_DESCRIPTION"
    printf ',"current_check_status":'
    os_guard_json_quote "$service_check_status"
    printf ',"active_unit_count":%s,"active_units":%s' "$service_active_count" "$active_units_json"
    printf ',"expected_state":"inactive; enabled units become disabled"'
    printf ',"proposed_change":"disable enabled target units and stop active target units"'
    printf ',"change_required":%s,"backup_required":%s' "$change_required" "$backup_required"
    printf ',"service_restart_required":false,"service_stop_required":%s' "$service_stop_required"
    printf ',"reboot_required":false,"risk":"HIGH","state_fingerprint":'
    os_guard_harden_json_nullable_string "$service_state_fingerprint"
    printf '},"execution":{"backup_created":%s,"backup_id":' "$service_backup_created"
    os_guard_harden_json_nullable_string "$service_backup_id"
    printf ',"changes_applied":%s,"validation_success":%s,"recheck_status":' \
        "$service_changes_applied" "$service_validation_success"
    os_guard_json_quote "$service_check_status"
    printf ',"rollback_attempted":%s,"rollback_success":%s},"error":' \
        "$service_rollback_attempted" "$service_rollback_success"
    if [ -n "$service_error_code" ]; then
        printf '{"code":'
        os_guard_json_quote "$service_error_code"
        printf ',"message":'
        os_guard_json_quote "$service_error_message"
        printf '}'
    else
        printf 'null'
    fi
    printf '}\n'
}

os_guard_service_run() {
    os_guard_service_initialize "$1"
    case "$service_requested_action" in
        PREVIEW|EXECUTE)
            ;;
        *)
            os_guard_service_set_error 'INVALID_ACTION' 'action must be PREVIEW or EXECUTE'
            os_guard_service_build_result
            return
            ;;
    esac
    if ! os_guard_harden_is_supported_os "$service_distro" "$service_version_id"; then
        os_guard_service_set_error 'UNSUPPORTED_OS_CONFIGURATION' 'the current operating system is not supported'
        os_guard_service_build_result
        return
    fi
    if [ "$service_requested_action" = 'EXECUTE' ] && [ -z "$service_test_root" ]; then
        process_uid=$(id -u 2>/dev/null || true)
        if [ "$process_uid" != '0' ]; then
            os_guard_service_set_error 'ROOT_PRIVILEGES_REQUIRED' 'EXECUTE requires root privileges'
            os_guard_service_build_result
            return
        fi
    fi
    if ! os_guard_service_resolve_commands; then
        os_guard_service_build_result
        return
    fi
    os_guard_service_require_actionable_check
    actionable_status=$?
    if [ "$actionable_status" -eq 2 ]; then
        os_guard_service_build_result
        return
    fi
    if [ "$actionable_status" -ne 0 ]; then
        os_guard_service_build_result
        return
    fi
    if os_guard_service_legacy_activation_is_enabled; then
        os_guard_service_set_error 'LEGACY_ACTIVATION_REQUIRES_MANUAL_REMEDIATION' 'active inetd or xinetd configuration is not changed automatically'
        os_guard_service_build_result
        return
    fi
    if os_guard_service_has_active_guard_unit; then
        os_guard_service_set_error 'OPERATIONAL_DEPENDENCY_REQUIRES_MANUAL_REMEDIATION' 'an operation-sensitive dependent service is active'
        os_guard_service_build_result
        return
    fi
    if ! os_guard_service_collect_active_units; then
        os_guard_service_build_result
        return
    fi
    if command -v os_guard_item_validate_service_policy >/dev/null 2>&1 && \
        ! os_guard_item_validate_service_policy; then
        if [ -z "$service_error_code" ]; then
            os_guard_service_set_error \
                'POLICY_PRECONDITION_FAILED' \
                'the item-specific service policy precondition failed'
        fi
        os_guard_service_build_result
        return
    fi
    if [ "$service_requested_action" = 'PREVIEW' ]; then
        service_outcome='PLANNED'
        os_guard_service_build_result
        return
    fi
    os_guard_service_execute || true
    os_guard_service_build_result
}
