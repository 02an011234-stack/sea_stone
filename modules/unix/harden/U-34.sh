#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"

HARDEN_ITEM_ID='U-34'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-34.sh"

requested_action=${1:-}
distro=${OS_GUARD_DISTRO:-unknown}
version_id=${OS_GUARD_VERSION_ID:-unknown}
test_root=${OS_GUARD_TEST_ROOT:-}

outcome='FAILED'
error_code=''
error_message=''
check_status='NOT_RUN'
active_unit_records=''
active_unit_count=0
state_fingerprint=''
backup_created=false
backup_id=''
backup_directory=''
changes_applied=false
validation_success=false
rollback_attempted=false
rollback_success=false

finger_units='finger.service
fingerd.service
finger.socket
fingerd.socket'

set_error() {
    error_code=$1
    error_message=$2
    outcome='FAILED'
}

resolve_systemctl() {
    if [ -n "$test_root" ] && [ -n "${OS_GUARD_TEST_SYSTEMCTL_BIN:-}" ]; then
        systemctl_command=$OS_GUARD_TEST_SYSTEMCTL_BIN
    else
        systemctl_command=$(command -v systemctl 2>/dev/null || true)
    fi

    if [ -z "$systemctl_command" ] || [ ! -x "$systemctl_command" ]; then
        set_error 'SYSTEMCTL_UNAVAILABLE' 'systemctl is required for the supported U-34 remediation path'
        return 1
    fi

    sha256_command=$(command -v sha256sum 2>/dev/null || true)
    if [ -z "$sha256_command" ] || [ ! -x "$sha256_command" ]; then
        set_error 'SHA256_COMMAND_UNAVAILABLE' 'sha256sum is required for approval state binding'
        return 1
    fi
    return 0
}

run_check() {
    if [ -n "$test_root" ] && [ "${OS_GUARD_TEST_CHECK_FAILURE:-false}" = 'true' ]; then
        check_status='ERROR'
        return 1
    fi

    check_output=$("$HARDEN_CHECK_SCRIPT" 2>/dev/null)
    if [ $? -ne 0 ]; then
        check_status='ERROR'
        return 1
    fi

    for possible_status in GOOD VULNERABLE UNCHECKABLE N/A; do
        if printf '%s\n' "$check_output" | grep -Eq \
            '"item_id":"U-34".*"status":"'"$possible_status"'"'; then
            check_status=$possible_status
            return 0
        fi
    done

    if printf '%s\n' "$check_output" | grep -Eq \
        '"item_id":"U-34".*"status":null'; then
        check_status='PENDING'
        return 0
    fi

    check_status='INVALID'
    return 1
}

require_actionable_check() {
    if ! run_check; then
        set_error 'CHECK_EXECUTION_FAILED' 'the existing U-34 CHECK could not be evaluated'
        return 1
    fi

    case "$check_status" in
        GOOD|N/A)
            outcome='NO_CHANGE'
            return 2
            ;;
        VULNERABLE)
            return 0
            ;;
        PENDING|UNCHECKABLE)
            set_error 'CHECK_STATE_NOT_ACTIONABLE' 'the U-34 CHECK result is not actionable'
            return 1
            ;;
        *)
            set_error 'CHECK_RESULT_INVALID' 'the U-34 CHECK returned an invalid result'
            return 1
            ;;
    esac
}

legacy_activation_is_enabled() {
    inetd_path="${test_root}/etc/inetd.conf"
    xinetd_path="${test_root}/etc/xinetd.d/finger"

    if [ -r "$inetd_path" ] && \
        grep -Eq '^[[:space:]]*finger[[:space:]]' "$inetd_path"; then
        return 0
    fi

    if [ -r "$xinetd_path" ] && \
        grep -Eiq 'disable[[:space:]]*=[[:space:]]*no' "$xinetd_path"; then
        return 0
    fi

    return 1
}

append_active_unit() {
    unit_name=$1
    enabled_state=$2
    unit_record="$unit_name|$enabled_state"

    if [ -z "$active_unit_records" ]; then
        active_unit_records=$unit_record
    else
        active_unit_records="$active_unit_records
$unit_record"
    fi
    active_unit_count=$((active_unit_count + 1))
}

collect_active_units() {
    active_unit_records=''
    active_unit_count=0

    while IFS= read -r unit_name; do
        [ -n "$unit_name" ] || continue

        unit_active_state=$("$systemctl_command" is-active "$unit_name" 2>/dev/null || true)
        [ "$unit_active_state" = 'active' ] || continue

        unit_enabled_state=$("$systemctl_command" is-enabled "$unit_name" 2>/dev/null || true)
        case "$unit_enabled_state" in
            enabled|enabled-runtime|disabled|static|indirect)
                ;;
            masked|masked-runtime)
                set_error 'MASKED_ACTIVE_UNIT_UNSAFE' 'an active masked Finger unit cannot be restored safely'
                return 1
                ;;
            *)
                set_error 'SYSTEMD_STATE_UNRESOLVED' 'an active Finger unit has an unsupported enablement state'
                return 1
                ;;
        esac

        append_active_unit "$unit_name" "$unit_enabled_state"
    done <<EOF
$finger_units
EOF

    if [ "$active_unit_count" -eq 0 ]; then
        set_error 'ACTIVE_UNIT_NOT_RESOLVED' 'the vulnerable Finger activation path is not a supported systemd unit'
        return 1
    fi

    state_fingerprint=$(printf '%s\n' "$active_unit_records" | \
        "$sha256_command" | awk '{ print $1 }')
    if [ -z "$state_fingerprint" ]; then
        set_error 'STATE_FINGERPRINT_FAILED' 'the Finger unit state fingerprint could not be created'
        return 1
    fi
    return 0
}

validate_authorization() {
    if [ "${OS_GUARD_HARDEN_APPROVED:-}" != 'true' ]; then
        set_error 'APPROVAL_REQUIRED' 'EXECUTE requires explicit administrator approval'
        return 1
    fi

    approved_fingerprint=${OS_GUARD_HARDEN_EXPECTED_STATE:-}
    if [ -z "$approved_fingerprint" ]; then
        set_error 'EXPECTED_STATE_REQUIRED' 'EXECUTE requires the PREVIEW state fingerprint'
        return 1
    fi

    if [ "$approved_fingerprint" != "$state_fingerprint" ]; then
        set_error 'STATE_DRIFT' 'the Finger unit state changed after PREVIEW'
        return 1
    fi
    return 0
}

create_backup() {
    if [ -n "$test_root" ] && [ "${OS_GUARD_TEST_FAIL_STEP:-}" = 'backup' ]; then
        set_error 'BACKUP_FAILED' 'Finger unit state backup creation failed'
        return 1
    fi

    if [ -n "$test_root" ]; then
        default_backup_root="${test_root}/var/lib/os-guard-agent/backups/U-34"
        backup_root=${OS_GUARD_TEST_BACKUP_ROOT:-$default_backup_root}
    else
        backup_root='/var/lib/os-guard-agent/backups/U-34'
    fi

    if ! os_guard_harden_create_private_directory "$backup_root"; then
        set_error 'BACKUP_FAILED' 'the private U-34 backup directory could not be prepared'
        return 1
    fi

    backup_directory=$(mktemp -d "$backup_root/backup.XXXXXX" 2>/dev/null || true)
    if [ -z "$backup_directory" ] || ! chmod 0700 -- "$backup_directory"; then
        set_error 'BACKUP_FAILED' 'the private U-34 backup could not be created'
        return 1
    fi

    if ! printf '%s\n' "$active_unit_records" > "$backup_directory/unit-state" || \
        ! chmod 0600 -- "$backup_directory/unit-state"; then
        set_error 'BACKUP_FAILED' 'the Finger unit state backup could not be written'
        return 1
    fi

    backup_created=true
    backup_id=${backup_directory##*/}
    return 0
}

disable_active_units() {
    while IFS='|' read -r unit_name original_enabled_state; do
        [ -n "$unit_name" ] || continue

        case "$original_enabled_state" in
            enabled)
                if ! "$systemctl_command" disable "$unit_name" >/dev/null 2>&1; then
                    set_error 'SERVICE_DISABLE_FAILED' 'a Finger systemd unit could not be disabled'
                    return 1
                fi
                ;;
            enabled-runtime)
                if ! "$systemctl_command" disable --runtime "$unit_name" >/dev/null 2>&1; then
                    set_error 'SERVICE_DISABLE_FAILED' 'a runtime-enabled Finger systemd unit could not be disabled'
                    return 1
                fi
                ;;
        esac

        if ! "$systemctl_command" stop "$unit_name" >/dev/null 2>&1; then
            set_error 'SERVICE_STOP_FAILED' 'a Finger systemd unit could not be stopped'
            return 1
        fi
        changes_applied=true
    done <<EOF
$active_unit_records
EOF
    return 0
}

validate_inactive_units() {
    while IFS='|' read -r unit_name original_enabled_state; do
        [ -n "$unit_name" ] || continue
        current_active_state=$("$systemctl_command" is-active "$unit_name" 2>/dev/null || true)
        if [ "$current_active_state" = 'active' ]; then
            set_error 'SERVICE_VALIDATION_FAILED' 'a Finger systemd unit remains active'
            return 1
        fi
    done <<EOF
$active_unit_records
EOF
    validation_success=true
    return 0
}

restore_original_units() {
    rollback_attempted=true
    rollback_success=true

    if [ -n "$test_root" ] && [ "${OS_GUARD_TEST_FAIL_STEP:-}" = 'rollback' ]; then
        rollback_success=false
        return 1
    fi

    while IFS='|' read -r unit_name original_enabled_state; do
        [ -n "$unit_name" ] || continue

        case "$original_enabled_state" in
            enabled)
                if ! "$systemctl_command" enable "$unit_name" >/dev/null 2>&1; then
                    rollback_success=false
                fi
                ;;
            enabled-runtime)
                if ! "$systemctl_command" enable --runtime "$unit_name" >/dev/null 2>&1; then
                    rollback_success=false
                fi
                ;;
        esac

        if ! "$systemctl_command" start "$unit_name" >/dev/null 2>&1; then
            rollback_success=false
        fi
    done <<EOF
$active_unit_records
EOF

    [ "$rollback_success" = true ]
}

execute_hardening() {
    if ! validate_authorization || ! create_backup; then
        return 1
    fi

    if ! disable_active_units || ! validate_inactive_units; then
        restore_original_units || true
        return 1
    fi

    if [ -n "$test_root" ] && \
        [ "${OS_GUARD_TEST_FORCE_RECHECK_FAILURE:-false}" = 'true' ]; then
        check_status='VULNERABLE'
    elif ! run_check; then
        check_status='ERROR'
    fi

    if [ "$check_status" != 'GOOD' ]; then
        set_error 'RECHECK_FAILED' 'the U-34 CHECK did not return GOOD after remediation'
        restore_original_units || true
        return 1
    fi

    outcome='SUCCESS'
    return 0
}

build_result_json() {
    change_required=false
    backup_required=false
    service_stop_required=false
    if [ "$active_unit_count" -gt 0 ]; then
        change_required=true
        backup_required=true
        service_stop_required=true
    fi

    active_units_json=$(printf '%s\n' "$active_unit_records" | \
        awk -F'|' 'NF { print $1 }' | os_guard_json_array_from_lines)

    printf '{"item_id":"U-34","action":'
    os_guard_json_quote "$requested_action"
    printf ',"outcome":'
    os_guard_json_quote "$outcome"
    printf ',"preview":{"target":"Finger systemd activation units","current_check_status":'
    os_guard_json_quote "$check_status"
    printf ',"active_unit_count":%s,"active_units":%s' \
        "$active_unit_count" "$active_units_json"
    printf ',"expected_state":"inactive; enabled units become disabled"'
    printf ',"proposed_change":"disable enabled Finger units and stop active Finger units","change_required":%s' \
        "$change_required"
    printf ',"backup_required":%s' "$backup_required"
    printf ',"service_restart_required":false,"service_stop_required":%s' \
        "$service_stop_required"
    printf ',"reboot_required":false,"risk":"HIGH","state_fingerprint":'
    os_guard_harden_json_nullable_string "$state_fingerprint"
    printf '},"execution":{"backup_created":%s,"backup_id":' "$backup_created"
    os_guard_harden_json_nullable_string "$backup_id"
    printf ',"changes_applied":%s,"validation_success":%s,"recheck_status":' \
        "$changes_applied" "$validation_success"
    os_guard_json_quote "$check_status"
    printf ',"rollback_attempted":%s,"rollback_success":%s},"error":' \
        "$rollback_attempted" "$rollback_success"

    if [ -n "$error_code" ]; then
        printf '{"code":'
        os_guard_json_quote "$error_code"
        printf ',"message":'
        os_guard_json_quote "$error_message"
        printf '}'
    else
        printf 'null'
    fi
    printf '}\n'
}

main() {
    case "$requested_action" in
        PREVIEW|EXECUTE)
            ;;
        *)
            set_error 'INVALID_ACTION' 'action must be PREVIEW or EXECUTE'
            build_result_json
            return
            ;;
    esac

    if ! os_guard_harden_is_supported_os "$distro" "$version_id"; then
        set_error 'UNSUPPORTED_OS_CONFIGURATION' 'the current operating system is not supported'
        build_result_json
        return
    fi

    if [ "$requested_action" = 'EXECUTE' ] && [ -z "$test_root" ]; then
        process_uid=$(id -u 2>/dev/null || true)
        if [ "$process_uid" != '0' ]; then
            set_error 'ROOT_PRIVILEGES_REQUIRED' 'EXECUTE requires root privileges'
            build_result_json
            return
        fi
    fi

    if ! resolve_systemctl; then
        build_result_json
        return
    fi

    require_actionable_check
    actionable_status=$?
    if [ "$actionable_status" -eq 2 ]; then
        build_result_json
        return
    fi
    if [ "$actionable_status" -ne 0 ]; then
        build_result_json
        return
    fi

    if legacy_activation_is_enabled; then
        set_error \
            'LEGACY_ACTIVATION_REQUIRES_MANUAL_REMEDIATION' \
            'active inetd or xinetd Finger configuration is not changed automatically'
        build_result_json
        return
    fi

    if ! collect_active_units; then
        build_result_json
        return
    fi

    if [ "$requested_action" = 'PREVIEW' ]; then
        outcome='PLANNED'
        build_result_json
        return
    fi

    execute_hardening || true
    build_result_json
}

main
