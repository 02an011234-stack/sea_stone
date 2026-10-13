#!/bin/sh

os_guard_harden_is_supported_os() {
    distro_name=$1
    distro_version=$2

    case "$distro_name:$distro_version" in
        rocky:9|rocky:9.*|rocky:10|rocky:10.*|ubuntu:22|ubuntu:22.*|ubuntu:24|ubuntu:24.*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

os_guard_harden_is_unsigned_integer() {
    candidate_value=$1

    case "$candidate_value" in
        ''|*[!0-9]*)
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}

os_guard_harden_is_octal_mode() {
    candidate_mode=$1

    case "$candidate_mode" in
        ''|*[!0-7]*)
            return 1
            ;;
    esac

    mode_length=${#candidate_mode}
    if [ "$mode_length" -lt 1 ] || [ "$mode_length" -gt 4 ]; then
        return 1
    fi

    return 0
}

os_guard_harden_create_private_directory() {
    directory_path=$1

    if [ ! -d "$directory_path" ]; then
        if ! mkdir -p -- "$directory_path"; then
            return 1
        fi
    fi

    if ! chmod 0700 -- "$directory_path"; then
        return 1
    fi

    return 0
}

os_guard_harden_json_nullable_string() {
    nullable_value=$1

    if [ -n "$nullable_value" ]; then
        os_guard_json_quote "$nullable_value"
    else
        printf 'null'
    fi
}

os_guard_harden_resolve_file_commands() {
    if [ -n "$harden_test_root" ] && [ -n "${OS_GUARD_TEST_STAT_BIN:-}" ]; then
        harden_stat_command=$OS_GUARD_TEST_STAT_BIN
    else
        harden_stat_command=$(command -v stat 2>/dev/null || true)
    fi

    if [ -n "$harden_test_root" ] && [ -n "${OS_GUARD_TEST_CHMOD_BIN:-}" ]; then
        harden_chmod_command=$OS_GUARD_TEST_CHMOD_BIN
    else
        harden_chmod_command=$(command -v chmod 2>/dev/null || true)
    fi

    if [ -n "$harden_test_root" ] && [ -n "${OS_GUARD_TEST_CHOWN_BIN:-}" ]; then
        harden_chown_command=$OS_GUARD_TEST_CHOWN_BIN
    else
        harden_chown_command=$(command -v chown 2>/dev/null || true)
    fi

    if [ -z "$harden_stat_command" ] || [ ! -x "$harden_stat_command" ]; then
        os_guard_harden_set_error 'STAT_COMMAND_UNAVAILABLE' 'required metadata command is unavailable'
        return 1
    fi

    if [ "$harden_requested_action" = 'EXECUTE' ]; then
        if [ -z "$harden_chmod_command" ] || [ ! -x "$harden_chmod_command" ]; then
            os_guard_harden_set_error 'CHMOD_COMMAND_UNAVAILABLE' 'required permission command is unavailable'
            return 1
        fi

        if [ -z "$harden_chown_command" ] || [ ! -x "$harden_chown_command" ]; then
            os_guard_harden_set_error 'CHOWN_COMMAND_UNAVAILABLE' 'required ownership command is unavailable'
            return 1
        fi
    fi

    return 0
}

os_guard_harden_set_error() {
    harden_error_code=$1
    harden_error_message=$2
    harden_outcome='FAILED'
}

os_guard_harden_detect_file_environment() {
    case "$harden_requested_action" in
        PREVIEW|EXECUTE)
            ;;
        *)
            os_guard_harden_set_error 'INVALID_ACTION' 'action must be PREVIEW or EXECUTE'
            return 1
            ;;
    esac

    if ! os_guard_harden_is_supported_os "$harden_distro" "$harden_version_id"; then
        os_guard_harden_set_error 'UNSUPPORTED_OS_CONFIGURATION' 'the current operating system is not supported'
        return 1
    fi

    if [ "$harden_requested_action" = 'EXECUTE' ] && [ -z "$harden_test_root" ]; then
        harden_process_uid=$(id -u 2>/dev/null || true)
        if [ "$harden_process_uid" != '0' ]; then
            os_guard_harden_set_error 'ROOT_PRIVILEGES_REQUIRED' 'EXECUTE requires root privileges'
            return 1
        fi
    fi

    os_guard_harden_resolve_file_commands
}

os_guard_harden_target_is_missing() {
    if [ ! -e "$harden_target_file" ] && [ ! -L "$harden_target_file" ]; then
        return 0
    fi

    return 1
}

os_guard_harden_test_forces_symlink() {
    if [ -n "$harden_test_root" ] && [ "${OS_GUARD_TEST_FORCE_SYMLINK:-false}" = 'true' ]; then
        return 0
    fi

    return 1
}

os_guard_harden_test_forces_nonregular() {
    if [ -n "$harden_test_root" ] && [ "${OS_GUARD_TEST_FORCE_NONREGULAR:-false}" = 'true' ]; then
        return 0
    fi

    return 1
}

os_guard_harden_validate_file_target() {
    if os_guard_harden_test_forces_symlink || [ -L "$harden_target_file" ]; then
        os_guard_harden_set_error 'SYMLINK_TARGET_REJECTED' 'the target is a symbolic link'
        return 1
    fi

    if os_guard_harden_target_is_missing; then
        os_guard_harden_set_error 'TARGET_NOT_FOUND' 'the target does not exist'
        return 1
    fi

    if os_guard_harden_test_forces_nonregular || [ ! -f "$harden_target_file" ]; then
        os_guard_harden_set_error 'TARGET_NOT_REGULAR_FILE' 'the target is not a regular file'
        return 1
    fi

    return 0
}

os_guard_harden_collect_file_state() {
    harden_metadata_output=$(
        "$harden_stat_command" -c '%d|%i|%u|%U|%g|%a|%Y|%Z|%C' -- "$harden_target_file" 2>/dev/null
    )
    harden_metadata_status=$?

    if [ "$harden_metadata_status" -ne 0 ]; then
        os_guard_harden_set_error 'STAT_COMMAND_FAILED' 'target metadata collection failed'
        return 1
    fi

    harden_metadata_valid=$(printf '%s\n' "$harden_metadata_output" | awk -F'|' '
        NF == 9 &&
        $1 ~ /^[0-9]+$/ &&
        $2 ~ /^[0-9]+$/ &&
        $3 ~ /^[0-9]+$/ &&
        $4 != "" &&
        $5 ~ /^[0-9]+$/ &&
        $6 ~ /^[0-7]+$/ &&
        length($6) <= 4 &&
        $7 ~ /^[0-9]+$/ &&
        $8 ~ /^[0-9]+$/ {
            valid_record_count++
            next
        }
        {
            invalid_record_count++
        }
        END {
            if (NR == 1 && valid_record_count == 1 && invalid_record_count == 0) {
                print "true"
            } else {
                print "false"
            }
        }
    ')

    if [ "$harden_metadata_valid" != 'true' ]; then
        os_guard_harden_set_error 'STAT_OUTPUT_INVALID' 'target metadata output is invalid'
        return 1
    fi

    harden_current_device=$(printf '%s\n' "$harden_metadata_output" | awk -F'|' '{ print $1 }')
    harden_current_inode=$(printf '%s\n' "$harden_metadata_output" | awk -F'|' '{ print $2 }')
    harden_current_owner_uid=$(printf '%s\n' "$harden_metadata_output" | awk -F'|' '{ print $3 }')
    harden_current_owner_name=$(printf '%s\n' "$harden_metadata_output" | awk -F'|' '{ print $4 }')
    harden_current_group_gid=$(printf '%s\n' "$harden_metadata_output" | awk -F'|' '{ print $5 }')
    harden_current_permission=$(printf '%s\n' "$harden_metadata_output" | awk -F'|' '{ print $6 }')
    harden_current_mtime=$(printf '%s\n' "$harden_metadata_output" | awk -F'|' '{ print $7 }')
    harden_current_ctime=$(printf '%s\n' "$harden_metadata_output" | awk -F'|' '{ print $8 }')
    harden_current_selinux_context=$(printf '%s\n' "$harden_metadata_output" | awk -F'|' '{ print $9 }')

    harden_state_fingerprint=$(printf '%s:%s:%s:%s:%s:%s:%s' \
        "$harden_current_device" \
        "$harden_current_inode" \
        "$harden_current_owner_uid" \
        "$harden_current_group_gid" \
        "$harden_current_permission" \
        "$harden_current_mtime" \
        "$harden_current_ctime")

    return 0
}

os_guard_harden_calculate_file_plan() {
    harden_owner_change_required=false
    harden_permission_change_required=false

    if ! os_guard_item_owner_is_acceptable "$harden_current_owner_uid" "$harden_current_owner_name"; then
        harden_owner_change_required=true
    fi

    harden_permission_value=$((0$harden_current_permission))
    harden_allowed_permission_value=$((HARDEN_ALLOWED_PERMISSION_MASK))
    harden_extra_permission_value=$((harden_permission_value & ~harden_allowed_permission_value))

    if [ "$harden_extra_permission_value" -eq 0 ]; then
        harden_expected_permission=$harden_current_permission
    else
        harden_reduced_permission_value=$((harden_permission_value & harden_allowed_permission_value))
        harden_expected_permission=$(printf '%03o' "$harden_reduced_permission_value")
        harden_permission_change_required=true
    fi

    if [ "$harden_owner_change_required" = true ] || [ "$harden_permission_change_required" = true ]; then
        harden_backup_required=true
    else
        harden_backup_required=false
    fi
}

os_guard_harden_run_existing_check() {
    if [ -n "$harden_test_root" ] && [ "${OS_GUARD_TEST_CHECK_FAILURE:-false}" = 'true' ]; then
        harden_recheck_status='ERROR'
        return 1
    fi

    harden_check_output=$(
        "$HARDEN_CHECK_SCRIPT" 2>/dev/null
    )
    harden_check_exit_status=$?

    if [ "$harden_check_exit_status" -ne 0 ]; then
        harden_recheck_status='ERROR'
        return 1
    fi

    if printf '%s\n' "$harden_check_output" | grep -Eq '"item_id":"'"$HARDEN_ITEM_ID"'".*"status":"GOOD"'; then
        harden_recheck_status='GOOD'
        return 0
    fi

    if printf '%s\n' "$harden_check_output" | grep -Eq '"item_id":"'"$HARDEN_ITEM_ID"'".*"status":"VULNERABLE"'; then
        harden_recheck_status='VULNERABLE'
        return 0
    fi

    if printf '%s\n' "$harden_check_output" | grep -Eq '"item_id":"'"$HARDEN_ITEM_ID"'".*"status":"UNCHECKABLE"'; then
        harden_recheck_status='UNCHECKABLE'
        return 0
    fi

    if printf '%s\n' "$harden_check_output" | grep -Eq '"item_id":"'"$HARDEN_ITEM_ID"'".*"status":"N/A"'; then
        harden_recheck_status='N/A'
        return 0
    fi

    if printf '%s\n' "$harden_check_output" | grep -Eq '"item_id":"'"$HARDEN_ITEM_ID"'".*"status":null'; then
        harden_recheck_status='PENDING'
        return 0
    fi

    harden_recheck_status='INVALID'
    return 1
}

os_guard_harden_require_vulnerable_check() {
    if ! os_guard_harden_run_existing_check; then
        os_guard_harden_set_error 'CHECK_EXECUTION_FAILED' 'the existing CHECK could not be evaluated'
        return 1
    fi

    case "$harden_recheck_status" in
        GOOD|N/A)
            harden_outcome='NO_CHANGE'
            return 2
            ;;
        VULNERABLE)
            return 0
            ;;
        PENDING|UNCHECKABLE)
            os_guard_harden_set_error 'CHECK_STATE_NOT_ACTIONABLE' 'the CHECK result is not actionable'
            return 1
            ;;
        *)
            os_guard_harden_set_error 'CHECK_RESULT_INVALID' 'the existing CHECK returned an invalid result'
            return 1
            ;;
    esac
}

os_guard_harden_validate_file_authorization() {
    if [ "${OS_GUARD_HARDEN_APPROVED:-}" != 'true' ]; then
        os_guard_harden_set_error 'APPROVAL_REQUIRED' 'EXECUTE requires an explicit approval flag'
        return 1
    fi

    harden_expected_state=${OS_GUARD_HARDEN_EXPECTED_STATE:-}
    if [ -z "$harden_expected_state" ]; then
        os_guard_harden_set_error 'EXPECTED_STATE_REQUIRED' 'EXECUTE requires the PREVIEW state fingerprint'
        return 1
    fi

    if [ "$harden_expected_state" != "$harden_state_fingerprint" ]; then
        os_guard_harden_set_error 'STATE_DRIFT' 'target metadata changed after PREVIEW'
        return 1
    fi

    return 0
}

os_guard_harden_create_file_backup() {
    if [ -n "$harden_test_root" ] && [ "${OS_GUARD_TEST_FAIL_STEP:-}" = 'backup' ]; then
        os_guard_harden_set_error 'BACKUP_FAILED' 'metadata backup creation failed'
        return 1
    fi

    if [ -n "$harden_test_root" ]; then
        default_test_backup_directory="${harden_test_root}/var/lib/os-guard-agent/backups/${HARDEN_ITEM_ID}"
        harden_backup_base_directory=${OS_GUARD_TEST_BACKUP_ROOT:-"$default_test_backup_directory"}
    else
        harden_backup_base_directory="/var/lib/os-guard-agent/backups/${HARDEN_ITEM_ID}"
    fi

    if ! os_guard_harden_create_private_directory "$harden_backup_base_directory"; then
        os_guard_harden_set_error 'BACKUP_FAILED' 'backup base directory creation failed'
        return 1
    fi

    harden_backup_directory=$(mktemp -d "$harden_backup_base_directory/backup.XXXXXX" 2>/dev/null || true)
    if [ -z "$harden_backup_directory" ]; then
        os_guard_harden_set_error 'BACKUP_FAILED' 'private backup directory creation failed'
        return 1
    fi

    if ! chmod 0700 -- "$harden_backup_directory"; then
        os_guard_harden_set_error 'BACKUP_FAILED' 'private backup directory permission setup failed'
        return 1
    fi

    harden_backup_identifier=${harden_backup_directory##*/}
    harden_backup_metadata_file="$harden_backup_directory/metadata"
    harden_backup_acl_file="$harden_backup_directory/acl.restore"

    if ! printf '%s|%s|%s|%s|%s|%s\n' \
        "$harden_current_device" \
        "$harden_current_inode" \
        "$harden_current_owner_uid" \
        "$harden_current_group_gid" \
        "$harden_current_permission" \
        "$harden_current_selinux_context" > "$harden_backup_metadata_file"; then
        os_guard_harden_set_error 'BACKUP_FAILED' 'metadata backup write failed'
        return 1
    fi

    if ! chmod 0600 -- "$harden_backup_metadata_file"; then
        os_guard_harden_set_error 'BACKUP_FAILED' 'metadata backup permission setup failed'
        return 1
    fi

    if [ -n "$harden_test_root" ] && [ "${OS_GUARD_TEST_DISABLE_ACL_BACKUP:-false}" = 'true' ]; then
        harden_getfacl_command=''
    else
        harden_getfacl_command=$(command -v getfacl 2>/dev/null || true)
    fi

    if [ -n "$harden_getfacl_command" ]; then
        if ! "$harden_getfacl_command" -p -- "$harden_target_file" > "$harden_backup_acl_file" 2>/dev/null; then
            os_guard_harden_set_error 'BACKUP_FAILED' 'ACL backup failed'
            return 1
        fi

        if ! chmod 0600 -- "$harden_backup_acl_file"; then
            os_guard_harden_set_error 'BACKUP_FAILED' 'ACL backup permission setup failed'
            return 1
        fi

        harden_acl_backup_created=true
    fi

    harden_backup_created=true
    return 0
}

os_guard_harden_apply_file_changes() {
    if [ "$harden_owner_change_required" = true ]; then
        if [ -n "$harden_test_root" ] && [ "${OS_GUARD_TEST_FAIL_STEP:-}" = 'chown' ]; then
            os_guard_harden_set_error 'CHOWN_FAILED' 'owner hardening failed'
            return 1
        fi

        if ! "$harden_chown_command" "$HARDEN_REMEDIATION_OWNER_UID" -- "$harden_target_file"; then
            os_guard_harden_set_error 'CHOWN_FAILED' 'owner hardening failed'
            return 1
        fi

        harden_changes_applied=true
    fi

    if [ "$harden_permission_change_required" = true ]; then
        if [ -n "$harden_test_root" ] && [ "${OS_GUARD_TEST_FAIL_STEP:-}" = 'chmod' ]; then
            os_guard_harden_set_error 'CHMOD_FAILED' 'permission hardening failed'
            return 1
        fi

        if ! "$harden_chmod_command" "$harden_expected_permission" -- "$harden_target_file"; then
            os_guard_harden_set_error 'CHMOD_FAILED' 'permission hardening failed'
            return 1
        fi

        harden_changes_applied=true
    fi

    return 0
}

os_guard_harden_validate_file_result() {
    if [ -n "$harden_test_root" ] && [ "${OS_GUARD_TEST_FORCE_VALIDATION_FAILURE:-false}" = 'true' ]; then
        os_guard_harden_set_error 'VALIDATION_FAILED' 'forced metadata validation failure'
        return 1
    fi

    if ! os_guard_harden_validate_file_target; then
        return 1
    fi

    if ! os_guard_harden_collect_file_state; then
        return 1
    fi

    if ! os_guard_item_owner_is_acceptable "$harden_current_owner_uid" "$harden_current_owner_name"; then
        os_guard_harden_set_error 'VALIDATION_FAILED' 'owner validation failed'
        return 1
    fi

    harden_permission_value=$((0$harden_current_permission))
    harden_allowed_permission_value=$((HARDEN_ALLOWED_PERMISSION_MASK))
    harden_extra_permission_value=$((harden_permission_value & ~harden_allowed_permission_value))
    if [ "$harden_extra_permission_value" -ne 0 ]; then
        os_guard_harden_set_error 'VALIDATION_FAILED' 'permission validation failed'
        return 1
    fi

    harden_validation_success=true
    return 0
}

os_guard_harden_run_final_file_check() {
    if [ -n "$harden_test_root" ] && [ "${OS_GUARD_TEST_FORCE_RECHECK_FAILURE:-false}" = 'true' ]; then
        harden_recheck_status='VULNERABLE'
        os_guard_harden_set_error 'RECHECK_FAILED' 'the existing CHECK did not return GOOD'
        return 1
    fi

    if ! os_guard_harden_run_existing_check; then
        os_guard_harden_set_error 'RECHECK_FAILED' 'the existing CHECK could not be evaluated'
        return 1
    fi

    if [ "$harden_recheck_status" != 'GOOD' ]; then
        os_guard_harden_set_error 'RECHECK_FAILED' 'the existing CHECK did not return GOOD'
        return 1
    fi

    return 0
}

os_guard_harden_rollback_file_changes() {
    harden_rollback_attempted=true
    harden_rollback_success=false

    if [ -n "$harden_test_root" ] && [ "${OS_GUARD_TEST_FAIL_STEP:-}" = 'rollback' ]; then
        return 1
    fi

    if [ -L "$harden_target_file" ] || [ ! -f "$harden_target_file" ]; then
        return 1
    fi

    harden_rollback_identity=$(
        "$harden_stat_command" -c '%d|%i' -- "$harden_target_file" 2>/dev/null
    )
    if [ "$harden_rollback_identity" != "$harden_original_device|$harden_original_inode" ]; then
        return 1
    fi

    OS_GUARD_HARDEN_ROLLBACK=true
    export OS_GUARD_HARDEN_ROLLBACK

    if ! "$harden_chown_command" "$harden_original_owner_uid:$harden_original_group_gid" -- "$harden_target_file"; then
        return 1
    fi

    if ! "$harden_chmod_command" "$harden_original_permission" -- "$harden_target_file"; then
        return 1
    fi

    if [ "$harden_acl_backup_created" = true ]; then
        harden_setfacl_command=$(command -v setfacl 2>/dev/null || true)
        if [ -z "$harden_setfacl_command" ]; then
            return 1
        fi

        if ! "$harden_setfacl_command" --restore="$harden_backup_acl_file" >/dev/null 2>&1; then
            return 1
        fi
    fi

    if ! os_guard_harden_collect_file_state; then
        return 1
    fi

    if [ "$harden_current_owner_uid" != "$harden_original_owner_uid" ]; then
        return 1
    fi

    if [ "$harden_current_group_gid" != "$harden_original_group_gid" ]; then
        return 1
    fi

    if [ "$harden_current_permission" != "$harden_original_permission" ]; then
        return 1
    fi

    harden_rollback_success=true
    return 0
}

os_guard_harden_remember_file_state() {
    harden_original_owner_uid=$harden_current_owner_uid
    harden_original_group_gid=$harden_current_group_gid
    harden_original_permission=$harden_current_permission
    harden_original_device=$harden_current_device
    harden_original_inode=$harden_current_inode
}

os_guard_harden_execute_file_changes() {
    if ! os_guard_harden_validate_file_authorization; then
        return 1
    fi

    if [ "$harden_owner_change_required" = false ] && [ "$harden_permission_change_required" = false ]; then
        harden_outcome='NO_CHANGE'
        harden_validation_success=true
        return 0
    fi

    os_guard_harden_remember_file_state

    if ! os_guard_harden_create_file_backup; then
        return 1
    fi

    if ! os_guard_harden_apply_file_changes; then
        os_guard_harden_rollback_file_changes || true
        return 1
    fi

    if ! os_guard_harden_validate_file_result; then
        os_guard_harden_rollback_file_changes || true
        return 1
    fi

    if ! os_guard_harden_run_final_file_check; then
        os_guard_harden_rollback_file_changes || true
        return 1
    fi

    harden_outcome='SUCCESS'
    return 0
}

os_guard_harden_build_file_result() {
    printf '{"item_id":'
    os_guard_json_quote "$HARDEN_ITEM_ID"
    printf ',"action":'
    os_guard_harden_json_nullable_string "$harden_requested_action"
    printf ',"outcome":'
    os_guard_json_quote "$harden_outcome"
    printf ',"target":'
    os_guard_json_quote "$HARDEN_TARGET_DISPLAY_PATH"

    printf ',"preview":{"current_owner":'
    os_guard_harden_json_nullable_string "$harden_current_owner_name"
    printf ',"current_owner_uid":'
    os_guard_harden_json_nullable_string "$harden_current_owner_uid"
    printf ',"current_gid":'
    os_guard_harden_json_nullable_string "$harden_current_group_gid"
    printf ',"current_permission":'
    os_guard_harden_json_nullable_string "$harden_current_permission"
    printf ',"expected_owner":'
    os_guard_json_quote "$HARDEN_EXPECTED_OWNER_POLICY"
    printf ',"expected_permission_policy":'
    os_guard_json_quote "$HARDEN_EXPECTED_PERMISSION_POLICY"
    printf ',"expected_permission":'
    os_guard_harden_json_nullable_string "$harden_expected_permission"
    printf ',"owner_change_required":%s' "$harden_owner_change_required"
    printf ',"permission_change_required":%s' "$harden_permission_change_required"
    printf ',"backup_required":%s' "$harden_backup_required"
    printf ',"service_restart_required":false'
    printf ',"reboot_required":false'
    printf ',"risk":"LOW"'
    printf ',"state_fingerprint":'
    os_guard_harden_json_nullable_string "$harden_state_fingerprint"
    printf '}'

    printf ',"execution":{"backup_created":%s' "$harden_backup_created"
    printf ',"backup_id":'
    os_guard_harden_json_nullable_string "$harden_backup_identifier"
    printf ',"changes_applied":%s' "$harden_changes_applied"
    printf ',"validation_success":%s' "$harden_validation_success"
    printf ',"recheck_status":'
    os_guard_harden_json_nullable_string "$harden_recheck_status"
    printf ',"rollback_attempted":%s' "$harden_rollback_attempted"
    printf ',"rollback_success":%s' "$harden_rollback_success"
    printf '}'

    printf ',"error":'
    if [ -n "$harden_error_code" ]; then
        printf '{"code":'
        os_guard_json_quote "$harden_error_code"
        printf ',"message":'
        os_guard_json_quote "$harden_error_message"
        printf '}'
    else
        printf 'null'
    fi

    printf '}\n'
}

os_guard_harden_initialize_file_state() {
    harden_requested_action=${1:-}
    harden_distro=${OS_GUARD_DISTRO:-unknown}
    harden_version_id=${OS_GUARD_VERSION_ID:-unknown}
    harden_test_root=${OS_GUARD_TEST_ROOT:-}
    harden_target_file="${harden_test_root}${HARDEN_TARGET_DISPLAY_PATH}"

    harden_outcome='FAILED'
    harden_error_code=''
    harden_error_message=''
    harden_current_owner_uid=''
    harden_current_owner_name=''
    harden_current_group_gid=''
    harden_current_permission=''
    harden_current_device=''
    harden_current_inode=''
    harden_current_mtime=''
    harden_current_ctime=''
    harden_current_selinux_context=''
    harden_state_fingerprint=''
    harden_expected_permission=''
    harden_owner_change_required=false
    harden_permission_change_required=false
    harden_backup_required=false
    harden_backup_created=false
    harden_backup_identifier=''
    harden_backup_directory=''
    harden_backup_acl_file=''
    harden_acl_backup_created=false
    harden_changes_applied=false
    harden_validation_success=false
    harden_recheck_status=''
    harden_rollback_attempted=false
    harden_rollback_success=false
    harden_stat_command=''
    harden_chmod_command=''
    harden_chown_command=''
}

os_guard_harden_run_file_module() {
    os_guard_harden_initialize_file_state "$1"

    if ! os_guard_harden_detect_file_environment; then
        os_guard_harden_build_file_result
        return
    fi

    if os_guard_harden_target_is_missing && [ "$HARDEN_MISSING_POLICY" = 'NO_CHANGE' ]; then
        if os_guard_harden_run_existing_check && [ "$harden_recheck_status" = 'GOOD' ]; then
            harden_outcome='NO_CHANGE'
            harden_validation_success=true
        else
            os_guard_harden_set_error \
                'CHECK_STATE_NOT_ACTIONABLE' \
                'missing target was not confirmed safe by the existing CHECK'
        fi
        os_guard_harden_build_file_result
        return
    fi

    if ! os_guard_harden_validate_file_target; then
        os_guard_harden_build_file_result
        return
    fi

    if ! os_guard_harden_collect_file_state; then
        os_guard_harden_build_file_result
        return
    fi

    os_guard_harden_calculate_file_plan

    os_guard_harden_require_vulnerable_check
    harden_applicability_status=$?
    if [ "$harden_applicability_status" -eq 2 ]; then
        harden_validation_success=true
        os_guard_harden_build_file_result
        return
    fi
    if [ "$harden_applicability_status" -ne 0 ]; then
        os_guard_harden_build_file_result
        return
    fi

    if [ "$harden_requested_action" = 'PREVIEW' ]; then
        harden_outcome='PLANNED'
        os_guard_harden_build_file_result
        return
    fi

    os_guard_harden_execute_file_changes || true
    os_guard_harden_build_file_result
}
