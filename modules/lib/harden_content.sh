#!/bin/sh

os_guard_content_set_error() {
    content_error_code=$1
    content_error_message=$2
    content_outcome='FAILED'
}

os_guard_content_resolve_commands() {
    if [ -n "$content_test_root" ] && [ -n "${OS_GUARD_TEST_STAT_BIN:-}" ]; then
        content_stat_command=$OS_GUARD_TEST_STAT_BIN
    else
        content_stat_command=$(command -v stat 2>/dev/null || true)
    fi

    if [ -n "$content_test_root" ] && [ -n "${OS_GUARD_TEST_CHMOD_BIN:-}" ]; then
        content_chmod_command=$OS_GUARD_TEST_CHMOD_BIN
    else
        content_chmod_command=$(command -v chmod 2>/dev/null || true)
    fi

    if [ -n "$content_test_root" ] && [ -n "${OS_GUARD_TEST_CHOWN_BIN:-}" ]; then
        content_chown_command=$OS_GUARD_TEST_CHOWN_BIN
    else
        content_chown_command=$(command -v chown 2>/dev/null || true)
    fi

    content_sha_command=$(command -v sha256sum 2>/dev/null || true)
    content_cp_command=$(command -v cp 2>/dev/null || true)
    content_mv_command=$(command -v mv 2>/dev/null || true)
    content_mktemp_command=$(command -v mktemp 2>/dev/null || true)
    if [ -n "$content_test_root" ] && \
        [ "${OS_GUARD_TEST_DISABLE_ACL_BACKUP:-false}" = 'true' ]; then
        content_getfacl_command=''
        content_setfacl_command=''
    else
        content_getfacl_command=$(command -v getfacl 2>/dev/null || true)
        content_setfacl_command=$(command -v setfacl 2>/dev/null || true)
    fi

    for required_command in \
        "$content_stat_command" \
        "$content_sha_command" \
        "$content_cp_command" \
        "$content_mv_command" \
        "$content_mktemp_command"; do
        if [ -z "$required_command" ] || [ ! -x "$required_command" ]; then
            os_guard_content_set_error \
                'REQUIRED_COMMAND_UNAVAILABLE' \
                'a required content hardening command is unavailable'
            return 1
        fi
    done

    if [ "$content_action" = 'EXECUTE' ]; then
        if [ -z "$content_chmod_command" ] || [ ! -x "$content_chmod_command" ] || \
            [ -z "$content_chown_command" ] || [ ! -x "$content_chown_command" ]; then
            os_guard_content_set_error \
                'METADATA_COMMAND_UNAVAILABLE' \
                'metadata preservation commands are unavailable'
            return 1
        fi
    fi

    return 0
}

os_guard_content_detect_environment() {
    case "$content_action" in
        PREVIEW|EXECUTE)
            ;;
        *)
            os_guard_content_set_error 'INVALID_ACTION' 'action must be PREVIEW or EXECUTE'
            return 1
            ;;
    esac

    if ! os_guard_harden_is_supported_os "$content_distro" "$content_version_id"; then
        os_guard_content_set_error \
            'UNSUPPORTED_OS_CONFIGURATION' \
            'the current operating system is not supported'
        return 1
    fi

    if [ "$content_action" = 'EXECUTE' ] && [ -z "$content_test_root" ]; then
        process_uid=$(id -u 2>/dev/null || true)
        if [ "$process_uid" != '0' ]; then
            os_guard_content_set_error \
                'ROOT_PRIVILEGES_REQUIRED' \
                'EXECUTE requires root privileges'
            return 1
        fi
    fi

    os_guard_content_resolve_commands
}

os_guard_content_hash_file() {
    hash_path=$1
    "$content_sha_command" "$hash_path" 2>/dev/null | awk '{ print $1 }'
}

os_guard_content_hash_rendered() {
    source_path=$1
    os_guard_item_render_content "$source_path" | "$content_sha_command" | awk '{ print $1 }'
}

os_guard_content_path_is_safe() {
    inspected_path=$1
    case "$inspected_path" in
        *[!A-Za-z0-9_./@+-]*)
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}

os_guard_content_add_target() {
    target_path=$1
    display_path=$2
    target_location=$3
    proposed_change=$4

    if ! os_guard_content_path_is_safe "$display_path"; then
        os_guard_content_set_error 'TARGET_PATH_UNSAFE' 'a target path contains unsupported characters'
        return 1
    fi
    if { [ -n "$content_test_root" ] &&
        [ "${OS_GUARD_TEST_FORCE_SYMLINK_PATH:-}" = "$display_path" ]; } ||
        [ -L "$target_path" ]; then
        os_guard_content_set_error 'SYMLINK_TARGET_REJECTED' 'a symbolic configuration target was detected'
        return 1
    fi
    if [ ! -f "$target_path" ] || [ ! -r "$target_path" ]; then
        os_guard_content_set_error \
            'CONFIGURATION_TARGET_INVALID' \
            'a configuration target is not a readable regular file'
        return 1
    fi
    if [ -n "$content_records" ] &&
        printf '%s\n' "$content_records" | awk -F'|' \
            -v target="$display_path" '$1 == target { found = 1 } END { exit found ? 0 : 1 }'; then
        os_guard_content_set_error \
            'TARGET_RELATIONSHIP_AMBIGUOUS' \
            'the same configuration target was selected more than once'
        return 1
    fi

    if ! os_guard_harden_collect_metadata_with_context \
        "$content_stat_command" \
        '%d|%i|%u|%g|%a|%Y|%Z' \
        "$target_path" \
        "$content_test_root"; then
        os_guard_content_set_error \
            "$os_guard_harden_stat_error_code" \
            'configuration metadata collection failed'
        return 1
    fi
    metadata=$os_guard_harden_stat_metadata
    if ! printf '%s\n' "$metadata" | awk -F'|' '
        NF == 8 &&
        $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ &&
        $3 ~ /^[0-9]+$/ && $4 ~ /^[0-9]+$/ &&
        $5 ~ /^[0-7]+$/ && length($5) <= 4 &&
        $6 ~ /^[0-9]+$/ && $7 ~ /^[0-9]+$/ {
            valid = 1
        }
        END { exit valid ? 0 : 1 }
    '; then
        os_guard_content_set_error 'STAT_OUTPUT_INVALID' 'configuration metadata output is invalid'
        return 1
    fi

    old_ifs=$IFS
    IFS='|'
    set -- $metadata
    IFS=$old_ifs
    device=$1
    inode=$2
    owner_uid=$3
    group_gid=$4
    permission=$5
    modified_time=$6
    changed_time=$7
    shift 7
    security_context=$1

    current_hash=$(os_guard_content_hash_file "$target_path")
    proposed_hash=$(os_guard_content_hash_rendered "$target_path")
    if [ -z "$current_hash" ] || [ -z "$proposed_hash" ]; then
        os_guard_content_set_error 'CONTENT_HASH_FAILED' 'configuration content hashing failed'
        return 1
    fi

    change_required=false
    if [ "$current_hash" != "$proposed_hash" ]; then
        change_required=true
        content_change_required=true
    fi

    record=$(printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s' \
        "$display_path" "$target_path" "$device" "$inode" "$owner_uid" \
        "$group_gid" "$permission" "$modified_time" "$changed_time" \
        "$security_context" "$current_hash" "$proposed_hash" \
        "$change_required" "$target_location" "$proposed_change")
    if [ -n "$content_records" ]; then
        content_records=$(printf '%s\n%s' "$content_records" "$record")
    else
        content_records=$record
    fi
    content_target_count=$((content_target_count + 1))
    return 0
}

os_guard_content_discover_targets() {
    content_records=''
    content_target_count=0
    content_change_required=false

    if ! os_guard_item_discover_content_targets; then
        if [ -z "$content_error_code" ]; then
            os_guard_content_set_error \
                'TARGET_DISCOVERY_FAILED' \
                'configuration target discovery failed'
        fi
        return 1
    fi

    if [ -z "$content_records" ]; then
        content_state_fingerprint='empty'
    else
        content_state_fingerprint=$(printf '%s\n' "$content_records" | awk -F'|' '
            {
                if (NR > 1) printf ";"
                printf "%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s", \
                    $1,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12
            }
            END { printf "\n" }
        ')
    fi
    return 0
}

os_guard_content_run_check() {
    if [ -n "$content_test_root" ] && [ "${OS_GUARD_TEST_CHECK_FAILURE:-false}" = 'true' ]; then
        content_check_status='ERROR'
        return 1
    fi

    check_output=$("$HARDEN_CHECK_SCRIPT" 2>/dev/null)
    if [ $? -ne 0 ]; then
        content_check_status='ERROR'
        return 1
    fi

    for possible_status in GOOD VULNERABLE UNCHECKABLE N/A; do
        if printf '%s\n' "$check_output" | grep -Eq \
            '"item_id":"'"$HARDEN_ITEM_ID"'".*"status":"'"$possible_status"'"'; then
            content_check_status=$possible_status
            return 0
        fi
    done
    if printf '%s\n' "$check_output" | grep -Eq \
        '"item_id":"'"$HARDEN_ITEM_ID"'".*"status":null'; then
        content_check_status='PENDING'
        return 0
    fi
    content_check_status='INVALID'
    return 1
}

os_guard_content_validate_authorization() {
    if [ "${OS_GUARD_HARDEN_APPROVED:-}" != 'true' ]; then
        os_guard_content_set_error 'APPROVAL_REQUIRED' 'EXECUTE requires explicit approval'
        return 1
    fi
    expected_state=${OS_GUARD_HARDEN_EXPECTED_STATE:-}
    if [ -z "$expected_state" ]; then
        os_guard_content_set_error \
            'EXPECTED_STATE_REQUIRED' \
            'EXECUTE requires the PREVIEW state fingerprint'
        return 1
    fi
    if [ "$expected_state" != "$content_state_fingerprint" ]; then
        os_guard_content_set_error \
            'STATE_DRIFT' \
            'configuration metadata or content changed after PREVIEW'
        return 1
    fi
    return 0
}

os_guard_content_create_backup() {
    if [ -n "$content_test_root" ] && [ "${OS_GUARD_TEST_FAIL_STEP:-}" = 'backup' ]; then
        os_guard_content_set_error 'BACKUP_FAILED' 'configuration backup failed'
        return 1
    fi

    if [ -n "$content_test_root" ]; then
        default_backup="${content_test_root}/var/lib/os-guard-agent/backups/${HARDEN_ITEM_ID}"
        backup_base=${OS_GUARD_TEST_BACKUP_ROOT:-"$default_backup"}
    else
        backup_base="/var/lib/os-guard-agent/backups/${HARDEN_ITEM_ID}"
    fi
    if ! os_guard_harden_create_private_directory "$backup_base"; then
        os_guard_content_set_error 'BACKUP_FAILED' 'backup directory creation failed'
        return 1
    fi
    content_backup_directory=$(mktemp -d "$backup_base/backup.XXXXXX" 2>/dev/null || true)
    if [ -z "$content_backup_directory" ]; then
        os_guard_content_set_error 'BACKUP_FAILED' 'private backup directory creation failed'
        return 1
    fi
    if ! chmod 0700 -- "$content_backup_directory"; then
        os_guard_content_set_error 'BACKUP_FAILED' 'backup directory permission setup failed'
        return 1
    fi
    content_backup_identifier=${content_backup_directory##*/}
    content_backup_metadata="$content_backup_directory/metadata"
    if ! printf '%s\n' "$content_records" > "$content_backup_metadata" || \
        ! chmod 0600 -- "$content_backup_metadata"; then
        os_guard_content_set_error 'BACKUP_FAILED' 'backup metadata write failed'
        return 1
    fi

    backup_index=0
    while IFS='|' read -r display_path target_path remaining_fields; do
        backup_index=$((backup_index + 1))
        backup_path="$content_backup_directory/content.$backup_index"
        if ! "$content_cp_command" -p --preserve=all -- "$target_path" "$backup_path"; then
            os_guard_content_set_error 'BACKUP_FAILED' 'configuration content backup failed'
            return 1
        fi
        if ! chmod 0600 -- "$backup_path"; then
            os_guard_content_set_error 'BACKUP_FAILED' 'backup content permission setup failed'
            return 1
        fi
    done <<EOF
$content_records
EOF

    if [ -n "$content_getfacl_command" ]; then
        content_backup_acl="$content_backup_directory/acl.restore"
        : > "$content_backup_acl"
        while IFS='|' read -r display_path target_path remaining_fields; do
            if ! "$content_getfacl_command" -p -- "$target_path" \
                >> "$content_backup_acl" 2>/dev/null; then
                os_guard_content_set_error 'BACKUP_FAILED' 'ACL backup failed'
                return 1
            fi
        done <<EOF
$content_records
EOF
        if ! chmod 0600 -- "$content_backup_acl"; then
            os_guard_content_set_error 'BACKUP_FAILED' 'ACL backup permission setup failed'
            return 1
        fi
    fi

    content_backup_created=true
    return 0
}

os_guard_content_replace_target() {
    target_path=$1
    expected_hash=$2
    owner_uid=$3
    group_gid=$4
    permission=$5

    target_directory=${target_path%/*}
    temporary_file=$(
        "$content_mktemp_command" "$target_directory/.os-guard.XXXXXX" 2>/dev/null || true
    )
    if [ -z "$temporary_file" ]; then
        os_guard_content_set_error 'TEMPORARY_FILE_FAILED' 'temporary file creation failed'
        return 1
    fi
    if ! "$content_cp_command" -p --preserve=all -- "$target_path" "$temporary_file"; then
        rm -f -- "$temporary_file"
        os_guard_content_set_error 'APPLY_FAILED' 'configuration metadata staging failed'
        return 1
    fi
    if ! os_guard_item_render_content "$target_path" > "$temporary_file"; then
        rm -f -- "$temporary_file"
        os_guard_content_set_error 'APPLY_FAILED' 'configuration transformation failed'
        return 1
    fi
    rendered_hash=$(os_guard_content_hash_file "$temporary_file")
    if [ "$rendered_hash" != "$expected_hash" ]; then
        rm -f -- "$temporary_file"
        os_guard_content_set_error 'APPLY_VALIDATION_FAILED' 'rendered content hash is unexpected'
        return 1
    fi
    "$content_chown_command" "$owner_uid:$group_gid" -- "$temporary_file" || return 1
    "$content_chmod_command" "$permission" -- "$temporary_file" || return 1
    if ! "$content_mv_command" -f -- "$temporary_file" "$target_path"; then
        rm -f -- "$temporary_file"
        os_guard_content_set_error 'ATOMIC_REPLACE_FAILED' 'atomic configuration replacement failed'
        return 1
    fi
    return 0
}

os_guard_content_apply() {
    while IFS='|' read -r \
        display_path target_path device inode owner_uid group_gid permission \
        modified_time changed_time context current_hash proposed_hash \
        change_required target_location proposed_change; do
        if [ "$change_required" != true ]; then
            continue
        fi
        if [ -n "$content_test_root" ] && [ "${OS_GUARD_TEST_FAIL_STEP:-}" = 'apply' ]; then
            os_guard_content_set_error 'APPLY_FAILED' 'forced configuration apply failure'
            return 1
        fi
        if ! os_guard_content_replace_target \
            "$target_path" "$proposed_hash" "$owner_uid" "$group_gid" "$permission"; then
            return 1
        fi
        content_changes_applied=true
    done <<EOF
$content_records
EOF
    return 0
}

os_guard_content_validate_result() {
    if [ -n "$content_test_root" ] && \
        [ "${OS_GUARD_TEST_FORCE_VALIDATION_FAILURE:-false}" = 'true' ]; then
        os_guard_content_set_error 'VALIDATION_FAILED' 'forced content validation failure'
        return 1
    fi

    while IFS='|' read -r \
        display_path target_path device inode owner_uid group_gid permission \
        modified_time changed_time context current_hash proposed_hash \
        change_required target_location proposed_change; do
        if [ -L "$target_path" ] || [ ! -f "$target_path" ]; then
            os_guard_content_set_error 'VALIDATION_FAILED' 'configuration target type changed'
            return 1
        fi
        actual_hash=$(os_guard_content_hash_file "$target_path")
        if [ "$actual_hash" != "$proposed_hash" ]; then
            os_guard_content_set_error 'VALIDATION_FAILED' 'configuration content validation failed'
            return 1
        fi
        actual_metadata=$(
            "$content_stat_command" -c '%u|%g|%a' -- "$target_path" 2>/dev/null
        )
        if [ "$actual_metadata" != "$owner_uid|$group_gid|$permission" ]; then
            os_guard_content_set_error 'VALIDATION_FAILED' 'configuration metadata was not preserved'
            return 1
        fi
    done <<EOF
$content_records
EOF
    if command -v os_guard_item_validate_configuration >/dev/null 2>&1 && \
        ! os_guard_item_validate_configuration; then
        if [ -z "$content_error_code" ]; then
            os_guard_content_set_error \
                'CONFIGURATION_VALIDATION_FAILED' \
                'the item-specific configuration validation failed'
        fi
        return 1
    fi
    content_validation_success=true
    return 0
}

os_guard_content_rollback() {
    content_rollback_attempted=true
    content_rollback_success=false
    if [ -n "$content_test_root" ] && [ "${OS_GUARD_TEST_FAIL_STEP:-}" = 'rollback' ]; then
        return 1
    fi

    original_records=$(cat "$content_backup_metadata" 2>/dev/null || true)
    reverse_records=$(printf '%s\n' "$original_records" | awk '
        { records[NR]=$0 }
        END {
            for (record_index=NR; record_index>=1; record_index--) {
                print records[record_index]
            }
        }
    ')
    record_count=$(printf '%s\n' "$original_records" | awk 'NF { count++ } END { print count+0 }')
    current_index=$record_count
    while IFS='|' read -r \
        display_path target_path device inode owner_uid group_gid permission \
        modified_time changed_time context current_hash remaining_fields; do
        backup_path="$content_backup_directory/content.$current_index"
        target_directory=${target_path%/*}
        temporary_file=$(
            "$content_mktemp_command" "$target_directory/.os-guard.rollback.XXXXXX" 2>/dev/null || true
        )
        if [ -z "$temporary_file" ] || \
            ! "$content_cp_command" -p --preserve=all -- "$backup_path" "$temporary_file" || \
            ! "$content_mv_command" -f -- "$temporary_file" "$target_path"; then
            return 1
        fi
        "$content_chown_command" "$owner_uid:$group_gid" -- "$target_path" || return 1
        "$content_chmod_command" "$permission" -- "$target_path" || return 1
        current_index=$((current_index - 1))
    done <<EOF
$reverse_records
EOF

    if [ -n "$content_backup_acl" ] && [ -s "$content_backup_acl" ]; then
        if [ -z "$content_setfacl_command" ] || \
            ! "$content_setfacl_command" --restore="$content_backup_acl" >/dev/null 2>&1; then
            return 1
        fi
    fi

    while IFS='|' read -r \
        display_path target_path device inode owner_uid group_gid permission \
        modified_time changed_time context current_hash remaining_fields; do
        restored_hash=$(os_guard_content_hash_file "$target_path")
        if ! os_guard_harden_collect_metadata_with_context \
            "$content_stat_command" \
            '%u|%g|%a' \
            "$target_path" \
            "$content_test_root"; then
            return 1
        fi
        restored_metadata=$os_guard_harden_stat_metadata
        if [ "$restored_hash" != "$current_hash" ] || \
            [ "$restored_metadata" != "$owner_uid|$group_gid|$permission|$context" ]; then
            return 1
        fi
    done <<EOF
$original_records
EOF
    content_rollback_success=true
    return 0
}

os_guard_content_final_check() {
    if [ -n "$content_test_root" ] && \
        [ "${OS_GUARD_TEST_FORCE_RECHECK_FAILURE:-false}" = 'true' ]; then
        content_check_status='VULNERABLE'
        os_guard_content_set_error 'RECHECK_FAILED' 'the existing CHECK did not return GOOD'
        return 1
    fi
    if ! os_guard_content_run_check || [ "$content_check_status" != 'GOOD' ]; then
        os_guard_content_set_error 'RECHECK_FAILED' 'the existing CHECK did not return GOOD'
        return 1
    fi
    return 0
}

os_guard_content_print_targets() {
    printf '['
    first=true
    while IFS='|' read -r \
        display_path target_path device inode owner_uid group_gid permission \
        modified_time changed_time context current_hash proposed_hash \
        change_required target_location proposed_change; do
        [ -n "$display_path" ] || continue
        [ "$first" = true ] || printf ','
        first=false
        printf '{"target":'
        os_guard_json_quote "$display_path"
        printf ',"current_content_hash":'
        os_guard_json_quote "$current_hash"
        printf ',"current_effective_value":'
        os_guard_json_quote "$CONTENT_CURRENT_EFFECTIVE_VALUE"
        printf ',"change_required":%s,"proposed_change":' "$change_required"
        os_guard_json_quote "$proposed_change"
        printf ',"change_location":'
        os_guard_json_quote "$target_location"
        printf '}'
    done <<EOF
$content_records
EOF
    printf ']'
}

os_guard_content_build_result() {
    content_service_reload_required=${HARDEN_SERVICE_RELOAD_REQUIRED:-false}
    printf '{"item_id":'
    os_guard_json_quote "$HARDEN_ITEM_ID"
    printf ',"action":'
    os_guard_harden_json_nullable_string "$content_action"
    printf ',"outcome":'
    os_guard_json_quote "$content_outcome"
    printf ',"target":'
    os_guard_json_quote "$HARDEN_TARGET_DESCRIPTION"
    printf ',"preview":{"targets":'
    os_guard_content_print_targets
    printf ',"change_required":%s,"backup_required":%s' \
        "$content_change_required" "$content_change_required"
    printf ',"service_restart_required":%s,"reboot_required":false,"risk":' \
        "$content_service_reload_required"
    os_guard_json_quote "$HARDEN_RISK_LEVEL"
    printf ',"state_fingerprint":'
    os_guard_harden_json_nullable_string "$content_state_fingerprint"
    printf '},"execution":{"backup_created":%s,"backup_id":' "$content_backup_created"
    os_guard_harden_json_nullable_string "$content_backup_identifier"
    printf ',"changes_applied":%s,"validation_success":%s,"recheck_status":' \
        "$content_changes_applied" "$content_validation_success"
    os_guard_harden_json_nullable_string "$content_check_status"
    printf ',"rollback_attempted":%s,"rollback_success":%s}' \
        "$content_rollback_attempted" "$content_rollback_success"
    printf ',"error":'
    if [ -n "$content_error_code" ]; then
        printf '{"code":'
        os_guard_json_quote "$content_error_code"
        printf ',"message":'
        os_guard_json_quote "$content_error_message"
        printf '}'
    else
        printf 'null'
    fi
    printf '}\n'
}

os_guard_content_initialize() {
    content_action=${1:-}
    content_distro=${OS_GUARD_DISTRO:-unknown}
    content_version_id=${OS_GUARD_VERSION_ID:-unknown}
    content_test_root=${OS_GUARD_TEST_ROOT:-}
    content_outcome='FAILED'
    content_error_code=''
    content_error_message=''
    content_check_status=''
    content_records=''
    content_target_count=0
    content_change_required=false
    content_state_fingerprint=''
    content_backup_created=false
    content_backup_identifier=''
    content_backup_directory=''
    content_backup_metadata=''
    content_backup_acl=''
    content_changes_applied=false
    content_validation_success=false
    content_rollback_attempted=false
    content_rollback_success=false
    CONTENT_CURRENT_EFFECTIVE_VALUE=''
}

os_guard_content_run_module() {
    os_guard_content_initialize "$1"
    if ! os_guard_content_detect_environment; then
        os_guard_content_build_result
        return
    fi
    if ! os_guard_content_run_check; then
        os_guard_content_set_error 'CHECK_EXECUTION_FAILED' 'the existing CHECK could not be evaluated'
        os_guard_content_build_result
        return
    fi
    case "$content_check_status" in
        GOOD|N/A)
            content_outcome='NO_CHANGE'
            content_validation_success=true
            content_state_fingerprint='empty'
            os_guard_content_build_result
            return
            ;;
        PENDING|UNCHECKABLE)
            os_guard_content_set_error 'CHECK_STATE_NOT_ACTIONABLE' 'the CHECK result is not actionable'
            os_guard_content_build_result
            return
            ;;
        VULNERABLE)
            ;;
        *)
            os_guard_content_set_error 'CHECK_RESULT_INVALID' 'the existing CHECK result is invalid'
            os_guard_content_build_result
            return
            ;;
    esac
    if command -v os_guard_item_validate_content_policy >/dev/null 2>&1 && \
        ! os_guard_item_validate_content_policy; then
        if [ -z "$content_error_code" ]; then
            os_guard_content_set_error \
                'POLICY_PRECONDITION_FAILED' \
                'the item-specific content policy precondition failed'
        fi
        os_guard_content_build_result
        return
    fi
    if ! os_guard_content_discover_targets; then
        os_guard_content_build_result
        return
    fi
    if [ "$content_change_required" != true ]; then
        os_guard_content_set_error 'NO_SAFE_AUTOMATIC_CHANGE' 'no safe automatic content change was found'
        os_guard_content_build_result
        return
    fi
    if [ "$content_action" = 'PREVIEW' ]; then
        content_outcome='PLANNED'
        os_guard_content_build_result
        return
    fi
    if ! os_guard_content_validate_authorization || ! os_guard_content_create_backup; then
        os_guard_content_build_result
        return
    fi
    if ! os_guard_content_apply || ! os_guard_content_validate_result; then
        os_guard_content_rollback || true
        os_guard_content_build_result
        return
    fi
    if ! os_guard_content_final_check; then
        os_guard_content_rollback || true
        os_guard_content_build_result
        return
    fi
    content_outcome='SUCCESS'
    os_guard_content_build_result
}
