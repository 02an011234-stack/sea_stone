#!/bin/sh

os_guard_multi_set_error() {
    multi_error_code=$1
    multi_error_message=$2
    multi_outcome='FAILED'
}

os_guard_multi_resolve_commands() {
    if [ -n "$multi_test_root" ] && [ -n "${OS_GUARD_TEST_STAT_BIN:-}" ]; then
        multi_stat_command=$OS_GUARD_TEST_STAT_BIN
    else
        multi_stat_command=$(command -v stat 2>/dev/null || true)
    fi

    if [ -n "$multi_test_root" ] && [ -n "${OS_GUARD_TEST_CHMOD_BIN:-}" ]; then
        multi_chmod_command=$OS_GUARD_TEST_CHMOD_BIN
    else
        multi_chmod_command=$(command -v chmod 2>/dev/null || true)
    fi

    if [ -n "$multi_test_root" ] && [ -n "${OS_GUARD_TEST_CHOWN_BIN:-}" ]; then
        multi_chown_command=$OS_GUARD_TEST_CHOWN_BIN
    else
        multi_chown_command=$(command -v chown 2>/dev/null || true)
    fi

    if [ -n "$multi_test_root" ] && [ -n "${OS_GUARD_TEST_GETFACL_BIN:-}" ]; then
        multi_getfacl_command=$OS_GUARD_TEST_GETFACL_BIN
    else
        multi_getfacl_command=$(command -v getfacl 2>/dev/null || true)
    fi

    if [ -n "$multi_test_root" ] && [ -n "${OS_GUARD_TEST_SETFACL_BIN:-}" ]; then
        multi_setfacl_command=$OS_GUARD_TEST_SETFACL_BIN
    else
        multi_setfacl_command=$(command -v setfacl 2>/dev/null || true)
    fi

    if [ -z "$multi_stat_command" ] || [ ! -x "$multi_stat_command" ]; then
        os_guard_multi_set_error 'STAT_COMMAND_UNAVAILABLE' 'required metadata command is unavailable'
        return 1
    fi

    if [ "$multi_requested_action" = 'EXECUTE' ]; then
        if [ -z "$multi_chmod_command" ] || [ ! -x "$multi_chmod_command" ]; then
            os_guard_multi_set_error 'CHMOD_COMMAND_UNAVAILABLE' 'required permission command is unavailable'
            return 1
        fi

        if [ -z "$multi_chown_command" ] || [ ! -x "$multi_chown_command" ]; then
            os_guard_multi_set_error 'CHOWN_COMMAND_UNAVAILABLE' 'required ownership command is unavailable'
            return 1
        fi
    fi

    return 0
}

os_guard_multi_detect_environment() {
    case "$multi_requested_action" in
        PREVIEW|EXECUTE)
            ;;
        *)
            os_guard_multi_set_error 'INVALID_ACTION' 'action must be PREVIEW or EXECUTE'
            return 1
            ;;
    esac

    if ! os_guard_harden_is_supported_os "$multi_distro" "$multi_version_id"; then
        os_guard_multi_set_error 'UNSUPPORTED_OS_CONFIGURATION' 'the current operating system is not supported'
        return 1
    fi

    if [ "$multi_requested_action" = 'EXECUTE' ] && [ -z "$multi_test_root" ]; then
        multi_process_uid=$(id -u 2>/dev/null || true)
        if [ "$multi_process_uid" != '0' ]; then
            os_guard_multi_set_error 'ROOT_PRIVILEGES_REQUIRED' 'EXECUTE requires root privileges'
            return 1
        fi
    fi

    os_guard_multi_resolve_commands
}

os_guard_multi_path_is_safe() {
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

os_guard_multi_collect_acl_state() {
    inspected_path=$1
    acl_policy=$2

    multi_collected_acl_fingerprint='none'
    multi_collected_acl_change=false

    if [ -z "$multi_getfacl_command" ]; then
        return 0
    fi

    multi_acl_output=$(
        "$multi_getfacl_command" -cp -- "$inspected_path" 2>/dev/null
    )
    multi_acl_status=$?
    if [ "$multi_acl_status" -ne 0 ]; then
        os_guard_multi_set_error 'ACL_COLLECTION_FAILED' 'target ACL metadata could not be collected'
        return 1
    fi

    multi_collected_acl_fingerprint=$(printf '%s\n' "$multi_acl_output" | cksum | awk '{ print $1 ":" $2 }')

    if [ "$acl_policy" = 'NO_NAMED_USER_OR_OTHER_WRITE' ]; then
        if printf '%s\n' "$multi_acl_output" | awk -F: '
            /^user:[^:]+:/ && $3 ~ /w/ {
                unsafe = 1
            }
            /^other::/ && $3 ~ /w/ {
                unsafe = 1
            }
            END {
                exit unsafe ? 0 : 1
            }
        '; then
            multi_collected_acl_change=true
        fi
    fi

    return 0
}

os_guard_multi_add_target() {
    target_path=$1
    target_display_path=$2
    target_type=$3
    expected_owner_uid=$4
    expected_owner_name=$5
    allowed_permission_mask=$6
    permission_policy=$7
    acl_policy=$8

    if ! os_guard_multi_path_is_safe "$target_display_path"; then
        os_guard_multi_set_error 'TARGET_PATH_UNSAFE' 'a target path contains unsupported characters'
        return 1
    fi

    if [ -n "$multi_target_records" ] &&
        printf '%s\n' "$multi_target_records" | awk -F'|' \
            -v target="$target_display_path" '$1 == target { found = 1 } END { exit found ? 0 : 1 }'; then
        os_guard_multi_set_error \
            'TARGET_RELATIONSHIP_AMBIGUOUS' \
            'the same target was discovered through more than one policy relationship'
        return 1
    fi

    if { [ -n "$multi_test_root" ] &&
        [ "${OS_GUARD_TEST_FORCE_SYMLINK_PATH:-}" = "$target_display_path" ]; } ||
        [ -L "$target_path" ]; then
        os_guard_multi_set_error 'SYMLINK_TARGET_REJECTED' 'an unexpected symbolic link target was detected'
        return 1
    fi

    case "$target_type" in
        file)
            if { [ -n "$multi_test_root" ] &&
                [ "${OS_GUARD_TEST_FORCE_NONREGULAR_PATH:-}" = "$target_display_path" ]; } ||
                [ ! -f "$target_path" ]; then
                os_guard_multi_set_error 'TARGET_TYPE_INVALID' 'an expected regular file has a different type'
                return 1
            fi
            ;;
        directory)
            if { [ -n "$multi_test_root" ] &&
                [ "${OS_GUARD_TEST_FORCE_NONREGULAR_PATH:-}" = "$target_display_path" ]; } ||
                [ ! -d "$target_path" ]; then
                os_guard_multi_set_error 'TARGET_TYPE_INVALID' 'an expected directory has a different type'
                return 1
            fi
            ;;
        *)
            os_guard_multi_set_error 'TARGET_TYPE_INVALID' 'an unsupported target type was requested'
            return 1
            ;;
    esac

    if ! os_guard_harden_collect_metadata_with_context \
        "$multi_stat_command" \
        '%d|%i|%u|%U|%g|%G|%a|%Y|%Z' \
        "$target_path" \
        "$multi_test_root"; then
        os_guard_multi_set_error \
            "$os_guard_harden_stat_error_code" \
            'target metadata collection failed'
        return 1
    fi
    metadata_output=$os_guard_harden_stat_metadata

    metadata_valid=$(printf '%s\n' "$metadata_output" | awk -F'|' '
        NF == 10 &&
        $1 ~ /^[0-9]+$/ &&
        $2 ~ /^[0-9]+$/ &&
        $3 ~ /^[0-9]+$/ &&
        $4 != "" &&
        $5 ~ /^[0-9]+$/ &&
        $6 != "" &&
        $7 ~ /^[0-7]+$/ &&
        length($7) <= 4 &&
        $8 ~ /^[0-9]+$/ &&
        $9 ~ /^[0-9]+$/ {
            print "true"
        }
    ')
    if [ "$metadata_valid" != 'true' ]; then
        os_guard_multi_set_error 'STAT_OUTPUT_INVALID' 'target metadata output is invalid'
        return 1
    fi

    old_ifs=$IFS
    IFS='|'
    set -- $metadata_output
    IFS=$old_ifs

    current_device=$1
    current_inode=$2
    current_owner_uid=$3
    current_owner_name=$4
    current_group_gid=$5
    current_group_name=$6
    current_permission=$7
    current_mtime=$8
    current_ctime=$9
    shift 9
    current_selinux_context=$1

    owner_change_required=false
    if [ "$current_owner_uid" != "$expected_owner_uid" ]; then
        owner_change_required=true
    elif [ "$current_owner_name" != "$expected_owner_name" ]; then
        os_guard_multi_set_error 'OWNER_IDENTITY_UNRESOLVED' 'owner UID and name do not agree with the expected identity'
        return 1
    fi

    current_permission_value=$((0$current_permission))
    allowed_permission_value=$((allowed_permission_mask))
    extra_permission_value=$((current_permission_value & ~allowed_permission_value))
    permission_change_required=false
    expected_permission=$current_permission
    if [ "$extra_permission_value" -ne 0 ]; then
        reduced_permission_value=$((current_permission_value & allowed_permission_value))
        expected_permission=$(printf '%03o' "$reduced_permission_value")
        permission_change_required=true
    fi

    if ! os_guard_multi_collect_acl_state "$target_path" "$acl_policy"; then
        return 1
    fi
    acl_change_required=$multi_collected_acl_change
    acl_fingerprint=$multi_collected_acl_fingerprint

    if [ "$owner_change_required" = true ] || \
        [ "$permission_change_required" = true ] || \
        [ "$acl_change_required" = true ]; then
        multi_backup_required=true
    fi

    target_record=$(printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s' \
        "$target_display_path" "$target_path" "$target_type" \
        "$current_device" "$current_inode" "$current_owner_uid" \
        "$current_owner_name" "$current_group_gid" "$current_group_name" \
        "$current_permission" "$current_mtime" "$current_ctime" \
        "$current_selinux_context" "$expected_owner_uid" "$expected_owner_name" \
        "$allowed_permission_mask" "$permission_policy" "$acl_policy" \
        "$expected_permission" "$owner_change_required" \
        "$permission_change_required" "$acl_change_required" "$acl_fingerprint" \
        "$target_type")

    if [ -n "$multi_target_records" ]; then
        multi_target_records=$(printf '%s\n%s' "$multi_target_records" "$target_record")
    else
        multi_target_records=$target_record
    fi

    multi_target_count=$((multi_target_count + 1))
    return 0
}

os_guard_multi_calculate_fingerprint() {
    if [ -z "$multi_target_records" ]; then
        multi_state_fingerprint='empty'
        return
    fi

    multi_state_fingerprint=$(printf '%s\n' "$multi_target_records" | awk -F'|' '
        {
            if (NR > 1) {
                printf ";"
            }
            printf "%s:%s:%s:%s:%s:%s:%s:%s:%s:%s", \
                $1, $4, $5, $6, $8, $10, $11, $12, $13, $23
        }
        END {
            printf "\n"
        }
    ')
}

os_guard_multi_discover_targets() {
    multi_target_records=''
    multi_target_count=0
    multi_backup_required=false

    if ! os_guard_item_discover_targets; then
        if [ -z "$multi_error_code" ]; then
            os_guard_multi_set_error 'TARGET_DISCOVERY_FAILED' 'target discovery failed'
        fi
        return 1
    fi

    os_guard_multi_calculate_fingerprint
    return 0
}

os_guard_multi_run_existing_check() {
    if [ -n "$multi_test_root" ] && [ "${OS_GUARD_TEST_CHECK_FAILURE:-false}" = 'true' ]; then
        multi_check_status='ERROR'
        return 1
    fi

    multi_check_output=$(
        "$HARDEN_CHECK_SCRIPT" 2>/dev/null
    )
    multi_check_exit_status=$?
    if [ "$multi_check_exit_status" -ne 0 ]; then
        multi_check_status='ERROR'
        return 1
    fi

    for possible_status in GOOD VULNERABLE UNCHECKABLE N/A; do
        if printf '%s\n' "$multi_check_output" | grep -Eq \
            '"item_id":"'"$HARDEN_ITEM_ID"'".*"status":"'"$possible_status"'"'; then
            multi_check_status=$possible_status
            return 0
        fi
    done

    if printf '%s\n' "$multi_check_output" | grep -Eq \
        '"item_id":"'"$HARDEN_ITEM_ID"'".*"status":null'; then
        multi_check_status='PENDING'
        return 0
    fi

    multi_check_status='INVALID'
    return 1
}

os_guard_multi_validate_authorization() {
    if [ "${OS_GUARD_HARDEN_APPROVED:-}" != 'true' ]; then
        os_guard_multi_set_error 'APPROVAL_REQUIRED' 'EXECUTE requires an explicit approval flag'
        return 1
    fi

    approved_fingerprint=${OS_GUARD_HARDEN_EXPECTED_STATE:-}
    if [ -z "$approved_fingerprint" ]; then
        os_guard_multi_set_error 'EXPECTED_STATE_REQUIRED' 'EXECUTE requires the PREVIEW state fingerprint'
        return 1
    fi

    if [ "$approved_fingerprint" != "$multi_state_fingerprint" ]; then
        os_guard_multi_set_error 'STATE_DRIFT' 'target metadata or target list changed after PREVIEW'
        return 1
    fi

    return 0
}

os_guard_multi_create_backup() {
    if [ -n "$multi_test_root" ] && [ "${OS_GUARD_TEST_FAIL_STEP:-}" = 'backup' ]; then
        os_guard_multi_set_error 'BACKUP_FAILED' 'metadata backup creation failed'
        return 1
    fi

    if [ -n "$multi_test_root" ]; then
        default_backup_directory="${multi_test_root}/var/lib/os-guard-agent/backups/${HARDEN_ITEM_ID}"
        backup_base_directory=${OS_GUARD_TEST_BACKUP_ROOT:-"$default_backup_directory"}
    else
        backup_base_directory="/var/lib/os-guard-agent/backups/${HARDEN_ITEM_ID}"
    fi

    if ! os_guard_harden_create_private_directory "$backup_base_directory"; then
        os_guard_multi_set_error 'BACKUP_FAILED' 'backup base directory creation failed'
        return 1
    fi

    multi_backup_directory=$(mktemp -d "$backup_base_directory/backup.XXXXXX" 2>/dev/null || true)
    if [ -z "$multi_backup_directory" ]; then
        os_guard_multi_set_error 'BACKUP_FAILED' 'private backup directory creation failed'
        return 1
    fi

    if ! chmod 0700 -- "$multi_backup_directory"; then
        os_guard_multi_set_error 'BACKUP_FAILED' 'private backup directory permission setup failed'
        return 1
    fi

    multi_backup_identifier=${multi_backup_directory##*/}
    multi_backup_metadata_file="$multi_backup_directory/metadata"
    if ! printf '%s\n' "$multi_target_records" > "$multi_backup_metadata_file"; then
        os_guard_multi_set_error 'BACKUP_FAILED' 'metadata backup write failed'
        return 1
    fi

    if ! chmod 0600 -- "$multi_backup_metadata_file"; then
        os_guard_multi_set_error 'BACKUP_FAILED' 'metadata backup permission setup failed'
        return 1
    fi

    if [ -n "$multi_getfacl_command" ]; then
        multi_backup_acl_file="$multi_backup_directory/acl.restore"
        : > "$multi_backup_acl_file"
        while IFS='|' read -r display_path actual_path remaining_fields; do
            if ! "$multi_getfacl_command" -p -- "$actual_path" \
                >> "$multi_backup_acl_file" 2>/dev/null; then
                os_guard_multi_set_error 'BACKUP_FAILED' 'ACL backup failed'
                return 1
            fi
        done <<EOF
$multi_target_records
EOF

        if ! chmod 0600 -- "$multi_backup_acl_file"; then
            os_guard_multi_set_error 'BACKUP_FAILED' 'ACL backup permission setup failed'
            return 1
        fi
    fi

    multi_backup_created=true
    return 0
}

os_guard_multi_remove_acl_write() {
    target_path=$1

    if [ -z "$multi_getfacl_command" ] || [ -z "$multi_setfacl_command" ]; then
        os_guard_multi_set_error 'ACL_COMMAND_UNAVAILABLE' 'ACL hardening commands are unavailable'
        return 1
    fi

    acl_output=$(
        "$multi_getfacl_command" -cp -- "$target_path" 2>/dev/null
    )
    if [ $? -ne 0 ]; then
        os_guard_multi_set_error 'ACL_COLLECTION_FAILED' 'ACL metadata could not be collected before change'
        return 1
    fi

    acl_modifications=$(printf '%s\n' "$acl_output" | awk -F: '
        /^user:[^:]+:/ && $3 ~ /w/ {
            permissions = $3
            gsub(/w/, "-", permissions)
            print "user:" $2 ":" permissions
        }
    ')

    while IFS= read -r acl_modification; do
        if [ -z "$acl_modification" ]; then
            continue
        fi

        if ! "$multi_setfacl_command" -m "$acl_modification" -- "$target_path"; then
            os_guard_multi_set_error 'ACL_CHANGE_FAILED' 'ACL write permission removal failed'
            return 1
        fi
    done <<EOF
$acl_modifications
EOF

    return 0
}

os_guard_multi_apply_changes() {
    while IFS='|' read -r \
        display_path actual_path target_type device inode owner_uid owner_name \
        group_gid group_name permission mtime ctime context expected_uid \
        expected_name allowed_mask permission_policy acl_policy expected_permission \
        owner_change permission_change acl_change acl_fingerprint record_type; do

        if [ "$owner_change" = true ]; then
            if [ -n "$multi_test_root" ] &&
                [ "${OS_GUARD_TEST_FAIL_STEP:-}" = 'chown' ] &&
                { [ -z "${OS_GUARD_TEST_FAIL_TARGET:-}" ] ||
                    [ "$OS_GUARD_TEST_FAIL_TARGET" = "$display_path" ]; }; then
                os_guard_multi_set_error 'CHOWN_FAILED' 'owner hardening failed'
                return 1
            fi

            if ! "$multi_chown_command" "$expected_uid" -- "$actual_path"; then
                os_guard_multi_set_error 'CHOWN_FAILED' 'owner hardening failed'
                return 1
            fi
            multi_changes_applied=true
        fi

        if [ "$permission_change" = true ]; then
            if [ -n "$multi_test_root" ] &&
                [ "${OS_GUARD_TEST_FAIL_STEP:-}" = 'chmod' ] &&
                { [ -z "${OS_GUARD_TEST_FAIL_TARGET:-}" ] ||
                    [ "$OS_GUARD_TEST_FAIL_TARGET" = "$display_path" ]; }; then
                os_guard_multi_set_error 'CHMOD_FAILED' 'permission hardening failed'
                return 1
            fi

            if ! "$multi_chmod_command" "$expected_permission" -- "$actual_path"; then
                os_guard_multi_set_error 'CHMOD_FAILED' 'permission hardening failed'
                return 1
            fi
            multi_changes_applied=true
        fi

        if [ "$acl_change" = true ]; then
            if [ -n "$multi_test_root" ] &&
                [ "${OS_GUARD_TEST_FAIL_STEP:-}" = 'acl' ] &&
                { [ -z "${OS_GUARD_TEST_FAIL_TARGET:-}" ] ||
                    [ "$OS_GUARD_TEST_FAIL_TARGET" = "$display_path" ]; }; then
                os_guard_multi_set_error 'ACL_CHANGE_FAILED' 'ACL hardening failed'
                return 1
            fi

            if ! os_guard_multi_remove_acl_write "$actual_path"; then
                return 1
            fi
            multi_changes_applied=true
        fi
    done <<EOF
$multi_target_records
EOF

    return 0
}

os_guard_multi_validate_result() {
    if [ -n "$multi_test_root" ] && \
        [ "${OS_GUARD_TEST_FORCE_VALIDATION_FAILURE:-false}" = 'true' ]; then
        os_guard_multi_set_error 'VALIDATION_FAILED' 'forced metadata validation failure'
        return 1
    fi

    if ! os_guard_multi_discover_targets; then
        os_guard_multi_set_error 'VALIDATION_FAILED' 'target metadata could not be validated'
        return 1
    fi

    while IFS='|' read -r \
        display_path actual_path target_type device inode owner_uid owner_name \
        group_gid group_name permission mtime ctime context expected_uid \
        expected_name allowed_mask permission_policy acl_policy expected_permission \
        owner_change permission_change acl_change remaining_fields; do

        if [ "$owner_change" = true ] || \
            [ "$permission_change" = true ] || \
            [ "$acl_change" = true ]; then
            os_guard_multi_set_error 'VALIDATION_FAILED' 'one or more target metadata violations remain'
            return 1
        fi
    done <<EOF
$multi_target_records
EOF

    multi_validation_success=true
    return 0
}

os_guard_multi_rollback() {
    multi_rollback_attempted=true
    multi_rollback_success=false

    if [ -n "$multi_test_root" ] && [ "${OS_GUARD_TEST_FAIL_STEP:-}" = 'rollback' ]; then
        return 1
    fi

    original_records=$(cat "$multi_backup_metadata_file" 2>/dev/null || true)
    if [ -z "$original_records" ]; then
        return 1
    fi

    reverse_records=$(printf '%s\n' "$original_records" | awk '
        {
            records[NR] = $0
        }
        END {
            for (record_index = NR; record_index >= 1; record_index--) {
                print records[record_index]
            }
        }
    ')

    OS_GUARD_HARDEN_ROLLBACK=true
    export OS_GUARD_HARDEN_ROLLBACK

    while IFS='|' read -r \
        display_path actual_path target_type device inode owner_uid owner_name \
        group_gid group_name permission remaining_fields; do

        current_identity=$(
            "$multi_stat_command" -c '%d|%i' -- "$actual_path" 2>/dev/null
        )
        if [ "$current_identity" != "$device|$inode" ]; then
            return 1
        fi

        if ! "$multi_chown_command" "$owner_uid:$group_gid" -- "$actual_path"; then
            return 1
        fi

        if ! "$multi_chmod_command" "$permission" -- "$actual_path"; then
            return 1
        fi
    done <<EOF
$reverse_records
EOF

    if [ -n "$multi_backup_acl_file" ] && [ -s "$multi_backup_acl_file" ]; then
        if [ -z "$multi_setfacl_command" ]; then
            return 1
        fi
        if ! "$multi_setfacl_command" --restore="$multi_backup_acl_file" >/dev/null 2>&1; then
            return 1
        fi
    fi

    while IFS='|' read -r \
        display_path actual_path target_type device inode owner_uid owner_name \
        group_gid group_name permission modified_time changed_time context remaining_fields; do

        if ! os_guard_harden_collect_metadata_with_context \
            "$multi_stat_command" \
            '%d|%i|%u|%g|%a' \
            "$actual_path" \
            "$multi_test_root"; then
            return 1
        fi
        restored_metadata=$os_guard_harden_stat_metadata
        expected_metadata="$device|$inode|$owner_uid|$group_gid|$permission|$context"
        if [ "$restored_metadata" != "$expected_metadata" ]; then
            return 1
        fi
    done <<EOF
$original_records
EOF

    multi_rollback_success=true
    return 0
}

os_guard_multi_run_final_check() {
    if [ -n "$multi_test_root" ] && \
        [ "${OS_GUARD_TEST_FORCE_RECHECK_FAILURE:-false}" = 'true' ]; then
        multi_check_status='VULNERABLE'
        os_guard_multi_set_error 'RECHECK_FAILED' 'the existing CHECK did not return GOOD'
        return 1
    fi

    if ! os_guard_multi_run_existing_check; then
        os_guard_multi_set_error 'RECHECK_FAILED' 'the existing CHECK could not be evaluated'
        return 1
    fi

    if [ "$multi_check_status" != 'GOOD' ]; then
        os_guard_multi_set_error 'RECHECK_FAILED' 'the existing CHECK did not return GOOD'
        return 1
    fi

    return 0
}

os_guard_multi_run_optional_hook() {
    hook_name=$1

    if command -v "$hook_name" >/dev/null 2>&1; then
        "$hook_name"
        return $?
    fi

    return 0
}

os_guard_multi_print_targets() {
    printf '['
    first_target=true

    while IFS='|' read -r \
        display_path actual_path target_type device inode owner_uid owner_name \
        group_gid group_name permission mtime ctime context expected_uid \
        expected_name allowed_mask permission_policy acl_policy expected_permission \
        owner_change permission_change acl_change remaining_fields; do

        if [ -z "$display_path" ]; then
            continue
        fi
        if [ "$first_target" = false ]; then
            printf ','
        fi
        first_target=false

        printf '{"target":'
        os_guard_json_quote "$display_path"
        printf ',"target_type":'
        os_guard_json_quote "$target_type"
        printf ',"current_owner":'
        os_guard_json_quote "$owner_name"
        printf ',"current_owner_uid":'
        os_guard_json_quote "$owner_uid"
        printf ',"current_gid":'
        os_guard_json_quote "$group_gid"
        printf ',"current_permission":'
        os_guard_json_quote "$permission"
        printf ',"expected_owner_policy":'
        os_guard_json_quote "$expected_name (UID $expected_uid)"
        printf ',"expected_permission_policy":'
        os_guard_json_quote "$permission_policy"
        printf ',"expected_permission":'
        os_guard_json_quote "$expected_permission"
        printf ',"owner_change_required":%s' "$owner_change"
        printf ',"permission_change_required":%s' "$permission_change"
        printf ',"acl_change_required":%s' "$acl_change"
        printf '}'
    done <<EOF
$multi_target_records
EOF

    printf ']'
}

os_guard_multi_build_result() {
    printf '{"item_id":'
    os_guard_json_quote "$HARDEN_ITEM_ID"
    printf ',"action":'
    os_guard_harden_json_nullable_string "$multi_requested_action"
    printf ',"outcome":'
    os_guard_json_quote "$multi_outcome"
    printf ',"target":'
    os_guard_json_quote "$HARDEN_TARGET_DESCRIPTION"
    printf ',"preview":{"targets":'
    os_guard_multi_print_targets
    printf ',"backup_required":%s' "$multi_backup_required"
    printf ',"service_restart_required":false'
    printf ',"reboot_required":false'
    printf ',"risk":'
    os_guard_json_quote "$HARDEN_RISK_LEVEL"
    printf ',"state_fingerprint":'
    os_guard_harden_json_nullable_string "$multi_state_fingerprint"
    printf '}'
    printf ',"execution":{"backup_created":%s' "$multi_backup_created"
    printf ',"backup_id":'
    os_guard_harden_json_nullable_string "$multi_backup_identifier"
    printf ',"changes_applied":%s' "$multi_changes_applied"
    printf ',"validation_success":%s' "$multi_validation_success"
    printf ',"recheck_status":'
    os_guard_harden_json_nullable_string "$multi_check_status"
    printf ',"rollback_attempted":%s' "$multi_rollback_attempted"
    printf ',"rollback_success":%s' "$multi_rollback_success"
    printf '}'
    printf ',"error":'
    if [ -n "$multi_error_code" ]; then
        printf '{"code":'
        os_guard_json_quote "$multi_error_code"
        printf ',"message":'
        os_guard_json_quote "$multi_error_message"
        printf '}'
    else
        printf 'null'
    fi
    printf '}\n'
}

os_guard_multi_initialize() {
    multi_requested_action=${1:-}
    multi_distro=${OS_GUARD_DISTRO:-unknown}
    multi_version_id=${OS_GUARD_VERSION_ID:-unknown}
    multi_test_root=${OS_GUARD_TEST_ROOT:-}
    multi_outcome='FAILED'
    multi_error_code=''
    multi_error_message=''
    multi_check_status=''
    multi_target_records=''
    multi_target_count=0
    multi_state_fingerprint=''
    multi_backup_required=false
    multi_backup_created=false
    multi_backup_identifier=''
    multi_backup_directory=''
    multi_backup_metadata_file=''
    multi_backup_acl_file=''
    multi_changes_applied=false
    multi_validation_success=false
    multi_rollback_attempted=false
    multi_rollback_success=false
    multi_stat_command=''
    multi_chmod_command=''
    multi_chown_command=''
    multi_getfacl_command=''
    multi_setfacl_command=''
}

os_guard_multi_run_module() {
    os_guard_multi_initialize "$1"

    if ! os_guard_multi_detect_environment; then
        os_guard_multi_build_result
        return
    fi

    if ! os_guard_multi_run_existing_check; then
        os_guard_multi_set_error 'CHECK_EXECUTION_FAILED' 'the existing CHECK could not be evaluated'
        os_guard_multi_build_result
        return
    fi

    case "$multi_check_status" in
        GOOD)
            if ! os_guard_multi_discover_targets; then
                os_guard_multi_build_result
                return
            fi
            multi_outcome='NO_CHANGE'
            multi_validation_success=true
            os_guard_multi_build_result
            return
            ;;
        N/A)
            multi_outcome='NO_CHANGE'
            multi_validation_success=true
            multi_state_fingerprint='empty'
            os_guard_multi_build_result
            return
            ;;
        VULNERABLE)
            ;;
        PENDING|UNCHECKABLE)
            os_guard_multi_set_error 'CHECK_STATE_NOT_ACTIONABLE' 'the CHECK result is not actionable'
            os_guard_multi_build_result
            return
            ;;
        *)
            os_guard_multi_set_error 'CHECK_RESULT_INVALID' 'the existing CHECK returned an invalid result'
            os_guard_multi_build_result
            return
            ;;
    esac

    if ! os_guard_multi_discover_targets; then
        os_guard_multi_build_result
        return
    fi

    if [ "$multi_target_count" -eq 0 ]; then
        os_guard_multi_set_error 'NO_ACTIONABLE_TARGETS' 'no actionable target was discovered'
        os_guard_multi_build_result
        return
    fi

    if [ "$multi_requested_action" = 'PREVIEW' ]; then
        multi_outcome='PLANNED'
        os_guard_multi_build_result
        return
    fi

    if ! os_guard_multi_validate_authorization; then
        os_guard_multi_build_result
        return
    fi

    if ! os_guard_multi_run_optional_hook os_guard_item_pre_execute_validation; then
        if [ -z "$multi_error_code" ]; then
            os_guard_multi_set_error \
                'PRE_EXECUTE_VALIDATION_FAILED' \
                'item-specific pre-execution validation failed'
        fi
        os_guard_multi_build_result
        return
    fi

    if ! os_guard_multi_create_backup; then
        os_guard_multi_build_result
        return
    fi

    if ! os_guard_multi_apply_changes; then
        os_guard_multi_rollback || true
        os_guard_multi_build_result
        return
    fi

    if ! os_guard_multi_validate_result; then
        os_guard_multi_rollback || true
        os_guard_multi_build_result
        return
    fi

    if ! os_guard_multi_run_optional_hook os_guard_item_post_apply_validation; then
        if [ -z "$multi_error_code" ]; then
            os_guard_multi_set_error \
                'POST_APPLY_VALIDATION_FAILED' \
                'item-specific post-apply validation failed'
        fi
        os_guard_multi_rollback || true
        os_guard_multi_build_result
        return
    fi

    if ! os_guard_multi_run_final_check; then
        os_guard_multi_rollback || true
        os_guard_multi_build_result
        return
    fi

    multi_outcome='SUCCESS'
    os_guard_multi_build_result
}
