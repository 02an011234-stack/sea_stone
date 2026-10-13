#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"

ITEM_ID='U-20'
CHECK_SCRIPT="$MODULES_DIR/unix/U-20.sh"
ALLOWED_PERMISSION_MASK='0600'

requested_action=${1:-}
distro=${OS_GUARD_DISTRO:-unknown}
version_id=${OS_GUARD_VERSION_ID:-unknown}
test_root=${OS_GUARD_TEST_ROOT:-}

outcome='FAILED'
error_code=''
error_message=''
check_status=''
target_records=''
state_fingerprint=''
backup_required=false
backup_created=false
backup_identifier=''
changes_applied=false
validation_success=false
rollback_attempted=false
rollback_success=false

stat_command=''
chmod_command=''
chown_command=''

set_error() {
    error_code=$1
    error_message=$2
    outcome='FAILED'
}

resolve_commands() {
    if [ -n "$test_root" ] && [ -n "${OS_GUARD_TEST_STAT_BIN:-}" ]; then
        stat_command=$OS_GUARD_TEST_STAT_BIN
    else
        stat_command=$(command -v stat 2>/dev/null || true)
    fi

    if [ -n "$test_root" ] && [ -n "${OS_GUARD_TEST_CHMOD_BIN:-}" ]; then
        chmod_command=$OS_GUARD_TEST_CHMOD_BIN
    else
        chmod_command=$(command -v chmod 2>/dev/null || true)
    fi

    if [ -n "$test_root" ] && [ -n "${OS_GUARD_TEST_CHOWN_BIN:-}" ]; then
        chown_command=$OS_GUARD_TEST_CHOWN_BIN
    else
        chown_command=$(command -v chown 2>/dev/null || true)
    fi

    if [ -z "$stat_command" ] || [ ! -x "$stat_command" ]; then
        set_error 'STAT_COMMAND_UNAVAILABLE' 'required metadata command is unavailable'
        return 1
    fi

    if [ "$requested_action" = 'EXECUTE' ]; then
        if [ -z "$chmod_command" ] || [ ! -x "$chmod_command" ]; then
            set_error 'CHMOD_COMMAND_UNAVAILABLE' 'required permission command is unavailable'
            return 1
        fi

        if [ -z "$chown_command" ] || [ ! -x "$chown_command" ]; then
            set_error 'CHOWN_COMMAND_UNAVAILABLE' 'required ownership command is unavailable'
            return 1
        fi
    fi

    return 0
}

detect_environment() {
    case "$requested_action" in
        PREVIEW|EXECUTE)
            ;;
        *)
            set_error 'INVALID_ACTION' 'action must be PREVIEW or EXECUTE'
            return 1
            ;;
    esac

    if ! os_guard_harden_is_supported_os "$distro" "$version_id"; then
        set_error 'UNSUPPORTED_OS_CONFIGURATION' 'the current operating system is not supported'
        return 1
    fi

    if [ "$requested_action" = 'EXECUTE' ] && [ -z "$test_root" ]; then
        process_uid=$(id -u 2>/dev/null || true)
        if [ "$process_uid" != '0' ]; then
            set_error 'ROOT_PRIVILEGES_REQUIRED' 'EXECUTE requires root privileges'
            return 1
        fi
    fi

    resolve_commands
}

run_existing_check() {
    if [ -n "$test_root" ] && [ "${OS_GUARD_TEST_CHECK_FAILURE:-false}" = 'true' ]; then
        check_status='ERROR'
        return 1
    fi

    check_output=$(
        "$CHECK_SCRIPT" 2>/dev/null
    )
    check_exit_status=$?

    if [ "$check_exit_status" -ne 0 ]; then
        check_status='ERROR'
        return 1
    fi

    for possible_status in GOOD VULNERABLE UNCHECKABLE N/A; do
        if printf '%s\n' "$check_output" | grep -Eq '"item_id":"U-20".*"status":"'"$possible_status"'"'; then
            check_status=$possible_status
            return 0
        fi
    done

    if printf '%s\n' "$check_output" | grep -Eq '"item_id":"U-20".*"status":null'; then
        check_status='PENDING'
        return 0
    fi

    check_status='INVALID'
    return 1
}

append_candidate() {
    candidate_path=$1
    candidate_display=${candidate_path#"$test_root"}

    case "$candidate_display" in
        *[!A-Za-z0-9_./-]*)
            set_error 'TARGET_PATH_UNSAFE' 'a U-20 target path contains unsupported characters'
            return 1
            ;;
    esac

    case "$candidate_display" in
        /etc/inetd.conf|/etc/xinetd.conf|/etc/xinetd.d/*)
            ;;
        *)
            set_error 'TARGET_OUTSIDE_SCOPE' 'a discovered target is outside the U-20 scope'
            return 1
            ;;
    esac

    forced_symlink_path=${OS_GUARD_TEST_FORCE_SYMLINK_PATH:-}
    forced_nonregular_path=${OS_GUARD_TEST_FORCE_NONREGULAR_PATH:-}

    if [ -n "$test_root" ] && [ "$forced_symlink_path" = "$candidate_display" ]; then
        set_error 'SYMLINK_TARGET_REJECTED' 'a U-20 target is a symbolic link'
        return 1
    fi

    if [ -L "$candidate_path" ]; then
        set_error 'SYMLINK_TARGET_REJECTED' 'a U-20 target is a symbolic link'
        return 1
    fi

    if [ -n "$test_root" ] && [ "$forced_nonregular_path" = "$candidate_display" ]; then
        set_error 'TARGET_NOT_REGULAR_FILE' 'a U-20 target is not a regular file'
        return 1
    fi

    if [ ! -f "$candidate_path" ]; then
        set_error 'TARGET_NOT_REGULAR_FILE' 'a U-20 target is not a regular file'
        return 1
    fi

    metadata_output=$(
        "$stat_command" -c '%d|%i|%u|%U|%g|%a|%Y|%Z|%C' -- "$candidate_path" 2>/dev/null
    )
    metadata_exit_status=$?
    if [ "$metadata_exit_status" -ne 0 ]; then
        set_error 'STAT_COMMAND_FAILED' 'U-20 target metadata collection failed'
        return 1
    fi

    metadata_valid=$(printf '%s\n' "$metadata_output" | awk -F'|' '
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
            print "true"
        }
    ')
    if [ "$metadata_valid" != 'true' ]; then
        set_error 'STAT_OUTPUT_INVALID' 'U-20 target metadata output is invalid'
        return 1
    fi

    old_ifs=$IFS
    IFS='|'
    set -- $metadata_output
    IFS=$old_ifs

    device_number=$1
    inode_number=$2
    owner_uid=$3
    owner_name=$4
    group_gid=$5
    permission_mode=$6
    modified_time=$7
    changed_time=$8
    selinux_context=$9

    owner_change=false
    if [ "$owner_uid" != '0' ] || [ "$owner_name" != 'root' ]; then
        owner_change=true
    fi

    permission_value=$((0$permission_mode))
    allowed_permission_value=$((ALLOWED_PERMISSION_MASK))
    extra_permission_value=$((permission_value & ~allowed_permission_value))
    permission_change=false
    expected_permission=$permission_mode
    if [ "$extra_permission_value" -ne 0 ]; then
        reduced_permission_value=$((permission_value & allowed_permission_value))
        expected_permission=$(printf '%03o' "$reduced_permission_value")
        permission_change=true
    fi

    if [ "$owner_change" = true ] || [ "$permission_change" = true ]; then
        backup_required=true
    fi

    record=$(printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s' \
        "$candidate_display" "$candidate_path" "$device_number" "$inode_number" \
        "$owner_uid" "$owner_name" "$group_gid" "$permission_mode" \
        "$modified_time" "$changed_time" "$selinux_context" \
        "$expected_permission" "$owner_change:$permission_change")

    if [ -n "$target_records" ]; then
        target_records=$(printf '%s\n%s' "$target_records" "$record")
    else
        target_records=$record
    fi

    return 0
}

discover_targets() {
    target_records=''
    backup_required=false

    for primary_target in "${test_root}/etc/inetd.conf" "${test_root}/etc/xinetd.conf"; do
        if [ -e "$primary_target" ] || [ -L "$primary_target" ]; then
            if ! append_candidate "$primary_target"; then
                return 1
            fi
        fi
    done

    xinetd_directory="${test_root}/etc/xinetd.d"
    if [ -e "$xinetd_directory" ] || [ -L "$xinetd_directory" ]; then
        if [ -L "$xinetd_directory" ] || [ ! -d "$xinetd_directory" ]; then
            set_error 'TARGET_NOT_REGULAR_FILE' 'the xinetd.d target is not a regular directory'
            return 1
        fi

        find_command=$(command -v find 2>/dev/null || true)
        if [ -z "$find_command" ]; then
            set_error 'FIND_COMMAND_UNAVAILABLE' 'xinetd.d discovery command is unavailable'
            return 1
        fi

        discovered_paths=$(
            "$find_command" "$xinetd_directory" -mindepth 1 ! -type d -print 2>/dev/null
        )
        find_exit_status=$?
        if [ "$find_exit_status" -ne 0 ]; then
            set_error 'TARGET_DISCOVERY_FAILED' 'xinetd.d target discovery failed'
            return 1
        fi

        while IFS= read -r discovered_path; do
            if [ -z "$discovered_path" ]; then
                continue
            fi

            if ! append_candidate "$discovered_path"; then
                return 1
            fi
        done <<EOF
$discovered_paths
EOF
    fi

    if [ -z "$target_records" ]; then
        return 2
    fi

    state_fingerprint=$(printf '%s\n' "$target_records" | awk -F'|' '
        {
            if (NR > 1) {
                printf ";"
            }
            printf "%s:%s:%s:%s:%s:%s:%s:%s", $1, $3, $4, $5, $7, $8, $9, $10
        }
        END {
            printf "\n"
        }
    ')

    return 0
}

validate_authorization() {
    if [ "${OS_GUARD_HARDEN_APPROVED:-}" != 'true' ]; then
        set_error 'APPROVAL_REQUIRED' 'EXECUTE requires an explicit approval flag'
        return 1
    fi

    expected_state=${OS_GUARD_HARDEN_EXPECTED_STATE:-}
    if [ -z "$expected_state" ]; then
        set_error 'EXPECTED_STATE_REQUIRED' 'EXECUTE requires the PREVIEW state fingerprint'
        return 1
    fi

    if [ "$expected_state" != "$state_fingerprint" ]; then
        set_error 'STATE_DRIFT' 'one or more U-20 targets changed after PREVIEW'
        return 1
    fi

    return 0
}

create_backup() {
    if [ -n "$test_root" ] && [ "${OS_GUARD_TEST_FAIL_STEP:-}" = 'backup' ]; then
        set_error 'BACKUP_FAILED' 'metadata backup creation failed'
        return 1
    fi

    if [ -n "$test_root" ]; then
        backup_base_directory=${OS_GUARD_TEST_BACKUP_ROOT:-"${test_root}/var/lib/os-guard-agent/backups/U-20"}
    else
        backup_base_directory='/var/lib/os-guard-agent/backups/U-20'
    fi

    if ! os_guard_harden_create_private_directory "$backup_base_directory"; then
        set_error 'BACKUP_FAILED' 'backup base directory creation failed'
        return 1
    fi

    backup_directory=$(mktemp -d "$backup_base_directory/backup.XXXXXX" 2>/dev/null || true)
    if [ -z "$backup_directory" ]; then
        set_error 'BACKUP_FAILED' 'private backup directory creation failed'
        return 1
    fi

    if ! chmod 0700 -- "$backup_directory"; then
        set_error 'BACKUP_FAILED' 'private backup directory permission setup failed'
        return 1
    fi

    backup_identifier=${backup_directory##*/}
    backup_metadata_file="$backup_directory/metadata"
    if ! printf '%s\n' "$target_records" > "$backup_metadata_file"; then
        set_error 'BACKUP_FAILED' 'metadata backup write failed'
        return 1
    fi

    if ! chmod 0600 -- "$backup_metadata_file"; then
        set_error 'BACKUP_FAILED' 'metadata backup permission setup failed'
        return 1
    fi

    if [ -z "$test_root" ] || [ "${OS_GUARD_TEST_DISABLE_ACL_BACKUP:-false}" != 'true' ]; then
        getfacl_command=$(command -v getfacl 2>/dev/null || true)
        if [ -n "$getfacl_command" ]; then
            backup_acl_file="$backup_directory/acl.restore"
            : > "$backup_acl_file"
            while IFS='|' read -r display_path actual_path remaining_fields; do
                if ! "$getfacl_command" -p -- "$actual_path" >> "$backup_acl_file" 2>/dev/null; then
                    set_error 'BACKUP_FAILED' 'ACL backup failed'
                    return 1
                fi
            done <<EOF
$target_records
EOF
            if ! chmod 0600 -- "$backup_acl_file"; then
                set_error 'BACKUP_FAILED' 'ACL backup permission setup failed'
                return 1
            fi
        fi
    fi

    backup_created=true
    return 0
}

apply_changes() {
    while IFS='|' read -r \
        display_path actual_path device inode owner_uid owner_name \
        group_gid permission_mode modified_time changed_time context \
        expected_permission change_flags; do
        owner_change=${change_flags%%:*}
        permission_change=${change_flags#*:}

        if [ "$owner_change" = true ]; then
            if [ -n "$test_root" ] && [ "${OS_GUARD_TEST_FAIL_STEP:-}" = 'chown' ]; then
                set_error 'CHOWN_FAILED' 'owner hardening failed'
                return 1
            fi
            if ! "$chown_command" 0 -- "$actual_path"; then
                set_error 'CHOWN_FAILED' 'owner hardening failed'
                return 1
            fi
            changes_applied=true
        fi

        if [ "$permission_change" = true ]; then
            if [ -n "$test_root" ] && [ "${OS_GUARD_TEST_FAIL_STEP:-}" = 'chmod' ]; then
                set_error 'CHMOD_FAILED' 'permission hardening failed'
                return 1
            fi
            if ! "$chmod_command" "$expected_permission" -- "$actual_path"; then
                set_error 'CHMOD_FAILED' 'permission hardening failed'
                return 1
            fi
            changes_applied=true
        fi
    done <<EOF
$target_records
EOF

    return 0
}

validate_applied_state() {
    if [ -n "$test_root" ] && [ "${OS_GUARD_TEST_FORCE_VALIDATION_FAILURE:-false}" = 'true' ]; then
        set_error 'VALIDATION_FAILED' 'forced metadata validation failure'
        return 1
    fi

    previous_fingerprint=$state_fingerprint
    if ! discover_targets; then
        set_error 'VALIDATION_FAILED' 'U-20 targets could not be validated'
        return 1
    fi

    while IFS='|' read -r \
        display_path actual_path device inode owner_uid owner_name \
        group_gid permission_mode remaining_fields; do
        if [ "$owner_uid" != '0' ] || [ "$owner_name" != 'root' ]; then
            set_error 'VALIDATION_FAILED' 'owner validation failed'
            return 1
        fi

        permission_value=$((0$permission_mode))
        allowed_permission_value=$((ALLOWED_PERMISSION_MASK))
        if [ $((permission_value & ~allowed_permission_value)) -ne 0 ]; then
            set_error 'VALIDATION_FAILED' 'permission validation failed'
            return 1
        fi
    done <<EOF
$target_records
EOF

    validation_success=true
    return 0
}

rollback_changes() {
    rollback_attempted=true
    rollback_success=false

    if [ -n "$test_root" ] && [ "${OS_GUARD_TEST_FAIL_STEP:-}" = 'rollback' ]; then
        return 1
    fi

    original_records=$(cat "$backup_metadata_file" 2>/dev/null || true)
    if [ -z "$original_records" ]; then
        return 1
    fi

    OS_GUARD_HARDEN_ROLLBACK=true
    export OS_GUARD_HARDEN_ROLLBACK

    while IFS='|' read -r \
        display_path actual_path device inode owner_uid owner_name \
        group_gid permission_mode remaining_fields; do
        current_identity=$(
            "$stat_command" -c '%d|%i' -- "$actual_path" 2>/dev/null
        )
        if [ "$current_identity" != "$device|$inode" ]; then
            return 1
        fi

        if ! "$chown_command" "$owner_uid:$group_gid" -- "$actual_path"; then
            return 1
        fi

        if ! "$chmod_command" "$permission_mode" -- "$actual_path"; then
            return 1
        fi
    done <<EOF
$original_records
EOF

    if [ -n "${backup_acl_file:-}" ] && [ -f "$backup_acl_file" ]; then
        setfacl_command=$(command -v setfacl 2>/dev/null || true)
        if [ -z "$setfacl_command" ]; then
            return 1
        fi
        if ! "$setfacl_command" --restore="$backup_acl_file" >/dev/null 2>&1; then
            return 1
        fi
    fi

    while IFS='|' read -r \
        display_path actual_path device inode owner_uid owner_name \
        group_gid permission_mode remaining_fields; do
        restored_metadata=$(
            "$stat_command" -c '%d|%i|%u|%U|%g|%a|%Y|%Z|%C' -- "$actual_path" 2>/dev/null
        )
        restored_status=$?
        if [ "$restored_status" -ne 0 ]; then
            return 1
        fi

        restored_values=$(printf '%s\n' "$restored_metadata" | awk -F'|' '
            NF == 9 {
                print $1 "|" $2 "|" $3 "|" $5 "|" $6
            }
        ')
        expected_values="$device|$inode|$owner_uid|$group_gid|$permission_mode"
        if [ "$restored_values" != "$expected_values" ]; then
            return 1
        fi
    done <<EOF
$original_records
EOF

    rollback_success=true
    return 0
}

run_final_check() {
    if [ -n "$test_root" ] && [ "${OS_GUARD_TEST_FORCE_RECHECK_FAILURE:-false}" = 'true' ]; then
        check_status='VULNERABLE'
        set_error 'RECHECK_FAILED' 'the existing U-20 CHECK did not return GOOD'
        return 1
    fi

    if ! run_existing_check; then
        set_error 'RECHECK_FAILED' 'the existing U-20 CHECK could not be evaluated'
        return 1
    fi

    if [ "$check_status" != 'GOOD' ]; then
        set_error 'RECHECK_FAILED' 'the existing U-20 CHECK did not return GOOD'
        return 1
    fi

    return 0
}

print_target_preview_array() {
    printf '['
    first_target=true
    while IFS='|' read -r \
        display_path actual_path device inode owner_uid owner_name \
        group_gid permission_mode modified_time changed_time context \
        expected_permission change_flags; do
        if [ -z "$display_path" ]; then
            continue
        fi
        if [ "$first_target" = false ]; then
            printf ','
        fi
        first_target=false
        owner_change=${change_flags%%:*}
        permission_change=${change_flags#*:}
        printf '{"target":'
        os_guard_json_quote "$display_path"
        printf ',"current_owner":'
        os_guard_json_quote "$owner_name"
        printf ',"current_owner_uid":'
        os_guard_json_quote "$owner_uid"
        printf ',"current_gid":'
        os_guard_json_quote "$group_gid"
        printf ',"current_permission":'
        os_guard_json_quote "$permission_mode"
        printf ',"expected_owner":"root (UID 0)"'
        printf ',"expected_permission_policy":"no permission bit outside the 0600 allowance mask"'
        printf ',"expected_permission":'
        os_guard_json_quote "$expected_permission"
        printf ',"owner_change_required":%s' "$owner_change"
        printf ',"permission_change_required":%s' "$permission_change"
        printf '}'
    done <<EOF
$target_records
EOF
    printf ']'
}

build_result_json() {
    printf '{"item_id":"U-20","action":'
    os_guard_harden_json_nullable_string "$requested_action"
    printf ',"outcome":'
    os_guard_json_quote "$outcome"
    printf ',"target":"inetd/xinetd configuration files"'
    printf ',"preview":{"targets":'
    print_target_preview_array
    printf ',"backup_required":%s' "$backup_required"
    printf ',"service_restart_required":false'
    printf ',"reboot_required":false'
    printf ',"risk":"MEDIUM"'
    printf ',"state_fingerprint":'
    os_guard_harden_json_nullable_string "$state_fingerprint"
    printf '}'
    printf ',"execution":{"backup_created":%s' "$backup_created"
    printf ',"backup_id":'
    os_guard_harden_json_nullable_string "$backup_identifier"
    printf ',"changes_applied":%s' "$changes_applied"
    printf ',"validation_success":%s' "$validation_success"
    printf ',"recheck_status":'
    os_guard_harden_json_nullable_string "$check_status"
    printf ',"rollback_attempted":%s' "$rollback_attempted"
    printf ',"rollback_success":%s' "$rollback_success"
    printf '}'
    printf ',"error":'
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
    if ! detect_environment; then
        build_result_json
        return
    fi

    if ! run_existing_check; then
        set_error 'CHECK_EXECUTION_FAILED' 'the existing U-20 CHECK could not be evaluated'
        build_result_json
        return
    fi

    case "$check_status" in
        GOOD)
            if ! discover_targets; then
                set_error 'TARGET_DISCOVERY_FAILED' 'GOOD U-20 targets could not be collected safely'
                build_result_json
                return
            fi
            outcome='NO_CHANGE'
            validation_success=true
            build_result_json
            return
            ;;
        N/A)
            outcome='NO_CHANGE'
            validation_success=true
            build_result_json
            return
            ;;
        VULNERABLE)
            ;;
        PENDING|UNCHECKABLE)
            set_error 'CHECK_STATE_NOT_ACTIONABLE' 'the U-20 CHECK result is not actionable'
            build_result_json
            return
            ;;
        *)
            set_error 'CHECK_RESULT_INVALID' 'the existing U-20 CHECK returned an invalid result'
            build_result_json
            return
            ;;
    esac

    if ! discover_targets; then
        set_error 'TARGET_DISCOVERY_FAILED' 'applicable U-20 targets could not be collected safely'
        build_result_json
        return
    fi

    if [ "$requested_action" = 'PREVIEW' ]; then
        outcome='PLANNED'
        build_result_json
        return
    fi

    if ! validate_authorization; then
        build_result_json
        return
    fi

    if ! create_backup; then
        build_result_json
        return
    fi

    if ! apply_changes; then
        rollback_changes || true
        build_result_json
        return
    fi

    if ! validate_applied_state; then
        rollback_changes || true
        build_result_json
        return
    fi

    if ! run_final_check; then
        rollback_changes || true
        build_result_json
        return
    fi

    outcome='SUCCESS'
    build_result_json
}

main
