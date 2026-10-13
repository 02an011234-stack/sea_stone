#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"

ITEM_ID='U-19'
TARGET_DISPLAY_PATH='/etc/hosts'
EXPECTED_OWNER_NAME='root'
EXPECTED_OWNER_UID='0'
ALLOWED_PERMISSION_MASK='0644'

requested_action=${1:-}
distro=${OS_GUARD_DISTRO:-unknown}
version_id=${OS_GUARD_VERSION_ID:-unknown}
module_version=${OS_GUARD_MODULE_VERSION:-unknown}
test_root=${OS_GUARD_TEST_ROOT:-}
target_file="${test_root}${TARGET_DISPLAY_PATH}"
check_script="$MODULES_DIR/unix/U-19.sh"

outcome='FAILED'
error_code=''
error_message=''

current_owner_uid=''
current_owner_name=''
current_group_gid=''
current_permission=''
current_device=''
current_inode=''
current_mtime=''
current_ctime=''
current_selinux_context=''
current_state_fingerprint=''

expected_permission=''
owner_change_required=false
permission_change_required=false
backup_required=false
service_restart_required=false
reboot_required=false
risk_level='LOW'

backup_created=false
backup_identifier=''
backup_directory=''
backup_metadata_file=''
backup_acl_file=''
acl_backup_created=false

changes_applied=false
validation_success=false
recheck_status=''
rollback_attempted=false
rollback_success=false

original_owner_uid=''
original_group_gid=''
original_permission=''
original_device=''
original_inode=''
original_selinux_context=''

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
        current_process_uid=$(id -u 2>/dev/null || true)
        if [ "$current_process_uid" != '0' ]; then
            set_error 'ROOT_PRIVILEGES_REQUIRED' 'EXECUTE requires root privileges'
            return 1
        fi
    fi

    resolve_commands
}

validate_target_object() {
    if { [ -n "$test_root" ] && [ "${OS_GUARD_TEST_FORCE_SYMLINK:-false}" = 'true' ]; } || [ -L "$target_file" ]; then
        set_error 'SYMLINK_TARGET_REJECTED' 'the hosts target is a symbolic link'
        return 1
    fi

    if [ ! -e "$target_file" ]; then
        set_error 'TARGET_NOT_FOUND' 'the hosts target does not exist'
        return 1
    fi

    if [ ! -f "$target_file" ]; then
        set_error 'TARGET_NOT_REGULAR_FILE' 'the hosts target is not a regular file'
        return 1
    fi

    return 0
}

collect_current_state() {
    metadata_output=$(
        "$stat_command" -c '%d|%i|%u|%U|%g|%a|%Y|%Z|%C' -- "$target_file" 2>/dev/null
    )
    metadata_status=$?

    if [ "$metadata_status" -ne 0 ]; then
        set_error 'STAT_COMMAND_FAILED' 'hosts metadata collection failed'
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

    if [ "$metadata_valid" != 'true' ]; then
        set_error 'STAT_OUTPUT_INVALID' 'hosts metadata output is invalid'
        return 1
    fi

    current_device=$(printf '%s\n' "$metadata_output" | awk -F'|' '{ print $1 }')
    current_inode=$(printf '%s\n' "$metadata_output" | awk -F'|' '{ print $2 }')
    current_owner_uid=$(printf '%s\n' "$metadata_output" | awk -F'|' '{ print $3 }')
    current_owner_name=$(printf '%s\n' "$metadata_output" | awk -F'|' '{ print $4 }')
    current_group_gid=$(printf '%s\n' "$metadata_output" | awk -F'|' '{ print $5 }')
    current_permission=$(printf '%s\n' "$metadata_output" | awk -F'|' '{ print $6 }')
    current_mtime=$(printf '%s\n' "$metadata_output" | awk -F'|' '{ print $7 }')
    current_ctime=$(printf '%s\n' "$metadata_output" | awk -F'|' '{ print $8 }')
    current_selinux_context=$(printf '%s\n' "$metadata_output" | awk -F'|' '{ print $9 }')

    current_state_fingerprint=$(printf '%s:%s:%s:%s:%s:%s:%s' \
        "$current_device" \
        "$current_inode" \
        "$current_owner_uid" \
        "$current_group_gid" \
        "$current_permission" \
        "$current_mtime" \
        "$current_ctime")

    return 0
}

calculate_change_plan() {
    owner_change_required=false
    permission_change_required=false

    if [ "$current_owner_uid" != "$EXPECTED_OWNER_UID" ] || [ "$current_owner_name" != "$EXPECTED_OWNER_NAME" ]; then
        owner_change_required=true
    fi

    permission_value=$((0$current_permission))
    allowed_permission_value=$((ALLOWED_PERMISSION_MASK))
    excessive_permission_value=$((permission_value & ~allowed_permission_value))

    if [ "$excessive_permission_value" -eq 0 ]; then
        expected_permission=$current_permission
    else
        reduced_permission_value=$((permission_value & allowed_permission_value))
        expected_permission=$(printf '%03o' "$reduced_permission_value")
        permission_change_required=true
    fi

    if [ "$owner_change_required" = true ] || [ "$permission_change_required" = true ]; then
        backup_required=true
    else
        backup_required=false
    fi
}

run_u19_check() {
    check_output=$(
        "$check_script" 2>/dev/null
    )
    check_status=$?

    if [ "$check_status" -ne 0 ]; then
        recheck_status='ERROR'
        return 1
    fi

    if printf '%s\n' "$check_output" | grep -Eq '"item_id":"U-19".*"status":"GOOD"'; then
        recheck_status='GOOD'
        return 0
    fi

    if printf '%s\n' "$check_output" | grep -Eq '"item_id":"U-19".*"status":"VULNERABLE"'; then
        recheck_status='VULNERABLE'
        return 0
    fi

    if printf '%s\n' "$check_output" | grep -Eq '"item_id":"U-19".*"status":"UNCHECKABLE"'; then
        recheck_status='UNCHECKABLE'
        return 0
    fi

    if printf '%s\n' "$check_output" | grep -Eq '"item_id":"U-19".*"status":"N/A"'; then
        recheck_status='N/A'
        return 0
    fi

    if printf '%s\n' "$check_output" | grep -Eq '"item_id":"U-19".*"status":null'; then
        recheck_status='PENDING'
        return 0
    fi

    recheck_status='INVALID'
    return 1
}

ensure_hardening_is_applicable() {
    if ! run_u19_check; then
        set_error 'CHECK_EXECUTION_FAILED' 'the existing U-19 CHECK could not be evaluated'
        return 1
    fi

    case "$recheck_status" in
        GOOD)
            outcome='NO_CHANGE'
            return 2
            ;;
        VULNERABLE)
            return 0
            ;;
        N/A|PENDING|UNCHECKABLE)
            set_error 'CHECK_STATE_NOT_ACTIONABLE' 'U-19 CHECK is not in an actionable VULNERABLE state'
            return 1
            ;;
        *)
            set_error 'CHECK_RESULT_INVALID' 'U-19 CHECK returned an invalid result'
            return 1
            ;;
    esac
}

generate_preview() {
    calculate_change_plan

    if [ "$owner_change_required" = false ] && [ "$permission_change_required" = false ]; then
        outcome='NO_CHANGE'
    else
        outcome='PLANNED'
    fi
}

validate_execute_authorization() {
    if [ "${OS_GUARD_HARDEN_APPROVED:-}" != 'true' ]; then
        set_error 'APPROVAL_REQUIRED' 'EXECUTE requires an explicit approval flag'
        return 1
    fi

    expected_state=${OS_GUARD_HARDEN_EXPECTED_STATE:-}
    if [ -z "$expected_state" ]; then
        set_error 'EXPECTED_STATE_REQUIRED' 'EXECUTE requires the PREVIEW state fingerprint'
        return 1
    fi

    if [ "$expected_state" != "$current_state_fingerprint" ]; then
        set_error 'TARGET_STATE_CHANGED' 'the hosts metadata changed after PREVIEW'
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
        backup_base_directory=${OS_GUARD_TEST_BACKUP_ROOT:-"${test_root}/var/lib/os-guard-agent/backups/U-19"}
    else
        backup_base_directory='/var/lib/os-guard-agent/backups/U-19'
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
    backup_acl_file="$backup_directory/acl.restore"

    if ! printf '%s|%s|%s|%s|%s|%s\n' \
        "$current_device" \
        "$current_inode" \
        "$current_owner_uid" \
        "$current_group_gid" \
        "$current_permission" \
        "$current_selinux_context" > "$backup_metadata_file"; then
        set_error 'BACKUP_FAILED' 'metadata backup write failed'
        return 1
    fi

    if ! chmod 0600 -- "$backup_metadata_file"; then
        set_error 'BACKUP_FAILED' 'metadata backup permission setup failed'
        return 1
    fi

    if [ -n "$test_root" ] && [ "${OS_GUARD_TEST_DISABLE_ACL_BACKUP:-false}" = 'true' ]; then
        getfacl_command=''
    else
        getfacl_command=$(command -v getfacl 2>/dev/null || true)
    fi
    if [ -n "$getfacl_command" ]; then
        if ! "$getfacl_command" -p -- "$target_file" > "$backup_acl_file" 2>/dev/null; then
            set_error 'BACKUP_FAILED' 'ACL backup failed'
            return 1
        fi

        if ! chmod 0600 -- "$backup_acl_file"; then
            set_error 'BACKUP_FAILED' 'ACL backup permission setup failed'
            return 1
        fi

        acl_backup_created=true
    fi

    backup_created=true
    return 0
}

apply_owner_change() {
    if [ "$owner_change_required" = false ]; then
        return 0
    fi

    if [ -n "$test_root" ] && [ "${OS_GUARD_TEST_FAIL_STEP:-}" = 'chown' ]; then
        set_error 'CHOWN_FAILED' 'owner hardening failed'
        return 1
    fi

    if ! "$chown_command" "$EXPECTED_OWNER_UID" -- "$target_file"; then
        set_error 'CHOWN_FAILED' 'owner hardening failed'
        return 1
    fi

    changes_applied=true
    return 0
}

apply_permission_change() {
    if [ "$permission_change_required" = false ]; then
        return 0
    fi

    if [ -n "$test_root" ] && [ "${OS_GUARD_TEST_FAIL_STEP:-}" = 'chmod' ]; then
        set_error 'CHMOD_FAILED' 'permission hardening failed'
        return 1
    fi

    if ! "$chmod_command" "$expected_permission" -- "$target_file"; then
        set_error 'CHMOD_FAILED' 'permission hardening failed'
        return 1
    fi

    changes_applied=true
    return 0
}

apply_hardening() {
    if ! apply_owner_change; then
        return 1
    fi

    if ! apply_permission_change; then
        return 1
    fi

    return 0
}

validate_result_metadata() {
    if ! validate_target_object; then
        return 1
    fi

    if ! collect_current_state; then
        return 1
    fi

    permission_value=$((0$current_permission))
    allowed_permission_value=$((ALLOWED_PERMISSION_MASK))
    excessive_permission_value=$((permission_value & ~allowed_permission_value))

    if [ "$current_owner_uid" != "$EXPECTED_OWNER_UID" ]; then
        set_error 'VALIDATION_FAILED' 'owner UID validation failed'
        return 1
    fi

    if [ "$current_owner_name" != "$EXPECTED_OWNER_NAME" ]; then
        set_error 'VALIDATION_FAILED' 'owner name validation failed'
        return 1
    fi

    if [ "$excessive_permission_value" -ne 0 ]; then
        set_error 'VALIDATION_FAILED' 'permission validation failed'
        return 1
    fi

    validation_success=true
    return 0
}

run_final_recheck() {
    if [ -n "$test_root" ] && [ "${OS_GUARD_TEST_FORCE_RECHECK_FAILURE:-}" = 'true' ]; then
        recheck_status='VULNERABLE'
        set_error 'RECHECK_FAILED' 'the existing U-19 CHECK did not return GOOD'
        return 1
    fi

    if ! run_u19_check; then
        set_error 'RECHECK_FAILED' 'the existing U-19 CHECK could not be evaluated'
        return 1
    fi

    if [ "$recheck_status" != 'GOOD' ]; then
        set_error 'RECHECK_FAILED' 'the existing U-19 CHECK did not return GOOD'
        return 1
    fi

    return 0
}

rollback_changes() {
    rollback_attempted=true
    rollback_success=false

    if [ -n "$test_root" ] && [ "${OS_GUARD_TEST_FAIL_STEP:-}" = 'rollback' ]; then
        return 1
    fi

    if [ -L "$target_file" ] || [ ! -f "$target_file" ]; then
        return 1
    fi

    rollback_identity=$(
        "$stat_command" -c '%d|%i' -- "$target_file" 2>/dev/null
    )
    if [ "$rollback_identity" != "$original_device|$original_inode" ]; then
        return 1
    fi

    OS_GUARD_HARDEN_ROLLBACK=true
    export OS_GUARD_HARDEN_ROLLBACK

    if ! "$chown_command" "$original_owner_uid:$original_group_gid" -- "$target_file"; then
        return 1
    fi

    if ! "$chmod_command" "$original_permission" -- "$target_file"; then
        return 1
    fi

    if [ "$acl_backup_created" = true ]; then
        setfacl_command=$(command -v setfacl 2>/dev/null || true)
        if [ -z "$setfacl_command" ]; then
            return 1
        fi

        if ! "$setfacl_command" --restore="$backup_acl_file" >/dev/null 2>&1; then
            return 1
        fi
    fi

    if ! collect_current_state; then
        return 1
    fi

    if [ "$current_owner_uid" != "$original_owner_uid" ]; then
        return 1
    fi

    if [ "$current_group_gid" != "$original_group_gid" ]; then
        return 1
    fi

    if [ "$current_permission" != "$original_permission" ]; then
        return 1
    fi

    rollback_success=true
    return 0
}

remember_original_state() {
    original_owner_uid=$current_owner_uid
    original_group_gid=$current_group_gid
    original_permission=$current_permission
    original_device=$current_device
    original_inode=$current_inode
    original_selinux_context=$current_selinux_context
}

execute_hardening() {
    if ! validate_execute_authorization; then
        return 1
    fi

    if [ "$owner_change_required" = false ] && [ "$permission_change_required" = false ]; then
        outcome='NO_CHANGE'
        validation_success=true
        return 0
    fi

    remember_original_state

    if ! create_backup; then
        return 1
    fi

    if ! apply_hardening; then
        rollback_changes || true
        return 1
    fi

    if ! validate_result_metadata; then
        rollback_changes || true
        return 1
    fi

    if ! run_final_recheck; then
        rollback_changes || true
        return 1
    fi

    outcome='SUCCESS'
    return 0
}

json_nullable_string() {
    value=$1

    if [ -n "$value" ]; then
        os_guard_json_quote "$value"
    else
        printf 'null'
    fi
}

build_result_json() {
    printf '{"item_id":"U-19","action":'
    json_nullable_string "$requested_action"
    printf ',"outcome":'
    os_guard_json_quote "$outcome"
    printf ',"target":"/etc/hosts"'

    printf ',"preview":{"current_owner":'
    json_nullable_string "$current_owner_name"
    printf ',"current_uid":'
    json_nullable_string "$current_owner_uid"
    printf ',"current_gid":'
    json_nullable_string "$current_group_gid"
    printf ',"current_permission":'
    json_nullable_string "$current_permission"
    printf ',"expected_owner":"root","expected_uid":"0","expected_permission":'
    json_nullable_string "$expected_permission"
    printf ',"owner_change_required":%s' "$owner_change_required"
    printf ',"permission_change_required":%s' "$permission_change_required"
    printf ',"backup_required":%s' "$backup_required"
    printf ',"service_restart_required":%s' "$service_restart_required"
    printf ',"reboot_required":%s' "$reboot_required"
    printf ',"risk":'
    os_guard_json_quote "$risk_level"
    printf ',"state_fingerprint":'
    json_nullable_string "$current_state_fingerprint"
    printf '}'

    printf ',"execution":{"backup_created":%s' "$backup_created"
    printf ',"backup_id":'
    json_nullable_string "$backup_identifier"
    printf ',"changes_applied":%s' "$changes_applied"
    printf ',"validation_success":%s' "$validation_success"
    printf ',"recheck_status":'
    json_nullable_string "$recheck_status"
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

    if ! validate_target_object; then
        build_result_json
        return
    fi

    if ! collect_current_state; then
        build_result_json
        return
    fi

    calculate_change_plan

    ensure_hardening_is_applicable
    applicability_status=$?
    if [ "$applicability_status" -eq 2 ]; then
        generate_preview
        validation_success=true
        build_result_json
        return
    fi
    if [ "$applicability_status" -ne 0 ]; then
        build_result_json
        return
    fi

    if [ "$requested_action" = 'PREVIEW' ]; then
        generate_preview
        build_result_json
        return
    fi

    if ! execute_hardening; then
        build_result_json
        return
    fi

    build_result_json
}

main
