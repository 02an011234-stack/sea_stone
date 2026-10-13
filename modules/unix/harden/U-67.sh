#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_multi.sh"

HARDEN_ITEM_ID='U-67'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-67.sh"
HARDEN_TARGET_DESCRIPTION='regular log files below /var/log with safely resolvable ownership'
HARDEN_RISK_LEVEL='HIGH'

u67_policy_path_is_approved() {
    wanted_path=$1
    printf '%s\n' "${OS_GUARD_TEST_APPROVED_LOG_PATHS:-}" | \
        grep -Fx -- "$wanted_path" >/dev/null 2>&1
}

u67_validate_fixture_policy() {
    if [ -z "$multi_test_root" ] || \
        [ "$multi_test_root" = '/' ] || \
        [ "${OS_GUARD_TEST_POLICY_FIXTURE:-false}" != 'true' ]; then
        os_guard_multi_set_error \
            'POLICY_INTEGRATION_REQUIRED' \
            'trusted U-67 log ownership and writer policy integration is not available'
        return 1
    fi
    if [ "${OS_GUARD_TEST_LOG_WRITER_VERIFIED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_LOGROTATE_POLICY_VERIFIED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_LOG_WRITE_HEALTHCHECK_APPROVED:-false}" != 'true' ]; then
        os_guard_multi_set_error \
            'LOG_OPERATING_EVIDENCE_REQUIRED' \
            'log writer, logrotate, and post-change write-health evidence are required'
        return 1
    fi
    return 0
}

add_log_target() {
    log_path=$1
    display_path=${log_path#"$multi_test_root"}

    if ! u67_policy_path_is_approved "$display_path"; then
        os_guard_multi_set_error \
            'LOG_PATH_NOT_APPROVED' \
            'a discovered log file is outside the approved fixture scope'
        return 1
    fi

    if [ -L "$log_path" ]; then
        os_guard_multi_set_error \
            'SYMLINK_TARGET_REJECTED' \
            'a symbolic log target cannot be hardened safely'
        return 1
    fi

    owner_output=$(
        "$multi_stat_command" -c '%u|%U' -- "$log_path" 2>/dev/null
    )
    if [ $? -ne 0 ]; then
        os_guard_multi_set_error 'STAT_COMMAND_FAILED' 'log owner metadata collection failed'
        return 1
    fi

    if [ "$owner_output" != '0|root' ]; then
        os_guard_multi_set_error \
            'LOG_OWNER_POLICY_UNRESOLVED' \
            'a non-root log owner cannot be changed automatically without service ownership policy'
        return 1
    fi

    os_guard_multi_add_target \
        "$log_path" \
        "$display_path" \
        'file' \
        '0' \
        'root' \
        '0644' \
        'no permission bit outside the 0644 log-file allowance mask' \
        'NONE'
}

os_guard_item_discover_targets() {
    if [ "$multi_check_status" = 'VULNERABLE' ] && \
        ! u67_validate_fixture_policy; then
        return 1
    fi
    log_directory="${multi_test_root}/var/log"
    if [ ! -d "$log_directory" ]; then
        os_guard_multi_set_error \
            'LOG_DIRECTORY_UNAVAILABLE' \
            'the log directory is unavailable'
        return 1
    fi

    find_command=$(command -v find 2>/dev/null || true)
    if [ -z "$find_command" ]; then
        os_guard_multi_set_error \
            'FIND_COMMAND_UNAVAILABLE' \
            'log target discovery command is unavailable'
        return 1
    fi

    log_paths=$(
        "$find_command" "$log_directory" -xdev -type f -print 2>/dev/null
    )
    if [ $? -ne 0 ]; then
        os_guard_multi_set_error 'LOG_DISCOVERY_FAILED' 'log target discovery failed'
        return 1
    fi

    while IFS= read -r log_path; do
        if [ -z "$log_path" ]; then
            continue
        fi
        if ! add_log_target "$log_path"; then
            return 1
        fi
    done <<EOF
$log_paths
EOF

    return 0
}

os_guard_multi_run_module "${1:-}"
