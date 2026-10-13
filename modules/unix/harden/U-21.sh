#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_multi.sh"

HARDEN_ITEM_ID='U-21'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-21.sh"
HARDEN_TARGET_DESCRIPTION='syslog and rsyslog configuration files'
HARDEN_RISK_LEVEL='LOW'

select_logging_owner_policy() {
    target_path=$1
    owner_output=$(
        "$multi_stat_command" -c '%u|%U' -- "$target_path" 2>/dev/null
    )
    if [ $? -ne 0 ]; then
        os_guard_multi_set_error 'STAT_COMMAND_FAILED' 'logging target owner metadata collection failed'
        return 1
    fi

    owner_uid=${owner_output%%|*}
    owner_name=${owner_output#*|}
    case "$owner_name" in
        root)
            if [ "$owner_uid" = '0' ]; then
                selected_owner_uid=$owner_uid
                selected_owner_name=$owner_name
                return 0
            fi
            ;;
        bin|sys)
            getent_command=$(command -v getent 2>/dev/null || true)
            if [ -n "$getent_command" ]; then
                identity_record=$($getent_command passwd "$owner_name" 2>/dev/null || true)
                identity_uid=$(printf '%s\n' "$identity_record" | awk -F: 'NF >= 3 { print $3; exit }')
                if [ "$identity_uid" = "$owner_uid" ]; then
                    selected_owner_uid=$owner_uid
                    selected_owner_name=$owner_name
                    return 0
                fi
            fi
            ;;
    esac

    selected_owner_uid='0'
    selected_owner_name='root'
    return 0
}

add_logging_target() {
    target_path=$1
    display_path=${target_path#"$multi_test_root"}

    if [ -L "$target_path" ]; then
        os_guard_multi_set_error \
            'SYMLINK_TARGET_REJECTED' \
            'an unexpected logging configuration symbolic link was detected'
        return 1
    fi

    if ! select_logging_owner_policy "$target_path"; then
        return 1
    fi

    os_guard_multi_add_target \
        "$target_path" \
        "$display_path" \
        'file' \
        "$selected_owner_uid" \
        "$selected_owner_name" \
        '0640' \
        'no permission bit outside the 0640 allowance mask' \
        'NONE'
}

scan_rsyslog_fragments() {
    fragment_directory="${multi_test_root}/etc/rsyslog.d"
    if [ ! -d "$fragment_directory" ]; then
        return 0
    fi

    find_command=$(command -v find 2>/dev/null || true)
    if [ -z "$find_command" ]; then
        os_guard_multi_set_error 'FIND_COMMAND_UNAVAILABLE' 'rsyslog target discovery command is unavailable'
        return 1
    fi

    fragment_paths=$(
        "$find_command" "$fragment_directory" -mindepth 1 ! -type d -print 2>/dev/null
    )
    if [ $? -ne 0 ]; then
        os_guard_multi_set_error 'TARGET_DISCOVERY_FAILED' 'rsyslog target discovery failed'
        return 1
    fi

    while IFS= read -r fragment_path; do
        if [ -z "$fragment_path" ]; then
            continue
        fi
        if ! add_logging_target "$fragment_path"; then
            return 1
        fi
    done <<EOF
$fragment_paths
EOF

    return 0
}

os_guard_item_discover_targets() {
    for primary_path in \
        "${multi_test_root}/etc/syslog.conf" \
        "${multi_test_root}/etc/rsyslog.conf"; do
        if [ -e "$primary_path" ] || [ -L "$primary_path" ]; then
            if ! add_logging_target "$primary_path"; then
                return 1
            fi
        fi
    done

    scan_rsyslog_fragments
}

os_guard_multi_run_module "${1:-}"
