#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_multi.sh"

HARDEN_ITEM_ID='U-17'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-17.sh"
HARDEN_TARGET_DESCRIPTION='system startup scripts and active systemd configuration targets'
HARDEN_RISK_LEVEL='MEDIUM'

determine_startup_permission_mask() {
    target_path=$1
    metadata_output=$(
        "$multi_stat_command" -c '%g|%G|%a' -- "$target_path" 2>/dev/null
    )
    if [ $? -ne 0 ]; then
        os_guard_multi_set_error 'STAT_COMMAND_FAILED' 'startup target group metadata collection failed'
        return 1
    fi

    old_ifs=$IFS
    IFS='|'
    set -- $metadata_output
    IFS=$old_ifs
    target_group_gid=$1
    target_group_name=$2
    target_permission=$3

    case "$target_group_gid:$target_group_name:$target_permission" in
        *[!0-9:A-Za-z_.-]*)
            os_guard_multi_set_error 'STAT_OUTPUT_INVALID' 'startup target group metadata is invalid'
            return 1
            ;;
    esac

    permission_value=$((0$target_permission))
    if [ $((permission_value & 0020)) -eq 0 ]; then
        startup_permission_mask='07775'
        return 0
    fi

    if [ "$target_group_gid" = '0' ] && [ "$target_group_name" = 'root' ]; then
        startup_permission_mask='07775'
        return 0
    fi

    passwd_path="${multi_test_root}/etc/passwd"
    group_path="${multi_test_root}/etc/group"
    if [ ! -r "$passwd_path" ] || [ ! -r "$group_path" ]; then
        os_guard_multi_set_error \
            'GROUP_RELATIONSHIP_UNRESOLVED' \
            'group-write safety cannot be determined from local account metadata'
        return 1
    fi

    if awk -F: -v gid="$target_group_gid" '
        FNR == NR {
            if ($3 ~ /^[0-9]+$/ && $3 != 0 && $4 == gid) {
                found = 1
            }
            next
        }
        $3 == gid && $4 != "" {
            found = 1
        }
        END {
            exit found ? 0 : 1
        }
    ' "$passwd_path" "$group_path"; then
        startup_permission_mask='07755'
        return 0
    fi

    os_guard_multi_set_error \
        'GROUP_RELATIONSHIP_UNRESOLVED' \
        'group-write safety requires manual account and group review'
    return 1
}

add_startup_target() {
    target_path=$1

    if [ -L "$target_path" ]; then
        resolved_path=$(readlink -f -- "$target_path" 2>/dev/null || true)
        if [ "$resolved_path" = '/dev/null' ] || \
            [ "$resolved_path" = "${multi_test_root}/dev/null" ]; then
            return 0
        fi
        os_guard_multi_set_error \
            'SYMLINK_TARGET_REJECTED' \
            'an unexpected startup symbolic link target was detected'
        return 1
    fi

    if ! determine_startup_permission_mask "$target_path"; then
        return 1
    fi

    display_path=${target_path#"$multi_test_root"}
    os_guard_multi_add_target \
        "$target_path" \
        "$display_path" \
        'file' \
        '0' \
        'root' \
        "$startup_permission_mask" \
        'preserve all bits except confirmed non-owner write access' \
        'NONE'
}

scan_startup_tree() {
    startup_directory=$1

    if [ ! -d "$startup_directory" ]; then
        return 0
    fi

    find_command=$(command -v find 2>/dev/null || true)
    if [ -z "$find_command" ]; then
        os_guard_multi_set_error 'FIND_COMMAND_UNAVAILABLE' 'startup target discovery command is unavailable'
        return 1
    fi

    startup_paths=$(
        "$find_command" "$startup_directory" -mindepth 1 ! -type d -print 2>/dev/null
    )
    if [ $? -ne 0 ]; then
        os_guard_multi_set_error 'TARGET_DISCOVERY_FAILED' 'startup target discovery failed'
        return 1
    fi

    while IFS= read -r startup_path; do
        if [ -z "$startup_path" ]; then
            continue
        fi
        if ! add_startup_target "$startup_path"; then
            return 1
        fi
    done <<EOF
$startup_paths
EOF

    return 0
}

os_guard_item_discover_targets() {
    if ! scan_startup_tree "${multi_test_root}/etc/systemd/system"; then
        return 1
    fi

    if [ -d "${multi_test_root}/etc/rc.d" ]; then
        if ! scan_startup_tree "${multi_test_root}/etc/rc.d"; then
            return 1
        fi
    elif [ -d "${multi_test_root}/etc/init.d" ]; then
        if ! scan_startup_tree "${multi_test_root}/etc/init.d"; then
            return 1
        fi
    fi

    for standalone_path in \
        "${multi_test_root}/etc/rc.local" \
        "${multi_test_root}/etc/rc.sysinit"; do
        if [ -e "$standalone_path" ] || [ -L "$standalone_path" ]; then
            if ! add_startup_target "$standalone_path"; then
                return 1
            fi
        fi
    done

    return 0
}

os_guard_multi_run_module "${1:-}"
