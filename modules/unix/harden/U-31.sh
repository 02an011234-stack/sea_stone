#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_multi.sh"

HARDEN_ITEM_ID='U-31'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-31.sh"
HARDEN_TARGET_DESCRIPTION='passwd account home directories'
HARDEN_RISK_LEVEL='MEDIUM'

determine_home_permission_mask() {
    home_path=$1
    account_name=$2

    group_output=$(
        "$multi_stat_command" -c '%g|%G|%a' -- "$home_path" 2>/dev/null
    )
    if [ $? -ne 0 ]; then
        os_guard_multi_set_error 'STAT_COMMAND_FAILED' 'home directory group metadata collection failed'
        return 1
    fi

    old_ifs=$IFS
    IFS='|'
    set -- $group_output
    IFS=$old_ifs
    home_group_gid=$1
    home_group_name=$2
    home_permission=$3
    permission_value=$((0$home_permission))

    if [ $((permission_value & 0020)) -eq 0 ]; then
        home_permission_mask='07775'
        return 0
    fi

    getent_command=$(command -v getent 2>/dev/null || true)
    if [ -z "$getent_command" ]; then
        os_guard_multi_set_error 'GROUP_RELATIONSHIP_UNRESOLVED' 'home group membership cannot be resolved'
        return 1
    fi

    group_record=$($getent_command group "$home_group_gid" 2>/dev/null || true)
    case "$group_record" in
        *:*:*:*)
            ;;
        *)
            os_guard_multi_set_error 'GROUP_RELATIONSHIP_UNRESOLVED' 'home group membership cannot be resolved'
            return 1
            ;;
    esac
    group_members=$(printf '%s\n' "$group_record" | awk -F: 'NF >= 4 { print $4; exit }')
    case ",$group_members," in
        ""|","|",$account_name,")
            home_permission_mask='07775'
            return 0
            ;;
        *)
            home_permission_mask='07755'
            return 0
            ;;
    esac
}

add_home_target() {
    home_path=$1
    account_name=$2
    account_uid=$3
    display_path=${home_path#"$multi_test_root"}

    if [ -L "$home_path" ]; then
        os_guard_multi_set_error \
            'SYMLINK_TARGET_REJECTED' \
            'an account home symbolic link cannot be hardened safely'
        return 1
    fi

    if ! determine_home_permission_mask "$home_path" "$account_name"; then
        return 1
    fi

    os_guard_multi_add_target \
        "$home_path" \
        "$display_path" \
        'directory' \
        "$account_uid" \
        "$account_name" \
        "$home_permission_mask" \
        'other write and confirmed non-owner group write are prohibited' \
        'NO_NAMED_USER_OR_OTHER_WRITE'
}

os_guard_item_discover_targets() {
    passwd_path="${multi_test_root}/etc/passwd"
    if [ ! -r "$passwd_path" ]; then
        os_guard_multi_set_error 'PASSWD_UNREADABLE' 'local account metadata cannot be read safely'
        return 1
    fi

    while IFS=: read -r \
        account_name password_field account_uid account_gid gecos home_directory \
        login_shell extra_field; do

        if [ -z "$account_name$password_field$account_uid$account_gid$gecos$home_directory$login_shell" ]; then
            continue
        fi
        case "$account_uid:$account_gid" in
            *[!0-9:]*|:*)
                os_guard_multi_set_error 'PASSWD_PARSE_FAILED' 'account UID or GID metadata is invalid'
                return 1
                ;;
        esac
        if [ -z "$home_directory" ] || [ "${home_directory#/}" = "$home_directory" ]; then
            os_guard_multi_set_error 'HOME_RELATIONSHIP_UNRESOLVED' 'an account home path is not absolute'
            return 1
        fi

        home_path="${multi_test_root}${home_directory}"
        if [ ! -e "$home_path" ] && [ ! -L "$home_path" ]; then
            continue
        fi
        if ! add_home_target "$home_path" "$account_name" "$account_uid"; then
            return 1
        fi
    done < "$passwd_path"

    return 0
}

os_guard_multi_run_module "${1:-}"
