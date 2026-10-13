#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_multi.sh"

HARDEN_ITEM_ID='U-24'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-24.sh"
HARDEN_TARGET_DESCRIPTION='bounded account home environment files'
HARDEN_RISK_LEVEL='MEDIUM'

add_environment_target() {
    target_path=$1
    account_name=$2
    account_uid=$3
    display_path=${target_path#"$multi_test_root"}

    if [ -L "$target_path" ]; then
        os_guard_multi_set_error \
            'SYMLINK_TARGET_REJECTED' \
            'an account environment symbolic link cannot be hardened safely'
        return 1
    fi

    owner_output=$(
        "$multi_stat_command" -c '%u|%U' -- "$target_path" 2>/dev/null
    )
    if [ $? -ne 0 ]; then
        os_guard_multi_set_error 'STAT_COMMAND_FAILED' 'environment file owner metadata collection failed'
        return 1
    fi
    current_uid=${owner_output%%|*}
    current_name=${owner_output#*|}

    if [ "$current_uid" = '0' ] && [ "$current_name" = 'root' ]; then
        expected_uid='0'
        expected_name='root'
    else
        expected_uid=$account_uid
        expected_name=$account_name
    fi

    os_guard_multi_add_target \
        "$target_path" \
        "$display_path" \
        'file' \
        "$expected_uid" \
        "$expected_name" \
        '07755' \
        'group and other write bits are prohibited' \
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

        for environment_name in \
            .profile .kshrc .cshrc .bashrc .bash_profile .login .exrc .netrc; do
            environment_path="${multi_test_root}${home_directory}/${environment_name}"
            if [ -e "$environment_path" ] || [ -L "$environment_path" ]; then
                if ! add_environment_target \
                    "$environment_path" "$account_name" "$account_uid"; then
                    return 1
                fi
            fi
        done
    done < "$passwd_path"

    return 0
}

os_guard_multi_run_module "${1:-}"
