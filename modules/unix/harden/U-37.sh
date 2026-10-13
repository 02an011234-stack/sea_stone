#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_multi.sh"

HARDEN_ITEM_ID='U-37'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-37.sh"
HARDEN_TARGET_DESCRIPTION='cron and at executables, configuration files, and spool directories'
HARDEN_RISK_LEVEL='MEDIUM'

add_cron_target() {
    target_path=$1
    target_type=$2
    target_class=$3
    display_path=${target_path#"$multi_test_root"}

    case "$target_class" in
        executable)
            allowed_mask='0750'
            permission_policy='no permission bit outside the 0750 executable allowance mask'
            ;;
        configuration)
            allowed_mask='0640'
            permission_policy='no permission bit outside the 0640 configuration allowance mask'
            ;;
        directory)
            allowed_mask='07775'
            permission_policy='other write permission is prohibited on spool directories'
            ;;
        *)
            os_guard_multi_set_error 'TARGET_CLASS_INVALID' 'an unsupported cron or at target class was selected'
            return 1
            ;;
    esac

    os_guard_multi_add_target \
        "$target_path" \
        "$display_path" \
        "$target_type" \
        '0' \
        'root' \
        "$allowed_mask" \
        "$permission_policy" \
        'NONE'
}

os_guard_item_discover_targets() {
    for executable_path in \
        "${multi_test_root}/usr/bin/crontab" \
        "${multi_test_root}/usr/bin/at" \
        "${multi_test_root}/usr/bin/atq" \
        "${multi_test_root}/usr/bin/atrm"; do
        if [ -e "$executable_path" ] || [ -L "$executable_path" ]; then
            if ! add_cron_target "$executable_path" 'file' 'executable'; then
                return 1
            fi
        fi
    done

    for configuration_path in \
        "${multi_test_root}/etc/cron.allow" \
        "${multi_test_root}/etc/cron.deny" \
        "${multi_test_root}/etc/at.allow" \
        "${multi_test_root}/etc/at.deny" \
        "${multi_test_root}/etc/crontab"; do
        if [ -e "$configuration_path" ] || [ -L "$configuration_path" ]; then
            if ! add_cron_target "$configuration_path" 'file' 'configuration'; then
                return 1
            fi
        fi
    done

    for directory_path in \
        "${multi_test_root}/etc/cron.d" \
        "${multi_test_root}/var/spool/cron" \
        "${multi_test_root}/var/spool/cron/crontabs" \
        "${multi_test_root}/var/spool/at" \
        "${multi_test_root}/var/spool/atjobs"; do
        if [ -e "$directory_path" ] || [ -L "$directory_path" ]; then
            if ! add_cron_target "$directory_path" 'directory' 'directory'; then
                return 1
            fi
        fi
    done

    return 0
}

os_guard_multi_run_module "${1:-}"
