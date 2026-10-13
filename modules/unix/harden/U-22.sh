#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"

HARDEN_ITEM_ID='U-22'
HARDEN_TARGET_DISPLAY_PATH='/etc/services'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-22.sh"
HARDEN_ALLOWED_PERMISSION_MASK='0644'
HARDEN_REMEDIATION_OWNER_UID='0'
HARDEN_EXPECTED_OWNER_POLICY='verified root, bin, or sys identity'
HARDEN_EXPECTED_PERMISSION_POLICY='no permission bit outside the 0644 allowance mask'
HARDEN_MISSING_POLICY='ERROR'

os_guard_item_owner_is_acceptable() {
    inspected_owner_uid=$1
    inspected_owner_name=$2

    case "$inspected_owner_name" in
        root|bin|sys)
            ;;
        *)
            return 1
            ;;
    esac

    getent_command=$(command -v getent 2>/dev/null || true)
    if [ -z "$getent_command" ]; then
        return 1
    fi

    identity_record=$($getent_command passwd "$inspected_owner_name" 2>/dev/null || true)
    identity_uid=$(printf '%s\n' "$identity_record" | awk -F: 'NF >= 3 { print $3; exit }')

    if [ -n "$identity_uid" ] && [ "$identity_uid" = "$inspected_owner_uid" ]; then
        return 0
    fi

    return 1
}

os_guard_harden_run_file_module "${1:-}"
