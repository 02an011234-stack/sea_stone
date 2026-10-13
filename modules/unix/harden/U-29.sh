#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"

HARDEN_ITEM_ID='U-29'
HARDEN_TARGET_DISPLAY_PATH='/etc/hosts.lpd'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-29.sh"
HARDEN_ALLOWED_PERMISSION_MASK='0600'
HARDEN_REMEDIATION_OWNER_UID='0'
HARDEN_EXPECTED_OWNER_POLICY='root (UID 0)'
HARDEN_EXPECTED_PERMISSION_POLICY='no permission bit outside the 0600 allowance mask'
HARDEN_MISSING_POLICY='NO_CHANGE'

os_guard_item_owner_is_acceptable() {
    inspected_owner_uid=$1
    inspected_owner_name=$2

    if [ "$inspected_owner_uid" = '0' ] && [ "$inspected_owner_name" = 'root' ]; then
        return 0
    fi

    return 1
}

os_guard_harden_run_file_module "${1:-}"
