#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_service.sh"

HARDEN_ITEM_ID='U-41'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-41.sh"
HARDEN_TARGET_DESCRIPTION='policy-approved autofs systemd service'
HARDEN_SYSTEMD_UNITS='autofs.service
automount.service'
HARDEN_LEGACY_FILES=''
HARDEN_LEGACY_PATTERN='a^'
HARDEN_GUARD_UNITS='nfs-server.service
nfs-client.target
smb.service
smbd.service'

u41_fixture_policy_available() {
    if [ -z "$service_test_root" ] || \
        [ "$service_test_root" = '/' ] || \
        [ "${OS_GUARD_TEST_POLICY_FIXTURE:-false}" != 'true' ]; then
        os_guard_service_set_error \
            'POLICY_INTEGRATION_REQUIRED' \
            'trusted U-41 operating policy integration is not available'
        return 1
    fi
}

u41_unit_is_approved() {
    wanted_unit=$1
    printf '%s\n' "${OS_GUARD_TEST_APPROVED_SERVICE_UNITS:-}" | \
        grep -Fx -- "$wanted_unit" >/dev/null 2>&1
}

os_guard_item_validate_service_policy() {
    if ! u41_fixture_policy_available; then
        return 1
    fi
    if [ "${OS_GUARD_TEST_AUTOFS_RETIREMENT_APPROVED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_SERVICE_STOP_APPROVED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_AUTOMOUNT_DEPENDENCIES_VERIFIED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_ACTIVE_AUTOMOUNTS_CLEARED:-false}" != 'true' ]; then
        os_guard_service_set_error \
            'AUTOFS_OPERATING_EVIDENCE_REQUIRED' \
            'retirement approval and verified automount dependency evidence are required'
        return 1
    fi
    while IFS='|' read -r unit_name enabled_state; do
        [ -n "$unit_name" ] || continue
        if ! u41_unit_is_approved "$unit_name"; then
            os_guard_service_set_error \
                'SERVICE_SCOPE_NOT_APPROVED' \
                'an active automount unit is outside the approved fixture scope'
            return 1
        fi
    done <<EOF
$service_active_records
EOF
}

os_guard_service_run "${1:-}"
