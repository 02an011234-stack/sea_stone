#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_service.sh"

HARDEN_ITEM_ID='U-36'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-36.sh"
HARDEN_TARGET_DESCRIPTION='policy-approved r-command systemd services and sockets'
HARDEN_SYSTEMD_UNITS='rsh.socket
rlogin.socket
rexec.socket
rsh.service
rlogin.service
rexec.service
rsync.service
rsyncd.service'
HARDEN_LEGACY_FILES='/etc/inetd.conf
/etc/xinetd.d/rsh
/etc/xinetd.d/rlogin
/etc/xinetd.d/rexec'
HARDEN_LEGACY_PATTERN='^[[:space:]]*(rsh|shell|login|exec)[[:space:]]|disable[[:space:]]*=[[:space:]]*no'

u36_fixture_policy_available() {
    if [ -z "$service_test_root" ] || \
        [ "$service_test_root" = '/' ] || \
        [ "${OS_GUARD_TEST_POLICY_FIXTURE:-false}" != 'true' ]; then
        os_guard_service_set_error \
            'POLICY_INTEGRATION_REQUIRED' \
            'trusted U-36 operating policy integration is not available'
        return 1
    fi
    return 0
}

u36_unit_is_approved() {
    wanted_unit=$1
    printf '%s\n' "${OS_GUARD_TEST_APPROVED_SERVICE_UNITS:-}" | \
        grep -Fx -- "$wanted_unit" >/dev/null 2>&1
}

os_guard_item_validate_service_policy() {
    if ! u36_fixture_policy_available; then
        return 1
    fi
    if [ "${OS_GUARD_TEST_SERVICE_STOP_APPROVED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_MANAGEMENT_PATH_VERIFIED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_DEPENDENCY_EVIDENCE_VERIFIED:-false}" != 'true' ]; then
        os_guard_service_set_error \
            'OPERATING_EVIDENCE_REQUIRED' \
            'service-stop, management-path, and dependency evidence are required'
        return 1
    fi
    while IFS='|' read -r unit_name enabled_state; do
        [ -n "$unit_name" ] || continue
        if ! u36_unit_is_approved "$unit_name"; then
            os_guard_service_set_error \
                'SERVICE_SCOPE_NOT_APPROVED' \
                'an active r-command unit is outside the approved fixture scope'
            return 1
        fi
    done <<EOF
$service_active_records
EOF
    return 0
}

os_guard_service_run "${1:-}"
