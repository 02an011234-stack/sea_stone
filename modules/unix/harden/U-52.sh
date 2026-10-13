#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_service.sh"

HARDEN_ITEM_ID='U-52'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-52.sh"
HARDEN_TARGET_DESCRIPTION='policy-approved Telnet server systemd service and socket'
HARDEN_SYSTEMD_UNITS='telnet.service
telnet.socket'
HARDEN_LEGACY_FILES='/etc/inetd.conf
/etc/xinetd.d/telnet'
HARDEN_LEGACY_PATTERN='^[[:space:]]*telnet[[:space:]]|disable[[:space:]]*=[[:space:]]*no'

u52_fixture_policy_available() {
    if [ -z "$service_test_root" ] || \
        [ "$service_test_root" = '/' ] || \
        [ "${OS_GUARD_TEST_POLICY_FIXTURE:-false}" != 'true' ]; then
        os_guard_service_set_error \
            'POLICY_INTEGRATION_REQUIRED' \
            'trusted U-52 operating policy integration is not available'
        return 1
    fi
    return 0
}

u52_unit_is_approved() {
    wanted_unit=$1
    printf '%s\n' "${OS_GUARD_TEST_APPROVED_SERVICE_UNITS:-}" | \
        grep -Fx -- "$wanted_unit" >/dev/null 2>&1
}

os_guard_item_validate_service_policy() {
    if ! u52_fixture_policy_available; then
        return 1
    fi
    if [ "${OS_GUARD_TEST_TELNET_DISABLE_APPROVED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_SERVICE_STOP_APPROVED:-false}" != 'true' ]; then
        os_guard_service_set_error \
            'ALTERNATIVE_MANAGEMENT_EVIDENCE_REQUIRED' \
            'Telnet-disable and service-stop approvals are required'
        return 1
    fi
    case "${OS_GUARD_TEST_ALTERNATIVE_MANAGEMENT_METHOD:-}" in
        ssh-verified|console-verified)
            ;;
        *)
            os_guard_service_set_error \
                'ALTERNATIVE_MANAGEMENT_EVIDENCE_REQUIRED' \
                'verified SSH login or verified console access evidence is required'
            return 1
            ;;
    esac
    if [ "${OS_GUARD_TEST_ACTIVE_TELNET_SESSIONS_CLEARED:-false}" != 'true' ]; then
        os_guard_service_set_error \
            'ACTIVE_SESSION_EVIDENCE_REQUIRED' \
            'active Telnet session impact must be reviewed before service stop'
        return 1
    fi
    while IFS='|' read -r unit_name enabled_state; do
        [ -n "$unit_name" ] || continue
        if ! u52_unit_is_approved "$unit_name"; then
            os_guard_service_set_error \
                'SERVICE_SCOPE_NOT_APPROVED' \
                'an active Telnet server unit is outside the approved fixture scope'
            return 1
        fi
    done <<EOF
$service_active_records
EOF
    return 0
}

os_guard_service_run "${1:-}"
