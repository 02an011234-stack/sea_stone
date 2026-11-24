#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_service.sh"

HARDEN_ITEM_ID='U-58'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-58.sh"
HARDEN_TARGET_DESCRIPTION='policy-approved SNMP systemd services and sockets'
HARDEN_SYSTEMD_UNITS='snmpd.service
snmpd.socket
snmptrapd.service
snmptrapd.socket'
HARDEN_LEGACY_FILES='/etc/inetd.conf
/etc/xinetd.d/snmpd
/etc/xinetd.d/snmptrapd'
HARDEN_LEGACY_PATTERN='^[[:space:]]*snmp(trap)?[[:space:]]|disable[[:space:]]*=[[:space:]]*no'

u58_fixture_policy_available() {
    if [ -z "$service_test_root" ] || \
        [ "$service_test_root" = '/' ] || \
        [ "${OS_GUARD_TEST_POLICY_FIXTURE:-false}" != 'true' ]; then
        os_guard_service_set_error \
            'POLICY_INTEGRATION_REQUIRED' \
            'trusted U-58 operating policy integration is not available'
        return 1
    fi
}

u58_unit_is_approved() {
    wanted_unit=$1
    printf '%s\n' "${OS_GUARD_TEST_APPROVED_SERVICE_UNITS:-}" | \
        grep -Fx -- "$wanted_unit" >/dev/null 2>&1
}

os_guard_item_validate_service_policy() {
    if ! u58_fixture_policy_available; then
        return 1
    fi
    if [ "${OS_GUARD_TEST_SNMP_RETIREMENT_APPROVED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_SERVICE_STOP_APPROVED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_MONITORING_IMPACT_VERIFIED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_ALTERNATIVE_MONITORING_VERIFIED:-false}" != 'true' ]; then
        os_guard_service_set_error \
            'SNMP_OPERATING_EVIDENCE_REQUIRED' \
            'SNMP retirement and monitoring-impact evidence are required'
        return 1
    fi
    while IFS='|' read -r unit_name enabled_state; do
        [ -n "$unit_name" ] || continue
        if ! u58_unit_is_approved "$unit_name"; then
            os_guard_service_set_error \
                'SERVICE_SCOPE_NOT_APPROVED' \
                'an active SNMP unit is outside the approved fixture scope'
            return 1
        fi
    done <<EOF
$service_active_records
EOF
}

os_guard_service_run "${1:-}"
