#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_service.sh"

HARDEN_ITEM_ID='U-38'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-38.sh"
HARDEN_TARGET_DESCRIPTION='policy-approved legacy echo, discard, daytime, and chargen units'
HARDEN_SYSTEMD_UNITS='echo.service
echo.socket
discard.service
discard.socket
daytime.service
daytime.socket
chargen.service
chargen.socket'
HARDEN_LEGACY_FILES='/etc/inetd.conf
/etc/xinetd.d/echo
/etc/xinetd.d/discard
/etc/xinetd.d/daytime
/etc/xinetd.d/chargen'
HARDEN_LEGACY_PATTERN='^[[:space:]]*(echo|discard|daytime|chargen)[[:space:]]|disable[[:space:]]*=[[:space:]]*no'
HARDEN_GUARD_UNITS='named.service
bind9.service
ntpd.service
ntp.service
chronyd.service
snmpd.service
snmptrapd.service'

u38_fixture_policy_available() {
    if [ -z "$service_test_root" ] || \
        [ "$service_test_root" = '/' ] || \
        [ "${OS_GUARD_TEST_POLICY_FIXTURE:-false}" != 'true' ]; then
        os_guard_service_set_error \
            'POLICY_INTEGRATION_REQUIRED' \
            'trusted U-38 operating policy integration is not available'
        return 1
    fi
}

u38_unit_is_approved() {
    wanted_unit=$1
    printf '%s\n' "${OS_GUARD_TEST_APPROVED_SERVICE_UNITS:-}" | \
        grep -Fx -- "$wanted_unit" >/dev/null 2>&1
}

os_guard_item_validate_service_policy() {
    if ! u38_fixture_policy_available; then
        return 1
    fi
    if [ "${OS_GUARD_TEST_LEGACY_DOS_SERVICE_RETIREMENT_APPROVED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_SERVICE_STOP_APPROVED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_DEPENDENCY_EVIDENCE_VERIFIED:-false}" != 'true' ]; then
        os_guard_service_set_error \
            'DOS_SERVICE_OPERATING_EVIDENCE_REQUIRED' \
            'legacy-service retirement and dependency evidence are required'
        return 1
    fi
    while IFS='|' read -r unit_name enabled_state; do
        [ -n "$unit_name" ] || continue
        if ! u38_unit_is_approved "$unit_name"; then
            os_guard_service_set_error \
                'SERVICE_SCOPE_NOT_APPROVED' \
                'an active legacy service unit is outside the approved fixture scope'
            return 1
        fi
    done <<EOF
$service_active_records
EOF
}

os_guard_service_run "${1:-}"
