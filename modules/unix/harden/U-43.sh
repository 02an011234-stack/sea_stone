#!/bin/sh
set -u
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_service.sh"

HARDEN_ITEM_ID='U-43'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-43.sh"
HARDEN_TARGET_DESCRIPTION='policy-approved NIS systemd services'
HARDEN_SYSTEMD_UNITS='ypserv.service
ypbind.service
ypxfrd.service
rpc.yppasswdd.service
rpc.ypupdated.service'
HARDEN_LEGACY_FILES='/etc/inetd.conf
/etc/xinetd.d/ypserv
/etc/xinetd.d/ypbind'
HARDEN_LEGACY_PATTERN='ypserv|ypbind|ypxfrd|rpc\.yppasswdd|rpc\.ypupdated'
HARDEN_GUARD_UNITS=''

u43_approved_unit() {
    printf '%s\n' "${OS_GUARD_TEST_APPROVED_SERVICE_UNITS:-}" | grep -Fx -- "$1" >/dev/null 2>&1
}

os_guard_item_validate_service_policy() {
    if [ -z "$service_test_root" ] || [ "$service_test_root" = '/' ] || \
        [ "${OS_GUARD_TEST_POLICY_FIXTURE:-false}" != 'true' ]; then
        os_guard_service_set_error 'POLICY_INTEGRATION_REQUIRED' 'trusted U-43 operating policy integration is unavailable'
        return 1
    fi
    if [ "${OS_GUARD_TEST_NIS_RETIREMENT_APPROVED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_SERVICE_STOP_APPROVED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_NIS_DEPENDENCIES_VERIFIED:-false}" != 'true' ]; then
        os_guard_service_set_error 'NIS_OPERATING_EVIDENCE_REQUIRED' 'NIS retirement and dependency evidence are required'
        return 1
    fi
    while IFS='|' read -r unit_name enabled_state; do
        [ -n "$unit_name" ] || continue
        if ! u43_approved_unit "$unit_name"; then
            os_guard_service_set_error 'SERVICE_SCOPE_NOT_APPROVED' 'an active NIS unit is outside the approved scope'
            return 1
        fi
    done <<EOF
$service_active_records
EOF
}

os_guard_service_run "${1:-}"
