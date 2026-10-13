#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_service.sh"

HARDEN_ITEM_ID='U-42'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-42.sh"
HARDEN_TARGET_DESCRIPTION='KISA-listed unnecessary RPC systemd services'
HARDEN_SYSTEMD_UNITS='rpc.cmsd.service
rpc.ttdbserverd.service
sadmind.service
rusersd.service
walld.service
sprayd.service
rstatd.service
rpc.nisd.service
rexd.service
rpc.pcnfsd.service
rpc.statd.service
rpc.ypupdated.service
rpc.rquotad.service
kcms_server.service
cachefsd.service'
HARDEN_LEGACY_FILES='/etc/inetd.conf
/etc/xinetd.d/rpc.cmsd
/etc/xinetd.d/rpc.ttdbserverd
/etc/xinetd.d/sadmind
/etc/xinetd.d/rusersd
/etc/xinetd.d/walld
/etc/xinetd.d/sprayd
/etc/xinetd.d/rstatd
/etc/xinetd.d/rpc.nisd
/etc/xinetd.d/rexd
/etc/xinetd.d/rpc.pcnfsd
/etc/xinetd.d/rpc.statd
/etc/xinetd.d/rpc.ypupdated
/etc/xinetd.d/rpc.rquotad
/etc/xinetd.d/kcms_server
/etc/xinetd.d/cachefsd'
HARDEN_LEGACY_PATTERN='^[[:space:]]*(rpc\.cmsd|rpc\.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc\.nisd|rexd|rpc\.pcnfsd|rpc\.statd|rpc\.ypupdated|rpc\.rquotad|kcms_server|cachefsd)[[:space:]]|disable[[:space:]]*=[[:space:]]*no'
HARDEN_GUARD_UNITS='nfs-server.service
nfs-client.target
nfs-mountd.service
autofs.service
automount.service'

u42_fixture_policy_available() {
    if [ -z "$service_test_root" ] || \
        [ "$service_test_root" = '/' ] || \
        [ "${OS_GUARD_TEST_POLICY_FIXTURE:-false}" != 'true' ]; then
        os_guard_service_set_error \
            'POLICY_INTEGRATION_REQUIRED' \
            'trusted U-42 operating policy integration is not available'
        return 1
    fi
    return 0
}

u42_unit_is_approved() {
    wanted_unit=$1
    printf '%s\n' "${OS_GUARD_TEST_APPROVED_SERVICE_UNITS:-}" | \
        grep -Fx -- "$wanted_unit" >/dev/null 2>&1
}

os_guard_item_validate_service_policy() {
    if ! u42_fixture_policy_available; then
        return 1
    fi
    if [ "${OS_GUARD_TEST_SERVICE_STOP_APPROVED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_DEPENDENCY_EVIDENCE_VERIFIED:-false}" != 'true' ]; then
        os_guard_service_set_error \
            'RPC_OPERATING_EVIDENCE_REQUIRED' \
            'service-stop approval and verified RPC dependency evidence are required'
        return 1
    fi
    while IFS='|' read -r unit_name enabled_state; do
        [ -n "$unit_name" ] || continue
        if ! u42_unit_is_approved "$unit_name"; then
            os_guard_service_set_error \
                'SERVICE_SCOPE_NOT_APPROVED' \
                'an active RPC unit is outside the approved fixture scope'
            return 1
        fi
    done <<EOF
$service_active_records
EOF
    return 0
}

os_guard_service_run "${1:-}"
