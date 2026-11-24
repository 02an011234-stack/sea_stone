#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_service.sh"

HARDEN_ITEM_ID='U-54'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-54.sh"
HARDEN_TARGET_DESCRIPTION='policy-approved plaintext FTP services'
HARDEN_SYSTEMD_UNITS='vsftpd.service
proftpd.service
ftp.service
ftp.socket'
HARDEN_LEGACY_FILES='/etc/inetd.conf
/etc/xinetd.d/ftp'
HARDEN_LEGACY_PATTERN='(^|[[:space:]])ftp([[:space:]]|$)|disable[[:space:]]*=[[:space:]]*no'
HARDEN_GUARD_UNITS=''

u54_fixture_policy_available() {
    if [ -z "$service_test_root" ] || \
        [ "$service_test_root" = '/' ] || \
        [ "${OS_GUARD_TEST_POLICY_FIXTURE:-false}" != 'true' ]; then
        os_guard_service_set_error \
            'POLICY_INTEGRATION_REQUIRED' \
            'trusted U-54 operating policy integration is not available'
        return 1
    fi
}

u54_unit_is_approved() {
    wanted_unit=$1
    printf '%s\n' "${OS_GUARD_TEST_APPROVED_SERVICE_UNITS:-}" | \
        grep -Fx -- "$wanted_unit" >/dev/null 2>&1
}

os_guard_item_validate_service_policy() {
    if ! u54_fixture_policy_available; then
        return 1
    fi
    if [ "${OS_GUARD_TEST_PLAINTEXT_FTP_RETIREMENT_APPROVED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_SERVICE_STOP_APPROVED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_SECURE_TRANSFER_ALTERNATIVE_VERIFIED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_FTP_CLIENT_MIGRATION_VERIFIED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_ACTIVE_FTP_SESSIONS_CLEARED:-false}" != 'true' ]; then
        os_guard_service_set_error \
            'FTP_RETIREMENT_EVIDENCE_REQUIRED' \
            'FTP retirement, alternative transfer, client, and session evidence are required'
        return 1
    fi

    while IFS='|' read -r unit_name enabled_state; do
        [ -n "$unit_name" ] || continue
        if ! u54_unit_is_approved "$unit_name"; then
            os_guard_service_set_error \
                'SERVICE_SCOPE_NOT_APPROVED' \
                'an active FTP unit is outside the approved fixture scope'
            return 1
        fi
    done <<EOF
$service_active_records
EOF
}

os_guard_service_run "${1:-}"
