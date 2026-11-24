#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_content.sh"

HARDEN_ITEM_ID='U-56'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-56.sh"
HARDEN_TARGET_DESCRIPTION='one static ProFTPD host access-control block'
HARDEN_RISK_LEVEL='HIGH'
HARDEN_SERVICE_RELOAD_REQUIRED=true

u56_configuration_path=''

u56_set_error() {
    os_guard_content_set_error "$1" "$2"
    return 1
}

u56_unit_is_active() {
    unit_name=$1
    systemctl_command=$(command -v systemctl 2>/dev/null || true)
    [ -n "$systemctl_command" ] && \
        [ "$("$systemctl_command" is-active "$unit_name" 2>/dev/null || true)" = 'active' ]
}

os_guard_item_validate_content_policy() {
    if [ -z "$content_test_root" ] || \
        [ "$content_test_root" = '/' ] || \
        [ "${OS_GUARD_TEST_POLICY_FIXTURE:-false}" != 'true' ]; then
        u56_set_error \
            'POLICY_INTEGRATION_REQUIRED' \
            'trusted U-56 operating policy integration is not available'
        return 1
    fi
    if [ "${OS_GUARD_TEST_APPROVED_FTP_DAEMON:-}" != 'proftpd' ] || \
        [ "${OS_GUARD_TEST_PROFTPD_CONFIGURATION_SOURCE:-}" != 'static-proftpd-conf' ] || \
        [ "${OS_GUARD_TEST_FTP_ACCESS_POLICY_APPROVED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_FTP_CLIENT_IMPACT_VERIFIED:-false}" != 'true' ]; then
        u56_set_error \
            'FTP_ACCESS_POLICY_EVIDENCE_REQUIRED' \
            'approved ProFTPD access policy and client-impact evidence are required'
        return 1
    fi
    if ! os_guard_harden_ipv4_cidr_is_bounded \
        "${OS_GUARD_TEST_APPROVED_FTP_NETWORK:-}"; then
        u56_set_error \
            'FTP_NETWORK_SCOPE_INVALID' \
            'one bounded approved FTP network is required'
        return 1
    fi
    if [ "$content_action" = 'EXECUTE' ] && \
        [ "${OS_GUARD_TEST_RELOAD_APPROVED:-false}" != 'true' ]; then
        u56_set_error \
            'SERVICE_RELOAD_APPROVAL_REQUIRED' \
            'ProFTPD reload approval is required'
        return 1
    fi
}

os_guard_item_render_content() {
    source_path=$1
    cat "$source_path"
    printf '<Limit LOGIN>\n'
    printf '  Allow from %s\n' "$OS_GUARD_TEST_APPROVED_FTP_NETWORK"
    printf '  DenyAll\n'
    printf '</Limit>\n'
}

os_guard_item_discover_content_targets() {
    if ! u56_unit_is_active 'proftpd.service'; then
        u56_set_error \
            'SUPPORTED_PROFTPD_SERVICE_REQUIRED' \
            'the approved ProFTPD service is not active'
        return 1
    fi
    for unsupported_unit in vsftpd.service ftp.service ftp.socket; do
        if u56_unit_is_active "$unsupported_unit"; then
            u56_set_error \
                'MULTIPLE_OR_UNSUPPORTED_FTP_DAEMONS' \
                'another active FTP daemon makes automatic access control unsafe'
            return 1
        fi
    done

    u56_configuration_path="${content_test_root}/etc/proftpd/proftpd.conf"
    if [ ! -f "$u56_configuration_path" ] || [ -L "$u56_configuration_path" ]; then
        u56_set_error \
            'PROFTPD_CONFIGURATION_AMBIGUOUS' \
            'one regular static ProFTPD configuration is required'
        return 1
    fi
    if grep -Eiq '^[[:space:]]*Include[[:space:]]' "$u56_configuration_path"; then
        u56_set_error \
            'PROFTPD_INCLUDE_NOT_SUPPORTED' \
            'included ProFTPD configuration is not safely editable'
        return 1
    fi
    if grep -Eiq '^[[:space:]]*(Allow[[:space:]]+from|DenyAll)([[:space:]]|$)' "$u56_configuration_path"; then
        u56_set_error \
            'PROFTPD_ACCESS_CONFIGURATION_AMBIGUOUS' \
            'an existing ProFTPD access-control rule requires manual review'
        return 1
    fi

    CONTENT_CURRENT_EFFECTIVE_VALUE='ProFTPD has no local host allow restriction'
    os_guard_content_add_target \
        "$u56_configuration_path" \
        '/etc/proftpd/proftpd.conf' \
        'ProFTPD LOGIN host restriction' \
        'append one policy-approved LOGIN allow block followed by DenyAll'
}

os_guard_item_validate_configuration() {
    if [ "${OS_GUARD_TEST_FORCE_ITEM_SYNTAX_FAILURE:-false}" = 'true' ]; then
        u56_set_error \
            'PROFTPD_ACCESS_VALIDATION_FAILED' \
            'forced ProFTPD access-policy validation failure'
        return 1
    fi
    approved_network=$OS_GUARD_TEST_APPROVED_FTP_NETWORK
    allow_count=$(awk -v network="$approved_network" '
        $1 == "Allow" && $2 == "from" && $3 == network { count++ }
        END { print count+0 }
    ' "$u56_configuration_path")
    deny_count=$(grep -Eic '^[[:space:]]*DenyAll[[:space:]]*$' "$u56_configuration_path")
    if [ "$allow_count" -ne 1 ] || [ "$deny_count" -ne 1 ]; then
        u56_set_error \
            'PROFTPD_ACCESS_VALIDATION_FAILED' \
            'the resulting ProFTPD host restriction is not unambiguous'
        return 1
    fi
}

os_guard_content_run_module "${1:-}"
