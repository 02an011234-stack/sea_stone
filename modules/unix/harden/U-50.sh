#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_content.sh"

HARDEN_ITEM_ID='U-50'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-50.sh"
HARDEN_TARGET_DESCRIPTION='one static BIND allow-transfer any clause'
HARDEN_RISK_LEVEL='HIGH'
HARDEN_SERVICE_RELOAD_REQUIRED=true
u50_configuration_path=''

u50_set_error() {
    os_guard_content_set_error "$1" "$2"
    return 1
}

u50_unit_is_active() {
    systemctl_command=$(command -v systemctl 2>/dev/null || true)
    [ -n "$systemctl_command" ] && \
        [ "$("$systemctl_command" is-active "$1" 2>/dev/null || true)" = 'active' ]
}

os_guard_item_validate_content_policy() {
    if [ -z "$content_test_root" ] || [ "$content_test_root" = '/' ] || \
        [ "${OS_GUARD_TEST_POLICY_FIXTURE:-false}" != 'true' ]; then
        u50_set_error 'POLICY_INTEGRATION_REQUIRED' 'trusted U-50 policy integration is unavailable'
        return 1
    fi
    if [ "${OS_GUARD_TEST_ZONE_TRANSFER_DISABLE_APPROVED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_SECONDARY_DNS_DEPENDENCIES_VERIFIED:-false}" != 'true' ]; then
        u50_set_error 'DNS_TRANSFER_POLICY_EVIDENCE_REQUIRED' 'zone-transfer and secondary DNS evidence are required'
        return 1
    fi
    if [ "$content_action" = 'EXECUTE' ] && \
        [ "${OS_GUARD_TEST_RELOAD_APPROVED:-false}" != 'true' ]; then
        u50_set_error 'SERVICE_RELOAD_APPROVAL_REQUIRED' 'DNS reload approval is required'
        return 1
    fi
}

os_guard_item_render_content() {
    sed -E 's/(allow-transfer[[:space:]]*\{[[:space:]]*)any([[:space:]]*;)/\1none\2/I' "$1"
}

os_guard_item_discover_content_targets() {
    if ! u50_unit_is_active named.service && ! u50_unit_is_active bind9.service; then
        u50_set_error 'SUPPORTED_DNS_SERVICE_REQUIRED' 'an approved BIND service is not active'
        return 1
    fi
    case "$content_distro" in
        rocky) u50_configuration_path="$content_test_root/etc/named.conf" ;;
        ubuntu) u50_configuration_path="$content_test_root/etc/bind/named.conf.options" ;;
        *)
            u50_set_error 'DNS_CONFIGURATION_AMBIGUOUS' 'the distribution-specific BIND file is unavailable'
            return 1
            ;;
    esac
    if [ ! -f "$u50_configuration_path" ] || [ -L "$u50_configuration_path" ]; then
        u50_set_error 'DNS_CONFIGURATION_AMBIGUOUS' 'one regular distribution-specific BIND file is required'
        return 1
    fi
    if grep -Eiq '^[[:space:]]*include[[:space:]]' "$u50_configuration_path"; then
        u50_set_error 'DNS_INCLUDE_NOT_SUPPORTED' 'included BIND configuration is unsupported'
        return 1
    fi
    transfer_count=$(grep -Eic 'allow-transfer[[:space:]]*\{' "$u50_configuration_path")
    if [ "$transfer_count" -ne 1 ] || \
        ! grep -Eiq 'allow-transfer[[:space:]]*\{[[:space:]]*any[[:space:]]*;' "$u50_configuration_path"; then
        u50_set_error 'DNS_TRANSFER_ASSIGNMENT_AMBIGUOUS' 'one explicit allow-transfer any clause is required'
        return 1
    fi
    CONTENT_CURRENT_EFFECTIVE_VALUE='BIND zone transfer is allowed to any source'
    display_path=${u50_configuration_path#"$content_test_root"}
    os_guard_content_add_target "$u50_configuration_path" "$display_path" 'allow-transfer' 'replace any with none'
}

os_guard_item_validate_configuration() {
    if [ "${OS_GUARD_TEST_FORCE_ITEM_SYNTAX_FAILURE:-false}" = 'true' ]; then
        u50_set_error 'DNS_TRANSFER_VALIDATION_FAILED' 'forced validation failure'
        return 1
    fi
    if ! grep -Eiq 'allow-transfer[[:space:]]*\{[[:space:]]*none[[:space:]]*;' "$u50_configuration_path"; then
        u50_set_error 'DNS_TRANSFER_VALIDATION_FAILED' 'zone-transfer validation failed'
        return 1
    fi
}

os_guard_content_run_module "${1:-}"
