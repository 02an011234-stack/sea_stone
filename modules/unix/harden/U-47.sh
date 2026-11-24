#!/bin/sh
set -u
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_content.sh"
HARDEN_ITEM_ID='U-47'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-47.sh"
HARDEN_TARGET_DESCRIPTION='one static Postfix relay restriction assignment'
HARDEN_RISK_LEVEL='HIGH'
HARDEN_SERVICE_RELOAD_REQUIRED=true
u47_configuration_path=''

u47_set_error() {
    os_guard_content_set_error "$1" "$2"
    return 1
}

u47_unit_is_active() {
    systemctl_command=$(command -v systemctl 2>/dev/null || true)
    [ -n "$systemctl_command" ] && \
        [ "$("$systemctl_command" is-active "$1" 2>/dev/null || true)" = 'active' ]
}

os_guard_item_validate_content_policy() {
    if [ -z "$content_test_root" ] || [ "$content_test_root" = '/' ] || \
        [ "${OS_GUARD_TEST_POLICY_FIXTURE:-false}" != 'true' ]; then
        u47_set_error 'POLICY_INTEGRATION_REQUIRED' 'trusted U-47 policy integration is unavailable'
        return 1
    fi
    if [ "${OS_GUARD_TEST_APPROVED_MTA:-}" != 'postfix' ] || \
        [ "${OS_GUARD_TEST_RELAY_POLICY_APPROVED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_MAIL_DEPENDENCIES_VERIFIED:-false}" != 'true' ]; then
        u47_set_error 'RELAY_POLICY_EVIDENCE_REQUIRED' 'approved Postfix relay and dependency evidence are required'
        return 1
    fi
    if [ "$content_action" = 'EXECUTE' ] && \
        [ "${OS_GUARD_TEST_RELOAD_APPROVED:-false}" != 'true' ]; then
        u47_set_error 'SERVICE_RELOAD_APPROVAL_REQUIRED' 'Postfix reload approval is required'
        return 1
    fi
}

os_guard_item_discover_content_targets() {
    if ! u47_unit_is_active postfix.service; then
        u47_set_error 'SUPPORTED_POSTFIX_SERVICE_REQUIRED' 'approved Postfix service is not active'
        return 1
    fi
    u47_configuration_path="$content_test_root/etc/postfix/main.cf"
    if [ ! -f "$u47_configuration_path" ] || [ -L "$u47_configuration_path" ]; then
        u47_set_error 'POSTFIX_CONFIGURATION_AMBIGUOUS' 'one regular Postfix main.cf is required'
        return 1
    fi
    if grep -Eiq '^[[:space:]]*(include|multi_instance_)' "$u47_configuration_path"; then
        u47_set_error 'POSTFIX_CONFIGURATION_COMPLEX' 'included or multi-instance Postfix configuration is unsupported'
        return 1
    fi
    assignment_count=$(grep -Eic '^[[:space:]]*smtpd_(relay|recipient)_restrictions[[:space:]]*=' "$u47_configuration_path")
    if [ "$assignment_count" -ne 1 ] || \
        ! grep -Eiq '^[[:space:]]*smtpd_(relay|recipient)_restrictions[[:space:]]*=[[:space:]]*$' "$u47_configuration_path"; then
        u47_set_error 'POSTFIX_RELAY_ASSIGNMENT_AMBIGUOUS' 'one explicitly empty vulnerable assignment is required'
        return 1
    fi
    CONTENT_CURRENT_EFFECTIVE_VALUE='Postfix relay restriction is explicitly empty'
    os_guard_content_add_target "$u47_configuration_path" '/etc/postfix/main.cf' 'smtpd relay restriction' 'set reject_unauth_destination'
}

os_guard_item_render_content() {
    awk '
        /^[[:space:]]*smtpd_(relay|recipient)_restrictions[[:space:]]*=/ {
            sub(/=[[:space:]]*$/, "= reject_unauth_destination")
        }
        { print }
    ' "$1"
}

os_guard_item_validate_configuration() {
    if [ "${OS_GUARD_TEST_FORCE_ITEM_SYNTAX_FAILURE:-false}" = 'true' ]; then
        u47_set_error 'POSTFIX_RELAY_VALIDATION_FAILED' 'forced validation failure'
        return 1
    fi
    if ! grep -Eiq '^[[:space:]]*smtpd_(relay|recipient)_restrictions[[:space:]]*=[[:space:]]*reject_unauth_destination[[:space:]]*$' "$u47_configuration_path"; then
        u47_set_error 'POSTFIX_RELAY_VALIDATION_FAILED' 'relay restriction validation failed'
        return 1
    fi
}

os_guard_content_run_module "${1:-}"
