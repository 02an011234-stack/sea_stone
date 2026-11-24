#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_content.sh"

HARDEN_ITEM_ID='U-62'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-62.sh"
HARDEN_TARGET_DESCRIPTION='approved static system login warning in /etc/issue.net'
HARDEN_RISK_LEVEL='MEDIUM'
HARDEN_SERVICE_RELOAD_REQUIRED=false

u62_banner_path=''
u62_approved_banner=''

u62_is_warning_text() {
    printf '%s' "$1" | grep -Eiq \
        '(authori[sz]ed|unauthori[sz]ed|prohibit|restricted|monitor|consent|warning|legal action|무단|허가|인가|경고)'
}

os_guard_item_validate_content_policy() {
    if [ -z "$content_test_root" ] || \
        [ "$content_test_root" = '/' ] || \
        [ "${OS_GUARD_TEST_POLICY_FIXTURE:-false}" != 'true' ]; then
        os_guard_content_set_error \
            'POLICY_INTEGRATION_REQUIRED' \
            'trusted U-62 operating policy integration is not available'
        return 1
    fi
    if [ "${OS_GUARD_TEST_LOGIN_WARNING_TARGET:-}" != '/etc/issue.net' ] || \
        [ "${OS_GUARD_TEST_LOGIN_WARNING_SCOPE:-}" != 'system-only' ]; then
        os_guard_content_set_error \
            'LOGIN_WARNING_SCOPE_NOT_APPROVED' \
            'the fixture policy must approve the supported system-only issue.net target'
        return 1
    fi
    u62_approved_banner=${OS_GUARD_TEST_APPROVED_BANNER_TEXT:-}
    banner_length=$(printf '%s' "$u62_approved_banner" | wc -c | tr -d '[:space:]')
    banner_line_count=$(printf '%s' "$u62_approved_banner" | wc -l | tr -d '[:space:]')
    if [ -z "$u62_approved_banner" ] || \
        [ "$banner_length" -gt 4096 ] || \
        [ "$banner_line_count" -ne 0 ] || \
        ! u62_is_warning_text "$u62_approved_banner"; then
        os_guard_content_set_error \
            'APPROVED_BANNER_INVALID' \
            'a non-empty single-line approved warning message is required'
        return 1
    fi
    if [ "${OS_GUARD_TEST_BANNER_APPROVAL_VERIFIED:-false}" != 'true' ]; then
        os_guard_content_set_error \
            'BANNER_APPROVAL_EVIDENCE_REQUIRED' \
            'institutional approval evidence for the warning text is required'
        return 1
    fi
    return 0
}

u62_unit_is_active() {
    unit_name=$1
    systemctl_command=$(command -v systemctl 2>/dev/null || true)
    [ -n "$systemctl_command" ] && \
        [ "$("$systemctl_command" is-active "$unit_name" 2>/dev/null || true)" = 'active' ]
}

os_guard_item_render_content() {
    unused_source_path=$1
    printf '%s\n' "$u62_approved_banner"
}

os_guard_item_discover_content_targets() {
    for unsupported_unit in \
        telnet.service telnet.socket vsftpd.service proftpd.service \
        postfix.service sendmail.service exim4.service named.service bind9.service; do
        if u62_unit_is_active "$unsupported_unit"; then
            os_guard_content_set_error \
                'ACTIVE_SERVICE_BANNER_UNSUPPORTED' \
                'an active service requires a separate service-specific warning policy'
            return 1
        fi
    done

    sshd_configuration="${content_test_root}/etc/ssh/sshd_config"
    if [ -r "$sshd_configuration" ] && \
        grep -Eiq '^[[:space:]]*Banner[[:space:]]+[^nN][^oO][^nN][^eE]' "$sshd_configuration"; then
        os_guard_content_set_error \
            'SSH_BANNER_CONFIGURATION_UNSUPPORTED' \
            'an existing SSH Banner directive requires separate target validation'
        return 1
    fi

    u62_banner_path="${content_test_root}/etc/issue.net"
    if [ ! -f "$u62_banner_path" ] || [ -L "$u62_banner_path" ]; then
        os_guard_content_set_error \
            'LOGIN_WARNING_TARGET_INVALID' \
            'a regular existing /etc/issue.net file is required'
        return 1
    fi
    CONTENT_CURRENT_EFFECTIVE_VALUE='redacted current system login warning summary'
    os_guard_content_add_target \
        "$u62_banner_path" \
        '/etc/issue.net' \
        'system login warning text' \
        'replace the target with the approved warning text'
}

os_guard_item_validate_configuration() {
    if [ -n "$content_test_root" ] && \
        [ "${OS_GUARD_TEST_FORCE_ITEM_SYNTAX_FAILURE:-false}" = 'true' ]; then
        os_guard_content_set_error \
            'LOGIN_WARNING_VALIDATION_FAILED' \
            'forced login warning validation failure'
        return 1
    fi
    actual_banner=$(cat "$u62_banner_path" 2>/dev/null || true)
    if [ "$actual_banner" != "$u62_approved_banner" ] || \
        ! u62_is_warning_text "$actual_banner"; then
        os_guard_content_set_error \
            'LOGIN_WARNING_VALIDATION_FAILED' \
            'the resulting login warning does not match the approved text'
        return 1
    fi
    return 0
}

os_guard_content_run_module "${1:-}"
