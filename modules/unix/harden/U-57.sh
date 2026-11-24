#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_content.sh"

HARDEN_ITEM_ID='U-57'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-57.sh"
HARDEN_TARGET_DESCRIPTION='static vsftpd PAM ftpusers root-login deny entry'
HARDEN_RISK_LEVEL='HIGH'
HARDEN_SERVICE_RELOAD_REQUIRED=false

u57_ftpusers_path=''

u57_require_fixture_policy() {
    if [ -z "$content_test_root" ] || \
        [ "$content_test_root" = '/' ] || \
        [ "${OS_GUARD_TEST_POLICY_FIXTURE:-false}" != 'true' ]; then
        os_guard_content_set_error \
            'POLICY_INTEGRATION_REQUIRED' \
            'trusted U-57 operating policy integration is not available'
        return 1
    fi
    if [ "${OS_GUARD_TEST_APPROVED_FTP_DAEMON:-}" != 'vsftpd' ]; then
        os_guard_content_set_error \
            'FTP_DAEMON_NOT_SUPPORTED' \
            'only an explicitly approved vsftpd fixture is supported'
        return 1
    fi
    if [ "${OS_GUARD_TEST_APPROVED_BLOCKED_ACCOUNT:-}" != 'root' ]; then
        os_guard_content_set_error \
            'FTP_ACCOUNT_POLICY_NOT_APPROVED' \
            'the fixture policy must approve only the root FTP restriction'
        return 1
    fi
    if [ "${OS_GUARD_TEST_VSFTPD_CONFIGURATION_SOURCE:-}" != 'static-vsftpd-conf' ] || \
        [ "${OS_GUARD_TEST_PAM_FTPUSERS_MECHANISM_VERIFIED:-false}" != 'true' ]; then
        os_guard_content_set_error \
            'FTP_RESTRICTION_MECHANISM_UNVERIFIED' \
            'the static vsftpd and PAM ftpusers deny mechanism must be verified'
        return 1
    fi
    if [ "${OS_GUARD_TEST_FTP_LOGIN_IMPACT_VERIFIED:-false}" != 'true' ]; then
        os_guard_content_set_error \
            'FTP_LOGIN_IMPACT_EVIDENCE_REQUIRED' \
            'FTP login impact evidence is required'
        return 1
    fi
    return 0
}

os_guard_item_validate_content_policy() {
    u57_require_fixture_policy
}

u57_exact_root_count() {
    awk '
        /^[[:space:]]*#/ { next }
        {
            value=$0
            sub(/[[:space:]]*#.*/, "", value)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            if (value == "root") count++
        }
        END { print count+0 }
    ' "$1"
}

u57_unit_is_active() {
    unit_name=$1
    systemctl_command=$(command -v systemctl 2>/dev/null || true)
    [ -n "$systemctl_command" ] && \
        [ "$("$systemctl_command" is-active "$unit_name" 2>/dev/null || true)" = 'active' ]
}

os_guard_item_render_content() {
    source_path=$1
    cat "$source_path"
    if [ "$(u57_exact_root_count "$source_path")" -eq 0 ]; then
        printf 'root\n'
    fi
}

os_guard_item_discover_content_targets() {
    if ! u57_unit_is_active 'vsftpd.service'; then
        os_guard_content_set_error \
            'SUPPORTED_VSFTPD_SERVICE_REQUIRED' \
            'the approved vsftpd service is not active'
        return 1
    fi
    for unsupported_unit in \
        proftpd.service pure-ftpd.service ftp.service ftp.socket; do
        if u57_unit_is_active "$unsupported_unit"; then
            os_guard_content_set_error \
                'MULTIPLE_OR_UNSUPPORTED_FTP_DAEMONS' \
                'another active FTP daemon makes the restriction target ambiguous'
            return 1
        fi
    done

    case "$content_distro" in
        rocky)
            configuration_path="${content_test_root}/etc/vsftpd/vsftpd.conf"
            unexpected_path="${content_test_root}/etc/vsftpd.conf"
            ;;
        ubuntu)
            configuration_path="${content_test_root}/etc/vsftpd.conf"
            unexpected_path="${content_test_root}/etc/vsftpd/vsftpd.conf"
            ;;
        *)
            os_guard_content_set_error \
                'VSFTPD_CONFIGURATION_AMBIGUOUS' \
                'the distribution-specific vsftpd configuration is unavailable'
            return 1
            ;;
    esac
    pam_path="${content_test_root}/etc/pam.d/vsftpd"
    user_list_path="${content_test_root}/etc/vsftpd/user_list"
    u57_ftpusers_path="${content_test_root}/etc/ftpusers"

    if [ -e "$unexpected_path" ] || [ -L "$unexpected_path" ] || \
        [ ! -f "$configuration_path" ] || [ -L "$configuration_path" ]; then
        os_guard_content_set_error \
            'VSFTPD_CONFIGURATION_AMBIGUOUS' \
            'exactly one regular distribution-specific vsftpd configuration is required'
        return 1
    fi
    if grep -Eiq '^[[:space:]]*(include|include_dir)[[:space:]]*=' "$configuration_path"; then
        os_guard_content_set_error \
            'VSFTPD_INCLUDE_NOT_SUPPORTED' \
            'included vsftpd configuration is not safely editable'
        return 1
    fi
    if ! grep -Eiq '^[[:space:]]*userlist_enable[[:space:]]*=[[:space:]]*YES' "$configuration_path" || \
        ! grep -Eiq '^[[:space:]]*userlist_deny[[:space:]]*=[[:space:]]*NO' "$configuration_path" || \
        [ ! -f "$user_list_path" ] || \
        [ "$(u57_exact_root_count "$user_list_path")" -eq 0 ]; then
        os_guard_content_set_error \
            'VSFTPD_ROOT_ALLOW_STATE_UNVERIFIED' \
            'the fixture must expose the explicit root allow state evaluated by CHECK'
        return 1
    fi
    pam_rule_count=$(grep -Eic \
        'pam_listfile\.so.*sense=deny.*file=/etc/ftpusers' \
        "$pam_path" 2>/dev/null || true)
    if [ ! -f "$pam_path" ] || [ -L "$pam_path" ] || [ "$pam_rule_count" -ne 1 ]; then
        os_guard_content_set_error \
            'PAM_FTPUSERS_DENY_RULE_UNVERIFIED' \
            'exactly one static PAM deny rule using /etc/ftpusers is required'
        return 1
    fi
    if [ ! -f "$u57_ftpusers_path" ] || [ -L "$u57_ftpusers_path" ]; then
        os_guard_content_set_error \
            'FTPUSERS_TARGET_INVALID' \
            'a regular existing /etc/ftpusers file is required'
        return 1
    fi
    if [ "$(u57_exact_root_count "$u57_ftpusers_path")" -ne 0 ]; then
        os_guard_content_set_error \
            'FTPUSERS_STATE_NOT_ACTIONABLE' \
            'the root restriction is already present or ambiguous'
        return 1
    fi

    CONTENT_CURRENT_EFFECTIVE_VALUE='root is absent from the verified PAM ftpusers deny file'
    os_guard_content_add_target \
        "$u57_ftpusers_path" \
        '/etc/ftpusers' \
        'root FTP deny entry' \
        'append one exact root entry to the verified PAM deny file'
}

os_guard_item_validate_configuration() {
    if [ -n "$content_test_root" ] && \
        [ "${OS_GUARD_TEST_FORCE_ITEM_SYNTAX_FAILURE:-false}" = 'true' ]; then
        os_guard_content_set_error \
            'FTPUSERS_VALIDATION_FAILED' \
            'forced ftpusers validation failure'
        return 1
    fi
    if [ "$(u57_exact_root_count "$u57_ftpusers_path")" -ne 1 ]; then
        os_guard_content_set_error \
            'FTPUSERS_VALIDATION_FAILED' \
            'the resulting ftpusers file must contain one exact root entry'
        return 1
    fi
    return 0
}

os_guard_content_run_module "${1:-}"
