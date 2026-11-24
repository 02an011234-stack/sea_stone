#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_content.sh"

HARDEN_ITEM_ID='U-55'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-55.sh"
HARDEN_TARGET_DESCRIPTION='local ftp account login shell'
HARDEN_RISK_LEVEL='HIGH'
HARDEN_SERVICE_RELOAD_REQUIRED=false
u55_passwd_path=''

u55_set_error() {
    os_guard_content_set_error "$1" "$2"
    return 1
}

os_guard_item_validate_content_policy() {
    if [ -z "$content_test_root" ] || [ "$content_test_root" = '/' ] || \
        [ "${OS_GUARD_TEST_POLICY_FIXTURE:-false}" != 'true' ]; then
        u55_set_error 'POLICY_INTEGRATION_REQUIRED' 'trusted U-55 policy integration is unavailable'
        return 1
    fi
    if [ "${OS_GUARD_TEST_FTP_ACCOUNT_SHELL_CHANGE_APPROVED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_LOCAL_IDENTITY_SOURCE_VERIFIED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_FTP_SESSIONS_CLEARED:-false}" != 'true' ]; then
        u55_set_error 'FTP_ACCOUNT_POLICY_EVIDENCE_REQUIRED' 'FTP account, identity-source, and session evidence are required'
        return 1
    fi
    if [ "$content_action" = 'EXECUTE' ] && \
        [ "${OS_GUARD_TEST_RELOAD_APPROVED:-false}" != 'true' ]; then
        u55_set_error 'SERVICE_RELOAD_APPROVAL_REQUIRED' 'account-change execution approval is required'
        return 1
    fi
}

os_guard_item_render_content() {
    awk -F: '
        BEGIN { OFS=":" }
        $1 == "ftp" { $7="/sbin/nologin" }
        { print }
    ' "$1"
}

os_guard_item_discover_content_targets() {
    u55_passwd_path="$content_test_root/etc/passwd"
    if [ ! -f "$u55_passwd_path" ] || [ -L "$u55_passwd_path" ]; then
        u55_set_error 'PASSWD_TARGET_INVALID' 'one regular passwd file is required'
        return 1
    fi
    account_count=$(awk -F: '$1 == "ftp" { count++ } END { print count+0 }' "$u55_passwd_path")
    if [ "$account_count" -ne 1 ]; then
        u55_set_error 'FTP_ACCOUNT_AMBIGUOUS' 'exactly one local ftp account is required'
        return 1
    fi
    current_shell=$(awk -F: '$1 == "ftp" { print $7 }' "$u55_passwd_path")
    case "$current_shell" in
        /bin/false|/sbin/nologin|/usr/sbin/nologin)
            u55_set_error 'FTP_ACCOUNT_ALREADY_RESTRICTED' 'ftp account already has a non-login shell'
            return 1
            ;;
        /*) ;;
        *)
            u55_set_error 'FTP_ACCOUNT_SHELL_INVALID' 'ftp account shell is invalid'
            return 1
            ;;
    esac
    CONTENT_CURRENT_EFFECTIVE_VALUE='local ftp account has a login-capable shell'
    os_guard_content_add_target "$u55_passwd_path" '/etc/passwd' 'ftp shell' 'set /sbin/nologin'
}

os_guard_item_validate_configuration() {
    if [ "${OS_GUARD_TEST_FORCE_ITEM_SYNTAX_FAILURE:-false}" = 'true' ]; then
        u55_set_error 'FTP_ACCOUNT_VALIDATION_FAILED' 'forced validation failure'
        return 1
    fi
    restricted_count=$(awk -F: '
        $1 == "ftp" && $7 == "/sbin/nologin" { count++ }
        END { print count+0 }
    ' "$u55_passwd_path")
    if [ "$restricted_count" -ne 1 ]; then
        u55_set_error 'FTP_ACCOUNT_VALIDATION_FAILED' 'ftp shell validation failed'
        return 1
    fi
}

os_guard_content_run_module "${1:-}"
