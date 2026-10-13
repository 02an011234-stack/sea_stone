#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_content.sh"

HARDEN_ITEM_ID='U-53'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-53.sh"
HARDEN_TARGET_DESCRIPTION='one static vsftpd banner assignment'
HARDEN_RISK_LEVEL='MEDIUM'
HARDEN_SERVICE_RELOAD_REQUIRED=true

u53_configuration_path=''
u53_approved_banner=''

os_guard_item_validate_content_policy() {
    if [ -z "$content_test_root" ] || \
        [ "$content_test_root" = '/' ] || \
        [ "${OS_GUARD_TEST_POLICY_FIXTURE:-false}" != 'true' ]; then
        os_guard_content_set_error \
            'POLICY_INTEGRATION_REQUIRED' \
            'trusted U-53 operating policy integration is not available'
        return 1
    fi
    if [ "${OS_GUARD_TEST_APPROVED_FTP_DAEMON:-}" != 'vsftpd' ]; then
        os_guard_content_set_error \
            'FTP_DAEMON_NOT_SUPPORTED' \
            'only the explicitly approved vsftpd fixture is supported'
        return 1
    fi
    if [ "${OS_GUARD_TEST_VSFTPD_CONFIGURATION_SOURCE:-}" != 'static-vsftpd-conf' ]; then
        os_guard_content_set_error \
            'VSFTPD_CONFIGURATION_SOURCE_UNVERIFIED' \
            'the fixture policy must verify a static vsftpd configuration source'
        return 1
    fi
    approved_version=${OS_GUARD_TEST_APPROVED_VSFTPD_VERSION:-}
    if ! printf '%s\n' "$approved_version" | \
        grep -Eq '^[0-9]+([.][0-9]+){1,3}$'; then
        os_guard_content_set_error \
            'VSFTPD_VERSION_UNVERIFIED' \
            'a verified supported vsftpd version is required'
        return 1
    fi
    u53_approved_banner=${OS_GUARD_TEST_APPROVED_BANNER:-}
    if ! printf '%s\n' "$u53_approved_banner" | \
        grep -Eq '^[A-Za-z0-9 ._@+-]{1,120}$' || \
        printf '%s\n' "$u53_approved_banner" | \
        grep -Eiq '(vsftpd|ftp[[:space:]]+server|version|[0-9]+\.[0-9]+)'; then
        os_guard_content_set_error \
            'APPROVED_BANNER_INVALID' \
            'the fixture banner is absent, unsafe, or exposes product information'
        return 1
    fi
    if [ "$content_action" = 'EXECUTE' ] && \
        [ "${OS_GUARD_TEST_RELOAD_APPROVED:-false}" != 'true' ]; then
        os_guard_content_set_error \
            'SERVICE_RELOAD_APPROVAL_REQUIRED' \
            'vsftpd reload approval is required before configuration mutation'
        return 1
    fi
    return 0
}

u53_banner_count() {
    grep -Eic '^[[:space:]]*ftpd_banner[[:space:]]*=' "$1"
}

os_guard_item_render_content() {
    source_path=$1
    awk -v approved_banner="$u53_approved_banner" '
        /^[[:space:]]*ftpd_banner[[:space:]]*=/ {
            print "ftpd_banner=" approved_banner
            next
        }
        { print }
    ' "$source_path"
}

os_guard_item_discover_content_targets() {
    rocky_path="${content_test_root}/etc/vsftpd/vsftpd.conf"
    ubuntu_path="${content_test_root}/etc/vsftpd.conf"
    case "$content_distro" in
        rocky)
            u53_configuration_path=$rocky_path
            unexpected_path=$ubuntu_path
            ;;
        ubuntu)
            u53_configuration_path=$ubuntu_path
            unexpected_path=$rocky_path
            ;;
        *)
            os_guard_content_set_error \
                'VSFTPD_CONFIGURATION_AMBIGUOUS' \
                'the supported distribution-specific vsftpd path is unavailable'
            return 1
            ;;
    esac
    if [ -e "$unexpected_path" ] || [ -L "$unexpected_path" ] || \
        [ ! -f "$u53_configuration_path" ] || \
        [ -L "$u53_configuration_path" ]; then
        os_guard_content_set_error \
            'VSFTPD_CONFIGURATION_AMBIGUOUS' \
            'exactly one regular distribution-specific vsftpd configuration is required'
        return 1
    fi
    if grep -Eiq '^[[:space:]]*(include|include_dir)[[:space:]]*=' "$u53_configuration_path"; then
        os_guard_content_set_error \
            'VSFTPD_INCLUDE_NOT_SUPPORTED' \
            'included vsftpd configuration is not safely editable'
        return 1
    fi
    if [ "$(u53_banner_count "$u53_configuration_path")" -ne 1 ]; then
        os_guard_content_set_error \
            'VSFTPD_BANNER_CONFIGURATION_AMBIGUOUS' \
            'exactly one static ftpd_banner assignment is required'
        return 1
    fi
    CONTENT_CURRENT_EFFECTIVE_VALUE='redacted FTP banner summary; see CHECK evidence'
    display_path=${u53_configuration_path#"$content_test_root"}
    os_guard_content_add_target \
        "$u53_configuration_path" \
        "$display_path" \
        'ftpd_banner' \
        'replace the exposed product banner with the approved non-product text'
}

os_guard_item_validate_configuration() {
    if [ -n "$content_test_root" ] && \
        [ "${OS_GUARD_TEST_FORCE_ITEM_SYNTAX_FAILURE:-false}" = 'true' ]; then
        os_guard_content_set_error \
            'VSFTPD_SYNTAX_VALIDATION_FAILED' \
            'forced vsftpd syntax validation failure'
        return 1
    fi
    if [ "$(u53_banner_count "$u53_configuration_path")" -ne 1 ]; then
        os_guard_content_set_error \
            'VSFTPD_SYNTAX_VALIDATION_FAILED' \
            'the resulting ftpd_banner assignment is ambiguous'
        return 1
    fi
    configured_banner=$(grep -Ei '^[[:space:]]*ftpd_banner[[:space:]]*=' "$u53_configuration_path")
    if [ "$configured_banner" != "ftpd_banner=$u53_approved_banner" ]; then
        os_guard_content_set_error \
            'VSFTPD_SYNTAX_VALIDATION_FAILED' \
            'the resulting ftpd_banner does not match the approved value'
        return 1
    fi
    return 0
}

os_guard_content_run_module "${1:-}"
