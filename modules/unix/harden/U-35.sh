#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_content.sh"

HARDEN_ITEM_ID='U-35'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-35.sh"
HARDEN_TARGET_DESCRIPTION='one static vsftpd anonymous access assignment'
HARDEN_RISK_LEVEL='HIGH'
HARDEN_SERVICE_RELOAD_REQUIRED=true

u35_configuration_path=''

os_guard_item_validate_content_policy() {
    if [ -z "$content_test_root" ] || \
        [ "$content_test_root" = '/' ] || \
        [ "${OS_GUARD_TEST_POLICY_FIXTURE:-false}" != 'true' ]; then
        os_guard_content_set_error \
            'POLICY_INTEGRATION_REQUIRED' \
            'trusted U-35 operating policy integration is not available'
        return 1
    fi
    if [ "${OS_GUARD_TEST_APPROVED_SHARE_SERVICE:-}" != 'vsftpd' ] || \
        [ "${OS_GUARD_TEST_ANONYMOUS_ACCESS_DISABLE_APPROVED:-false}" != 'true' ]; then
        os_guard_content_set_error \
            'ANONYMOUS_ACCESS_POLICY_NOT_APPROVED' \
            'the fixture policy must approve disabling vsftpd anonymous access'
        return 1
    fi
    if [ "${OS_GUARD_TEST_VSFTPD_CONFIGURATION_SOURCE:-}" != 'static-vsftpd-conf' ]; then
        os_guard_content_set_error \
            'VSFTPD_CONFIGURATION_SOURCE_UNVERIFIED' \
            'the fixture policy must verify a static vsftpd configuration source'
        return 1
    fi
    if [ "${OS_GUARD_TEST_SHARE_BUSINESS_IMPACT_VERIFIED:-false}" != 'true' ]; then
        os_guard_content_set_error \
            'SHARE_BUSINESS_IMPACT_EVIDENCE_REQUIRED' \
            'anonymous sharing business-impact evidence is required'
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

u35_unit_is_active() {
    unit_name=$1
    systemctl_command=$(command -v systemctl 2>/dev/null || true)
    [ -n "$systemctl_command" ] && \
        [ "$("$systemctl_command" is-active "$unit_name" 2>/dev/null || true)" = 'active' ]
}

u35_anonymous_assignment_count() {
    grep -Eic '^[[:space:]]*anonymous_enable[[:space:]]*=' "$1"
}

os_guard_item_render_content() {
    source_path=$1
    awk '
        /^[[:space:]]*anonymous_enable[[:space:]]*=/ {
            print "anonymous_enable=NO"
            next
        }
        { print }
    ' "$source_path"
}

os_guard_item_discover_content_targets() {
    if ! u35_unit_is_active 'vsftpd.service'; then
        os_guard_content_set_error \
            'SUPPORTED_VSFTPD_SERVICE_REQUIRED' \
            'the approved vsftpd service is not active'
        return 1
    fi
    for unsupported_unit in \
        proftpd.service pure-ftpd.service nfs-server.service smb.service smbd.service; do
        if u35_unit_is_active "$unsupported_unit"; then
            os_guard_content_set_error \
                'MULTIPLE_OR_UNSUPPORTED_SHARE_SERVICES' \
                'another active sharing service makes automatic remediation unsafe'
            return 1
        fi
    done

    rocky_path="${content_test_root}/etc/vsftpd/vsftpd.conf"
    ubuntu_path="${content_test_root}/etc/vsftpd.conf"
    case "$content_distro" in
        rocky)
            u35_configuration_path=$rocky_path
            unexpected_path=$ubuntu_path
            ;;
        ubuntu)
            u35_configuration_path=$ubuntu_path
            unexpected_path=$rocky_path
            ;;
        *)
            os_guard_content_set_error \
                'VSFTPD_CONFIGURATION_AMBIGUOUS' \
                'the distribution-specific vsftpd configuration is unavailable'
            return 1
            ;;
    esac
    if [ -e "$unexpected_path" ] || [ -L "$unexpected_path" ] || \
        [ ! -f "$u35_configuration_path" ] || [ -L "$u35_configuration_path" ]; then
        os_guard_content_set_error \
            'VSFTPD_CONFIGURATION_AMBIGUOUS' \
            'exactly one regular distribution-specific vsftpd configuration is required'
        return 1
    fi
    if grep -Eiq '^[[:space:]]*(include|include_dir)[[:space:]]*=' "$u35_configuration_path"; then
        os_guard_content_set_error \
            'VSFTPD_INCLUDE_NOT_SUPPORTED' \
            'included vsftpd configuration is not safely editable'
        return 1
    fi
    if [ "$(u35_anonymous_assignment_count "$u35_configuration_path")" -ne 1 ] || \
        ! grep -Eiq \
            '^[[:space:]]*anonymous_enable[[:space:]]*=[[:space:]]*YES' \
            "$u35_configuration_path"; then
        os_guard_content_set_error \
            'VSFTPD_ANONYMOUS_CONFIGURATION_AMBIGUOUS' \
            'one explicit vulnerable anonymous_enable assignment is required'
        return 1
    fi

    CONTENT_CURRENT_EFFECTIVE_VALUE='vsftpd anonymous access is explicitly enabled'
    display_path=${u35_configuration_path#"$content_test_root"}
    os_guard_content_add_target \
        "$u35_configuration_path" \
        "$display_path" \
        'anonymous_enable' \
        'replace the single anonymous_enable assignment with NO'
}

os_guard_item_validate_configuration() {
    if [ -n "$content_test_root" ] && \
        [ "${OS_GUARD_TEST_FORCE_ITEM_SYNTAX_FAILURE:-false}" = 'true' ]; then
        os_guard_content_set_error \
            'VSFTPD_ANONYMOUS_VALIDATION_FAILED' \
            'forced vsftpd anonymous policy validation failure'
        return 1
    fi
    if [ "$(u35_anonymous_assignment_count "$u35_configuration_path")" -ne 1 ] || \
        ! grep -Eiq \
            '^[[:space:]]*anonymous_enable[[:space:]]*=[[:space:]]*NO([[:space:]]|$)' \
            "$u35_configuration_path"; then
        os_guard_content_set_error \
            'VSFTPD_ANONYMOUS_VALIDATION_FAILED' \
            'the resulting anonymous access assignment is not an unambiguous NO'
        return 1
    fi
    return 0
}

os_guard_content_run_module "${1:-}"
