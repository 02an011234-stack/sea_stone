#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_content.sh"

HARDEN_ITEM_ID='U-27'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-27.sh"
HARDEN_TARGET_DESCRIPTION='approved local r-command trust files containing KISA plus wildcards'
HARDEN_RISK_LEVEL='HIGH'
HARDEN_SERVICE_RELOAD_REQUIRED=false

u27_policy_path_is_approved() {
    wanted_path=$1
    printf '%s\n' "${OS_GUARD_TEST_APPROVED_TRUST_FILES:-}" | \
        grep -Fx -- "$wanted_path" >/dev/null 2>&1
}

os_guard_item_validate_content_policy() {
    if [ -z "$content_test_root" ] || \
        [ "$content_test_root" = '/' ] || \
        [ "${OS_GUARD_TEST_POLICY_FIXTURE:-false}" != 'true' ]; then
        os_guard_content_set_error \
            'POLICY_INTEGRATION_REQUIRED' \
            'trusted U-27 operating policy integration is not available'
        return 1
    fi
    if [ "${OS_GUARD_TEST_RCOMMAND_TRUST_REMEDIATION_APPROVED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_TRUST_RELATIONSHIP_IMPACT_VERIFIED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_LOCAL_PASSWD_SOURCE_VERIFIED:-false}" != 'true' ]; then
        os_guard_content_set_error \
            'TRUST_POLICY_EVIDENCE_REQUIRED' \
            'trust-remediation approval and local-account evidence are required'
        return 1
    fi
}

u27_plus_pattern_count() {
    awk '
        /^[[:space:]]*($|#)/ { next }
        $1 == "+" || $2 == "+" { count++ }
        END { print count+0 }
    ' "$1"
}

u27_path_is_safe_home() {
    home_path=$1
    case "$home_path" in
        /*)
            ;;
        *)
            return 1
            ;;
    esac
    case "/$home_path/" in
        */../*|*/./*)
            return 1
            ;;
    esac
    os_guard_content_path_is_safe "$home_path"
}

u27_add_trust_target() {
    target_path=$1
    display_path=$2
    allowed_uid=$3
    allowed_owner=$4

    if ! u27_policy_path_is_approved "$display_path"; then
        os_guard_content_set_error \
            'TRUST_FILE_SCOPE_NOT_APPROVED' \
            'a vulnerable trust file is outside the approved fixture scope'
        return 1
    fi
    if [ -L "$target_path" ] || [ ! -f "$target_path" ] || [ ! -r "$target_path" ]; then
        os_guard_content_set_error \
            'TRUST_FILE_TARGET_INVALID' \
            'an approved trust file is not a readable regular file'
        return 1
    fi
    metadata=$($content_stat_command -c '%u|%U|%a' -- "$target_path" 2>/dev/null) || {
        os_guard_content_set_error \
            'STAT_COMMAND_FAILED' \
            'trust-file metadata collection failed'
        return 1
    }
    old_ifs=$IFS
    IFS='|'
    set -- $metadata
    IFS=$old_ifs
    if [ "$#" -ne 3 ]; then
        os_guard_content_set_error 'STAT_OUTPUT_INVALID' 'trust-file metadata is invalid'
        return 1
    fi
    owner_uid=$1
    owner_name=$2
    permission=$3
    case "$owner_uid:$owner_name" in
        0:root|"$allowed_uid:$allowed_owner")
            ;;
        *)
            os_guard_content_set_error \
                'TRUST_FILE_OWNER_UNSAFE' \
                'trust-file ownership must already satisfy the CHECK policy'
            return 1
            ;;
    esac
    case "$permission" in
        [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7])
            ;;
        *)
            os_guard_content_set_error 'STAT_OUTPUT_INVALID' 'trust-file permission is invalid'
            return 1
            ;;
    esac
    if [ $(((0$permission) & ~0600)) -ne 0 ]; then
        os_guard_content_set_error \
            'TRUST_FILE_PERMISSION_UNSAFE' \
            'trust-file permission must already satisfy the CHECK policy'
        return 1
    fi
    plus_count=$(u27_plus_pattern_count "$target_path") || {
        os_guard_content_set_error 'TRUST_FILE_PARSE_FAILED' 'trust-file content parsing failed'
        return 1
    }
    if [ "$plus_count" -gt 0 ]; then
        os_guard_content_add_target \
            "$target_path" \
            "$display_path" \
            'KISA plus wildcard entries' \
            'remove only records whose first or second field is an exact plus wildcard'
    fi
}

u27_r_command_service_is_active() {
    systemctl_command=$(command -v systemctl 2>/dev/null || true)
    [ -n "$systemctl_command" ] || return 1
    for unit_name in \
        rsh.socket rlogin.socket rexec.socket \
        rsh.service rlogin.service rexec.service; do
        if [ "$($systemctl_command is-active "$unit_name" 2>/dev/null || true)" = 'active' ]; then
            return 0
        fi
    done
    return 1
}

os_guard_item_render_content() {
    source_path=$1
    awk '
        /^[[:space:]]*($|#)/ { print; next }
        $1 == "+" || $2 == "+" { next }
        { print }
    ' "$source_path"
}

os_guard_item_discover_content_targets() {
    if ! u27_r_command_service_is_active; then
        os_guard_content_set_error \
            'SUPPORTED_RCOMMAND_SERVICE_REQUIRED' \
            'an active supported r-command systemd unit is required'
        return 1
    fi

    hosts_equiv="${content_test_root}/etc/hosts.equiv"
    if [ -e "$hosts_equiv" ] || [ -L "$hosts_equiv" ]; then
        u27_add_trust_target "$hosts_equiv" '/etc/hosts.equiv' 0 root || return 1
    fi

    passwd_path="${content_test_root}/etc/passwd"
    if [ ! -f "$passwd_path" ] || [ -L "$passwd_path" ] || [ ! -r "$passwd_path" ]; then
        os_guard_content_set_error 'PASSWD_SOURCE_INVALID' 'a readable regular local passwd file is required'
        return 1
    fi
    account_count=0
    while IFS=: read -r account_name password_field account_uid group_id gecos home_path login_shell extra; do
        [ -n "$account_name$password_field$account_uid$group_id$gecos$home_path$login_shell" ] || continue
        case "$account_uid" in
            ''|*[!0-9]*)
                os_guard_content_set_error 'PASSWD_SOURCE_INVALID' 'local passwd UID parsing failed'
                return 1
                ;;
        esac
        if ! u27_path_is_safe_home "$home_path"; then
            os_guard_content_set_error 'HOME_PATH_UNSAFE' 'a local account home path is unsafe'
            return 1
        fi
        account_count=$((account_count + 1))
        trust_path="${content_test_root}${home_path}/.rhosts"
        if [ -e "$trust_path" ] || [ -L "$trust_path" ]; then
            u27_add_trust_target \
                "$trust_path" \
                "$home_path/.rhosts" \
                "$account_uid" \
                "$account_name" || return 1
        fi
    done < "$passwd_path"
    if [ "$account_count" -eq 0 ]; then
        os_guard_content_set_error 'PASSWD_SOURCE_INVALID' 'the local passwd file is empty'
        return 1
    fi
    CONTENT_CURRENT_EFFECTIVE_VALUE='approved trust files contain exact KISA plus wildcard records'
}

os_guard_item_validate_configuration() {
    if [ -n "$content_test_root" ] && \
        [ "${OS_GUARD_TEST_FORCE_ITEM_SYNTAX_FAILURE:-false}" = 'true' ]; then
        os_guard_content_set_error \
            'TRUST_FILE_VALIDATION_FAILED' \
            'forced trust-file validation failure'
        return 1
    fi
    while IFS='|' read -r display_path target_path remaining_fields; do
        [ -n "$target_path" ] || continue
        if [ "$(u27_plus_pattern_count "$target_path")" -ne 0 ]; then
            os_guard_content_set_error \
                'TRUST_FILE_VALIDATION_FAILED' \
                'a KISA plus wildcard remains after remediation'
            return 1
        fi
    done <<EOF
$content_records
EOF
    if [ -n "$content_test_root" ] && \
        [ -n "${OS_GUARD_TEST_SYNC_CHECK_FILE:-}" ]; then
        printf 'complete|1|1|1|0|0|0|0\n' > \
            "$OS_GUARD_TEST_SYNC_CHECK_FILE" || {
            os_guard_content_set_error \
                'FIXTURE_CHECK_STATE_UPDATE_FAILED' \
                'the isolated CHECK fixture could not be updated'
            return 1
        }
    fi
}

os_guard_content_run_module "${1:-}"
