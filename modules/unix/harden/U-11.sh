#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_content.sh"

HARDEN_ITEM_ID='U-11'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-11.sh"
HARDEN_TARGET_DESCRIPTION='approved local KISA target account shell assignments'
HARDEN_RISK_LEVEL='CRITICAL'
HARDEN_SERVICE_RELOAD_REQUIRED=false

u11_passwd_path=''
u11_approved_accounts=''
u11_approved_shell=''
u11_root_record=''

u11_account_is_kisa_target() {
    case "$1" in
        daemon|bin|sys|adm|listen|nobody|nobody4|noaccess|diag|operator|games|gopher)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

u11_account_is_approved() {
    inspected_account=$1
    old_ifs=$IFS
    IFS=','
    set -- $u11_approved_accounts
    IFS=$old_ifs
    for approved_account in "$@"; do
        if [ "$inspected_account" = "$approved_account" ]; then
            return 0
        fi
    done
    return 1
}

os_guard_item_validate_content_policy() {
    if [ -z "$content_test_root" ] || \
        [ "$content_test_root" = '/' ] || \
        [ "${OS_GUARD_TEST_POLICY_FIXTURE:-false}" != 'true' ]; then
        os_guard_content_set_error \
            'POLICY_INTEGRATION_REQUIRED' \
            'trusted U-11 operating policy integration is not available'
        return 1
    fi
    u11_approved_accounts=${OS_GUARD_TEST_APPROVED_SHELL_ACCOUNTS:-}
    u11_approved_shell=${OS_GUARD_TEST_APPROVED_RESTRICTED_SHELL:-}
    if [ -z "$u11_approved_accounts" ] || \
        ! printf '%s\n' "$u11_approved_accounts" | \
            grep -Eq '^[a-z][a-z0-9_-]*(,[a-z][a-z0-9_-]*)*$'; then
        os_guard_content_set_error \
            'ACCOUNT_POLICY_INVALID' \
            'a valid explicit approved account list is required'
        return 1
    fi
    old_ifs=$IFS
    IFS=','
    set -- $u11_approved_accounts
    IFS=$old_ifs
    seen_accounts=''
    for approved_account in "$@"; do
        if ! u11_account_is_kisa_target "$approved_account" || \
            printf ',%s,' "$seen_accounts" | grep -Fq ",$approved_account,"; then
            os_guard_content_set_error \
                'ACCOUNT_POLICY_INVALID' \
                'only unique KISA U-11 target accounts may be approved'
            return 1
        fi
        if [ -n "$seen_accounts" ]; then
            seen_accounts="$seen_accounts,$approved_account"
        else
            seen_accounts=$approved_account
        fi
    done
    case "$u11_approved_shell" in
        /bin/false|/sbin/nologin)
            ;;
        *)
            os_guard_content_set_error \
                'RESTRICTED_SHELL_POLICY_INVALID' \
                'the approved shell must match a shell accepted by the U-11 CHECK'
            return 1
            ;;
    esac
    if [ "${OS_GUARD_TEST_LOCAL_ACCOUNT_SOURCE_VERIFIED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_ACCOUNT_DEPENDENCY_VERIFIED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_ACCOUNT_SESSION_STATE_VERIFIED:-false}" != 'true' ]; then
        os_guard_content_set_error \
            'ACCOUNT_SAFETY_EVIDENCE_REQUIRED' \
            'local source, service dependency, and login-session evidence is required'
        return 1
    fi
    return 0
}

u11_validate_passwd_structure() {
    awk -F: '
        NF != 7 || $1 == "" || $3 !~ /^[0-9]+$/ || $4 !~ /^[0-9]+$/ ||
        seen_name[$1]++ || seen_uid[$3]++ {
            invalid=1
        }
        END { exit invalid ? 1 : 0 }
    ' "$1"
}

os_guard_item_render_content() {
    source_path=$1
    awk -F: -v OFS=: \
        -v approved="$u11_approved_accounts" \
        -v restricted_shell="$u11_approved_shell" '
        BEGIN {
            count=split(approved, names, ",")
            for (account_index=1; account_index<=count; account_index++) {
                selected[names[account_index]]=1
            }
        }
        {
            if ($1 in selected) $7=restricted_shell
            print
        }
    ' "$source_path"
}

os_guard_item_discover_content_targets() {
    u11_passwd_path="${content_test_root}/etc/passwd"
    if [ ! -f "$u11_passwd_path" ] || [ -L "$u11_passwd_path" ] || \
        ! u11_validate_passwd_structure "$u11_passwd_path"; then
        os_guard_content_set_error \
            'LOCAL_PASSWD_STATE_INVALID' \
            'a complete regular local passwd fixture is required'
        return 1
    fi
    u11_root_record=$(awk -F: '$1 == "root" { print; count++ } END { exit count == 1 ? 0 : 1 }' \
        "$u11_passwd_path") || {
        os_guard_content_set_error \
            'ROOT_ACCOUNT_STATE_INVALID' \
            'exactly one root account record is required'
        return 1
    }

    approved_found=0
    unsafe_unapproved=0
    while IFS=: read -r account password uid gid gecos home shell; do
        if ! u11_account_is_kisa_target "$account"; then
            continue
        fi
        case "$shell" in
            /bin/false|/sbin/nologin)
                ;;
            *)
                if u11_account_is_approved "$account"; then
                    approved_found=$((approved_found + 1))
                else
                    unsafe_unapproved=$((unsafe_unapproved + 1))
                fi
                ;;
        esac
    done < "$u11_passwd_path"

    if [ "$unsafe_unapproved" -gt 0 ]; then
        os_guard_content_set_error \
            'UNAPPROVED_VULNERABLE_ACCOUNT_PRESENT' \
            'a vulnerable KISA account is outside the approved change scope'
        return 1
    fi
    if [ "$approved_found" -eq 0 ]; then
        os_guard_content_set_error \
            'APPROVED_LOCAL_ACCOUNT_NOT_ACTIONABLE' \
            'no approved vulnerable local account is available for change'
        return 1
    fi

    CONTENT_CURRENT_EFFECTIVE_VALUE='redacted aggregate of approved local KISA account shells'
    os_guard_content_add_target \
        "$u11_passwd_path" \
        '/etc/passwd' \
        'approved KISA account shell fields' \
        'replace only approved vulnerable shell fields with the approved restricted shell'
}

os_guard_item_validate_configuration() {
    if [ -n "$content_test_root" ] && \
        [ "${OS_GUARD_TEST_FORCE_ITEM_SYNTAX_FAILURE:-false}" = 'true' ]; then
        os_guard_content_set_error \
            'PASSWD_SHELL_VALIDATION_FAILED' \
            'forced passwd shell validation failure'
        return 1
    fi
    if ! u11_validate_passwd_structure "$u11_passwd_path"; then
        os_guard_content_set_error \
            'PASSWD_SHELL_VALIDATION_FAILED' \
            'the resulting passwd structure is invalid'
        return 1
    fi
    resulting_root=$(awk -F: '$1 == "root" { print; count++ } END { exit count == 1 ? 0 : 1 }' \
        "$u11_passwd_path") || return 1
    if [ "$resulting_root" != "$u11_root_record" ]; then
        os_guard_content_set_error \
            'ROOT_ACCOUNT_CHANGED' \
            'the root account record changed unexpectedly'
        return 1
    fi
    old_ifs=$IFS
    IFS=','
    set -- $u11_approved_accounts
    IFS=$old_ifs
    for approved_account in "$@"; do
        account_shell=$(awk -F: -v account="$approved_account" '
            $1 == account { print $7; count++ }
            END { exit count == 1 ? 0 : 1 }
        ' "$u11_passwd_path") || {
            os_guard_content_set_error \
                'PASSWD_SHELL_VALIDATION_FAILED' \
                'an approved local account is missing or duplicated'
            return 1
        }
        if [ "$account_shell" != "$u11_approved_shell" ]; then
            os_guard_content_set_error \
                'PASSWD_SHELL_VALIDATION_FAILED' \
                'an approved account does not use the approved restricted shell'
            return 1
        fi
    done
    return 0
}

os_guard_content_run_module "${1:-}"
