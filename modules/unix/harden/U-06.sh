#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_content.sh"

HARDEN_ITEM_ID='U-06'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-06.sh"
HARDEN_TARGET_DESCRIPTION='one approved local PAM su restriction rule'
HARDEN_RISK_LEVEL='HIGH'
HARDEN_SERVICE_RELOAD_REQUIRED=false

u06_approved_group=''
u06_pam_path=''

u06_validate_local_group() {
    passwd_path="${content_test_root}/etc/passwd"
    group_path="${content_test_root}/etc/group"

    if [ ! -f "$passwd_path" ] || [ -L "$passwd_path" ] || \
        [ ! -f "$group_path" ] || [ -L "$group_path" ]; then
        os_guard_content_set_error \
            'LOCAL_IDENTITY_SOURCE_INVALID' \
            'regular local passwd and group files are required'
        return 1
    fi

    group_summary=$(awk -F: -v wanted="$u06_approved_group" '
        FILENAME == ARGV[1] {
            if (NF != 7 || $1 == "" || $3 !~ /^[0-9]+$/ || $4 !~ /^[0-9]+$/) {
                malformed++
                next
            }
            primary_group[$1]=$4
            next
        }
        {
            if (NF != 4 || $1 == "" || $3 !~ /^[0-9]+$/) {
                malformed++
                next
            }
            if ($1 != wanted) next
            found++
            group_id=$3
            listed_count=split($4, listed_members, ",")
            for (member_index=1; member_index<=listed_count; member_index++) {
                if (listed_members[member_index] != "") {
                    listed_accounts[listed_members[member_index]]=1
                }
            }
        }
        END {
            if (found == 1) {
                for (account in listed_accounts) {
                    if (account in primary_group) members[account]=1
                    else unresolved_member_count++
                }
                for (account in primary_group) {
                    if (primary_group[account] == group_id) members[account]=1
                }
                for (account in members) member_count++
            }
            print found+0 "|" member_count+0 "|" malformed+0 "|" unresolved_member_count+0
        }
    ' "$passwd_path" "$group_path" 2>/dev/null) || {
        os_guard_content_set_error \
            'LOCAL_IDENTITY_SOURCE_UNREADABLE' \
            'the approved local su group could not be verified'
        return 1
    }

    old_ifs=$IFS
    IFS='|'
    set -- $group_summary
    IFS=$old_ifs
    if [ "$#" -ne 4 ] || [ "$3" -ne 0 ] || [ "$4" -ne 0 ]; then
        os_guard_content_set_error \
            'LOCAL_IDENTITY_SOURCE_INVALID' \
            'the local identity files contain an unsupported structure'
        return 1
    fi
    if [ "$1" -ne 1 ] || [ "$2" -lt 1 ]; then
        os_guard_content_set_error \
            'APPROVED_SU_GROUP_NOT_ACTIONABLE' \
            'the approved local su group must exist and contain at least one account'
        return 1
    fi
    return 0
}

os_guard_item_validate_content_policy() {
    if [ -z "$content_test_root" ] || \
        [ "$content_test_root" = '/' ] || \
        [ "${OS_GUARD_TEST_POLICY_FIXTURE:-false}" != 'true' ]; then
        os_guard_content_set_error \
            'POLICY_INTEGRATION_REQUIRED' \
            'trusted U-06 operating policy integration is not available'
        return 1
    fi

    u06_approved_group=${OS_GUARD_TEST_APPROVED_SU_GROUP:-}
    if ! printf '%s\n' "$u06_approved_group" | \
        grep -Eq '^[A-Za-z_][A-Za-z0-9_.-]{0,31}$'; then
        os_guard_content_set_error \
            'APPROVED_SU_GROUP_INVALID' \
            'one bounded approved local su group is required'
        return 1
    fi
    if [ "${OS_GUARD_TEST_IDENTITY_SOURCE:-}" != 'local-files' ] || \
        [ "${OS_GUARD_TEST_SU_GROUP_MEMBERSHIP_VERIFIED:-false}" != 'true' ]; then
        os_guard_content_set_error \
            'LOCAL_GROUP_EVIDENCE_REQUIRED' \
            'local identity provenance and approved group membership evidence are required'
        return 1
    fi
    if [ "${OS_GUARD_TEST_ALTERNATIVE_ADMIN_ACCESS_VERIFIED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_CONSOLE_RECOVERY_VERIFIED:-false}" != 'true' ]; then
        os_guard_content_set_error \
            'ADMIN_RECOVERY_EVIDENCE_REQUIRED' \
            'verified alternative administration and console recovery paths are required'
        return 1
    fi
    u06_validate_local_group
}

u06_pam_wheel_count() {
    grep -Eic '^[[:space:]]*auth[[:space:]]+[^[:space:]]+[[:space:]]+([^[:space:]]*/)?pam_wheel\.so([[:space:]]|$)' "$1"
}

os_guard_item_render_content() {
    source_path=$1
    printf 'auth required pam_wheel.so use_uid group=%s\n' "$u06_approved_group"
    cat "$source_path"
}

os_guard_item_discover_content_targets() {
    u06_pam_path="${content_test_root}/etc/pam.d/su"
    if [ ! -f "$u06_pam_path" ] || [ -L "$u06_pam_path" ]; then
        os_guard_content_set_error \
            'PAM_SU_TARGET_INVALID' \
            'a regular existing PAM su configuration is required'
        return 1
    fi
    if grep -Eq '\\[[:space:]]*$' "$u06_pam_path" || \
        grep -Eiq '^[[:space:]]*(auth[[:space:]]+(include|substack)|@include)[[:space:]]' "$u06_pam_path"; then
        os_guard_content_set_error \
            'PAM_SU_COMPLEX_CONFIGURATION' \
            'included or multiline PAM su configurations are not safely editable'
        return 1
    fi
    if [ "$(u06_pam_wheel_count "$u06_pam_path")" -ne 0 ]; then
        os_guard_content_set_error \
            'PAM_WHEEL_STATE_AMBIGUOUS' \
            'an existing PAM wheel rule must be reviewed rather than rewritten'
        return 1
    fi
    if ! grep -Eq '^[[:space:]]*auth[[:space:]]+[^[:space:]]+[[:space:]]+([^[:space:]]*/)?pam_unix\.so([[:space:]]|$)' "$u06_pam_path"; then
        os_guard_content_set_error \
            'PAM_SU_BASELINE_UNVERIFIED' \
            'one directly verifiable PAM unix authentication rule is required'
        return 1
    fi

    CONTENT_CURRENT_EFFECTIVE_VALUE='no compliant local PAM su group restriction is active'
    os_guard_content_add_target \
        "$u06_pam_path" \
        '/etc/pam.d/su' \
        'PAM su authentication stack' \
        'prepend one required pam_wheel rule for the approved local group'
}

os_guard_item_validate_configuration() {
    if [ -n "$content_test_root" ] && \
        [ "${OS_GUARD_TEST_FORCE_ITEM_SYNTAX_FAILURE:-false}" = 'true' ]; then
        os_guard_content_set_error \
            'PAM_SU_VALIDATION_FAILED' \
            'forced PAM su validation failure'
        return 1
    fi
    if [ "$(u06_pam_wheel_count "$u06_pam_path")" -ne 1 ] || \
        ! grep -Eq \
            "^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\\.so[[:space:]]+use_uid[[:space:]]+group=${u06_approved_group}[[:space:]]*$" \
            "$u06_pam_path"; then
        os_guard_content_set_error \
            'PAM_SU_VALIDATION_FAILED' \
            'the resulting PAM su restriction is not the approved exact rule'
        return 1
    fi
    return 0
}

os_guard_content_run_module "${1:-}"
