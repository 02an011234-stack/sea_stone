#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/../lib/common.sh"

distro=${OS_GUARD_DISTRO:-unknown}
version_id=${OS_GUARD_VERSION_ID:-unknown}
module_version=${OS_GUARD_MODULE_VERSION:-unknown}
observed_at=$(os_guard_utc_now)
test_root=${OS_GUARD_TEST_ROOT:-}
passwd_path="${test_root}/etc/passwd"
shadow_path="${test_root}/etc/shadow"
login_defs_path="${test_root}/etc/login.defs"

passwd_present=false; passwd_readable=false
valid_account_count=0; malformed_entry_count=0; root_account_count=0; non_root_account_count=0
system_account_count=''; regular_account_count=''; uid_min=''
non_login_shell_count=0; login_shell_candidate_count=0
locked_account_count=''; unlocked_account_count=''; missing_shadow_account_count=''
shadow_collection_state='not_present'; manual_review_target_count=0
automatic_judgment_target_count=0; manual_review_required=false
status_json='null'; review_state='PENDING'; collection_error=''; error_json='null'
reason_code='KISA_U07_ACCOUNT_NECESSITY_REQUIRES_REVIEW'
decision_reason='Account necessity must be confirmed against service and organizational use'

[ -e "$passwd_path" ] && passwd_present=true
[ -r "$passwd_path" ] && passwd_readable=true

case "$distro" in rocky|ubuntu) ;; *) collection_error='UNSUPPORTED_OS_CONFIGURATION' ;; esac
if [ -z "$collection_error" ] && [ "$passwd_present" != true ]; then
    collection_error='PASSWD_FILE_NOT_FOUND'
elif [ -z "$collection_error" ] && [ "$passwd_readable" != true ]; then
    collection_error='PASSWD_FILE_UNREADABLE'
fi

if [ -r "$login_defs_path" ]; then
    uid_min=$(awk '
        /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
        toupper($1) == "UID_MIN" { value=$2 }
        END { if (value ~ /^[0-9]+$/ && value > 0) print value }
    ' "$login_defs_path" 2>/dev/null || true)
fi

if [ -z "$collection_error" ]; then
    if counts=$(awk -F: -v uid_min="$uid_min" '
        BEGIN { valid=malformed=root_count=nonroot=system_count=regular=nonlogin=login_candidate=0 }
        {
            if (NF != 7 || $1 == "" || $3 !~ /^[0-9]+$/ || $4 !~ /^[0-9]+$/) { malformed++; next }
            valid++; uid=$3+0
            if ($1 == "root") root_count++; else nonroot++
            if (uid_min != "") {
                if (uid < uid_min) system_count++; else regular++
            }
            shell=$7
            if (shell ~ /\/(nologin|false)$/) nonlogin++; else login_candidate++
        }
        END { print valid, malformed, root_count, nonroot, system_count, regular, nonlogin, login_candidate }
    ' "$passwd_path" 2>/dev/null); then
        set -- $counts
        if [ "$#" -eq 8 ]; then
            valid_account_count=$1; malformed_entry_count=$2; root_account_count=$3
            non_root_account_count=$4; classified_system=$5; classified_regular=$6
            non_login_shell_count=$7; login_shell_candidate_count=$8
            if [ -n "$uid_min" ]; then
                system_account_count=$classified_system; regular_account_count=$classified_regular
            fi
        else
            collection_error='PASSWD_FILE_PARSE_ERROR'
        fi
    else
        collection_error='PASSWD_FILE_READ_ERROR'
    fi
fi
if [ -z "$collection_error" ] && { [ "$valid_account_count" -eq 0 ] || [ "$malformed_entry_count" -gt 0 ]; }; then
    collection_error='PASSWD_FILE_PARSE_ERROR'
fi

# Shadow data is optional supporting evidence for review. Hashes are inspected
# only as lock markers and are never retained or emitted.
if [ -z "$collection_error" ] && [ -e "$shadow_path" ]; then
    if [ -r "$shadow_path" ]; then
        if shadow_counts=$(awk -F: '
            FILENAME == ARGV[1] {
                if (NF == 7 && $1 != "" && $1 != "root") targets[$1]=1
                next
            }
            {
                if (NF != 9 || $1 == "") { malformed++; next }
                if (!($1 in targets)) next
                seen[$1]=1
                if ($2 ~ /^[!*]/) locked++; else unlocked++
            }
            END {
                for (account in targets) if (!(account in seen)) missing++
                print locked+0, unlocked+0, missing+0, malformed+0
            }
        ' "$passwd_path" "$shadow_path" 2>/dev/null); then
            set -- $shadow_counts
            if [ "$#" -eq 4 ]; then
                locked_account_count=$1; unlocked_account_count=$2; missing_shadow_account_count=$3
                if [ "$4" -eq 0 ]; then shadow_collection_state='collected'; else shadow_collection_state='parse_warning'; fi
            else
                shadow_collection_state='parse_warning'
            fi
        else
            shadow_collection_state='read_error'
        fi
    else
        shadow_collection_state='unreadable'
    fi
fi

if [ -n "$collection_error" ]; then
    status_json='"UNCHECKABLE"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U07_COLLECTION_FAILED'
    decision_reason='The local account database could not be read or parsed completely'
    error_json=$(printf '{"code":'; os_guard_json_quote "$collection_error"; printf ',"message":"Local account inventory collection or parsing failed"}')
elif [ "$root_account_count" -eq 1 ] && [ "$non_root_account_count" -eq 0 ]; then
    status_json='"GOOD"'; review_state='NOT_REQUIRED'; automatic_judgment_target_count=1
    reason_code='KISA_U07_NO_NON_ROOT_ACCOUNTS'
    decision_reason='Only the root account exists, so no unnecessary non-root account is present'
else
    manual_review_required=true
    manual_review_target_count=$non_root_account_count
fi

json_number_or_null() { if [ -n "$1" ]; then printf '%s' "$1"; else printf 'null'; fi; }

printf '{"item_id":"U-07","status":%s,"review_state":"%s",' "$status_json" "$review_state"
printf '"current_value":{"passwd_file_present":%s,"passwd_file_readable":%s,' "$passwd_present" "$passwd_readable"
printf '"valid_account_count":%s,"root_account_count":%s,"non_root_account_count":%s,' "$valid_account_count" "$root_account_count" "$non_root_account_count"
printf '"uid_min":'; json_number_or_null "$uid_min"; printf ',"system_account_count":'; json_number_or_null "$system_account_count"
printf ',"regular_account_count":'; json_number_or_null "$regular_account_count"
printf ',"non_login_shell_count":%s,"login_shell_candidate_count":%s,' "$non_login_shell_count" "$login_shell_candidate_count"
printf '"shadow_collection_state":'; os_guard_json_quote "$shadow_collection_state"
printf ',"locked_account_count":'; json_number_or_null "$locked_account_count"; printf ',"unlocked_account_count":'; json_number_or_null "$unlocked_account_count"
printf ',"missing_shadow_account_count":'; json_number_or_null "$missing_shadow_account_count"
printf ',"malformed_entry_count":%s,"automatic_judgment_target_count":%s,' "$malformed_entry_count" "$automatic_judgment_target_count"
printf '"manual_review_target_count":%s,"manual_review_required":%s},' "$manual_review_target_count" "$manual_review_required"
printf '"evidence":{"item_id":"U-07","collection_method":"Inspect aggregate local account, UID class, login shell, and optional lock-state metadata without exporting account identifiers",'
printf '"configuration_paths":["/etc/passwd","/etc/login.defs","/etc/shadow"],'
printf '"kisa_basis_type":"ACCOUNT_NECESSITY_REVIEW","reason_code":'; os_guard_json_quote "$reason_code"
printf ',"os":{"distro":'; os_guard_json_quote "$distro"; printf ',"version_id":'; os_guard_json_quote "$version_id"
printf '},"observed_at":'; os_guard_json_quote "$observed_at"; printf ',"module_version":'; os_guard_json_quote "$module_version"
printf ',"decision_reason":'; os_guard_json_quote "$decision_reason"
printf '},"error":%s}\n' "$error_json"
exit 0
