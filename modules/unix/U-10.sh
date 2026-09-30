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

passwd_present=false; passwd_readable=false
valid_entry_count=0; unique_uid_count=0
duplicate_uid_group_count=0; accounts_in_duplicate_uid_groups=0
duplicate_uid_exists=false; malformed_entry_count=0
status_json='null'; review_state='PENDING'; collection_error=''; error_json='null'
reason_code='KISA_U10_UID_ANALYSIS_PENDING'
decision_reason='The complete local UID set could not yet be judged'

[ -e "$passwd_path" ] && passwd_present=true
[ -r "$passwd_path" ] && passwd_readable=true

case "$distro" in rocky|ubuntu) ;; *) collection_error='UNSUPPORTED_OS_CONFIGURATION' ;; esac
if [ -z "$collection_error" ] && [ "$passwd_present" != true ]; then
    collection_error='PASSWD_FILE_NOT_FOUND'
elif [ -z "$collection_error" ] && [ "$passwd_readable" != true ]; then
    collection_error='PASSWD_FILE_UNREADABLE'
fi

# UID values are compared numerically. Account names, password fields, shells,
# and the UID values themselves are not emitted.
if [ -z "$collection_error" ]; then
    if counts=$(awk -F: '
        BEGIN { valid=malformed=unique=duplicate_groups=duplicate_accounts=0 }
        {
            if (NF != 7 || $1 == "" || $3 !~ /^[0-9]+$/ || $4 !~ /^[0-9]+$/) {
                malformed++
                next
            }
            valid++; uid=$3+0; uid_count[uid]++
        }
        END {
            for (uid in uid_count) {
                unique++
                if (uid_count[uid] > 1) {
                    duplicate_groups++
                    duplicate_accounts+=uid_count[uid]
                }
            }
            print valid, unique, duplicate_groups, duplicate_accounts, malformed
        }
    ' "$passwd_path" 2>/dev/null); then
        set -- $counts
        if [ "$#" -eq 5 ]; then
            valid_entry_count=$1; unique_uid_count=$2
            duplicate_uid_group_count=$3; accounts_in_duplicate_uid_groups=$4
            malformed_entry_count=$5
        else
            collection_error='PASSWD_FILE_PARSE_ERROR'
        fi
    else
        collection_error='PASSWD_FILE_READ_ERROR'
    fi
fi

if [ -z "$collection_error" ] && { [ "$valid_entry_count" -eq 0 ] || [ "$malformed_entry_count" -gt 0 ]; }; then
    collection_error='PASSWD_FILE_PARSE_ERROR'
fi

if [ -n "$collection_error" ]; then
    status_json='"UNCHECKABLE"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U10_COLLECTION_FAILED'
    decision_reason='The local passwd UID set could not be read or parsed completely'
    error_json=$(printf '{"code":'; os_guard_json_quote "$collection_error"; printf ',"message":"Local UID collection or parsing failed"}')
elif [ "$duplicate_uid_group_count" -gt 0 ]; then
    status_json='"VULNERABLE"'; review_state='NOT_REQUIRED'; duplicate_uid_exists=true
    reason_code='KISA_U10_DUPLICATE_UID_FOUND'
    decision_reason='At least one UID is assigned to two or more local accounts'
else
    status_json='"GOOD"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U10_ALL_UIDS_UNIQUE'
    decision_reason='Every valid local account has a unique UID'
fi

printf '{"item_id":"U-10","status":%s,"review_state":"%s",' "$status_json" "$review_state"
printf '"current_value":{"passwd_file_present":%s,"passwd_file_readable":%s,' "$passwd_present" "$passwd_readable"
printf '"valid_entry_count":%s,"unique_uid_count":%s,' "$valid_entry_count" "$unique_uid_count"
printf '"duplicate_uid_group_count":%s,"accounts_in_duplicate_uid_groups":%s,' "$duplicate_uid_group_count" "$accounts_in_duplicate_uid_groups"
printf '"duplicate_uid_exists":%s,"malformed_entry_count":%s},' "$duplicate_uid_exists" "$malformed_entry_count"
printf '"evidence":{"item_id":"U-10","collection_method":"Parse all standard local passwd entries and aggregate integer UID multiplicity without exporting identifiers",'
printf '"configuration_paths":["/etc/passwd"],"reason_code":'; os_guard_json_quote "$reason_code"
printf ',"os":{"distro":'; os_guard_json_quote "$distro"; printf ',"version_id":'; os_guard_json_quote "$version_id"
printf '},"observed_at":'; os_guard_json_quote "$observed_at"; printf ',"module_version":'; os_guard_json_quote "$module_version"
printf ',"decision_reason":'; os_guard_json_quote "$decision_reason"
printf '},"error":%s}\n' "$error_json"
exit 0
