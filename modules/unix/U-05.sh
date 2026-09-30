#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/../lib/common.sh"

distro=${OS_GUARD_DISTRO:-unknown}
version_id=${OS_GUARD_VERSION_ID:-unknown}
module_version=${OS_GUARD_MODULE_VERSION:-unknown}
observed_at=$(os_guard_utc_now)
# ModuleRunner does not pass this test-only fixture root.
test_root=${OS_GUARD_TEST_ROOT:-}
passwd_path="${test_root}/etc/passwd"

passwd_present=false
passwd_readable=false
valid_entry_count=0
uid_zero_count=0
non_root_uid0_count=0
root_entry_count=0
root_uid=''
malformed_entry_count=0
status_json='null'
review_state='PENDING'
reason_code='KISA_U05_NONSTANDARD_ROOT_REQUIRES_REVIEW'
decision_reason='The root account structure is nonstandard and requires manual review'
review_reason=''
collection_error=''
error_json='null'

[ -e "$passwd_path" ] && passwd_present=true
[ -r "$passwd_path" ] && passwd_readable=true

case "$distro" in rocky|ubuntu) ;; *) collection_error='UNSUPPORTED_OS_CONFIGURATION' ;; esac
if [ -z "$collection_error" ] && [ "$passwd_present" != true ]; then
    collection_error='PASSWD_FILE_NOT_FOUND'
elif [ -z "$collection_error" ] && [ "$passwd_readable" != true ]; then
    collection_error='PASSWD_FILE_UNREADABLE'
fi

# Only aggregate counts and root's numeric UID leave awk. Account names and the
# password field are never emitted to stdout, stderr, or Evidence.
if [ -z "$collection_error" ]; then
    if counts=$(awk -F: '
        BEGIN { valid=uid0=nonroot0=root_entries=malformed=0; root_uid=-1 }
        {
            if (NF != 7 || $1 == "" || $3 !~ /^[0-9]+$/) {
                malformed++
                next
            }
            valid++
            numeric_uid=$3 + 0
            if (numeric_uid == 0) {
                uid0++
                if ($1 != "root") nonroot0++
            }
            if ($1 == "root") {
                root_entries++
                root_uid=numeric_uid
            }
        }
        END { print valid, uid0, nonroot0, root_entries, root_uid, malformed }
    ' "$passwd_path" 2>/dev/null); then
        set -- $counts
        if [ "$#" -eq 6 ]; then
            valid_entry_count=$1
            uid_zero_count=$2
            non_root_uid0_count=$3
            root_entry_count=$4
            root_uid=$5
            malformed_entry_count=$6
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
    status_json='"UNCHECKABLE"'
    review_state='NOT_REQUIRED'
    reason_code='KISA_U05_COLLECTION_FAILED'
    decision_reason='The local account database could not be read or parsed completely'
    error_json=$(printf '{"code":'; os_guard_json_quote "$collection_error"; printf ',"message":"Local account UID metadata collection or parsing failed"}')
elif [ "$non_root_uid0_count" -gt 0 ]; then
    status_json='"VULNERABLE"'
    review_state='NOT_REQUIRED'
    reason_code='KISA_U05_NON_ROOT_UID_ZERO_FOUND'
    decision_reason='At least one account other than root has UID 0'
elif [ "$root_entry_count" -eq 1 ] && [ "$root_uid" -eq 0 ]; then
    status_json='"GOOD"'
    review_state='NOT_REQUIRED'
    reason_code='KISA_U05_ONLY_ROOT_HAS_UID_ZERO'
    decision_reason='No account other than root has UID 0'
else
    review_reason='ROOT_ACCOUNT_STRUCTURE_NONSTANDARD'
fi

if [ "$root_uid" -ge 0 ]; then root_uid_json=$root_uid; else root_uid_json='null'; fi
if [ "$non_root_uid0_count" -gt 0 ]; then non_root_uid0_exists=true; else non_root_uid0_exists=false; fi

printf '{"item_id":"U-05","status":%s,"review_state":"%s",' "$status_json" "$review_state"
printf '"current_value":{"passwd_file_present":%s,"passwd_file_readable":%s,' "$passwd_present" "$passwd_readable"
printf '"valid_entry_count":%s,"uid_zero_count":%s,"root_entry_count":%s,' "$valid_entry_count" "$uid_zero_count" "$root_entry_count"
printf '"root_uid":%s,"non_root_uid0_count":%s,"non_root_uid0_exists":%s,' "$root_uid_json" "$non_root_uid0_count" "$non_root_uid0_exists"
printf '"malformed_entry_count":%s},' "$malformed_entry_count"
printf '"evidence":{"item_id":"U-05",'
printf '"collection_method":"Read and aggregate account UID fields from the local passwd database without collecting account names or password data",'
printf '"configuration_paths":["/etc/passwd"],"reason_code":'; os_guard_json_quote "$reason_code"
printf ',"review_reason":'; if [ -n "$review_reason" ]; then os_guard_json_quote "$review_reason"; else printf 'null'; fi
printf ',"os":{"distro":'; os_guard_json_quote "$distro"; printf ',"version_id":'; os_guard_json_quote "$version_id"
printf '},"observed_at":'; os_guard_json_quote "$observed_at"; printf ',"module_version":'; os_guard_json_quote "$module_version"
printf ',"decision_reason":'; os_guard_json_quote "$decision_reason"
printf '},"error":%s}\n' "$error_json"
exit 0
