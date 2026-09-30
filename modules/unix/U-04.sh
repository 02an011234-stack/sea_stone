#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/../lib/common.sh"

distro=${OS_GUARD_DISTRO:-unknown}
version_id=${OS_GUARD_VERSION_ID:-unknown}
module_version=${OS_GUARD_MODULE_VERSION:-unknown}
observed_at=$(os_guard_utc_now)
# ModuleRunner never passes this test-only root override.
test_root=${OS_GUARD_TEST_ROOT:-}
passwd_path="${test_root}/etc/passwd"
shadow_path="${test_root}/etc/shadow"

passwd_present=false; passwd_readable=false
shadow_present=false; shadow_readable=false; shadow_structure_valid=false
passwd_entry_count=0; shadow_entry_count=0; shadow_reference_count=0
empty_field_count=0; locked_field_count=0
direct_encrypted_candidate_count=0; unknown_field_count=0
malformed_passwd_entry_count=0; malformed_shadow_entry_count=0
missing_shadow_entry_count=0
status_json='null'; review_state='PENDING'
reason_code='KISA_U04_REVIEW_REQUIRED'
decision_reason='The password storage structure requires manual review'
review_reason=''; collection_error=''; error_json='null'
passwd_collection_ok=false

[ -e "$passwd_path" ] && passwd_present=true
[ -r "$passwd_path" ] && passwd_readable=true
[ -e "$shadow_path" ] && shadow_present=true
[ -r "$shadow_path" ] && shadow_readable=true

case "$distro" in rocky|ubuntu) ;; *) collection_error='UNSUPPORTED_OS_CONFIGURATION' ;; esac
if [ -z "$collection_error" ] && [ "$passwd_present" != true ]; then
    collection_error='PASSWD_FILE_NOT_FOUND'
elif [ -z "$collection_error" ] && [ "$passwd_readable" != true ]; then
    collection_error='PASSWD_FILE_UNREADABLE'
fi

if [ -z "$collection_error" ]; then
    if counts=$(awk -F: '
        BEGIN { entries=shadow=empty=locked=direct=unknown=malformed=0 }
        {
            entries++
            if (NF != 7 || $1 == "") { malformed++; next }
            value=$2
            if (value == "x") shadow++
            else if (value == "") empty++
            else if (value == "!" || value == "!!" || value == "*" || value == "!*") locked++
            else if (value ~ /^\$[^$]+\$[^$]+/) direct++
            else unknown++
        }
        END { print entries, shadow, empty, locked, direct, unknown, malformed }
    ' "$passwd_path" 2>/dev/null); then
        set -- $counts
        if [ "$#" -eq 7 ]; then
            passwd_entry_count=$1; shadow_reference_count=$2; empty_field_count=$3
            locked_field_count=$4; direct_encrypted_candidate_count=$5
            unknown_field_count=$6; malformed_passwd_entry_count=$7
        else
            collection_error='PASSWD_FILE_PARSE_ERROR'
        fi
    else
        collection_error='PASSWD_FILE_READ_ERROR'
    fi
fi
if [ -z "$collection_error" ] && { [ "$passwd_entry_count" -eq 0 ] || [ "$malformed_passwd_entry_count" -gt 0 ]; }; then
    collection_error='PASSWD_FILE_PARSE_ERROR'
elif [ -z "$collection_error" ]; then
    passwd_collection_ok=true
fi

# Only structural metadata is retained. Shadow password fields are never output.
if [ -z "$collection_error" ] && [ "$shadow_present" = true ] && [ "$shadow_readable" = true ]; then
    if counts=$(awk -F: '
        FILENAME == ARGV[1] {
            if (NF == 7 && $1 != "" && $2 == "x") references[$1]=1
            next
        }
        {
            entries++
            if (NF != 9 || $1 == "") { malformed++; next }
            accounts[$1]=1
        }
        END {
            for (account in references) if (!(account in accounts)) missing++
            print entries, malformed+0, missing+0
        }
    ' "$passwd_path" "$shadow_path" 2>/dev/null); then
        set -- $counts
        if [ "$#" -eq 3 ]; then
            shadow_entry_count=$1; malformed_shadow_entry_count=$2; missing_shadow_entry_count=$3
            if [ "$shadow_entry_count" -gt 0 ] && [ "$malformed_shadow_entry_count" -eq 0 ]; then
                shadow_structure_valid=true
            fi
        else
            collection_error='SHADOW_FILE_PARSE_ERROR'
        fi
    else
        collection_error='SHADOW_FILE_READ_ERROR'
    fi
fi

# A clearly empty field is unprotected and takes precedence over ambiguity elsewhere.
if [ "$passwd_collection_ok" = true ] && [ "$empty_field_count" -gt 0 ]; then
    status_json='"VULNERABLE"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U04_UNPROTECTED_PASSWORD_FIELD'
    decision_reason='At least one account has a clearly unprotected empty password field in /etc/passwd'
elif [ -n "$collection_error" ]; then
    status_json='"UNCHECKABLE"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U04_COLLECTION_FAILED'
    decision_reason='The password storage configuration could not be read or parsed safely'
    error_json=$(printf '{"code":'; os_guard_json_quote "$collection_error"; printf ',"message":"Password storage metadata collection or parsing failed"}')
elif [ "$shadow_reference_count" -gt 0 ]; then
    if [ "$shadow_present" != true ]; then
        review_reason='SHADOW_REFERENCE_WITHOUT_SHADOW_FILE'
    elif [ "$shadow_readable" != true ]; then
        status_json='"UNCHECKABLE"'; review_state='NOT_REQUIRED'
        reason_code='KISA_U04_COLLECTION_FAILED'
        decision_reason='The shadow structure required to confirm protected password storage could not be read'
        error_json='{"code":"SHADOW_FILE_UNREADABLE","message":"Required shadow password metadata could not be read"}'
    elif [ "$shadow_structure_valid" != true ]; then
        status_json='"UNCHECKABLE"'; review_state='NOT_REQUIRED'
        reason_code='KISA_U04_COLLECTION_FAILED'
        decision_reason='The shadow structure required to confirm protected password storage could not be parsed'
        error_json='{"code":"SHADOW_FILE_PARSE_ERROR","message":"Required shadow password metadata could not be parsed"}'
    elif [ "$missing_shadow_entry_count" -gt 0 ]; then
        review_reason='SHADOW_REFERENCE_MAPPING_INCOMPLETE'
    elif [ "$direct_encrypted_candidate_count" -gt 0 ]; then
        review_reason='DIRECT_ENCRYPTED_CANDIDATE_REQUIRES_REVIEW'
    elif [ "$unknown_field_count" -gt 0 ]; then
        review_reason='NONSTANDARD_PASSWORD_FIELD_REQUIRES_REVIEW'
    else
        status_json='"GOOD"'; review_state='NOT_REQUIRED'
        reason_code='KISA_U04_SHADOW_PASSWORDS_CONFIRMED'
        decision_reason='All active password references use a readable and structurally valid shadow password store'
    fi
elif [ "$direct_encrypted_candidate_count" -gt 0 ]; then
    review_reason='DIRECT_ENCRYPTED_CANDIDATE_REQUIRES_REVIEW'
elif [ "$unknown_field_count" -gt 0 ]; then
    review_reason='NONSTANDARD_PASSWORD_FIELD_REQUIRES_REVIEW'
elif [ "$locked_field_count" -gt 0 ]; then
    review_reason='LOCKED_ONLY_PASSWORD_STRUCTURE_REQUIRES_REVIEW'
else
    review_reason='PASSWORD_STORAGE_STRUCTURE_REQUIRES_REVIEW'
fi
if [ "$status_json" = 'null' ]; then
    reason_code='KISA_U04_REVIEW_REQUIRED'
    decision_reason='The collected password field structure is not sufficient for a safe automatic KISA judgment'
fi

printf '{"item_id":"U-04","status":%s,"review_state":"%s",' "$status_json" "$review_state"
printf '"current_value":{"passwd_file_present":%s,"passwd_file_readable":%s,' "$passwd_present" "$passwd_readable"
printf '"shadow_file_present":%s,"shadow_file_readable":%s,"shadow_structure_valid":%s,' "$shadow_present" "$shadow_readable" "$shadow_structure_valid"
printf '"passwd_entry_count":%s,"shadow_entry_count":%s,"shadow_reference_count":%s,' "$passwd_entry_count" "$shadow_entry_count" "$shadow_reference_count"
printf '"empty_field_count":%s,"locked_field_count":%s,' "$empty_field_count" "$locked_field_count"
printf '"direct_encrypted_candidate_count":%s,"unknown_field_count":%s,' "$direct_encrypted_candidate_count" "$unknown_field_count"
printf '"malformed_passwd_entry_count":%s,"malformed_shadow_entry_count":%s,' "$malformed_passwd_entry_count" "$malformed_shadow_entry_count"
printf '"missing_shadow_entry_count":%s},' "$missing_shadow_entry_count"
printf '"evidence":{"item_id":"U-04",'
printf '"collection_method":"Read aggregate passwd field classifications and shadow structure without collecting account names or password data",'
printf '"configuration_paths":["/etc/passwd","/etc/shadow"],"reason_code":'; os_guard_json_quote "$reason_code"
printf ',"review_reason":'; if [ -n "$review_reason" ]; then os_guard_json_quote "$review_reason"; else printf 'null'; fi
printf ',"os":{"distro":'; os_guard_json_quote "$distro"; printf ',"version_id":'; os_guard_json_quote "$version_id"
printf '},"observed_at":'; os_guard_json_quote "$observed_at"; printf ',"module_version":'; os_guard_json_quote "$module_version"
printf ',"decision_reason":'; os_guard_json_quote "$decision_reason"
printf '},"error":%s}\n' "$error_json"
exit 0
