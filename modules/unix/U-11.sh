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

target_account_definition_count=12
passwd_present=false; passwd_readable=false
valid_entry_count=0; existing_target_count=0; compliant_shell_count=0
violating_target_count=0; missing_target_count=$target_account_definition_count
nonstandard_shell_count=0; malformed_entry_count=0
status_json='null'; review_state='PENDING'; collection_error=''; error_json='null'
reason_code='KISA_U11_SHELL_ANALYSIS_PENDING'
decision_reason='The shell assignment check has not completed'

[ -e "$passwd_path" ] && passwd_present=true
[ -r "$passwd_path" ] && passwd_readable=true

case "$distro" in rocky|ubuntu) ;; *) collection_error='UNSUPPORTED_OS_CONFIGURATION' ;; esac
if [ -z "$collection_error" ] && [ "$passwd_present" != true ]; then
    collection_error='PASSWD_FILE_NOT_FOUND'
elif [ -z "$collection_error" ] && [ "$passwd_readable" != true ]; then
    collection_error='PASSWD_FILE_UNREADABLE'
fi

# The target set and compliant shells are taken directly from KISA U-11.
# No account names or passwd fields are emitted.
if [ -z "$collection_error" ]; then
    if counts=$(awk -F: '
        BEGIN {
            split("daemon bin sys adm listen nobody nobody4 noaccess diag operator games gopher", names, " ")
            for (i in names) target[names[i]]=1
            valid=existing=compliant=violating=malformed=0
        }
        {
            if (NF != 7 || $1 == "" || $3 !~ /^[0-9]+$/ || $4 !~ /^[0-9]+$/ || seen[$1]++) {
                malformed++
                next
            }
            valid++
            if (!($1 in target)) next
            existing++
            if ($7 == "/bin/false" || $7 == "/sbin/nologin") compliant++
            else violating++
        }
        END { print valid, existing, compliant, violating, malformed }
    ' "$passwd_path" 2>/dev/null); then
        set -- $counts
        if [ "$#" -eq 5 ]; then
            valid_entry_count=$1; existing_target_count=$2
            compliant_shell_count=$3; violating_target_count=$4
            malformed_entry_count=$5
            missing_target_count=$((target_account_definition_count - existing_target_count))
            nonstandard_shell_count=$violating_target_count
        else
            collection_error='PASSWD_FILE_PARSE_ERROR'
        fi
    else
        collection_error='PASSWD_FILE_READ_ERROR'
    fi
fi

if [ -z "$collection_error" ] && { [ "$valid_entry_count" -eq 0 ] || [ "$malformed_entry_count" -gt 0 ] || [ "$missing_target_count" -lt 0 ]; }; then
    collection_error='PASSWD_FILE_PARSE_ERROR'
fi

if [ -n "$collection_error" ]; then
    status_json='"UNCHECKABLE"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U11_COLLECTION_FAILED'
    decision_reason='The local passwd shell assignments could not be read or parsed completely'
    error_json=$(printf '{"code":'; os_guard_json_quote "$collection_error"; printf ',"message":"Local account shell collection or parsing failed"}')
elif [ "$violating_target_count" -gt 0 ]; then
    status_json='"VULNERABLE"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U11_LOGIN_SHELL_ASSIGNED'
    decision_reason='At least one existing KISA target account is not assigned /bin/false or /sbin/nologin'
else
    status_json='"GOOD"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U11_TARGET_SHELLS_RESTRICTED'
    decision_reason='Every existing KISA target account uses /bin/false or /sbin/nologin'
fi

printf '{"item_id":"U-11","status":%s,"review_state":"%s",' "$status_json" "$review_state"
printf '"current_value":{"passwd_file_present":%s,"passwd_file_readable":%s,' "$passwd_present" "$passwd_readable"
printf '"valid_entry_count":%s,"target_account_definition_count":%s,' "$valid_entry_count" "$target_account_definition_count"
printf '"existing_target_count":%s,"compliant_shell_count":%s,' "$existing_target_count" "$compliant_shell_count"
printf '"violating_target_count":%s,"missing_target_count":%s,' "$violating_target_count" "$missing_target_count"
printf '"nonstandard_shell_count":%s,"malformed_entry_count":%s},' "$nonstandard_shell_count" "$malformed_entry_count"
printf '"evidence":{"item_id":"U-11","collection_method":"Check only KISA-defined local account shell fields against exact false and nologin paths without exporting identifiers",'
printf '"configuration_paths":["/etc/passwd"],"reason_code":'; os_guard_json_quote "$reason_code"
printf ',"os":{"distro":'; os_guard_json_quote "$distro"; printf ',"version_id":'; os_guard_json_quote "$version_id"
printf '},"observed_at":'; os_guard_json_quote "$observed_at"; printf ',"module_version":'; os_guard_json_quote "$module_version"
printf ',"decision_reason":'; os_guard_json_quote "$decision_reason"
printf '},"error":%s}\n' "$error_json"
exit 0
