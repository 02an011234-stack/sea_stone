#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=../lib/common.sh
. "$SCRIPT_DIR/../lib/common.sh"

distro=${OS_GUARD_DISTRO:-unknown}
version_id=${OS_GUARD_VERSION_ID:-unknown}
module_version=${OS_GUARD_MODULE_VERSION:-unknown}
observed_at=$(os_guard_utc_now)

faillock_conf='/etc/security/faillock.conf'

case "$distro" in
    rocky)
        pam_paths='/etc/pam.d/system-auth
/etc/pam.d/password-auth'
        primary_auth_path='/etc/pam.d/system-auth'
        secondary_auth_path='/etc/pam.d/password-auth'
        account_path='/etc/pam.d/system-auth'
        ;;
    ubuntu)
        pam_paths='/etc/pam.d/common-auth
/etc/pam.d/common-account'
        primary_auth_path='/etc/pam.d/common-auth'
        secondary_auth_path=''
        account_path='/etc/pam.d/common-account'
        ;;
    *)
        pam_paths=''
        primary_auth_path=''
        secondary_auth_path=''
        account_path=''
        ;;
esac

json_nullable_string() {
    if [ -n "$1" ]; then
        os_guard_json_quote "$1"
    else
        printf 'null'
    fi
}

is_integer() {
    printf '%s\n' "$1" | awk 'BEGIN { valid = 0 } /^-?[0-9]+$/ { valid = 1 } END { exit valid ? 0 : 1 }'
}

json_nullable_number() {
    if [ -n "$1" ] && is_integer "$1"; then
        printf '%s' "$1"
    else
        printf 'null'
    fi
}

append_failure() {
    if [ -z "$failure_messages" ]; then
        failure_messages=$1
    else
        failure_messages="$failure_messages
$1"
    fi
}

append_pending() {
    case "
$pending_messages
" in
        *"
$1
"*) return ;;
    esac
    if [ -z "$pending_messages" ]; then
        pending_messages=$1
    else
        pending_messages="$pending_messages
$1"
    fi
}

get_faillock_setting() {
    wanted=$1
    awk -v wanted="$wanted" '
        /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
        {
            line = $0
            sub(/[[:space:]]*#.*/, "", line)
            equals = index(line, "=")
            if (!equals) next
            key = substr(line, 1, equals - 1)
            value = substr(line, equals + 1)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            if (tolower(key) == wanted) found = value
        }
        END { if (found != "") print found }
    ' "$faillock_conf" 2>/dev/null
}

collect_pam_records() (
    wanted=$1
    file_list=$2
    old_ifs=$IFS
    IFS='
'
    for pam_file in $file_list; do
        IFS=$old_ifs
        [ -r "$pam_file" ] || { IFS='
'; continue; }
        awk -v source="$pam_file" -v wanted="$wanted" '
            /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
            tolower($1) != "auth" && tolower($1) != "account" { next }
            {
                for (field = 2; field <= NF; field++) {
                    module = $field
                    sub(/^.*\//, "", module)
                    module = tolower(module)
                    matches = 0
                    if (wanted == "faillock" && module == "pam_faillock.so") matches = 1
                    if (wanted == "tally" && (module == "pam_tally.so" || module == "pam_tally2.so")) matches = 1
                    if (!matches) continue

                    deny = ""
                    alternate_conf = ""
                    actions = ""
                    for (arg = field + 1; arg <= NF; arg++) {
                        if ($arg ~ /^deny=/) { deny = $arg; sub(/^deny=/, "", deny) }
                        if ($arg ~ /^conf=/) { alternate_conf = $arg; sub(/^conf=/, "", alternate_conf) }
                        if ($arg == "preauth" || $arg == "authfail" || $arg == "authsucc") {
                            if (actions != "") actions = actions ","
                            actions = actions $arg
                        }
                    }
                    control = field > 2 ? $(field - 1) : ""
                    print source "|" tolower($1) "|" NR "|" module "|" control "|" deny "|" alternate_conf "|" actions
                    break
                }
            }
        ' "$pam_file" 2>/dev/null
        IFS='
'
    done
    IFS=$old_ifs
)

path_has_record() {
    records=$1
    wanted_path=$2
    wanted_type=$3
    printf '%s\n' "$records" | awk -F'|' -v path="$wanted_path" -v type="$wanted_type" '
        $1 == path && $2 == type { found = 1 }
        END { exit found ? 0 : 1 }
    '
}

record_count() {
    if [ -z "$1" ]; then
        printf '0'
    else
        printf '%s\n' "$1" | awk 'NF { count++ } END { print count + 0 }'
    fi
}

failure_messages=''
pending_messages=''
collection_error=''

if [ -z "$pam_paths" ]; then
    collection_error='UNSUPPORTED_OS_CONFIGURATION'
fi
if [ -e "$faillock_conf" ] && [ ! -r "$faillock_conf" ]; then
    collection_error='FAILLOCK_CONFIGURATION_UNREADABLE'
fi

old_ifs=$IFS
IFS='
'
for pam_file in $pam_paths; do
    IFS=$old_ifs
    if [ -e "$pam_file" ] && [ ! -r "$pam_file" ]; then
        collection_error='PAM_CONFIGURATION_UNREADABLE'
    fi
    IFS='
'
done
IFS=$old_ifs

faillock_deny=''
unlock_time=''
if [ -r "$faillock_conf" ]; then
    faillock_deny=$(get_faillock_setting deny)
    unlock_time=$(get_faillock_setting unlock_time)
fi
if [ -n "$faillock_deny" ] && ! is_integer "$faillock_deny"; then
    collection_error='DENY_VALUE_PARSE_ERROR'
fi
if [ -n "$unlock_time" ] && ! is_integer "$unlock_time"; then
    unlock_time=''
fi

pam_complex=false
old_ifs=$IFS
IFS='
'
for pam_file in $pam_paths; do
    IFS=$old_ifs
    [ -r "$pam_file" ] || { IFS='
'; continue; }
    if awk '
        /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
        tolower($1) == "@include" { complex = 1 }
        (tolower($1) == "auth" || tolower($1) == "account") &&
            (tolower($2) == "include" || tolower($2) == "substack") { complex = 1 }
        /\\[[:space:]]*$/ { complex = 1 }
        END { exit complex ? 0 : 1 }
    ' "$pam_file" 2>/dev/null; then
        pam_complex=true
        append_pending 'PAM_INCLUDE_OR_MULTILINE_REQUIRES_REVIEW'
    fi
    IFS='
'
done
IFS=$old_ifs

faillock_records=$(collect_pam_records faillock "$pam_paths")
tally_records=$(collect_pam_records tally "$pam_paths")
faillock_count=$(record_count "$faillock_records")
tally_count=$(record_count "$tally_records")

lockout_module=''
policy_active='false'
if [ "$faillock_count" -gt 0 ] && [ "$tally_count" -gt 0 ]; then
    lockout_module='multiple'
    policy_active='unknown'
    append_pending 'MULTIPLE_LOCKOUT_MODULE_TYPES_REQUIRE_REVIEW'
elif [ "$faillock_count" -gt 0 ]; then
    lockout_module='pam_faillock'
elif [ "$tally_count" -gt 0 ]; then
    lockout_module='pam_tally_or_tally2'
fi

authselect_state='not_applicable'
authselect_profile=''
with_faillock='unknown'
if [ "$distro" = 'rocky' ]; then
    authselect_state='unavailable'
    if authselect_bin=$(command -v authselect 2>/dev/null) && [ -x "$authselect_bin" ]; then
        if authselect_output=$("$authselect_bin" current 2>/dev/null); then
            authselect_state='configured'
            authselect_profile=$(printf '%s\n' "$authselect_output" | awk -F':' '
                /^[[:space:]]*Profile ID[[:space:]]*:/ {
                    value = $2
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                    print value
                    exit
                }
            ')
            if printf '%s\n' "$authselect_output" | awk '
                /^[[:space:]]*-[[:space:]]*with-faillock[[:space:]]*$/ { found = 1 }
                END { exit found ? 0 : 1 }
            '; then
                with_faillock=true
            else
                with_faillock=false
            fi
        else
            authselect_state='not_configured'
            with_faillock=false
        fi
    fi
fi

if [ "$lockout_module" = 'pam_faillock' ] && [ "$pam_complex" = 'false' ]; then
    if [ "$distro" = 'rocky' ]; then
        if path_has_record "$faillock_records" "$primary_auth_path" auth && \
           path_has_record "$faillock_records" "$secondary_auth_path" auth; then
            policy_active=true
        fi
        if [ "$with_faillock" = 'true' ] && [ "$policy_active" != 'true' ]; then
            policy_active='unknown'
            append_pending 'AUTHSELECT_AND_PAM_CONFIGURATION_MISMATCH'
        fi
    elif [ "$distro" = 'ubuntu' ]; then
        if path_has_record "$faillock_records" "$primary_auth_path" auth && \
           path_has_record "$faillock_records" "$account_path" account; then
            policy_active=true
        fi
    fi
elif [ "$lockout_module" = 'pam_tally_or_tally2' ] && [ "$pam_complex" = 'false' ]; then
    if printf '%s\n' "$tally_records" | awk -F'|' '$2 == "auth" { found = 1 } END { exit found ? 0 : 1 }' && \
       printf '%s\n' "$tally_records" | awk -F'|' '$2 == "account" { found = 1 } END { exit found ? 0 : 1 }'; then
        policy_active=true
    fi
fi

all_records=''
if [ "$lockout_module" = 'pam_faillock' ]; then
    all_records=$faillock_records
elif [ "$lockout_module" = 'pam_tally_or_tally2' ]; then
    all_records=$tally_records
fi

deny_observations=''
if [ -n "$all_records" ]; then
    old_ifs=$IFS
    IFS='
'
    for record in $all_records; do
        IFS=$old_ifs
        record_type=$(printf '%s' "$record" | awk -F'|' '{print $2}')
        record_source=$(printf '%s' "$record" | awk -F'|' '{print $1}')
        record_line=$(printf '%s' "$record" | awk -F'|' '{print $3}')
        record_deny=$(printf '%s' "$record" | awk -F'|' '{print $6}')
        alternate_conf=$(printf '%s' "$record" | awk -F'|' '{print $7}')

        if [ -n "$alternate_conf" ]; then
            append_pending 'ALTERNATE_FAILLOCK_CONFIG_REQUIRES_REVIEW'
        fi
        if [ "$record_type" != 'auth' ]; then
            IFS='
'
            continue
        fi
        if [ -z "$record_deny" ] && [ "$lockout_module" = 'pam_faillock' ]; then
            record_deny=$faillock_deny
            deny_source=$faillock_conf
        else
            deny_source="$record_source:$record_line"
        fi
        if [ -n "$record_deny" ]; then
            if ! is_integer "$record_deny"; then
                collection_error='DENY_VALUE_PARSE_ERROR'
            elif [ -z "$deny_observations" ]; then
                deny_observations="$record_deny|$deny_source"
            else
                deny_observations="$deny_observations
$record_deny|$deny_source"
            fi
        fi
        IFS='
'
    done
    IFS=$old_ifs
fi

unique_deny_values=$(printf '%s\n' "$deny_observations" | awk -F'|' 'NF && !seen[$1]++ { print $1 }')
unique_deny_count=$(record_count "$unique_deny_values")
effective_deny=''
if [ "$unique_deny_count" -eq 1 ]; then
    effective_deny=$(printf '%s\n' "$unique_deny_values" | awk 'NF { print; exit }')
elif [ "$unique_deny_count" -gt 1 ]; then
    append_pending 'CONFLICTING_EFFECTIVE_DENY_VALUES'
fi

if [ "$pam_complex" = 'false' ] && [ -z "$pending_messages" ]; then
    if [ -z "$lockout_module" ]; then
        append_failure 'LOCKOUT_MODULE_NOT_APPLIED'
    elif [ "$policy_active" != 'true' ]; then
        append_failure 'LOCKOUT_POLICY_NOT_ACTIVE'
    elif [ -z "$effective_deny" ]; then
        append_failure 'DENY_NOT_CONFIGURED'
    elif [ "$effective_deny" -lt 1 ]; then
        append_failure 'DENY_NOT_POSITIVE'
    elif [ "$effective_deny" -gt 10 ]; then
        append_failure 'DENY_EXCEEDS_10'
    fi
fi

status_json='"GOOD"'
review_state='NOT_REQUIRED'
reason_code='KISA_U03_COMPLIANT'
decision_reason='An active account lockout policy has an effective deny threshold between 1 and 10'
error_json='null'

if [ -n "$collection_error" ]; then
    status_json='"UNCHECKABLE"'
    reason_code='KISA_U03_COLLECTION_FAILED'
    decision_reason='The active account lockout policy could not be read or parsed safely'
    error_json=$(
        printf '{"code":'
        os_guard_json_quote "$collection_error"
        printf ',"message":"Account lockout policy collection or parsing failed"}'
    )
elif [ -n "$failure_messages" ]; then
    status_json='"VULNERABLE"'
    reason_code='KISA_U03_POLICY_INSUFFICIENT'
    decision_reason='The account lockout policy is inactive, missing, or has a threshold outside 1 through 10'
elif [ -n "$pending_messages" ]; then
    status_json='null'
    review_state='PENDING'
    reason_code='KISA_U03_EFFECTIVE_POLICY_REVIEW_REQUIRED'
    decision_reason='Multiple or indirect PAM policies prevent a safe determination of one effective lockout threshold'
fi

checked_paths=$faillock_conf
if [ -n "$pam_paths" ]; then checked_paths="$checked_paths
$pam_paths"; fi
paths_json=$(printf '%s\n' "$checked_paths" | os_guard_json_array_from_lines)
deny_sources=$(printf '%s\n' "$deny_observations" | awk -F'|' 'NF { print $2 }')
deny_sources_json=$(printf '%s\n' "$deny_sources" | os_guard_json_array_from_lines)
failures_json=$(printf '%s\n' "$failure_messages" | os_guard_json_array_from_lines)
pending_json=$(printf '%s\n' "$pending_messages" | os_guard_json_array_from_lines)

printf '{'
printf '"item_id":"U-03",'
printf '"status":%s,' "$status_json"
printf '"review_state":"%s",' "$review_state"
printf '"current_value":{'
printf '"lockout_module":'; json_nullable_string "$lockout_module"
printf ',"policy_active":'; case "$policy_active" in true|false) printf '%s' "$policy_active" ;; *) printf 'null' ;; esac
printf ',"effective_deny":'; json_nullable_number "$effective_deny"
printf ',"unlock_time":'; json_nullable_number "$unlock_time"
printf ',"pam":{'
printf '"configuration_paths":%s,' "$paths_json"
printf '"faillock_record_count":%s,' "$faillock_count"
printf '"tally_record_count":%s,' "$tally_count"
printf '"complex_structure":%s' "$pam_complex"
printf '},"authselect":{'
printf '"state":'; os_guard_json_quote "$authselect_state"
printf ',"profile_id":'; json_nullable_string "$authselect_profile"
printf ',"with_faillock":'; case "$with_faillock" in true|false) printf '%s' "$with_faillock" ;; *) printf 'null' ;; esac
printf '}},'
printf '"evidence":{'
printf '"item_id":"U-03",'
printf '"collection_method":"Read faillock configuration, inspect PAM auth/account stacks, and query Rocky authselect state without changing counters",'
printf '"configuration_paths":%s,' "$paths_json"
printf '"deny_sources":%s,' "$deny_sources_json"
printf '"criteria_failures":%s,' "$failures_json"
printf '"review_reasons":%s,' "$pending_json"
printf '"reason_code":'; os_guard_json_quote "$reason_code"
printf ',"unlock_time_used_for_judgment":false,'
printf '"os":{"distro":'; os_guard_json_quote "$distro"
printf ',"version_id":'; os_guard_json_quote "$version_id"
printf '},"observed_at":'; os_guard_json_quote "$observed_at"
printf ',"module_version":'; os_guard_json_quote "$module_version"
printf ',"decision_reason":'; os_guard_json_quote "$decision_reason"
printf '},"error":%s}\n' "$error_json"

exit 0
