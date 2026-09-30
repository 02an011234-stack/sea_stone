#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=../lib/common.sh
. "$SCRIPT_DIR/../lib/common.sh"

distro=${OS_GUARD_DISTRO:-unknown}
version_id=${OS_GUARD_VERSION_ID:-unknown}
module_version=${OS_GUARD_MODULE_VERSION:-unknown}
observed_at=$(os_guard_utc_now)

login_defs='/etc/login.defs'
pwquality_main='/etc/security/pwquality.conf'
pwquality_dir='/etc/security/pwquality.conf.d'
pwhistory_conf='/etc/security/pwhistory.conf'

case "$distro" in
    rocky)
        pam_primary='/etc/pam.d/system-auth'
        pam_secondary='/etc/pam.d/password-auth'
        ;;
    ubuntu)
        pam_primary='/etc/pam.d/common-password'
        pam_secondary=''
        ;;
    *)
        pam_primary=''
        pam_secondary=''
        ;;
esac

json_nullable_string() {
    if [ -n "$1" ]; then
        os_guard_json_quote "$1"
    else
        printf 'null'
    fi
}

json_nullable_number() {
    if [ -n "$1" ] && printf '%s\n' "$1" | awk 'BEGIN { valid = 0 } /^-?[0-9]+$/ { valid = 1 } END { exit valid ? 0 : 1 }'; then
        printf '%s' "$1"
    else
        printf 'null'
    fi
}

json_nullable_boolean() {
    case "$1" in
        true|false) printf '%s' "$1" ;;
        *) printf 'null' ;;
    esac
}

is_integer() {
    printf '%s\n' "$1" | awk 'BEGIN { valid = 0 } /^-?[0-9]+$/ { valid = 1 } END { exit valid ? 0 : 1 }'
}

append_line() {
    if [ -z "$policy_messages" ]; then
        policy_messages=$1
    else
        policy_messages="$policy_messages
$1"
    fi
}

append_pending() {
    if [ -z "$pending_messages" ]; then
        pending_messages=$1
    else
        pending_messages="$pending_messages
$1"
    fi
}

get_config_setting() (
    wanted=$1
    file_list=$2
    result=''
    old_ifs=$IFS
    IFS='
'
    for config_file in $file_list; do
        IFS=$old_ifs
        candidate=$(awk -v wanted="$wanted" '
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
        ' "$config_file" 2>/dev/null)
        if [ -n "$candidate" ]; then
            result="$candidate|$config_file"
        fi
        IFS='
'
    done
    IFS=$old_ifs
    printf '%s' "$result"
)

config_has_flag() (
    wanted=$1
    file_list=$2
    old_ifs=$IFS
    IFS='
'
    found=''
    for config_file in $file_list; do
        IFS=$old_ifs
        if awk -v wanted="$wanted" '
            /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
            {
                line = $0
                sub(/[[:space:]]*#.*/, "", line)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
                split(line, fields, /[[:space:]=]+/)
                if (tolower(fields[1]) == wanted) present = 1
            }
            END { exit present ? 0 : 1 }
        ' "$config_file" 2>/dev/null; then
            found=$config_file
        fi
        IFS='
'
    done
    IFS=$old_ifs
    printf '%s' "$found"
)

get_login_setting() {
    wanted=$1
    awk -v wanted="$wanted" '
        /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
        toupper($1) == wanted { value = $2 }
        END { if (value != "") print value }
    ' "$login_defs" 2>/dev/null
}

get_pam_records() {
    module_name=$1
    awk -v module_name="$module_name" '
        /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
        tolower($1) != "password" { next }
        {
            for (field = 2; field <= NF; field++) {
                module = $field
                sub(/^.*\//, "", module)
                if (tolower(module) == module_name ".so") {
                    line = $0
                    gsub(/[[:space:]]+/, " ", line)
                    sub(/^ /, "", line)
                    sub(/ $/, "", line)
                    control = field > 2 ? $(field - 1) : ""
                    print NR "|" control "|" line
                    break
                }
            }
        }
    ' "$pam_primary" 2>/dev/null
}

get_pam_argument() (
    pam_line=$1
    module_name=$2
    wanted=$3
    after_module=0
    for token in $pam_line; do
        module_token=${token##*/}
        if [ "$after_module" -eq 0 ] && [ "$module_token" = "$module_name.so" ]; then
            after_module=1
            continue
        fi
        if [ "$after_module" -eq 1 ]; then
            case "$token" in
                "$wanted"=*) printf '%s' "${token#*=}"; exit ;;
            esac
        fi
    done
)

pam_has_argument() (
    pam_line=$1
    module_name=$2
    wanted=$3
    after_module=0
    for token in $pam_line; do
        module_token=${token##*/}
        if [ "$after_module" -eq 0 ] && [ "$module_token" = "$module_name.so" ]; then
            after_module=1
            continue
        fi
        if [ "$after_module" -eq 1 ] && [ "$token" = "$wanted" ]; then
            exit 0
        fi
    done
    exit 1
)

collection_error=''
policy_messages=''
pending_messages=''

if [ -z "$pam_primary" ]; then
    collection_error='UNSUPPORTED_OS_CONFIGURATION'
fi

pwquality_files=''
if [ -d "$pwquality_dir" ] && [ ! -r "$pwquality_dir" ]; then
    collection_error='POLICY_DIRECTORY_UNREADABLE'
fi
for policy_file in "$pwquality_dir"/*.conf; do
    [ -e "$policy_file" ] || continue
    if [ ! -r "$policy_file" ]; then
        collection_error='POLICY_FILE_UNREADABLE'
        continue
    fi
    if [ -z "$pwquality_files" ]; then
        pwquality_files=$policy_file
    else
        pwquality_files="$pwquality_files
$policy_file"
    fi
done
if [ -e "$pwquality_main" ]; then
    if [ ! -r "$pwquality_main" ]; then
        collection_error='POLICY_FILE_UNREADABLE'
    elif [ -z "$pwquality_files" ]; then
        pwquality_files=$pwquality_main
    else
        pwquality_files="$pwquality_files
$pwquality_main"
    fi
fi

if [ -e "$login_defs" ] && [ ! -r "$login_defs" ]; then
    collection_error='LOGIN_DEFS_UNREADABLE'
fi
if [ -e "$pwhistory_conf" ] && [ ! -r "$pwhistory_conf" ]; then
    collection_error='POLICY_FILE_UNREADABLE'
fi
if [ -n "$pam_primary" ] && [ -e "$pam_primary" ] && [ ! -r "$pam_primary" ]; then
    collection_error='PAM_CONFIGURATION_UNREADABLE'
fi

pass_min_days=''
pass_max_days=''
if [ -r "$login_defs" ]; then
    pass_min_days=$(get_login_setting PASS_MIN_DAYS)
    pass_max_days=$(get_login_setting PASS_MAX_DAYS)
fi

minlen_pair=$(get_config_setting minlen "$pwquality_files")
dcredit_pair=$(get_config_setting dcredit "$pwquality_files")
ucredit_pair=$(get_config_setting ucredit "$pwquality_files")
lcredit_pair=$(get_config_setting lcredit "$pwquality_files")
ocredit_pair=$(get_config_setting ocredit "$pwquality_files")

minlen=${minlen_pair%%|*}; minlen_source=${minlen_pair#*|}
dcredit=${dcredit_pair%%|*}; dcredit_source=${dcredit_pair#*|}
ucredit=${ucredit_pair%%|*}; ucredit_source=${ucredit_pair#*|}
lcredit=${lcredit_pair%%|*}; lcredit_source=${lcredit_pair#*|}
ocredit=${ocredit_pair%%|*}; ocredit_source=${ocredit_pair#*|}
[ "$minlen_pair" = "$minlen" ] && minlen_source=''
[ "$dcredit_pair" = "$dcredit" ] && dcredit_source=''
[ "$ucredit_pair" = "$ucredit" ] && ucredit_source=''
[ "$lcredit_pair" = "$lcredit" ] && lcredit_source=''
[ "$ocredit_pair" = "$ocredit" ] && ocredit_source=''

pwquality_root_source=$(config_has_flag enforce_for_root "$pwquality_files")
pwquality_root=false
[ -n "$pwquality_root_source" ] && pwquality_root=true

pwhistory_files=''
if [ -r "$pwhistory_conf" ]; then
    pwhistory_files=$pwhistory_conf
fi
remember_pair=$(get_config_setting remember "$pwhistory_files")
remember=${remember_pair%%|*}; remember_source=${remember_pair#*|}
[ "$remember_pair" = "$remember" ] && remember_source=''
pwhistory_root_source=$(config_has_flag enforce_for_root "$pwhistory_files")
pwhistory_root=false
[ -n "$pwhistory_root_source" ] && pwhistory_root=true

pwquality_records=''
pwhistory_records=''
pam_unix_records=''
pam_complex=false
if [ -r "$pam_primary" ]; then
    pwquality_records=$(get_pam_records pam_pwquality)
    pwhistory_records=$(get_pam_records pam_pwhistory)
    pam_unix_records=$(get_pam_records pam_unix)
    if awk '
        /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
        tolower($1) == "@include" { complex = 1 }
        tolower($1) == "password" && (tolower($2) == "include" || tolower($2) == "substack") { complex = 1 }
        /\\[[:space:]]*$/ { complex = 1 }
        END { exit complex ? 0 : 1 }
    ' "$pam_primary" 2>/dev/null; then
        pam_complex=true
        append_pending 'PAM_INCLUDE_OR_MULTILINE_REQUIRES_REVIEW'
    fi
fi

record_count() {
    if [ -z "$1" ]; then
        printf '0'
    else
        printf '%s\n' "$1" | awk 'NF { count++ } END { print count + 0 }'
    fi
}

pwquality_count=$(record_count "$pwquality_records")
pwhistory_count=$(record_count "$pwhistory_records")
pam_unix_count=$(record_count "$pam_unix_records")

if [ "$pwquality_count" -gt 1 ] || [ "$pwhistory_count" -gt 1 ] || [ "$pam_unix_count" -gt 1 ]; then
    pam_complex=true
    append_pending 'MULTIPLE_PAM_MODULES_REQUIRE_REVIEW'
fi

pwquality_record=$(printf '%s\n' "$pwquality_records" | awk 'NF { print; exit }')
pwhistory_record=$(printf '%s\n' "$pwhistory_records" | awk 'NF { print; exit }')
pam_unix_record=$(printf '%s\n' "$pam_unix_records" | awk 'NF { print; exit }')

pwquality_line_no=${pwquality_record%%|*}
pwquality_rest=${pwquality_record#*|}
pwquality_control=${pwquality_rest%%|*}
pwquality_line=${pwquality_rest#*|}
[ "$pwquality_record" = "$pwquality_line_no" ] && pwquality_line_no=''

pwhistory_line_no=${pwhistory_record%%|*}
pwhistory_rest=${pwhistory_record#*|}
pwhistory_control=${pwhistory_rest%%|*}
pwhistory_line=${pwhistory_rest#*|}
[ "$pwhistory_record" = "$pwhistory_line_no" ] && pwhistory_line_no=''

pam_unix_line_no=${pam_unix_record%%|*}
[ "$pam_unix_record" = "$pam_unix_line_no" ] && pam_unix_line_no=''

if [ "$pwquality_count" -eq 1 ]; then
    for setting in minlen dcredit ucredit lcredit ocredit; do
        argument=$(get_pam_argument "$pwquality_line" pam_pwquality "$setting")
        [ -n "$argument" ] || continue
        case "$setting" in
            minlen) minlen=$argument; minlen_source=$pam_primary ;;
            dcredit) dcredit=$argument; dcredit_source=$pam_primary ;;
            ucredit) ucredit=$argument; ucredit_source=$pam_primary ;;
            lcredit) lcredit=$argument; lcredit_source=$pam_primary ;;
            ocredit) ocredit=$argument; ocredit_source=$pam_primary ;;
        esac
    done
    if pam_has_argument "$pwquality_line" pam_pwquality enforce_for_root; then
        pwquality_root=true
        pwquality_root_source=$pam_primary
    fi
    alternate_conf=$(get_pam_argument "$pwquality_line" pam_pwquality conf)
    if [ -n "$alternate_conf" ]; then
        pam_complex=true
        append_pending 'ALTERNATE_PWQUALITY_CONFIG_REQUIRES_REVIEW'
    fi
    case "$pwquality_control" in
        required|requisite) ;;
        *) pam_complex=true; append_pending 'PWQUALITY_PAM_CONTROL_REQUIRES_REVIEW' ;;
    esac
fi

if [ "$pwhistory_count" -eq 1 ]; then
    argument=$(get_pam_argument "$pwhistory_line" pam_pwhistory remember)
    if [ -n "$argument" ]; then
        remember=$argument
        remember_source=$pam_primary
    fi
    if pam_has_argument "$pwhistory_line" pam_pwhistory enforce_for_root; then
        pwhistory_root=true
        pwhistory_root_source=$pam_primary
    fi
    alternate_conf=$(get_pam_argument "$pwhistory_line" pam_pwhistory conf)
    if [ -n "$alternate_conf" ]; then
        pam_complex=true
        append_pending 'ALTERNATE_PWHISTORY_CONFIG_REQUIRES_REVIEW'
    fi
    case "$pwhistory_control" in
        required|requisite) ;;
        *) pam_complex=true; append_pending 'PWHISTORY_PAM_CONTROL_REQUIRES_REVIEW' ;;
    esac
fi

for numeric_value in "$pass_min_days" "$pass_max_days" "$minlen" "$dcredit" "$ucredit" "$lcredit" "$ocredit" "$remember"; do
    if [ -n "$numeric_value" ] && ! is_integer "$numeric_value"; then
        collection_error='POLICY_VALUE_PARSE_ERROR'
    fi
done

if [ -z "$pass_min_days" ]; then
    append_line 'PASS_MIN_DAYS_BELOW_1'
elif is_integer "$pass_min_days" && [ "$pass_min_days" -lt 1 ]; then
    append_line 'PASS_MIN_DAYS_BELOW_1'
fi
if [ -z "$pass_max_days" ]; then
    append_line 'PASS_MAX_DAYS_OUTSIDE_1_TO_90'
elif is_integer "$pass_max_days" && { [ "$pass_max_days" -lt 1 ] || [ "$pass_max_days" -gt 90 ]; }; then
    append_line 'PASS_MAX_DAYS_OUTSIDE_1_TO_90'
fi

if [ "$pam_complex" = 'false' ]; then
    if [ "$pwquality_count" -eq 0 ]; then append_line 'PAM_PWQUALITY_NOT_APPLIED'; fi
    if [ "$pwhistory_count" -eq 0 ]; then append_line 'PAM_PWHISTORY_NOT_APPLIED'; fi
    if [ "$pam_unix_count" -eq 0 ]; then append_line 'PAM_UNIX_NOT_FOUND'; fi

    if [ -z "$minlen" ]; then
        append_line 'MIN_LENGTH_BELOW_8'
    elif is_integer "$minlen" && [ "$minlen" -lt 8 ]; then
        append_line 'MIN_LENGTH_BELOW_8'
    fi
    if [ "$dcredit" != '-1' ]; then append_line 'DIGIT_REQUIREMENT_NOT_MINUS_1'; fi
    if [ "$ucredit" != '-1' ]; then append_line 'UPPERCASE_REQUIREMENT_NOT_MINUS_1'; fi
    if [ "$lcredit" != '-1' ]; then append_line 'LOWERCASE_REQUIREMENT_NOT_MINUS_1'; fi
    if [ "$ocredit" != '-1' ]; then append_line 'SPECIAL_CHARACTER_REQUIREMENT_NOT_MINUS_1'; fi
    if [ -z "$remember" ]; then
        append_line 'PASSWORD_HISTORY_BELOW_4'
    elif is_integer "$remember" && [ "$remember" -lt 4 ]; then
        append_line 'PASSWORD_HISTORY_BELOW_4'
    fi
    if [ "$pwquality_root" != 'true' ]; then append_line 'PWQUALITY_NOT_ENFORCED_FOR_ROOT'; fi
    if [ "$pwhistory_root" != 'true' ]; then append_line 'PWHISTORY_NOT_ENFORCED_FOR_ROOT'; fi

    if [ -n "$pwquality_line_no" ] && [ -n "$pam_unix_line_no" ] && \
       [ "$pwquality_line_no" -ge "$pam_unix_line_no" ]; then
        append_line 'PAM_PWQUALITY_NOT_BEFORE_PAM_UNIX'
    fi
    if [ -n "$pwhistory_line_no" ] && [ -n "$pam_unix_line_no" ] && \
       [ "$pwhistory_line_no" -ge "$pam_unix_line_no" ]; then
        append_line 'PAM_PWHISTORY_NOT_BEFORE_PAM_UNIX'
    fi
fi

status_json='"GOOD"'
review_state='NOT_REQUIRED'
reason_code='KISA_U02_COMPLIANT'
decision_reason='All automatically verifiable KISA U-02 password management requirements are satisfied'
error_json='null'

if [ -n "$collection_error" ]; then
    status_json='"UNCHECKABLE"'
    reason_code='KISA_U02_COLLECTION_FAILED'
    decision_reason='Required password policy configuration could not be read or parsed safely'
    error_json=$(
        printf '{"code":'
        os_guard_json_quote "$collection_error"
        printf ',"message":"Password policy collection or parsing failed"}'
    )
elif [ -n "$policy_messages" ]; then
    status_json='"VULNERABLE"'
    reason_code='KISA_U02_POLICY_INSUFFICIENT'
    decision_reason='One or more required KISA U-02 password policy settings are missing or insufficient'
elif [ -n "$pending_messages" ]; then
    status_json='null'
    review_state='PENDING'
    reason_code='KISA_U02_EFFECTIVE_POLICY_REVIEW_REQUIRED'
    decision_reason='The effective password policy cannot be determined safely from the detected PAM structure'
fi

checked_paths="$login_defs
$pwquality_main
$pwquality_dir/*.conf
$pwhistory_conf"
if [ -n "$pam_primary" ]; then checked_paths="$checked_paths
$pam_primary"; fi
if [ -n "$pam_secondary" ]; then checked_paths="$checked_paths
$pam_secondary"; fi

paths_json=$(printf '%s\n' "$checked_paths" | os_guard_json_array_from_lines)
failures_json=$(printf '%s\n' "$policy_messages" | os_guard_json_array_from_lines)
pending_json=$(printf '%s\n' "$pending_messages" | os_guard_json_array_from_lines)

printf '{'
printf '"item_id":"U-02",'
printf '"status":%s,' "$status_json"
printf '"review_state":"%s",' "$review_state"
printf '"current_value":{'
printf '"min_length":{"value":'; json_nullable_number "$minlen"; printf ',"source":'; json_nullable_string "$minlen_source"; printf '},'
printf '"character_requirements":{'
printf '"dcredit":'; json_nullable_number "$dcredit"
printf ',"ucredit":'; json_nullable_number "$ucredit"
printf ',"lcredit":'; json_nullable_number "$lcredit"
printf ',"ocredit":'; json_nullable_number "$ocredit"
printf '},"pass_min_days":'; json_nullable_number "$pass_min_days"
printf ',"pass_max_days":'; json_nullable_number "$pass_max_days"
printf ',"password_history":{"remember":'; json_nullable_number "$remember"
printf ',"source":'; json_nullable_string "$remember_source"
printf '},"root_enforcement":{"pwquality":%s,"pwhistory":%s},' "$pwquality_root" "$pwhistory_root"
printf '"pam":{'
printf '"configuration_path":'; json_nullable_string "$pam_primary"
printf ',"pam_pwquality_present":'; [ "$pwquality_count" -gt 0 ] && printf 'true' || printf 'false'
printf ',"pam_pwhistory_present":'; [ "$pwhistory_count" -gt 0 ] && printf 'true' || printf 'false'
printf ',"pam_unix_present":'; [ "$pam_unix_count" -gt 0 ] && printf 'true' || printf 'false'
printf ',"pwquality_before_unix":'
if [ -n "$pwquality_line_no" ] && [ -n "$pam_unix_line_no" ]; then [ "$pwquality_line_no" -lt "$pam_unix_line_no" ] && printf 'true' || printf 'false'; else printf 'null'; fi
printf ',"pwhistory_before_unix":'
if [ -n "$pwhistory_line_no" ] && [ -n "$pam_unix_line_no" ]; then [ "$pwhistory_line_no" -lt "$pam_unix_line_no" ] && printf 'true' || printf 'false'; else printf 'null'; fi
printf ',"complex_structure":%s' "$pam_complex"
printf '}},'
printf '"evidence":{'
printf '"item_id":"U-02",'
printf '"collection_method":"Read login.defs, resolve libpwquality and pwhistory configuration precedence, and inspect the active PAM password stack",'
printf '"configuration_paths":%s,' "$paths_json"
printf '"effective_value_sources":{'
printf '"minlen":'; json_nullable_string "$minlen_source"
printf ',"dcredit":'; json_nullable_string "$dcredit_source"
printf ',"ucredit":'; json_nullable_string "$ucredit_source"
printf ',"lcredit":'; json_nullable_string "$lcredit_source"
printf ',"ocredit":'; json_nullable_string "$ocredit_source"
printf ',"remember":'; json_nullable_string "$remember_source"
printf ',"pwquality_root":'; json_nullable_string "$pwquality_root_source"
printf ',"pwhistory_root":'; json_nullable_string "$pwhistory_root_source"
printf '},"criteria_failures":%s,' "$failures_json"
printf '"review_reasons":%s,' "$pending_json"
printf '"reason_code":'; os_guard_json_quote "$reason_code"
printf ',"pass_min_days_criterion":{"value":1,"basis":"KISA action text, final Red Hat step, Debian step, and recommendation table; Red Hat step 1 contains 0"},'
printf '"os":{"distro":'; os_guard_json_quote "$distro"
printf ',"version_id":'; os_guard_json_quote "$version_id"
printf '},"observed_at":'; os_guard_json_quote "$observed_at"
printf ',"module_version":'; os_guard_json_quote "$module_version"
printf ',"decision_reason":'; os_guard_json_quote "$decision_reason"
printf '},"error":%s}\n' "$error_json"

exit 0
