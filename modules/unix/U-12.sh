#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/../lib/common.sh"

distro=${OS_GUARD_DISTRO:-unknown}
version_id=${OS_GUARD_VERSION_ID:-unknown}
module_version=${OS_GUARD_MODULE_VERSION:-unknown}
observed_at=$(os_guard_utc_now)
test_root=${OS_GUARD_TEST_ROOT:-}

profile_path="${test_root}/etc/profile"
profile_d_path="${test_root}/etc/profile.d"
csh_cshrc_path="${test_root}/etc/csh.cshrc"
csh_login_path="${test_root}/etc/csh.login"

status_json='null'
review_state='PENDING'
manual_review_required=true
collection_error=''
error_json='null'
reason_code='KISA_U12_TIMEOUT_ANALYSIS_PENDING'
decision_reason='The effective global session timeout has not been determined'

timeout_configured=false
effective_timeout_seconds=''
timeout_source=''
export_state='not_applicable'
duplicate_setting_count=0
conflict_detected=false
dynamic_setting_detected=false
checked_config_count=0
assignment_count=0

case "$distro" in
    rocky|ubuntu) ;;
    *) collection_error='UNSUPPORTED_OS_CONFIGURATION' ;;
esac

config_files=''
configuration_paths=''

append_config() {
    actual_path=$1
    evidence_path=${actual_path#"$test_root"}
    if [ -z "$config_files" ]; then
        config_files=$actual_path
        configuration_paths=$evidence_path
    else
        config_files="$config_files
$actual_path"
        configuration_paths="$configuration_paths
$evidence_path"
    fi
    checked_config_count=$((checked_config_count + 1))
}

if [ -z "$collection_error" ]; then
    if [ ! -e "$profile_path" ]; then
        collection_error='PROFILE_FILE_NOT_FOUND'
    elif [ ! -r "$profile_path" ]; then
        collection_error='PROFILE_FILE_UNREADABLE'
    else
        append_config "$profile_path"
    fi
fi

profile_d_active=false
if [ -z "$collection_error" ] && [ -r "$profile_path" ]; then
    if awk '
        /^[[:space:]]*#/ { next }
        /\/etc\/profile\.d/ { directory = 1 }
        /(^|[;[:space:]])(\.|source)[[:space:]].*\$\{?i\}?/ { sourced = 1 }
        END { exit directory && sourced ? 0 : 1 }
    ' "$profile_path" 2>/dev/null; then
        profile_d_active=true
    fi
fi

if [ -z "$collection_error" ] && [ "$profile_d_active" = true ] && [ -e "$profile_d_path" ]; then
    if [ ! -d "$profile_d_path" ] || [ ! -r "$profile_d_path" ]; then
        collection_error='PROFILE_DIRECTORY_UNREADABLE'
    else
        for config_path in "$profile_d_path"/*.sh; do
            [ -e "$config_path" ] || continue
            if [ ! -r "$config_path" ]; then
                collection_error='PROFILE_FRAGMENT_UNREADABLE'
                break
            fi
            append_config "$config_path"
        done
    fi
fi

if [ -z "$collection_error" ]; then
    for config_path in "$csh_cshrc_path" "$csh_login_path"; do
        [ -e "$config_path" ] || continue
        if [ ! -r "$config_path" ]; then
            collection_error='CSH_CONFIGURATION_UNREADABLE'
            break
        fi
        append_config "$config_path"
    done
fi

if [ -z "$collection_error" ]; then
    old_ifs=$IFS
    IFS='
'
    # The file list contains only fixed local global-profile paths discovered above.
    # shellcheck disable=SC2086
    analysis=$(awk '
        function trim(value) {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            return value
        }
        function display_path(value,    normalized_root) {
            normalized_root = ENVIRON["OS_GUARD_TEST_ROOT"]
            gsub(/\\/, "/", normalized_root)
            gsub(/\\/, "/", value)
            if (normalized_root != "" && index(value, normalized_root) == 1) {
                return substr(value, length(normalized_root) + 1)
            }
            return value
        }
        function remember_value(seconds, source, kind, exported,    key) {
            assignment_count++
            key = seconds ""
            if (!(key in seen_value)) {
                seen_value[key] = 1
                distinct_count++
            }
            if (kind == "TMOUT") {
                tmout_seen = 1
                if (exported) tmout_exported = 1
                tmout_seconds = seconds
                tmout_source = display_path(source)
                last_tmout_assignment_order = statement_order
            } else {
                csh_seen = 1
                csh_seconds = seconds
                csh_source = display_path(source)
                last_csh_assignment_order = statement_order
            }
            last_assignment_order = statement_order
        }
        function process_statement(raw, source,    statement, value, quoted, seconds) {
            statement_order++
            statement = trim(raw)
            if (statement == "" || statement ~ /^#/) return
            sub(/[[:space:]]+#.*/, "", statement)
            statement = trim(statement)
            if (statement == "") return

            if (statement ~ /^(if|case|for|while|until)[[:space:]]/) depth++
            if (statement ~ /^(fi|esac|done)([[:space:]]|$)/ && depth > 0) depth--

            if (statement ~ /^(\.|source)[[:space:]]+/) {
                if (statement !~ /\/etc\/profile\.d\// && statement !~ /\$\{?i\}?/ &&
                    statement !~ /\/etc\/bash\.bashrc([[:space:]]|$)/ &&
                    statement !~ /\/etc\/bashrc([[:space:]]|$)/) {
                    last_unknown_source_order = statement_order
                }
                return
            }

            if (statement ~ /^export[[:space:]]+TMOUT([[:space:]]|$)/ && statement !~ /^export[[:space:]]+TMOUT=/) {
                tmout_exported = 1
                return
            }
            if (statement ~ /^unset[[:space:]]+TMOUT([[:space:]]|$)/) {
                tmout_exported = 0
                remember_value(0, source, "TMOUT", 0)
                return
            }
            if (statement ~ /^unset[[:space:]]+autologout([[:space:]]|$)/) {
                remember_value(0, source, "autologout", 0)
                return
            }

            if (statement ~ /^(export[[:space:]]+)?TMOUT=/) {
                if (depth > 0) {
                    last_tmout_dynamic_order = statement_order
                    return
                }
                value = statement
                sub(/^export[[:space:]]+/, "", value)
                sub(/^TMOUT=/, "", value)
                value = trim(value)
                quoted = 0
                if ((value ~ /^"[0-9]+"$/) || (value ~ /^\047[0-9]+\047$/)) {
                    value = substr(value, 2, length(value) - 2)
                    quoted = 1
                }
                if (value ~ /^[0-9]+$/) {
                    remember_value(value + 0, source, "TMOUT", statement ~ /^export[[:space:]]+/)
                } else if (value == "") {
                    remember_value(0, source, "TMOUT", statement ~ /^export[[:space:]]+/)
                } else {
                    last_tmout_dynamic_order = statement_order
                }
                return
            }

            if (statement ~ /^set[[:space:]]+autologout[[:space:]]*=/) {
                if (depth > 0) {
                    last_csh_dynamic_order = statement_order
                    return
                }
                value = statement
                sub(/^set[[:space:]]+autologout[[:space:]]*=[[:space:]]*/, "", value)
                value = trim(value)
                if (value ~ /^[0-9]+$/) {
                    seconds = (value + 0) * 60
                    remember_value(seconds, source, "autologout", 0)
                } else {
                    last_csh_dynamic_order = statement_order
                }
                return
            }

            if (statement ~ /(^|[^[:alnum:]_])(TMOUT|autologout)([^[:alnum:]_]|$)/ &&
                statement !~ /^(readonly|typeset[[:space:]]+-r)[[:space:]]+TMOUT([[:space:]]|$)/) {
                if (statement ~ /TMOUT/) last_tmout_dynamic_order = statement_order
                if (statement ~ /autologout/) last_csh_dynamic_order = statement_order
            }
        }
        {
            line = $0
            count = split(line, statements, ";")
            for (index_part = 1; index_part <= count; index_part++) {
                process_statement(statements[index_part], FILENAME)
            }
        }
        END {
            assignment_count += 0
            if (last_tmout_dynamic_order > last_tmout_assignment_order) dynamic = 1
            if (last_csh_dynamic_order > last_csh_assignment_order) dynamic = 1
            if (last_unknown_source_order > last_assignment_order) dynamic = 1
            duplicate_count = assignment_count > 0 ? assignment_count - 1 : 0
            conflict = distinct_count > 1 ? 1 : 0
            configured = ((tmout_seen && tmout_seconds > 0) ||
                          (csh_seen && csh_seconds > 0)) ? 1 : 0
            unsafe_count = 0
            if (tmout_seen && (tmout_seconds <= 0 || tmout_seconds > 600)) unsafe_count++
            if (csh_seen && (csh_seconds <= 0 || csh_seconds > 600)) unsafe_count++
            if (tmout_seen && csh_seen) {
                if (tmout_seconds >= csh_seconds) {
                    effective_seconds = tmout_seconds
                    effective_source = tmout_source
                } else {
                    effective_seconds = csh_seconds
                    effective_source = csh_source
                }
            } else if (tmout_seen) {
                effective_seconds = tmout_seconds
                effective_source = tmout_source
            } else if (csh_seen) {
                effective_seconds = csh_seconds
                effective_source = csh_source
            }
            if (tmout_seen && csh_seen) export_state = tmout_exported ? "mixed" : "mixed_not_exported"
            else if (tmout_seen) export_state = tmout_exported ? "exported" : "not_exported"
            else export_state = "not_applicable"

            print "assignment_count=" assignment_count
            print "duplicate_setting_count=" duplicate_count
            print "conflict_detected=" (conflict ? "true" : "false")
            print "dynamic_setting_detected=" (dynamic ? "true" : "false")
            print "timeout_configured=" (configured ? "true" : "false")
            print "effective_timeout_seconds=" (assignment_count ? effective_seconds : "")
            print "timeout_source=" effective_source
            print "export_state=" export_state
            print "unsafe_count=" unsafe_count
        }
    ' $config_files 2>/dev/null)
    analysis_status=$?
    IFS=$old_ifs

    if [ "$analysis_status" -ne 0 ]; then
        collection_error='TIMEOUT_CONFIGURATION_PARSE_ERROR'
    else
        assignment_count=$(printf '%s\n' "$analysis" | awk -F= '$1 == "assignment_count" { print $2 }')
        duplicate_setting_count=$(printf '%s\n' "$analysis" | awk -F= '$1 == "duplicate_setting_count" { print $2 }')
        conflict_detected=$(printf '%s\n' "$analysis" | awk -F= '$1 == "conflict_detected" { print $2 }')
        dynamic_setting_detected=$(printf '%s\n' "$analysis" | awk -F= '$1 == "dynamic_setting_detected" { print $2 }')
        timeout_configured=$(printf '%s\n' "$analysis" | awk -F= '$1 == "timeout_configured" { print $2 }')
        effective_timeout_seconds=$(printf '%s\n' "$analysis" | awk -F= '$1 == "effective_timeout_seconds" { print $2 }')
        timeout_source=$(printf '%s\n' "$analysis" | awk -F= '$1 == "timeout_source" { sub(/^[^=]*=/, ""); print }')
        export_state=$(printf '%s\n' "$analysis" | awk -F= '$1 == "export_state" { print $2 }')
        unsafe_count=$(printf '%s\n' "$analysis" | awk -F= '$1 == "unsafe_count" { print $2 }')

        case "$assignment_count:$duplicate_setting_count:$conflict_detected:$dynamic_setting_detected:$timeout_configured:$unsafe_count" in
            *[!0-9:truefals]*) collection_error='TIMEOUT_CONFIGURATION_PARSE_ERROR' ;;
        esac
    fi
fi

if [ -n "$collection_error" ]; then
    status_json='"UNCHECKABLE"'
    review_state='NOT_REQUIRED'
    manual_review_required=false
    reason_code='KISA_U12_COLLECTION_FAILED'
    decision_reason='The global session timeout configuration could not be read or parsed safely'
    error_json=$(printf '{"code":'; os_guard_json_quote "$collection_error"; printf ',"message":"Session timeout collection or parsing failed"}')
elif [ "$dynamic_setting_detected" = true ]; then
    status_json='null'
    review_state='PENDING'
    manual_review_required=true
    reason_code='KISA_U12_EFFECTIVE_TIMEOUT_REVIEW_REQUIRED'
    decision_reason='Conditional, dynamic, or sourced configuration prevents a safe effective timeout determination'
elif [ "$timeout_configured" != true ] || [ "$assignment_count" -eq 0 ]; then
    status_json='"VULNERABLE"'
    review_state='NOT_REQUIRED'
    manual_review_required=false
    reason_code='KISA_U12_TIMEOUT_NOT_CONFIGURED'
    decision_reason='No active positive global session timeout is configured'
elif [ "$unsafe_count" -gt 0 ] || [ "$effective_timeout_seconds" -gt 600 ]; then
    status_json='"VULNERABLE"'
    review_state='NOT_REQUIRED'
    manual_review_required=false
    reason_code='KISA_U12_TIMEOUT_EXCEEDS_LIMIT'
    decision_reason='At least one effective global shell timeout is disabled or exceeds 600 seconds'
else
    status_json='"GOOD"'
    review_state='NOT_REQUIRED'
    manual_review_required=false
    reason_code='KISA_U12_TIMEOUT_WITHIN_LIMIT'
    decision_reason='The effective global session timeout is between 1 and 600 seconds'
fi

configuration_paths_json=$(printf '%s\n' "$configuration_paths" | os_guard_json_array_from_lines)
kernel=$(uname -r 2>/dev/null || true)

printf '{"item_id":"U-12","status":%s,"review_state":"%s",' "$status_json" "$review_state"
printf '"current_value":{"timeout_configured":%s,"effective_timeout_seconds":' "$timeout_configured"
if [ -n "$effective_timeout_seconds" ]; then printf '%s' "$effective_timeout_seconds"; else printf 'null'; fi
printf ',"timeout_source":'
if [ -n "$timeout_source" ]; then os_guard_json_quote "$timeout_source"; else printf 'null'; fi
printf ',"export_state":'; os_guard_json_quote "$export_state"
printf ',"assignment_count":%s,"duplicate_setting_count":%s,' "$assignment_count" "$duplicate_setting_count"
printf '"conflict_detected":%s,"dynamic_setting_detected":%s,' "$conflict_detected" "$dynamic_setting_detected"
printf '"checked_config_count":%s,"manual_review_required":%s},' "$checked_config_count" "$manual_review_required"
printf '"evidence":{"item_id":"U-12","collection_method":"Static read-only evaluation of global sh, ksh, bash, and csh timeout assignments",'
printf '"configuration_paths":%s,"reason_code":' "$configuration_paths_json"; os_guard_json_quote "$reason_code"
printf ',"os":{"distro":'; os_guard_json_quote "$distro"; printf ',"version_id":'; os_guard_json_quote "$version_id"
printf '},"kernel":'; os_guard_json_quote "$kernel"
printf ',"observed_at":'; os_guard_json_quote "$observed_at"; printf ',"module_version":'; os_guard_json_quote "$module_version"
printf ',"decision_reason":'; os_guard_json_quote "$decision_reason"
printf '},"error":%s}\n' "$error_json"
exit 0
