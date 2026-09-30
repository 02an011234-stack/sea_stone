#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/../lib/common.sh"

distro=${OS_GUARD_DISTRO:-unknown}
version_id=${OS_GUARD_VERSION_ID:-unknown}
module_version=${OS_GUARD_MODULE_VERSION:-unknown}
observed_at=$(os_guard_utc_now)
kernel=$(uname -r 2>/dev/null || printf 'unknown')
test_root=${OS_GUARD_TEST_ROOT:-}

passwd_path="${test_root}/etc/passwd"
profile_path="${test_root}/etc/profile"
profile_d_path="${test_root}/etc/profile.d"

status_json='null'
review_state='PENDING'
manual_review_required=true
collection_error=''
error_json='null'
reason_code='KISA_U14_PATH_ANALYSIS_PENDING'
decision_reason='The effective root login PATH has not been determined'

root_entry_found=false
root_home_source='not_available'
root_shell_type='unknown'
path_detected=false
path_component_count=0
current_directory_component_found=false
current_directory_position='none'
empty_component_found=false
dynamic_path_detected=false
conflict_detected=false
checked_config_count=0
effective_path_state='indeterminate'
assignment_count=0

case "$distro:$version_id" in
    rocky:9|rocky:9.*|rocky:10|rocky:10.*|ubuntu:22|ubuntu:22.*|ubuntu:24|ubuntu:24.*) ;;
    *) collection_error='UNSUPPORTED_OS_CONFIGURATION' ;;
esac

root_home=''
root_shell=''
if [ -z "$collection_error" ]; then
    if [ ! -e "$passwd_path" ]; then
        collection_error='PASSWD_FILE_NOT_FOUND'
    elif [ ! -r "$passwd_path" ]; then
        collection_error='PASSWD_FILE_UNREADABLE'
    else
        root_record=$(awk -F: '
            $1 == "root" {
                count++
                if (NF != 7 || $6 == "" || $7 == "") malformed=1
                home=$6
                shell=$7
            }
            END {
                if (count != 1 || malformed) exit 2
                printf "%s\n%s\n", home, shell
            }
        ' "$passwd_path" 2>/dev/null)
        root_rc=$?
        if [ "$root_rc" -ne 0 ]; then
            collection_error='ROOT_ENTRY_INVALID'
        else
            root_home=$(printf '%s\n' "$root_record" | sed -n '1p')
            root_shell=$(printf '%s\n' "$root_record" | sed -n '2p')
            root_entry_found=true
            root_home_source='/etc/passwd'
            root_shell_type=${root_shell##*/}
        fi
    fi
fi

nonstandard_root_home=false
nonstandard_root_shell=false
if [ -z "$collection_error" ]; then
    case "$root_home" in
        /*) ;;
        *) collection_error='ROOT_HOME_INVALID' ;;
    esac
    case "$root_home" in
        *'/../'*|*/..|*'/./'*|*/.) collection_error='ROOT_HOME_INVALID' ;;
    esac
    [ "$root_home" = '/root' ] || nonstandard_root_home=true
    case "$root_shell" in
        /bin/bash|/usr/bin/bash|/bin/sh|/usr/bin/sh) ;;
        *) nonstandard_root_shell=true ;;
    esac
fi

config_files=''
configuration_paths=''
analysis_files=''
profile_fragments=''
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

append_analysis_config() {
    if [ -z "$analysis_files" ]; then
        analysis_files=$1
    else
        analysis_files="$analysis_files
$1"
    fi
}

if [ -z "$collection_error" ]; then
    if [ ! -e "$profile_path" ]; then
        collection_error='PROFILE_FILE_NOT_FOUND'
    elif [ ! -r "$profile_path" ]; then
        collection_error='PROFILE_FILE_UNREADABLE'
    else
        append_config "$profile_path"
        append_analysis_config "$profile_path"
    fi
fi

profile_d_active=false
if [ -z "$collection_error" ]; then
    if awk '
        /^[[:space:]]*#/ { next }
        /\/etc\/profile\.d/ { directory=1 }
        /(^|[;[:space:]])(\.|source)[[:space:]]/ {
            if (index($0, "$i") || index($0, "${i}") || $0 ~ /profile\.d/) sourced=1
        }
        END { exit directory && sourced ? 0 : 1 }
    ' "$profile_path" 2>/dev/null; then
        profile_d_active=true
    fi
    if [ "$profile_d_active" = true ] && [ -e "$profile_d_path" ]; then
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
                if [ -z "$profile_fragments" ]; then
                    profile_fragments=$config_path
                else
                    profile_fragments="$profile_fragments
$config_path"
                fi
            done
        fi
    fi
fi

root_profile=''
root_bashrc=''
if [ -z "$collection_error" ] && [ "$nonstandard_root_shell" = false ]; then
    root_home_path="${test_root}${root_home}"
    case "$root_shell_type" in
        bash)
            for candidate in .bash_profile .bash_login .profile; do
                candidate_path="$root_home_path/$candidate"
                if [ -e "$candidate_path" ]; then
                    if [ ! -r "$candidate_path" ]; then
                        collection_error='ROOT_PROFILE_UNREADABLE'
                    else
                        root_profile=$candidate_path
                        append_config "$candidate_path"
                        append_analysis_config "$candidate_path"
                    fi
                    break
                fi
            done
            if [ -z "$collection_error" ] && [ -n "$root_profile" ] && awk '
                /^[[:space:]]*#/ { next }
                /(^|[;[:space:]])(\.|source)[[:space:]].*(\.bashrc|BASHRC)/ { found=1 }
                END { exit found ? 0 : 1 }
            ' "$root_profile" 2>/dev/null; then
                root_bashrc="$root_home_path/.bashrc"
                if [ -e "$root_bashrc" ]; then
                    if [ ! -r "$root_bashrc" ]; then
                        collection_error='ROOT_BASHRC_UNREADABLE'
                    else
                        append_config "$root_bashrc"
                    fi
                else
                    collection_error='SOURCED_ROOT_BASHRC_NOT_FOUND'
                fi
            fi
            ;;
        sh)
            candidate_path="$root_home_path/.profile"
            if [ -e "$candidate_path" ]; then
                if [ ! -r "$candidate_path" ]; then
                    collection_error='ROOT_PROFILE_UNREADABLE'
                else
                    root_profile=$candidate_path
                    append_config "$candidate_path"
                    append_analysis_config "$candidate_path"
                fi
            fi
            ;;
    esac
fi

if [ -z "$collection_error" ]; then
    analysis_files=$profile_path
    if [ -n "$profile_fragments" ]; then
        analysis_files="$analysis_files
$profile_fragments"
    fi
    if [ -n "$root_profile" ]; then
        analysis_files="$analysis_files
$root_profile"
    fi
    if [ -n "$root_bashrc" ]; then
        analysis_files="$analysis_files
$root_bashrc"
    fi
    old_ifs=$IFS
    IFS='
'
    # Only locally discovered, fixed startup files are passed to awk.
    # shellcheck disable=SC2086
    analysis=$(awk -v has_profile_fragments="$profile_d_active" -v has_root_bashrc="$([ -n "$root_bashrc" ] && printf true || printf false)" '
        function trim(value) {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            return value
        }
        function replace_path(value, replacement,    pos, result) {
            result=""
            while ((pos=index(value, "${PATH}")) > 0) {
                result=result substr(value,1,pos-1) replacement
                value=substr(value,pos+7)
            }
            value=result value
            result=""
            while ((pos=index(value, "$PATH")) > 0) {
                result=result substr(value,1,pos-1) replacement
                value=substr(value,pos+5)
            }
            return result value
        }
        function remember(value,    key) {
            assignment_count++
            key=value
            if (!(key in seen)) { seen[key]=1; distinct_count++ }
            effective=value
            path_known=1
            last_known_order=statement_order
        }
        function process(raw,    statement,value,first,last) {
            statement_order++
            statement=trim(raw)
            if (statement == "" || statement ~ /^#/) return
            sub(/[[:space:]]+#.*/, "", statement)
            statement=trim(statement)
            if (statement == "") return

            if (statement ~ /^(if|case|for|while|until)([[:space:]]|$)/ ||
                statement ~ /^[[:alnum:]_]+[[:space:]]*\(\)[[:space:]]*\{/) depth++
            if ((statement ~ /^(fi|esac|done)([[:space:]]|$)/ || statement ~ /^}/) && depth > 0) depth--

            if (statement ~ /(^|[[:space:]])(\.|source)[[:space:]]+/) {
                if (current_line_profile_source || statement ~ /profile\.d/) {
                    known_include_order=statement_order
                    known_include_file=FILENAME
                    return
                }
                if (statement ~ /(\.bashrc|BASHRC)/ && has_root_bashrc == "true") {
                    known_include_order=statement_order
                    known_include_file=FILENAME
                    return
                }
                last_unknown_order=statement_order
                dynamic_seen=1
                return
            }

            if (statement ~ /^(export|readonly)[[:space:]]+PATH([[:space:]]|$)/ && statement !~ /PATH=/) return
            if (statement !~ /^(export[[:space:]]+|readonly[[:space:]]+)?PATH=/) {
                if (statement ~ /(^|[[:space:]])PATH=/) {
                    last_unknown_order=statement_order
                    dynamic_seen=1
                }
                return
            }
            if (known_include_file == FILENAME && statement_order > known_include_order) {
                include_order_ambiguous=1
                dynamic_seen=1
            }
            if (depth > 0) {
                last_unknown_order=statement_order
                dynamic_seen=1
                return
            }

            value=statement
            sub(/^(export[[:space:]]+|readonly[[:space:]]+)?PATH=/, "", value)
            value=trim(value)
            first=substr(value,1,1); last=substr(value,length(value),1)
            if ((first == "\"" && last == "\"") || (first == "\047" && last == "\047")) {
                value=substr(value,2,length(value)-2)
            }
            if (value ~ /`/ || value ~ /\$\(/) {
                last_unknown_order=statement_order
                dynamic_seen=1
                return
            }
            if (value ~ /\$PATH|\$\{PATH\}/) {
                if (!path_known) {
                    last_unknown_order=statement_order
                    dynamic_seen=1
                    return
                }
                value=replace_path(value,effective)
            }
            if (value ~ /\$/ || value ~ /[{}]/) {
                last_unknown_order=statement_order
                dynamic_seen=1
                return
            }
            remember(value)
        }
        {
            current_line_profile_source=(has_profile_fragments == "true" && $0 ~ /\/etc\/profile\.d/ && $0 ~ /[.][[:space:]]+/)
            count=split($0, statements, ";")
            for (i=1; i<=count; i++) process(statements[i])
        }
        END {
            unresolved=(last_unknown_order > last_known_order || include_order_ambiguous)
            printf "path_known=%d\n", path_known+0
            printf "effective=%s\n", effective
            printf "assignment_count=%d\n", assignment_count+0
            printf "distinct_count=%d\n", distinct_count+0
            printf "dynamic_seen=%d\n", dynamic_seen+0
            printf "unresolved=%d\n", unresolved+0
        }
    ' $analysis_files 2>/dev/null)
    analysis_rc=$?
    IFS=$old_ifs
    if [ "$analysis_rc" -ne 0 ]; then
        collection_error='PROFILE_PARSE_ERROR'
    else
        path_known=$(printf '%s\n' "$analysis" | awk -F= '$1=="path_known" {print $2}')
        effective_path=$(printf '%s\n' "$analysis" | sed -n 's/^effective=//p')
        assignment_count=$(printf '%s\n' "$analysis" | awk -F= '$1=="assignment_count" {print $2}')
        distinct_count=$(printf '%s\n' "$analysis" | awk -F= '$1=="distinct_count" {print $2}')
        dynamic_seen=$(printf '%s\n' "$analysis" | awk -F= '$1=="dynamic_seen" {print $2}')
        unresolved=$(printf '%s\n' "$analysis" | awk -F= '$1=="unresolved" {print $2}')
        [ "$path_known" = 1 ] && path_detected=true
        [ "$dynamic_seen" = 1 ] && dynamic_path_detected=true
        [ "$distinct_count" -gt 1 ] && conflict_detected=true

        if [ "$path_detected" = true ]; then
            path_metrics=$(printf '%s\n' "$effective_path" | awk '
                {
                    original=$0; value=$0; count=1; current=0; empty=0; early=0; trailing=0
                    while (1) {
                        pos=index(value, ":")
                        if (pos == 0) { component=value; final=1 }
                        else { component=substr(value,1,pos-1); final=0 }
                        if (component == "." || component == "") {
                            current++
                            if (component == "") empty++
                            if (final) trailing=1; else early=1
                        }
                        if (final) break
                        count++
                        value=substr(value,pos+1)
                    }
                    if (current == 0) position="none"
                    else if (current > 1) position="multiple"
                    else if (early && (substr(original,1,2) == ".:" || substr(original,1,1) == ":")) position="leading"
                    else if (early) position="middle"
                    else position="trailing"
                    printf "%d %d %d %d %s\n", count,current,empty,early,position
                }
            ')
            set -- $path_metrics
            path_component_count=$1
            current_count=$2
            empty_count=$3
            early_current=$4
            current_directory_position=$5
            [ "$current_count" -gt 0 ] && current_directory_component_found=true
            [ "$empty_count" -gt 0 ] && empty_component_found=true
        fi

        if [ "$unresolved" = 1 ] || [ "$path_detected" != true ]; then
            effective_path_state='indeterminate'
        elif [ "$early_current" -eq 1 ]; then
            effective_path_state='vulnerable_current_directory_early'
        elif [ "$current_directory_component_found" = true ]; then
            effective_path_state='safe_current_directory_last'
        else
            effective_path_state='safe_no_current_directory'
        fi
    fi
fi

if [ -n "$collection_error" ]; then
    status_json='"UNCHECKABLE"'
    review_state='NOT_REQUIRED'
    manual_review_required=false
    reason_code='KISA_U14_COLLECTION_FAILED'
    decision_reason='The root login PATH configuration could not be collected or parsed safely'
    error_json=$(printf '{"code":'; os_guard_json_quote "$collection_error"; printf ',"message":"Root PATH configuration collection or parsing failed"}')
elif [ "$effective_path_state" = 'vulnerable_current_directory_early' ]; then
    status_json='"VULNERABLE"'
    review_state='NOT_REQUIRED'
    manual_review_required=false
    reason_code='KISA_U14_CURRENT_DIRECTORY_PRECEDES_FINAL_POSITION'
    decision_reason='The effective root PATH contains the current directory before the final component'
elif [ "$nonstandard_root_home" = true ] || [ "$nonstandard_root_shell" = true ] || \
     [ "$effective_path_state" = 'indeterminate' ]; then
    status_json='null'
    review_state='PENDING'
    manual_review_required=true
    reason_code='KISA_U14_REVIEW_REQUIRED'
    decision_reason='The effective root login PATH requires manual review because the startup structure or final value is not statically determinable'
else
    status_json='"GOOD"'
    review_state='NOT_REQUIRED'
    manual_review_required=false
    reason_code='KISA_U14_CURRENT_DIRECTORY_ABSENT_OR_LAST'
    decision_reason='The effective root PATH omits the current directory or places it only in the final component'
fi

configuration_paths_json=$(printf '%s\n' "$configuration_paths" | os_guard_json_array_from_lines)

printf '{"item_id":"U-14","status":%s,"review_state":"%s",' "$status_json" "$review_state"
printf '"current_value":{"root_entry_found":%s,"root_home_source":' "$root_entry_found"; os_guard_json_quote "$root_home_source"
printf ',"root_shell_type":'; os_guard_json_quote "$root_shell_type"
printf ',"path_detected":%s,"path_component_count":%s,' "$path_detected" "$path_component_count"
printf '"current_directory_component_found":%s,"current_directory_position":' "$current_directory_component_found"; os_guard_json_quote "$current_directory_position"
printf ',"empty_component_found":%s,"dynamic_path_detected":%s,' "$empty_component_found" "$dynamic_path_detected"
printf '"conflict_detected":%s,"checked_config_count":%s,' "$conflict_detected" "$checked_config_count"
printf '"assignment_count":%s,"effective_path_state":' "$assignment_count"; os_guard_json_quote "$effective_path_state"
printf ',"manual_review_required":%s},' "$manual_review_required"
printf '"evidence":{"item_id":"U-14","collection_method":"Statically resolve the root login PATH from locally discovered startup files without executing them",'
printf '"configuration_paths":%s,"root_home_source":' "$configuration_paths_json"; os_guard_json_quote "$root_home_source"
printf ',"empty_component_semantics":"Linux PATH empty components are treated as current-directory components and use the KISA position rule",'
printf '"reason_code":'; os_guard_json_quote "$reason_code"
printf ',"os":{"distro":'; os_guard_json_quote "$distro"; printf ',"version_id":'; os_guard_json_quote "$version_id"; printf '}'
printf ',"kernel":'; os_guard_json_quote "$kernel"
printf ',"observed_at":'; os_guard_json_quote "$observed_at"; printf ',"module_version":'; os_guard_json_quote "$module_version"
printf ',"decision_reason":'; os_guard_json_quote "$decision_reason"
printf '},"error":%s}\n' "$error_json"
