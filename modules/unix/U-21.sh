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

status_json='null'
review_state='PENDING'
error_json='null'
reason_code='KISA_U21_ANALYSIS_PENDING'
judgment_basis='Logging configuration metadata has not been evaluated'

detected_logging_model='unknown'
syslog_conf_present=false
rsyslog_conf_present=false
rsyslog_fragment_dir_present=false
journald_present=false
applicable_file_count=0
checked_file_count=0
allowed_owner_count=0
disallowed_owner_count=0
compliant_permission_count=0
noncompliant_permission_count=0
symlink_count=0
unresolved_count=0
scan_completed=true
scan_error_count=0
vulnerable_object_detected=false
review_required=false
collection_error=''

case "$distro:$version_id" in
    rocky:9|rocky:9.*|rocky:10|rocky:10.*|ubuntu:22|ubuntu:22.*|ubuntu:24|ubuntu:24.*) ;;
    *) scan_completed=false; scan_error_count=1; collection_error='UNSUPPORTED_OS_CONFIGURATION' ;;
esac

stat_bin=$(command -v stat 2>/dev/null || true)
readlink_bin=$(command -v readlink 2>/dev/null || true)
getent_bin=$(command -v getent 2>/dev/null || true)
if [ -z "$collection_error" ] && { [ -z "$stat_bin" ] || [ ! -x "$stat_bin" ]; }; then
    scan_completed=false; scan_error_count=$((scan_error_count + 1)); collection_error='STAT_COMMAND_UNUSABLE'
fi
if [ -z "$collection_error" ] && { [ -z "$readlink_bin" ] || [ ! -x "$readlink_bin" ]; }; then
    scan_completed=false; scan_error_count=$((scan_error_count + 1)); collection_error='READLINK_COMMAND_UNUSABLE'
fi

owner_identity_is_valid() {
    identity_uid=$1
    identity_name=$2
    identity_hint=${3:-}
    if [ "$identity_name" = 'root' ]; then
        [ "$identity_uid" -eq 0 ]
        return
    fi
    case "$identity_name" in bin|sys) ;; *) return 1 ;; esac
    if [ -n "$identity_hint" ]; then
        [ "$identity_hint" = 'verified' ]
        return
    fi
    if [ -z "$getent_bin" ] || [ ! -x "$getent_bin" ]; then return 2; fi
    identity_record=$($getent_bin passwd "$identity_name" 2>/dev/null) || return 2
    old_ifs=$IFS; IFS=':'; set -- $identity_record; IFS=$old_ifs
    [ "$#" -ge 3 ] || return 2
    [ "$1" = "$identity_name" ] || return 2
    case "$3" in ''|*[!0-9]*) return 2 ;; esac
    [ "$3" -eq "$identity_uid" ]
}

inspect_metadata() {
    metadata_uid=$1
    metadata_owner=$2
    metadata_mode=$3
    identity_hint=${4:-}
    if ! printf '%s|%s|%s\n' "$metadata_uid" "$metadata_owner" "$metadata_mode" | awk -F'|' '
        NF == 3 && $1 ~ /^[0-9]+$/ && $2 != "" && $3 ~ /^[0-7][0-7][0-7]([0-7])?$/ { valid=1 }
        END { exit valid ? 0 : 1 }
    ' >/dev/null 2>&1; then
        scan_completed=false; scan_error_count=$((scan_error_count + 1)); unresolved_count=$((unresolved_count + 1)); return
    fi

    applicable_file_count=$((applicable_file_count + 1))
    checked_file_count=$((checked_file_count + 1))
    case "$metadata_owner" in
        root|bin|sys)
            owner_identity_is_valid "$metadata_uid" "$metadata_owner" "$identity_hint"
            identity_result=$?
            if [ "$identity_result" -eq 0 ]; then
                allowed_owner_count=$((allowed_owner_count + 1))
            else
                unresolved_count=$((unresolved_count + 1)); review_required=true
            fi
            ;;
        *)
            disallowed_owner_count=$((disallowed_owner_count + 1)); vulnerable_object_detected=true
            ;;
    esac

    permission_value=$((0$metadata_mode))
    extra_permission_value=$((permission_value & ~0640))
    if [ "$extra_permission_value" -eq 0 ]; then
        compliant_permission_count=$((compliant_permission_count + 1))
    else
        noncompliant_permission_count=$((noncompliant_permission_count + 1)); vulnerable_object_detected=true
    fi
}

inspect_regular_file() {
    inspected_path=$1
    metadata_output=$($stat_bin -c '%u|%U|%a' -- "$inspected_path" 2>/dev/null)
    if [ $? -ne 0 ]; then
        scan_completed=false; scan_error_count=$((scan_error_count + 1)); unresolved_count=$((unresolved_count + 1)); return
    fi
    old_ifs=$IFS; IFS='|'; set -- $metadata_output; IFS=$old_ifs
    if [ "$#" -ne 3 ]; then
        scan_completed=false; scan_error_count=$((scan_error_count + 1)); unresolved_count=$((unresolved_count + 1)); return
    fi
    inspect_metadata "$1" "$2" "$3"
}

target_is_in_scope() {
    target_path=$1
    case "$target_path" in
        "${test_root}/etc/syslog.conf"|"${test_root}/etc/rsyslog.conf"|"${test_root}/etc/rsyslog.d"/*) return 0 ;;
        *) return 1 ;;
    esac
}

inspect_path() {
    candidate=$1
    if [ -L "$candidate" ]; then
        symlink_count=$((symlink_count + 1))
        resolved=$($readlink_bin -f -- "$candidate" 2>/dev/null)
        if [ -z "$resolved" ] || [ ! -e "$resolved" ]; then
            unresolved_count=$((unresolved_count + 1)); review_required=true
        elif ! target_is_in_scope "$resolved"; then
            unresolved_count=$((unresolved_count + 1)); review_required=true
        elif [ -f "$resolved" ]; then
            inspect_regular_file "$resolved"
        else
            unresolved_count=$((unresolved_count + 1)); review_required=true
        fi
    elif [ -f "$candidate" ]; then
        inspect_regular_file "$candidate"
    elif [ -e "$candidate" ]; then
        unresolved_count=$((unresolved_count + 1)); review_required=true
    fi
}

scan_rsyslog_directory() {
    scan_dir=$1
    if [ ! -r "$scan_dir" ] || [ ! -x "$scan_dir" ]; then
        scan_completed=false; scan_error_count=$((scan_error_count + 1)); return
    fi
    for entry in "$scan_dir"/* "$scan_dir"/.[!.]* "$scan_dir"/..?*; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        if [ -d "$entry" ] && [ ! -L "$entry" ]; then
            unresolved_count=$((unresolved_count + 1)); review_required=true
        else
            inspect_path "$entry"
        fi
    done
}

process_fixture_scan() {
    fixture_file=$1
    if [ ! -r "$fixture_file" ]; then
        scan_completed=false; scan_error_count=$((scan_error_count + 1)); collection_error='FIXTURE_SCAN_UNREADABLE'; return
    fi
    while IFS='|' read -r object_kind object_uid object_owner object_mode identity_hint extra; do
        [ -n "$object_kind" ] || continue
        case "$object_kind" in
            regular|symlink)
                [ "$object_kind" = 'symlink' ] && symlink_count=$((symlink_count + 1))
                inspect_metadata "$object_uid" "$object_owner" "$object_mode" "$identity_hint"
                ;;
            broken_symlink|external_symlink)
                symlink_count=$((symlink_count + 1)); unresolved_count=$((unresolved_count + 1)); review_required=true
                ;;
            metadata_error)
                scan_completed=false; scan_error_count=$((scan_error_count + 1)); unresolved_count=$((unresolved_count + 1))
                ;;
            scan_error)
                scan_completed=false; scan_error_count=$((scan_error_count + 1))
                ;;
            *)
                scan_completed=false; scan_error_count=$((scan_error_count + 1)); unresolved_count=$((unresolved_count + 1))
                ;;
        esac
    done < "$fixture_file"
}

set_logging_model() {
    detected_logging_model=$1
    case "$detected_logging_model" in
        syslog) syslog_conf_present=true ;;
        rsyslog) rsyslog_conf_present=true ;;
        rsyslog_fragments) rsyslog_fragment_dir_present=true ;;
        syslog_and_rsyslog) syslog_conf_present=true; rsyslog_conf_present=true ;;
        rsyslog_with_fragments) rsyslog_conf_present=true; rsyslog_fragment_dir_present=true ;;
        journald_only) journald_present=true ;;
        *) ;;
    esac
}

if [ -z "$collection_error" ]; then
    if [ -n "$test_root" ] && [ -n "${OS_GUARD_TEST_SCAN_FILE:-}" ]; then
        set_logging_model "${OS_GUARD_TEST_LOGGING_MODEL:-rsyslog}"
        process_fixture_scan "$OS_GUARD_TEST_SCAN_FILE"
    else
        if [ -e "${test_root}/etc/syslog.conf" ] || [ -L "${test_root}/etc/syslog.conf" ]; then
            syslog_conf_present=true; inspect_path "${test_root}/etc/syslog.conf"
        fi
        if [ -e "${test_root}/etc/rsyslog.conf" ] || [ -L "${test_root}/etc/rsyslog.conf" ]; then
            rsyslog_conf_present=true; inspect_path "${test_root}/etc/rsyslog.conf"
        fi
        if [ -d "${test_root}/etc/rsyslog.d" ]; then
            rsyslog_fragment_dir_present=true; scan_rsyslog_directory "${test_root}/etc/rsyslog.d"
        fi
        if [ -e "${test_root}/etc/systemd/journald.conf" ] || [ -d "${test_root}/etc/systemd/journald.conf.d" ]; then journald_present=true; fi
        if [ "$syslog_conf_present" = true ] && { [ "$rsyslog_conf_present" = true ] || [ "$rsyslog_fragment_dir_present" = true ]; }; then detected_logging_model='syslog_and_rsyslog'
        elif [ "$rsyslog_conf_present" = true ] && [ "$rsyslog_fragment_dir_present" = true ]; then detected_logging_model='rsyslog_with_fragments'
        elif [ "$rsyslog_conf_present" = true ]; then detected_logging_model='rsyslog'
        elif [ "$rsyslog_fragment_dir_present" = true ]; then detected_logging_model='rsyslog_fragments'
        elif [ "$syslog_conf_present" = true ]; then detected_logging_model='syslog'
        elif [ "$journald_present" = true ]; then detected_logging_model='journald_only'
        fi
    fi
fi

if [ "$vulnerable_object_detected" = true ]; then
    status_json='"VULNERABLE"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U21_OWNER_OR_PERMISSION_VIOLATION'
    judgment_basis='At least one applicable logging configuration file has an owner outside verified root, bin, or sys identities or permission bits outside the KISA 0640 allowance mask'
    if [ "$scan_completed" != true ]; then error_json='{"code":"PARTIAL_SCAN_FAILED","message":"a vulnerability was confirmed although part of the metadata scan could not be completed"}'; fi
elif [ "$scan_completed" != true ]; then
    status_json='"UNCHECKABLE"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U21_COLLECTION_FAILED'
    judgment_basis='The applicable logging configuration scope or required metadata could not be collected completely'
    error_code=${collection_error:-CONFIGURATION_SCAN_INCOMPLETE}
    error_json=$(printf '{"code":'; os_guard_json_quote "$error_code"; printf ',"message":"logging configuration metadata collection failed"}')
elif [ "$checked_file_count" -eq 0 ] && [ "$detected_logging_model" = 'journald_only' ]; then
    status_json='"N/A"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U21_NOT_APPLICABLE_JOURNALD_ONLY'
    judgment_basis='No syslog or rsyslog configuration target exists and the local logging configuration is explicitly identified as journald-only'
elif [ "$review_required" = true ]; then
    status_json='null'; review_state='PENDING'
    reason_code='KISA_U21_REVIEW_REQUIRED'
    judgment_basis='An owner identity, symlink target, or nonstandard configuration object requires manual review'
elif [ "$checked_file_count" -eq 0 ]; then
    status_json='"UNCHECKABLE"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U21_NO_APPLICABLE_FILES'
    judgment_basis='No applicable syslog or rsyslog configuration file and no conclusive journald-only model was available'
    error_json='{"code":"NO_APPLICABLE_CONFIGURATION_FOUND","message":"no assessable U-21 configuration file was found"}'
else
    status_json='"GOOD"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U21_ALLOWED_OWNER_AND_PERMISSION'
    judgment_basis='All applicable logging configuration files have a verified root, bin, or sys owner and no permission bit outside the KISA 0640 allowance mask'
fi

printf '{"item_id":"U-21","status":%s,"review_state":"%s",' "$status_json" "$review_state"
printf '"current_value":{"detected_logging_model":'; os_guard_json_quote "$detected_logging_model"
printf ',"syslog_conf_present":%s,"rsyslog_conf_present":%s,"rsyslog_fragment_dir_present":%s,"journald_present":%s,' "$syslog_conf_present" "$rsyslog_conf_present" "$rsyslog_fragment_dir_present" "$journald_present"
printf '"applicable_file_count":%s,"checked_file_count":%s,"allowed_owner_count":%s,"disallowed_owner_count":%s,' "$applicable_file_count" "$checked_file_count" "$allowed_owner_count" "$disallowed_owner_count"
printf '"compliant_permission_count":%s,"noncompliant_permission_count":%s,"symlink_count":%s,"unresolved_count":%s,"scan_completed":%s},' "$compliant_permission_count" "$noncompliant_permission_count" "$symlink_count" "$unresolved_count" "$scan_completed"
printf '"evidence":{"item_id":"U-21","inspection_target":"syslog and rsyslog configuration file metadata",'
printf '"collection_method":"Read-only bounded discovery and structured stat metadata without reading logging configuration or log contents",'
printf '"detected_logging_model":'; os_guard_json_quote "$detected_logging_model"
printf ',"syslog_conf_present":%s,"rsyslog_conf_present":%s,"rsyslog_fragment_dir_present":%s,"journald_present":%s,' "$syslog_conf_present" "$rsyslog_conf_present" "$rsyslog_fragment_dir_present" "$journald_present"
printf '"applicable_file_count":%s,"checked_file_count":%s,"allowed_owner_count":%s,"disallowed_owner_count":%s,' "$applicable_file_count" "$checked_file_count" "$allowed_owner_count" "$disallowed_owner_count"
printf '"compliant_permission_count":%s,"noncompliant_permission_count":%s,"symlink_count":%s,"unresolved_count":%s,"scan_completed":%s,"reason_code":' "$compliant_permission_count" "$noncompliant_permission_count" "$symlink_count" "$unresolved_count" "$scan_completed"; os_guard_json_quote "$reason_code"
printf ',"os":{"distro":'; os_guard_json_quote "$distro"; printf ',"version_id":'; os_guard_json_quote "$version_id"; printf '}'
printf ',"kernel":'; os_guard_json_quote "$kernel"
printf ',"observed_at":'; os_guard_json_quote "$observed_at"; printf ',"module_version":'; os_guard_json_quote "$module_version"
printf ',"judgment_basis":'; os_guard_json_quote "$judgment_basis"
printf '},"error":%s}\n' "$error_json"
