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
reason_code='KISA_U20_ANALYSIS_PENDING'
judgment_basis='Applicable inetd, xinetd, and systemd configuration metadata has not been evaluated'

detected_service_model='unknown'
inetd_present=false
xinetd_present=false
systemd_present=false
applicable_file_count=0
checked_file_count=0
root_owned_count=0
non_root_owned_count=0
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
if [ -z "$collection_error" ] && { [ -z "$stat_bin" ] || [ ! -x "$stat_bin" ]; }; then
    scan_completed=false; scan_error_count=$((scan_error_count + 1)); collection_error='STAT_COMMAND_UNUSABLE'
fi
if [ -z "$collection_error" ] && { [ -z "$readlink_bin" ] || [ ! -x "$readlink_bin" ]; }; then
    scan_completed=false; scan_error_count=$((scan_error_count + 1)); collection_error='READLINK_COMMAND_UNUSABLE'
fi

inspect_metadata() {
    metadata_uid=$1
    metadata_owner=$2
    metadata_mode=$3
    if ! printf '%s|%s|%s\n' "$metadata_uid" "$metadata_owner" "$metadata_mode" | awk -F'|' '
        NF == 3 && $1 ~ /^[0-9]+$/ && $2 != "" && $3 ~ /^[0-7][0-7][0-7]([0-7])?$/ { valid=1 }
        END { exit valid ? 0 : 1 }
    ' >/dev/null 2>&1; then
        scan_completed=false
        scan_error_count=$((scan_error_count + 1))
        unresolved_count=$((unresolved_count + 1))
        return
    fi

    applicable_file_count=$((applicable_file_count + 1))
    checked_file_count=$((checked_file_count + 1))
    if [ "$metadata_uid" -eq 0 ]; then
        root_owned_count=$((root_owned_count + 1))
        if [ "$metadata_owner" != 'root' ]; then review_required=true; fi
    else
        non_root_owned_count=$((non_root_owned_count + 1))
        vulnerable_object_detected=true
    fi

    permission_value=$((0$metadata_mode))
    extra_permission_value=$((permission_value & ~0600))
    if [ "$extra_permission_value" -eq 0 ]; then
        compliant_permission_count=$((compliant_permission_count + 1))
    else
        noncompliant_permission_count=$((noncompliant_permission_count + 1))
        vulnerable_object_detected=true
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
        "${test_root}/etc/inetd.conf"|"${test_root}/etc/xinetd.conf"|"${test_root}/etc/xinetd.d"/*|\
        "${test_root}/etc/systemd"/*.conf|"${test_root}/etc/systemd"/*.conf.d/*) return 0 ;;
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

scan_config_directory() {
    scan_dir=$1
    if [ ! -r "$scan_dir" ] || [ ! -x "$scan_dir" ]; then
        scan_completed=false; scan_error_count=$((scan_error_count + 1)); return
    fi
    for entry in "$scan_dir"/* "$scan_dir"/.[!.]* "$scan_dir"/..?*; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        if [ -d "$entry" ] && [ ! -L "$entry" ]; then
            scan_config_directory "$entry"
        else
            inspect_path "$entry"
        fi
    done
}

scan_systemd_scope() {
    systemd_dir="${test_root}/etc/systemd"
    if [ ! -r "$systemd_dir" ] || [ ! -x "$systemd_dir" ]; then
        scan_completed=false; scan_error_count=$((scan_error_count + 1)); return
    fi
    for entry in "$systemd_dir"/*.conf; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        inspect_path "$entry"
    done
    for conf_dir in "$systemd_dir"/*.conf.d; do
        [ -d "$conf_dir" ] && scan_config_directory "$conf_dir"
    done
}

process_fixture_scan() {
    fixture_file=$1
    if [ ! -r "$fixture_file" ]; then
        scan_completed=false; scan_error_count=$((scan_error_count + 1)); collection_error='FIXTURE_SCAN_UNREADABLE'; return
    fi
    while IFS='|' read -r object_kind object_uid object_owner object_mode extra; do
        [ -n "$object_kind" ] || continue
        case "$object_kind" in
            regular|symlink)
                [ "$object_kind" = 'symlink' ] && symlink_count=$((symlink_count + 1))
                inspect_metadata "$object_uid" "$object_owner" "$object_mode"
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

if [ -z "$collection_error" ]; then
    if [ -n "$test_root" ] && [ -n "${OS_GUARD_TEST_SCAN_FILE:-}" ]; then
        detected_service_model=${OS_GUARD_TEST_SERVICE_MODEL:-systemd}
        case "$detected_service_model" in
            inetd) inetd_present=true ;;
            xinetd) xinetd_present=true ;;
            systemd) systemd_present=true ;;
            *inetd*xinetd*|*xinetd*inetd*) inetd_present=true; xinetd_present=true ;;
            *) systemd_present=true ;;
        esac
        process_fixture_scan "$OS_GUARD_TEST_SCAN_FILE"
    else
        if [ -e "${test_root}/etc/inetd.conf" ] || [ -L "${test_root}/etc/inetd.conf" ]; then
            inetd_present=true; inspect_path "${test_root}/etc/inetd.conf"
        fi
        if [ -e "${test_root}/etc/xinetd.conf" ] || [ -L "${test_root}/etc/xinetd.conf" ]; then
            xinetd_present=true; inspect_path "${test_root}/etc/xinetd.conf"
        fi
        if [ -d "${test_root}/etc/xinetd.d" ]; then
            xinetd_present=true; scan_config_directory "${test_root}/etc/xinetd.d"
        fi
        if [ -d "${test_root}/etc/systemd" ]; then
            systemd_present=true; scan_systemd_scope
        fi
        if [ "$systemd_present" = true ]; then
            if [ "$inetd_present" = true ] || [ "$xinetd_present" = true ]; then detected_service_model='systemd_with_legacy'; else detected_service_model='systemd'; fi
        elif [ "$xinetd_present" = true ] && [ "$inetd_present" = true ]; then detected_service_model='inetd_and_xinetd'
        elif [ "$xinetd_present" = true ]; then detected_service_model='xinetd'
        elif [ "$inetd_present" = true ]; then detected_service_model='inetd'
        fi
    fi
fi

if [ "$vulnerable_object_detected" = true ]; then
    status_json='"VULNERABLE"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U20_OWNER_OR_PERMISSION_VIOLATION'
    judgment_basis='At least one applicable configuration file has a non-root UID owner or permission bits outside the KISA 0600 allowance mask'
    if [ "$scan_completed" != true ]; then error_json='{"code":"PARTIAL_SCAN_FAILED","message":"a vulnerability was confirmed although part of the configuration scan could not be completed"}'; fi
elif [ "$scan_completed" != true ]; then
    status_json='"UNCHECKABLE"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U20_COLLECTION_FAILED'
    judgment_basis='The applicable configuration scope or required metadata could not be collected completely'
    error_code=${collection_error:-CONFIGURATION_SCAN_INCOMPLETE}
    error_json=$(printf '{"code":'; os_guard_json_quote "$error_code"; printf ',"message":"configuration metadata collection failed"}')
elif [ "$checked_file_count" -eq 0 ]; then
    status_json='"UNCHECKABLE"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U20_NO_APPLICABLE_FILES'
    judgment_basis='No applicable inetd, xinetd, or systemd configuration file was available for assessment'
    error_json='{"code":"NO_APPLICABLE_CONFIGURATION_FOUND","message":"no assessable U-20 configuration file was found"}'
elif [ "$review_required" = true ]; then
    status_json='null'; review_state='PENDING'
    reason_code='KISA_U20_REVIEW_REQUIRED'
    judgment_basis='A symlink target, owner identity, or nonstandard configuration object requires manual review'
else
    status_json='"GOOD"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U20_ROOT_OWNER_AND_PERMISSION_ALLOWED'
    judgment_basis='All applicable configuration files are owned by root UID 0 and have no permission bit outside the KISA 0600 allowance mask'
fi

printf '{"item_id":"U-20","status":%s,"review_state":"%s",' "$status_json" "$review_state"
printf '"current_value":{"detected_service_model":'; os_guard_json_quote "$detected_service_model"
printf ',"inetd_present":%s,"xinetd_present":%s,"systemd_present":%s,' "$inetd_present" "$xinetd_present" "$systemd_present"
printf '"applicable_file_count":%s,"checked_file_count":%s,"root_owned_count":%s,' "$applicable_file_count" "$checked_file_count" "$root_owned_count"
printf '"non_root_owned_count":%s,"compliant_permission_count":%s,"noncompliant_permission_count":%s,' "$non_root_owned_count" "$compliant_permission_count" "$noncompliant_permission_count"
printf '"symlink_count":%s,"unresolved_count":%s,"scan_completed":%s},' "$symlink_count" "$unresolved_count" "$scan_completed"
printf '"evidence":{"item_id":"U-20","inspection_target":"inetd, xinetd, and bounded systemd configuration files",'
printf '"collection_method":"Read-only bounded discovery and structured stat metadata without reading configuration contents",'
printf '"detected_service_model":'; os_guard_json_quote "$detected_service_model"
printf ',"inetd_present":%s,"xinetd_present":%s,"systemd_present":%s,' "$inetd_present" "$xinetd_present" "$systemd_present"
printf '"applicable_file_count":%s,"checked_file_count":%s,"root_owned_count":%s,' "$applicable_file_count" "$checked_file_count" "$root_owned_count"
printf '"non_root_owned_count":%s,"compliant_permission_count":%s,"noncompliant_permission_count":%s,' "$non_root_owned_count" "$compliant_permission_count" "$noncompliant_permission_count"
printf '"symlink_count":%s,"unresolved_count":%s,"scan_completed":%s,"reason_code":' "$symlink_count" "$unresolved_count" "$scan_completed"; os_guard_json_quote "$reason_code"
printf ',"os":{"distro":'; os_guard_json_quote "$distro"; printf ',"version_id":'; os_guard_json_quote "$version_id"; printf '}'
printf ',"kernel":'; os_guard_json_quote "$kernel"
printf ',"observed_at":'; os_guard_json_quote "$observed_at"; printf ',"module_version":'; os_guard_json_quote "$module_version"
printf ',"judgment_basis":'; os_guard_json_quote "$judgment_basis"
printf '},"error":%s}\n' "$error_json"
