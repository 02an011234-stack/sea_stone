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
reason_code='KISA_U17_ANALYSIS_PENDING'
decision_reason='Startup file ownership and non-owner write access have not been evaluated'

startup_system_type='unknown'
scan_completed=true
scan_root_found=false
checked_object_count=0
regular_file_count=0
symlink_count=0
masked_symlink_count=0
root_owned_count=0
non_root_owned_count=0
writable_by_non_owner_count=0
group_write_detected_count=0
other_write_detected_count=0
unresolved_object_count=0
scan_error_count=0
owner_identity_conflict_count=0
group_write_review_count=0
vulnerable_object_detected=false
review_required=false

case "$distro:$version_id" in
    rocky:9|rocky:9.*|rocky:10|rocky:10.*|ubuntu:22|ubuntu:22.*|ubuntu:24|ubuntu:24.*) ;;
    *)
        scan_completed=false
        scan_error_count=1
        collection_error='UNSUPPORTED_OS_CONFIGURATION'
        ;;
esac

stat_bin=$(command -v stat 2>/dev/null || true)
readlink_bin=$(command -v readlink 2>/dev/null || true)
if [ -z "${collection_error:-}" ] && { [ -z "$stat_bin" ] || [ ! -x "$stat_bin" ]; }; then
    scan_completed=false
    scan_error_count=$((scan_error_count + 1))
    collection_error='STAT_COMMAND_UNUSABLE'
fi
if [ -z "${collection_error:-}" ] && { [ -z "$readlink_bin" ] || [ ! -x "$readlink_bin" ]; }; then
    scan_completed=false
    scan_error_count=$((scan_error_count + 1))
    collection_error='READLINK_COMMAND_UNUSABLE'
fi

passwd_path="${test_root}/etc/passwd"
group_path="${test_root}/etc/group"

group_access_state() {
    checked_gid=$1
    checked_group=$2
    if [ ! -r "$passwd_path" ] || [ ! -r "$group_path" ]; then
        printf 'unknown'
        return
    fi
    if awk -F: -v gid="$checked_gid" '
        NR == FNR {
            if ($3 ~ /^[0-9]+$/ && $3 != 0) non_root[$1] = 1
            if ($3 ~ /^[0-9]+$/ && $3 != 0 && $4 == gid) found = 1
            next
        }
        $3 == gid {
            count = split($4, members, ",")
            for (i = 1; i <= count; i++) if (members[i] in non_root) found = 1
        }
        END { exit found ? 0 : 1 }
    ' "$passwd_path" "$group_path" >/dev/null 2>&1; then
        printf 'confirmed_non_owner'
    elif [ "$checked_gid" = '0' ] && [ "$checked_group" = 'root' ]; then
        printf 'none'
    else
        printf 'unknown'
    fi
}

inspect_metadata() {
    metadata_uid=$1
    metadata_owner=$2
    metadata_gid=$3
    metadata_group=$4
    metadata_mode=$5
    supplied_group_access=${6:-auto}

    if ! printf '%s|%s|%s|%s|%s\n' \
        "$metadata_uid" "$metadata_owner" "$metadata_gid" "$metadata_group" "$metadata_mode" | awk -F'|' '
        NF == 5 && $1 ~ /^[0-9]+$/ && $2 != "" && $3 ~ /^[0-9]+$/ && $4 != "" &&
        $5 ~ /^[0-7][0-7][0-7]([0-7])?$/ { valid=1 }
        END { exit valid ? 0 : 1 }
    ' >/dev/null 2>&1; then
        scan_completed=false
        scan_error_count=$((scan_error_count + 1))
        unresolved_object_count=$((unresolved_object_count + 1))
        return
    fi

    checked_object_count=$((checked_object_count + 1))
    regular_file_count=$((regular_file_count + 1))

    owner_conflict=false
    if [ "$metadata_uid" -eq 0 ]; then
        if [ "$metadata_owner" = 'root' ]; then
            root_owned_count=$((root_owned_count + 1))
        else
            root_owned_count=$((root_owned_count + 1))
            owner_conflict=true
            owner_identity_conflict_count=$((owner_identity_conflict_count + 1))
            review_required=true
        fi
    else
        non_root_owned_count=$((non_root_owned_count + 1))
        vulnerable_object_detected=true
    fi

    mode_value=$((0$metadata_mode))
    group_write=false
    other_write=false
    if [ $((mode_value & 0020)) -ne 0 ]; then
        group_write=true
        group_write_detected_count=$((group_write_detected_count + 1))
    fi
    if [ $((mode_value & 0002)) -ne 0 ]; then
        other_write=true
        other_write_detected_count=$((other_write_detected_count + 1))
        writable_by_non_owner_count=$((writable_by_non_owner_count + 1))
        vulnerable_object_detected=true
    fi

    if [ "$group_write" = true ] && [ "$other_write" = false ]; then
        if [ "$supplied_group_access" = 'auto' ]; then
            supplied_group_access=$(group_access_state "$metadata_gid" "$metadata_group")
        fi
        case "$supplied_group_access" in
            confirmed_non_owner)
                writable_by_non_owner_count=$((writable_by_non_owner_count + 1))
                vulnerable_object_detected=true
                ;;
            none) ;;
            *)
                group_write_review_count=$((group_write_review_count + 1))
                review_required=true
                ;;
        esac
    fi
    [ "$owner_conflict" = false ] || review_required=true
}

inspect_regular_file() {
    inspected_path=$1
    metadata_output=$($stat_bin -c '%u|%U|%g|%G|%a' -- "$inspected_path" 2>/dev/null)
    if [ $? -ne 0 ]; then
        scan_completed=false
        scan_error_count=$((scan_error_count + 1))
        unresolved_object_count=$((unresolved_object_count + 1))
        return
    fi
    old_ifs=$IFS
    IFS='|'
    set -- $metadata_output
    IFS=$old_ifs
    if [ "$#" -ne 5 ]; then
        scan_completed=false
        scan_error_count=$((scan_error_count + 1))
        unresolved_object_count=$((unresolved_object_count + 1))
        return
    fi
    inspect_metadata "$1" "$2" "$3" "$4" "$5" auto
}

target_is_in_scope() {
    target_path=$1
    case "$target_path" in
        "${test_root}/etc/systemd/system"/*|"${test_root}/usr/lib/systemd/system"/*|\
        "${test_root}/lib/systemd/system"/*|"${test_root}/etc/init.d"/*|\
        "${test_root}/etc/rc.d"/*|"${test_root}/etc/rc.local"|"${test_root}/etc/rc.sysinit") return 0 ;;
        *) return 1 ;;
    esac
}

inspect_path() {
    candidate=$1
    if [ -L "$candidate" ]; then
        symlink_count=$((symlink_count + 1))
        resolved=$($readlink_bin -f -- "$candidate" 2>/dev/null)
        if [ -z "$resolved" ] || { [ ! -e "$resolved" ] && [ ! -L "$resolved" ]; }; then
            unresolved_object_count=$((unresolved_object_count + 1))
            review_required=true
        elif [ "$resolved" = '/dev/null' ] || [ "$resolved" = "${test_root}/dev/null" ]; then
            masked_symlink_count=$((masked_symlink_count + 1))
        elif ! target_is_in_scope "$resolved"; then
            unresolved_object_count=$((unresolved_object_count + 1))
            review_required=true
        elif [ -f "$resolved" ]; then
            inspect_regular_file "$resolved"
        else
            unresolved_object_count=$((unresolved_object_count + 1))
            review_required=true
        fi
    elif [ -f "$candidate" ]; then
        inspect_regular_file "$candidate"
    elif [ -d "$candidate" ]; then
        scan_tree "$candidate"
    else
        unresolved_object_count=$((unresolved_object_count + 1))
        review_required=true
    fi
}

scan_tree() {
    scan_dir=$1
    if [ ! -r "$scan_dir" ] || [ ! -x "$scan_dir" ]; then
        scan_completed=false
        scan_error_count=$((scan_error_count + 1))
        return
    fi
    for entry in "$scan_dir"/* "$scan_dir"/.[!.]* "$scan_dir"/..?*; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        inspect_path "$entry"
    done
}

process_fixture_scan() {
    fixture_file=$1
    if [ ! -r "$fixture_file" ]; then
        scan_completed=false
        scan_error_count=$((scan_error_count + 1))
        collection_error='FIXTURE_SCAN_UNREADABLE'
        return
    fi
    scan_root_found=true
    while IFS='|' read -r object_kind object_uid object_owner object_gid object_group object_mode object_group_access extra; do
        [ -n "$object_kind" ] || continue
        case "$object_kind" in
            regular|symlink)
                [ "$object_kind" = 'symlink' ] && symlink_count=$((symlink_count + 1))
                inspect_metadata "$object_uid" "$object_owner" "$object_gid" "$object_group" "$object_mode" "${object_group_access:-auto}"
                ;;
            masked_symlink)
                symlink_count=$((symlink_count + 1))
                masked_symlink_count=$((masked_symlink_count + 1))
                ;;
            broken_symlink|external_symlink)
                symlink_count=$((symlink_count + 1))
                unresolved_object_count=$((unresolved_object_count + 1))
                review_required=true
                ;;
            metadata_error)
                scan_completed=false
                scan_error_count=$((scan_error_count + 1))
                unresolved_object_count=$((unresolved_object_count + 1))
                ;;
            scan_error)
                scan_completed=false
                scan_error_count=$((scan_error_count + 1))
                ;;
            *)
                scan_completed=false
                scan_error_count=$((scan_error_count + 1))
                unresolved_object_count=$((unresolved_object_count + 1))
                ;;
        esac
    done < "$fixture_file"
}

if [ -z "${collection_error:-}" ]; then
    if [ -n "$test_root" ] && [ -n "${OS_GUARD_TEST_SCAN_FILE:-}" ]; then
        startup_system_type=${OS_GUARD_TEST_STARTUP_SYSTEM:-systemd}
        process_fixture_scan "$OS_GUARD_TEST_SCAN_FILE"
    else
        systemd_present=false
        init_present=false
        if [ -d "${test_root}/etc/systemd/system" ]; then
            systemd_present=true
            scan_root_found=true
            scan_tree "${test_root}/etc/systemd/system"
        fi
        if [ -d "${test_root}/etc/rc.d" ]; then
            init_present=true
            scan_root_found=true
            scan_tree "${test_root}/etc/rc.d"
        elif [ -d "${test_root}/etc/init.d" ]; then
            init_present=true
            scan_root_found=true
            scan_tree "${test_root}/etc/init.d"
        fi
        for standalone in "${test_root}/etc/rc.local" "${test_root}/etc/rc.sysinit"; do
            if [ -e "$standalone" ] || [ -L "$standalone" ]; then
                init_present=true
                scan_root_found=true
                inspect_path "$standalone"
            fi
        done
        if [ "$systemd_present" = true ] && [ "$init_present" = true ]; then
            startup_system_type='systemd_and_init'
        elif [ "$systemd_present" = true ]; then
            startup_system_type='systemd'
        elif [ "$init_present" = true ]; then
            startup_system_type='init'
        fi
    fi
fi

if [ "$scan_root_found" != true ] && [ -z "${collection_error:-}" ]; then
    scan_completed=false
    scan_error_count=$((scan_error_count + 1))
    collection_error='STARTUP_SCOPE_NOT_FOUND'
fi

if [ "$vulnerable_object_detected" = true ]; then
    status_json='"VULNERABLE"'
    review_state='NOT_REQUIRED'
    reason_code='KISA_U17_OWNER_OR_NON_OWNER_WRITE_VIOLATION'
    decision_reason='At least one startup file has a non-root UID owner or confirmed non-owner write access'
    if [ "$scan_completed" != true ]; then
        error_json='{"code":"PARTIAL_SCAN_FAILED","message":"a vulnerability was confirmed although part of the startup-file scan could not be completed"}'
    fi
elif [ "$scan_completed" != true ]; then
    status_json='"UNCHECKABLE"'
    review_state='NOT_REQUIRED'
    reason_code='KISA_U17_COLLECTION_FAILED'
    decision_reason='The startup-file scope or required metadata could not be collected completely'
    error_code=${collection_error:-STARTUP_SCAN_INCOMPLETE}
    error_json=$(printf '{"code":'; os_guard_json_quote "$error_code"; printf ',"message":"startup file metadata collection failed"}')
elif [ "$checked_object_count" -eq 0 ] && [ "$unresolved_object_count" -eq 0 ]; then
    status_json='"UNCHECKABLE"'
    review_state='NOT_REQUIRED'
    reason_code='KISA_U17_NO_STARTUP_OBJECTS'
    decision_reason='No startup script or unit target was available for a complete KISA assessment'
    error_json='{"code":"NO_STARTUP_OBJECTS_FOUND","message":"no assessable startup file was found"}'
elif [ "$review_required" = true ]; then
    status_json='null'
    review_state='PENDING'
    reason_code='KISA_U17_REVIEW_REQUIRED'
    decision_reason='A symlink target, owner identity, or group-write relationship requires manual review'
else
    status_json='"GOOD"'
    review_state='NOT_REQUIRED'
    reason_code='KISA_U17_ROOT_OWNER_AND_NON_OWNER_WRITE_BLOCKED'
    decision_reason='All assessed startup files are owned by root UID 0 and have no confirmed non-owner write access'
fi

printf '{"item_id":"U-17","status":%s,"review_state":"%s",' "$status_json" "$review_state"
printf '"current_value":{"startup_system_type":'; os_guard_json_quote "$startup_system_type"
printf ',"scan_completed":%s,"checked_object_count":%s,"regular_file_count":%s,' "$scan_completed" "$checked_object_count" "$regular_file_count"
printf '"symlink_count":%s,"masked_symlink_count":%s,"root_owned_count":%s,' "$symlink_count" "$masked_symlink_count" "$root_owned_count"
printf '"non_root_owned_count":%s,"writable_by_non_owner_count":%s,' "$non_root_owned_count" "$writable_by_non_owner_count"
printf '"group_write_detected_count":%s,"other_write_detected_count":%s,' "$group_write_detected_count" "$other_write_detected_count"
printf '"unresolved_object_count":%s,"vulnerable_object_detected":%s},' "$unresolved_object_count" "$vulnerable_object_detected"
printf '"evidence":{"item_id":"U-17","inspection_target":"system startup scripts and active systemd configuration targets",'
printf '"collection_method":"Read-only bounded traversal and structured stat metadata; symlinks are resolved without executing units",'
printf '"assessment_condition":"root UID ownership and no confirmed write access for a non-owner principal",'
printf '"startup_system_type":'; os_guard_json_quote "$startup_system_type"
printf ',"scan_completed":%s,"checked_object_count":%s,"regular_file_count":%s,' "$scan_completed" "$checked_object_count" "$regular_file_count"
printf '"symlink_count":%s,"root_owned_count":%s,"non_root_owned_count":%s,' "$symlink_count" "$root_owned_count" "$non_root_owned_count"
printf '"writable_by_non_owner_count":%s,"group_write_detected_count":%s,' "$writable_by_non_owner_count" "$group_write_detected_count"
printf '"other_write_detected_count":%s,"unresolved_object_count":%s,' "$other_write_detected_count" "$unresolved_object_count"
printf '"owner_identity_conflict_count":%s,"group_write_review_count":%s,' "$owner_identity_conflict_count" "$group_write_review_count"
printf '"vulnerable_object_detected":%s,"reason_code":' "$vulnerable_object_detected"; os_guard_json_quote "$reason_code"
printf ',"os":{"distro":'; os_guard_json_quote "$distro"; printf ',"version_id":'; os_guard_json_quote "$version_id"; printf '}'
printf ',"kernel":'; os_guard_json_quote "$kernel"
printf ',"observed_at":'; os_guard_json_quote "$observed_at"; printf ',"module_version":'; os_guard_json_quote "$module_version"
printf ',"decision_reason":'; os_guard_json_quote "$decision_reason"
printf '},"error":%s}\n' "$error_json"
