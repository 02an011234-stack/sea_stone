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
target="${test_root}/etc/services"

status_json='null'
review_state='PENDING'
error_json='null'
reason_code='KISA_U22_ANALYSIS_PENDING'
judgment_basis='The services file metadata has not been evaluated'

file_exists=false
file_type='unknown'
metadata_collection_success=false
owner_allowed_json='null'
owner_identity_consistent_json='null'
permission_octal='unknown'
permission_within_0644_json='null'
extra_permission_bits_detected_json='null'
collection_error=''
review_required=false
vulnerability_detected=false

case "$distro:$version_id" in
    rocky:9|rocky:9.*|rocky:10|rocky:10.*|ubuntu:22|ubuntu:22.*|ubuntu:24|ubuntu:24.*) ;;
    *) collection_error='UNSUPPORTED_OS_CONFIGURATION' ;;
esac

stat_bin=$(command -v stat 2>/dev/null || true)
readlink_bin=$(command -v readlink 2>/dev/null || true)
getent_bin=$(command -v getent 2>/dev/null || true)
if [ -z "$collection_error" ] && { [ -z "$stat_bin" ] || [ ! -x "$stat_bin" ]; }; then collection_error='STAT_COMMAND_UNUSABLE'; fi
if [ -z "$collection_error" ] && { [ -z "$readlink_bin" ] || [ ! -x "$readlink_bin" ]; }; then collection_error='READLINK_COMMAND_UNUSABLE'; fi

verify_allowed_owner() {
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

evaluate_metadata() {
    metadata_uid=$1
    metadata_owner=$2
    metadata_mode=$3
    identity_hint=${4:-}
    if ! printf '%s|%s|%s\n' "$metadata_uid" "$metadata_owner" "$metadata_mode" | awk -F'|' '
        NF == 3 && $1 ~ /^[0-9]+$/ && $2 != "" && $3 ~ /^[0-7][0-7][0-7]([0-7])?$/ { valid=1 }
        END { exit valid ? 0 : 1 }
    ' >/dev/null 2>&1; then
        collection_error='METADATA_PARSE_FAILED'
        return
    fi

    metadata_collection_success=true
    permission_octal=$metadata_mode
    case "$metadata_owner" in
        root|bin|sys)
            verify_allowed_owner "$metadata_uid" "$metadata_owner" "$identity_hint"
            identity_result=$?
            if [ "$identity_result" -eq 0 ]; then
                owner_allowed_json=true; owner_identity_consistent_json=true
            else
                owner_allowed_json='null'; owner_identity_consistent_json=false; review_required=true
            fi
            ;;
        *)
            owner_allowed_json=false; owner_identity_consistent_json=true; vulnerability_detected=true
            ;;
    esac

    permission_value=$((0$metadata_mode))
    extra_permission_value=$((permission_value & ~0644))
    if [ "$extra_permission_value" -eq 0 ]; then
        permission_within_0644_json=true; extra_permission_bits_detected_json=false
    else
        permission_within_0644_json=false; extra_permission_bits_detected_json=true; vulnerability_detected=true
    fi
}

collect_regular_metadata() {
    inspected_path=$1
    metadata_output=$($stat_bin -c '%u|%U|%a' -- "$inspected_path" 2>/dev/null)
    if [ $? -ne 0 ]; then collection_error='STAT_FAILED'; return; fi
    old_ifs=$IFS; IFS='|'; set -- $metadata_output; IFS=$old_ifs
    if [ "$#" -ne 3 ]; then collection_error='METADATA_PARSE_FAILED'; return; fi
    evaluate_metadata "$1" "$2" "$3"
}

process_fixture_metadata() {
    fixture_file=$1
    if [ ! -r "$fixture_file" ]; then collection_error='FIXTURE_METADATA_UNREADABLE'; return; fi
    IFS='|' read -r object_kind object_uid object_owner object_mode identity_hint extra < "$fixture_file" || true
    case "${object_kind:-}" in
        regular|symlink)
            file_exists=true; file_type=$object_kind
            evaluate_metadata "$object_uid" "$object_owner" "$object_mode" "$identity_hint"
            ;;
        broken_symlink)
            file_exists=true; file_type='broken_symlink'; review_required=true
            ;;
        nonstandard)
            file_exists=true; file_type='nonstandard'; review_required=true
            ;;
        absent) file_exists=false; file_type='missing'; collection_error='TARGET_NOT_FOUND' ;;
        stat_error) file_exists=true; file_type='regular'; collection_error='STAT_FAILED' ;;
        *) file_exists=true; file_type='unknown'; collection_error='METADATA_PARSE_FAILED' ;;
    esac
}

if [ -z "$collection_error" ]; then
    if [ -n "$test_root" ] && [ -n "${OS_GUARD_TEST_METADATA_FILE:-}" ]; then
        process_fixture_metadata "$OS_GUARD_TEST_METADATA_FILE"
    elif [ -L "$target" ]; then
        file_exists=true; file_type='symlink'
        resolved=$($readlink_bin -f -- "$target" 2>/dev/null)
        if [ -z "$resolved" ] || [ ! -e "$resolved" ]; then
            file_type='broken_symlink'; review_required=true
        elif [ -f "$resolved" ]; then
            collect_regular_metadata "$resolved"
        else
            file_type='nonstandard'; review_required=true
        fi
    elif [ -f "$target" ]; then
        file_exists=true; file_type='regular'; collect_regular_metadata "$target"
    elif [ -e "$target" ]; then
        file_exists=true; file_type='nonstandard'; review_required=true
    else
        file_exists=false; file_type='missing'; collection_error='TARGET_NOT_FOUND'
    fi
fi

if [ "$vulnerability_detected" = true ]; then
    status_json='"VULNERABLE"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U22_OWNER_OR_PERMISSION_VIOLATION'
    judgment_basis='The services file has an owner outside verified root, bin, or sys identities or permission bits outside the KISA 0644 allowance mask'
elif [ -n "$collection_error" ]; then
    status_json='"UNCHECKABLE"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U22_COLLECTION_FAILED'
    judgment_basis='The services file or its required metadata could not be collected and validated'
    error_json=$(printf '{"code":'; os_guard_json_quote "$collection_error"; printf ',"message":"services file metadata collection failed"}')
elif [ "$review_required" = true ]; then
    status_json='null'; review_state='PENDING'
    reason_code='KISA_U22_REVIEW_REQUIRED'
    judgment_basis='The owner identity, symbolic-link target, or nonstandard file type requires manual review'
else
    status_json='"GOOD"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U22_ALLOWED_OWNER_AND_PERMISSION'
    judgment_basis='The services file has a verified root, bin, or sys owner and no permission bit outside the KISA 0644 allowance mask'
fi

printf '{"item_id":"U-22","status":%s,"review_state":"%s",' "$status_json" "$review_state"
printf '"current_value":{"target":"/etc/services","file_exists":%s,"file_type":' "$file_exists"; os_guard_json_quote "$file_type"
printf ',"metadata_collection_success":%s,"owner_allowed":%s,"owner_identity_consistent":%s,' "$metadata_collection_success" "$owner_allowed_json" "$owner_identity_consistent_json"
printf '"permission_octal":'; os_guard_json_quote "$permission_octal"
printf ',"permission_within_0644":%s,"extra_permission_bits_detected":%s},' "$permission_within_0644_json" "$extra_permission_bits_detected_json"
printf '"evidence":{"item_id":"U-22","target":"/etc/services","collection_method":"Read-only structured stat metadata without reading services file contents",'
printf '"file_exists":%s,"file_type":' "$file_exists"; os_guard_json_quote "$file_type"
printf ',"metadata_collection_success":%s,"owner_allowed":%s,"owner_identity_consistent":%s,' "$metadata_collection_success" "$owner_allowed_json" "$owner_identity_consistent_json"
printf '"permission_octal":'; os_guard_json_quote "$permission_octal"
printf ',"permission_within_0644":%s,"extra_permission_bits_detected":%s,"reason_code":' "$permission_within_0644_json" "$extra_permission_bits_detected_json"; os_guard_json_quote "$reason_code"
printf ',"os":{"distro":'; os_guard_json_quote "$distro"; printf ',"version_id":'; os_guard_json_quote "$version_id"; printf '}'
printf ',"kernel":'; os_guard_json_quote "$kernel"
printf ',"observed_at":'; os_guard_json_quote "$observed_at"; printf ',"module_version":'; os_guard_json_quote "$module_version"
printf ',"judgment_basis":'; os_guard_json_quote "$judgment_basis"
printf '},"error":%s}\n' "$error_json"
