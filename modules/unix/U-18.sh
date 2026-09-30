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
shadow_path="${test_root}/etc/shadow"

status_json='null'
review_state='PENDING'
manual_review_required=true
collection_error=''
error_json='null'
reason_code='KISA_U18_METADATA_ANALYSIS_PENDING'
decision_reason='The /etc/shadow ownership and permission metadata has not been evaluated'

file_exists=false
file_type='unknown'
metadata_collection_success=false
owner_is_root=false
owner_uid_is_zero=false
owner_name_state='unknown'
permission_octal=''
permission_within_0400=false
extra_permission_bits_detected=false

case "$distro:$version_id" in
    rocky:9|rocky:9.*|rocky:10|rocky:10.*|ubuntu:22|ubuntu:22.*|ubuntu:24|ubuntu:24.*) ;;
    *) collection_error='UNSUPPORTED_OS_CONFIGURATION' ;;
esac

if [ -z "$collection_error" ]; then
    if [ -e "$shadow_path" ] || [ -L "$shadow_path" ]; then
        file_exists=true
        if [ -L "$shadow_path" ]; then
            file_type='symbolic_link'
        elif [ -f "$shadow_path" ]; then
            file_type='regular_file'
        elif [ -d "$shadow_path" ]; then
            file_type='directory'
        else
            file_type='special_file'
        fi
    else
        collection_error='SHADOW_FILE_NOT_FOUND'
    fi
fi

stat_bin=''
test_stat_override=false
if [ -z "$collection_error" ]; then
    if [ -n "$test_root" ] && [ -n "${OS_GUARD_TEST_STAT_BIN:-}" ]; then
        stat_bin=$OS_GUARD_TEST_STAT_BIN
        test_stat_override=true
    else
        stat_bin=$(command -v stat 2>/dev/null || true)
    fi
    if [ -z "$stat_bin" ]; then
        collection_error='STAT_COMMAND_NOT_FOUND'
    elif [ ! -f "$stat_bin" ] || { [ "$test_stat_override" = false ] && [ ! -x "$stat_bin" ]; }; then
        collection_error='STAT_COMMAND_UNUSABLE'
    fi
fi

owner_uid=''
owner_name=''
if [ -z "$collection_error" ]; then
    metadata_output=$("$stat_bin" -c '%u|%U|%a' -- "$shadow_path" 2>/dev/null)
    stat_rc=$?
    if [ "$stat_rc" -ne 0 ]; then
        collection_error='STAT_COMMAND_FAILED'
    elif ! printf '%s\n' "$metadata_output" | awk -F'|' '
        NF == 3 && $1 ~ /^[0-9]+$/ && $2 != "" && $3 ~ /^[0-7][0-7][0-7]([0-7])?$/ { valid=1 }
        END { exit valid ? 0 : 1 }
    ' >/dev/null 2>&1; then
        collection_error='STAT_OUTPUT_INVALID'
    else
        owner_uid=$(printf '%s\n' "$metadata_output" | awk -F'|' '{print $1}')
        owner_name=$(printf '%s\n' "$metadata_output" | awk -F'|' '{print $2}')
        permission_octal=$(printf '%s\n' "$metadata_output" | awk -F'|' '{print $3}')
        metadata_collection_success=true
    fi
fi

owner_identity_conflict=false
if [ "$metadata_collection_success" = true ]; then
    if [ "$owner_uid" -eq 0 ]; then
        owner_uid_is_zero=true
    fi
    case "$owner_name" in
        root)
            owner_name_state='root'
            if [ "$owner_uid_is_zero" = true ]; then
                owner_is_root=true
            else
                owner_identity_conflict=true
            fi
            ;;
        0|UNKNOWN|unknown)
            owner_name_state='numeric_or_unresolved'
            if [ "$owner_uid_is_zero" = true ]; then
                owner_identity_conflict=true
            fi
            ;;
        *)
            owner_name_state='non_root'
            if [ "$owner_uid_is_zero" = true ]; then
                owner_identity_conflict=true
            fi
            ;;
    esac

    permission_value=$((0$permission_octal))
    extra_permission_value=$((permission_value & ~0400))
    if [ "$extra_permission_value" -eq 0 ]; then
        permission_within_0400=true
    else
        extra_permission_bits_detected=true
    fi
fi

if [ -n "$collection_error" ]; then
    status_json='"UNCHECKABLE"'
    review_state='NOT_REQUIRED'
    manual_review_required=false
    reason_code='KISA_U18_COLLECTION_FAILED'
    decision_reason='The /etc/shadow ownership or permission metadata could not be collected safely'
    error_json=$(printf '{"code":'; os_guard_json_quote "$collection_error"; printf ',"message":"shadow file metadata collection failed"}')
elif [ "$owner_uid_is_zero" != true ] || [ "$permission_within_0400" != true ]; then
    status_json='"VULNERABLE"'
    review_state='NOT_REQUIRED'
    manual_review_required=false
    reason_code='KISA_U18_OWNER_OR_PERMISSION_VIOLATION'
    decision_reason='The /etc/shadow owner is not UID 0 or permission bits exist outside the KISA 0400 allowance mask'
elif [ "$file_type" != 'regular_file' ] || [ "$owner_identity_conflict" = true ]; then
    status_json='null'
    review_state='PENDING'
    manual_review_required=true
    reason_code='KISA_U18_REVIEW_REQUIRED'
    decision_reason='The metadata is readable but a nonstandard file type or owner name resolution conflict requires manual review'
else
    status_json='"GOOD"'
    review_state='NOT_REQUIRED'
    manual_review_required=false
    reason_code='KISA_U18_ROOT_OWNER_AND_PERMISSION_ALLOWED'
    decision_reason='The /etc/shadow file is a regular file owned by root UID 0 with no permission bit outside the KISA 0400 allowance mask'
fi

printf '{"item_id":"U-18","status":%s,"review_state":"%s",' "$status_json" "$review_state"
printf '"current_value":{"target":"/etc/shadow","file_exists":%s,"file_type":' "$file_exists"; os_guard_json_quote "$file_type"
printf ',"owner_is_root":%s,"owner_uid_is_zero":%s,"owner_name_state":' "$owner_is_root" "$owner_uid_is_zero"; os_guard_json_quote "$owner_name_state"
printf ',"permission_octal":'; if [ -n "$permission_octal" ]; then os_guard_json_quote "$permission_octal"; else printf 'null'; fi
printf ',"permission_within_0400":%s,"extra_permission_bits_detected":%s,' "$permission_within_0400" "$extra_permission_bits_detected"
printf '"metadata_collection_success":%s,"manual_review_required":%s},' "$metadata_collection_success" "$manual_review_required"
printf '"evidence":{"item_id":"U-18","target":"/etc/shadow","inspection_target":"/etc/shadow file metadata",'
printf '"collection_method":"Read file type and structured stat UID, owner-name, and octal permission metadata without reading file contents",'
printf '"assessment_condition":"UID 0 resolving to root and no permission bit outside the 0400 allowance mask",'
printf '"file_exists":%s,"file_type":' "$file_exists"; os_guard_json_quote "$file_type"
printf ',"owner_is_root":%s,"owner_uid_is_zero":%s,"owner_name_state":' "$owner_is_root" "$owner_uid_is_zero"; os_guard_json_quote "$owner_name_state"
printf ',"permission_octal":'; if [ -n "$permission_octal" ]; then os_guard_json_quote "$permission_octal"; else printf 'null'; fi
printf ',"permission_within_0400":%s,"extra_permission_bits_detected":%s,' "$permission_within_0400" "$extra_permission_bits_detected"
printf '"metadata_collection_success":%s,"reason_code":' "$metadata_collection_success"; os_guard_json_quote "$reason_code"
printf ',"os":{"distro":'; os_guard_json_quote "$distro"; printf ',"version_id":'; os_guard_json_quote "$version_id"; printf '}'
printf ',"kernel":'; os_guard_json_quote "$kernel"
printf ',"observed_at":'; os_guard_json_quote "$observed_at"; printf ',"module_version":'; os_guard_json_quote "$module_version"
printf ',"decision_reason":'; os_guard_json_quote "$decision_reason"
printf '},"error":%s}\n' "$error_json"
