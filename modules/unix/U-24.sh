#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/../lib/common.sh"

distro=${OS_GUARD_DISTRO:-unknown}; version_id=${OS_GUARD_VERSION_ID:-unknown}
module_version=${OS_GUARD_MODULE_VERSION:-unknown}; observed_at=$(os_guard_utc_now)
kernel=$(uname -r 2>/dev/null || printf 'unknown'); test_root=${OS_GUARD_TEST_ROOT:-}

status_json='null'; review_state='PENDING'; error_json='null'; collection_error=''
reason_code='KISA_U24_ANALYSIS_PENDING'; judgment_basis='User environment file metadata has not been evaluated'
account_count=0; existing_file_count=0; checked_file_count=0; root_owned_count=0; account_owned_count=0
owner_violation_count=0; writable_by_others_count=0; acl_write_count=0; symlink_count=0; unresolved_count=0
scan_completed=false; manual_review_required=false

case "$distro:$version_id" in rocky:9|rocky:9.*|rocky:10|rocky:10.*|ubuntu:22|ubuntu:22.*|ubuntu:24|ubuntu:24.*) ;; *) collection_error='UNSUPPORTED_OS_CONFIGURATION' ;; esac
stat_bin=$(command -v stat 2>/dev/null || true); getfacl_bin=$(command -v getfacl 2>/dev/null || true)
if [ -z "$collection_error" ] && { [ -z "$stat_bin" ] || [ ! -x "$stat_bin" ]; }; then collection_error='STAT_COMMAND_UNUSABLE'; fi

inspect_environment_file() {
    env_file=$1; account_name=$2; account_uid=$3
    existing_file_count=$((existing_file_count + 1))
    [ -L "$env_file" ] && symlink_count=$((symlink_count + 1))
    if [ ! -f "$env_file" ]; then unresolved_count=$((unresolved_count + 1)); manual_review_required=true; return; fi
    metadata=$($stat_bin -c '%u|%U|%a' -- "$env_file" 2>/dev/null) || { collection_error='STAT_FAILED'; return; }
    old_ifs=$IFS; IFS='|'; set -- $metadata; IFS=$old_ifs
    if [ "$#" -ne 3 ]; then collection_error='METADATA_PARSE_FAILED'; return; fi
    file_uid=$1; file_owner=$2; file_mode=$3
    if ! printf '%s|%s|%s\n' "$file_uid" "$file_owner" "$file_mode" | awk -F'|' 'NF==3 && $1~/^[0-9]+$/ && $2!="" && $3~/^[0-7][0-7][0-7]([0-7])?$/ {ok=1} END{exit ok?0:1}'; then collection_error='METADATA_PARSE_FAILED'; return; fi
    checked_file_count=$((checked_file_count + 1))
    if [ "$file_uid" -eq 0 ] && [ "$file_owner" = root ]; then root_owned_count=$((root_owned_count + 1))
    elif [ "$file_uid" -eq "$account_uid" ] && [ "$file_owner" = "$account_name" ]; then account_owned_count=$((account_owned_count + 1))
    elif [ "$file_owner" = root ] || [ "$file_owner" = "$account_name" ]; then unresolved_count=$((unresolved_count + 1)); manual_review_required=true
    else owner_violation_count=$((owner_violation_count + 1)); fi
    mode_value=$((0$file_mode))
    if [ $((mode_value & 0022)) -ne 0 ]; then writable_by_others_count=$((writable_by_others_count + 1)); fi
    if [ -n "$getfacl_bin" ] && [ -x "$getfacl_bin" ]; then
        acl_output=$($getfacl_bin -cp -- "$env_file" 2>/dev/null) || { unresolved_count=$((unresolved_count + 1)); manual_review_required=true; return; }
        if printf '%s\n' "$acl_output" | awk -F: '
            /^user:[^:]+:/ && $3 ~ /w/ {bad=1}
            /^group:/ && $3 ~ /w/ {bad=1}
            /^other::/ && $3 ~ /w/ {bad=1}
            END {exit bad?0:1}
        '; then acl_write_count=$((acl_write_count + 1)); fi
    fi
}

process_fixture() {
    fixture=$1
    IFS='|' read -r state accounts files checked root_owned account_owned owner_bad mode_bad acl_bad symlinks unresolved extra < "$fixture" || true
    case "${state:-}" in complete|scan_error) ;; *) collection_error='SCAN_RESULT_PARSE_FAILED'; return ;; esac
    for value in "$accounts" "$files" "$checked" "$root_owned" "$account_owned" "$owner_bad" "$mode_bad" "$acl_bad" "$symlinks" "$unresolved"; do case "$value" in ''|*[!0-9]*) collection_error='SCAN_RESULT_PARSE_FAILED'; return ;; esac; done
    account_count=$accounts; existing_file_count=$files; checked_file_count=$checked; root_owned_count=$root_owned
    account_owned_count=$account_owned; owner_violation_count=$owner_bad; writable_by_others_count=$mode_bad
    acl_write_count=$acl_bad; symlink_count=$symlinks; unresolved_count=$unresolved
    if [ "$state" = complete ]; then scan_completed=true; else collection_error='ENVIRONMENT_FILE_SCAN_FAILED'; fi
    [ "$unresolved_count" -gt 0 ] && manual_review_required=true
    return 0
}

if [ -z "$collection_error" ]; then
    if [ -n "$test_root" ] && [ -n "${OS_GUARD_TEST_SCAN_FILE:-}" ]; then
        [ -r "$OS_GUARD_TEST_SCAN_FILE" ] && process_fixture "$OS_GUARD_TEST_SCAN_FILE" || collection_error='FIXTURE_SCAN_UNREADABLE'
    else
        passwd_file="${test_root}/etc/passwd"
        if [ ! -r "$passwd_file" ]; then collection_error='PASSWD_UNREADABLE'
        else
            while IFS=: read -r account_name password_field account_uid account_gid gecos home_dir login_shell extra; do
                [ -n "$account_name$password_field$account_uid$account_gid$gecos$home_dir$login_shell" ] || continue
                case "$account_uid" in ''|*[!0-9]*) collection_error='PASSWD_PARSE_FAILED'; break ;; esac
                [ -n "$home_dir" ] || { unresolved_count=$((unresolved_count + 1)); manual_review_required=true; continue; }
                account_count=$((account_count + 1))
                for env_name in .profile .kshrc .cshrc .bashrc .bash_profile .login .exrc .netrc; do
                    candidate="${test_root}${home_dir}/$env_name"
                    if [ -e "$candidate" ] || [ -L "$candidate" ]; then inspect_environment_file "$candidate" "$account_name" "$account_uid"; fi
                    [ -z "$collection_error" ] || break
                done
                [ -z "$collection_error" ] || break
            done < "$passwd_file"
            [ "$account_count" -gt 0 ] || collection_error='PASSWD_EMPTY_OR_INVALID'
            [ -z "$collection_error" ] && scan_completed=true
        fi
    fi
fi

if [ "$owner_violation_count" -gt 0 ] || [ "$writable_by_others_count" -gt 0 ] || [ "$acl_write_count" -gt 0 ]; then
    status_json='"VULNERABLE"'; review_state='NOT_REQUIRED'; reason_code='KISA_U24_OWNER_OR_WRITE_PERMISSION_VIOLATION'; judgment_basis='At least one bounded user environment file has an invalid owner or write permission for a non-owner principal'
elif [ -n "$collection_error" ] || [ "$scan_completed" != true ]; then
    status_json='"UNCHECKABLE"'; review_state='NOT_REQUIRED'; reason_code='KISA_U24_COLLECTION_FAILED'; judgment_basis='Account-to-home relationships or required environment file metadata could not be collected completely'
    error_code=${collection_error:-ENVIRONMENT_FILE_SCAN_INCOMPLETE}; error_json=$(printf '{"code":'; os_guard_json_quote "$error_code"; printf ',"message":"environment file metadata collection failed"}')
elif [ "$manual_review_required" = true ]; then
    status_json='null'; review_state='PENDING'; reason_code='KISA_U24_REVIEW_REQUIRED'; judgment_basis='An account-home identity, file type, symbolic link, or ACL result requires manual review'
else status_json='"GOOD"'; review_state='NOT_REQUIRED'; reason_code='KISA_U24_OWNER_AND_WRITE_PERMISSIONS_ALLOWED'; judgment_basis='All existing bounded environment files are owned by root or their home account and are not writable by other principals'; fi

printf '{"item_id":"U-24","status":%s,"review_state":"%s","current_value":{' "$status_json" "$review_state"
printf '"account_count":%s,"existing_file_count":%s,"checked_file_count":%s,"root_owned_count":%s,"account_owned_count":%s,' "$account_count" "$existing_file_count" "$checked_file_count" "$root_owned_count" "$account_owned_count"
printf '"owner_violation_count":%s,"writable_by_others_count":%s,"acl_write_count":%s,"symlink_count":%s,"unresolved_count":%s,"scan_completed":%s},' "$owner_violation_count" "$writable_by_others_count" "$acl_write_count" "$symlink_count" "$unresolved_count" "$scan_completed"
printf '"evidence":{"item_id":"U-24","inspection_target":"bounded account home environment files","collection_method":"Read-only passwd relationship and stat/ACL metadata inspection",'
printf '"account_count":%s,"existing_file_count":%s,"checked_file_count":%s,"root_owned_count":%s,"account_owned_count":%s,' "$account_count" "$existing_file_count" "$checked_file_count" "$root_owned_count" "$account_owned_count"
printf '"owner_violation_count":%s,"writable_by_others_count":%s,"acl_write_count":%s,"symlink_count":%s,"unresolved_count":%s,"scan_completed":%s,"reason_code":' "$owner_violation_count" "$writable_by_others_count" "$acl_write_count" "$symlink_count" "$unresolved_count" "$scan_completed"; os_guard_json_quote "$reason_code"
printf ',"os":{"distro":'; os_guard_json_quote "$distro"; printf ',"version_id":'; os_guard_json_quote "$version_id"; printf '},"kernel":'; os_guard_json_quote "$kernel"; printf ',"module_version":'; os_guard_json_quote "$module_version"; printf ',"observed_at":'; os_guard_json_quote "$observed_at"; printf ',"judgment_basis":'; os_guard_json_quote "$judgment_basis"; printf '},"error":%s}\n' "$error_json"
