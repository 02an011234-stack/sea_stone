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
reason_code='KISA_U23_ANALYSIS_PENDING'
judgment_basis='The root filesystem special-permission scan has not been evaluated'

scan_scope='root_filesystem_root_owned_regular_files'
xdev_enabled=true
scan_completed=false
suid_count=0
sgid_count=0
suid_sgid_count=0
sticky_count=0
unresolved_count=0
scan_error_count=0
warning_count=0
manual_review_required=false
verified_unnecessary_suid_count=0
verified_unnecessary_sgid_count=0
collection_error=''
record_limit=100000

case "$distro:$version_id" in
    rocky:9|rocky:9.*|rocky:10|rocky:10.*|ubuntu:22|ubuntu:22.*|ubuntu:24|ubuntu:24.*) ;;
    *) collection_error='UNSUPPORTED_OS_CONFIGURATION'; scan_error_count=1 ;;
esac

find_bin=$(command -v find 2>/dev/null || true)
timeout_bin=$(command -v timeout 2>/dev/null || true)
if [ -z "$collection_error" ] && { [ -z "$find_bin" ] || [ ! -x "$find_bin" ]; }; then collection_error='FIND_COMMAND_UNUSABLE'; scan_error_count=1; fi
if [ -z "$collection_error" ] && { [ -z "$timeout_bin" ] || [ ! -x "$timeout_bin" ]; }; then collection_error='TIMEOUT_COMMAND_UNUSABLE'; scan_error_count=1; fi

count_mode() {
    scanned_mode=$1
    case "$scanned_mode" in
        [0-7]|[0-7][0-7]|[0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;;
        *) collection_error='SCAN_RESULT_PARSE_FAILED'; scan_error_count=$((scan_error_count + 1)); return ;;
    esac
    mode_value=$((0$scanned_mode))
    has_suid=false; has_sgid=false
    if [ $((mode_value & 04000)) -ne 0 ]; then suid_count=$((suid_count + 1)); has_suid=true; fi
    if [ $((mode_value & 02000)) -ne 0 ]; then sgid_count=$((sgid_count + 1)); has_sgid=true; fi
    if [ "$has_suid" = true ] && [ "$has_sgid" = true ]; then suid_sgid_count=$((suid_sgid_count + 1)); fi
    if [ $((mode_value & 01000)) -ne 0 ]; then sticky_count=$((sticky_count + 1)); fi
}

process_fixture_scan() {
    fixture_file=$1
    if [ ! -r "$fixture_file" ]; then collection_error='FIXTURE_SCAN_UNREADABLE'; scan_error_count=1; return; fi
    IFS='|' read -r fixture_state fixture_suid fixture_sgid fixture_both fixture_sticky fixture_bad_suid fixture_bad_sgid fixture_unresolved fixture_warnings extra < "$fixture_file" || true
    case "${fixture_state:-}" in
        complete|partial_warning|scan_error|timeout) ;;
        *) collection_error='SCAN_RESULT_PARSE_FAILED'; scan_error_count=1; return ;;
    esac
    for fixture_value in "$fixture_suid" "$fixture_sgid" "$fixture_both" "$fixture_sticky" "$fixture_bad_suid" "$fixture_bad_sgid" "$fixture_unresolved" "$fixture_warnings"; do
        case "$fixture_value" in ''|*[!0-9]*) collection_error='SCAN_RESULT_PARSE_FAILED'; scan_error_count=1; return ;; esac
    done
    suid_count=$fixture_suid; sgid_count=$fixture_sgid; suid_sgid_count=$fixture_both; sticky_count=$fixture_sticky
    verified_unnecessary_suid_count=$fixture_bad_suid; verified_unnecessary_sgid_count=$fixture_bad_sgid
    unresolved_count=$fixture_unresolved; warning_count=$fixture_warnings
    case "$fixture_state" in
        complete|partial_warning) scan_completed=true ;;
        scan_error) collection_error='FILESYSTEM_SCAN_FAILED'; scan_error_count=1 ;;
        timeout) collection_error='FILESYSTEM_SCAN_TIMEOUT'; scan_error_count=1 ;;
    esac
}

scan_root_filesystem() {
    scan_output=$($timeout_bin 10 "$find_bin" / -xdev -user root -type f \( -perm -04000 -o -perm -02000 -o -perm -01000 \) -printf '%m\n' 2>/dev/null)
    scan_exit=$?
    if [ "$scan_exit" -eq 124 ]; then collection_error='FILESYSTEM_SCAN_TIMEOUT'; scan_error_count=1; return; fi
    if [ "$scan_exit" -ne 0 ]; then collection_error='FILESYSTEM_SCAN_FAILED'; scan_error_count=1; return; fi

    record_count=0
    while IFS= read -r mode_record; do
        [ -n "$mode_record" ] || continue
        record_count=$((record_count + 1))
        if [ "$record_count" -gt "$record_limit" ]; then
            collection_error='SCAN_RESULT_LIMIT_EXCEEDED'; scan_error_count=1; return
        fi
        count_mode "$mode_record"
        [ -z "$collection_error" ] || return
    done <<EOF
$scan_output
EOF
    scan_completed=true
}

if [ -z "$collection_error" ]; then
    if [ -n "$test_root" ] && [ -n "${OS_GUARD_TEST_SCAN_FILE:-}" ]; then
        process_fixture_scan "$OS_GUARD_TEST_SCAN_FILE"
    else
        scan_root_filesystem
    fi
fi

if [ "$verified_unnecessary_suid_count" -gt 0 ] || [ "$verified_unnecessary_sgid_count" -gt 0 ]; then
    status_json='"VULNERABLE"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U23_VERIFIED_UNNECESSARY_SPECIAL_PERMISSION'
    judgment_basis='A locally verified unnecessary root-owned regular file with SUID or SGID permission was identified'
elif [ -n "$collection_error" ] || [ "$scan_completed" != true ]; then
    status_json='"UNCHECKABLE"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U23_SCAN_INCOMPLETE'
    judgment_basis='The bounded root filesystem scan could not be completed or its result could not be validated'
    error_code=${collection_error:-FILESYSTEM_SCAN_INCOMPLETE}
    error_json=$(printf '{"code":'; os_guard_json_quote "$error_code"; printf ',"message":"special-permission filesystem scan failed"}')
elif [ "$unresolved_count" -gt 0 ]; then
    status_json='"UNCHECKABLE"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U23_SCAN_UNRESOLVED'
    judgment_basis='The scan completed but one or more result records could not be resolved reliably'
    error_json='{"code":"SCAN_RESULT_UNRESOLVED","message":"special-permission scan contains unresolved records"}'
elif [ "$suid_count" -gt 0 ] || [ "$sgid_count" -gt 0 ]; then
    status_json='null'; review_state='PENDING'; manual_review_required=true
    reason_code='KISA_U23_MANUAL_REVIEW_REQUIRED'
    judgment_basis='SUID or SGID root-owned regular files were found, but operational necessity cannot be established automatically without an approved local policy'
else
    status_json='"GOOD"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U23_NO_SUID_OR_SGID_FOUND'
    judgment_basis='The completed root filesystem scan found no root-owned regular file with SUID or SGID permission'
fi

printf '{"item_id":"U-23","status":%s,"review_state":"%s",' "$status_json" "$review_state"
printf '"current_value":{"scan_scope":'; os_guard_json_quote "$scan_scope"
printf ',"xdev_enabled":%s,"scan_completed":%s,"suid_count":%s,"sgid_count":%s,"suid_sgid_count":%s,' "$xdev_enabled" "$scan_completed" "$suid_count" "$sgid_count" "$suid_sgid_count"
printf '"sticky_count":%s,"unresolved_count":%s,"scan_error_count":%s,"warning_count":%s,' "$sticky_count" "$unresolved_count" "$scan_error_count" "$warning_count"
printf '"manual_review_required":%s,"verified_unnecessary_suid_count":%s,"verified_unnecessary_sgid_count":%s},' "$manual_review_required" "$verified_unnecessary_suid_count" "$verified_unnecessary_sgid_count"
printf '"evidence":{"item_id":"U-23","scan_scope":'; os_guard_json_quote "$scan_scope"
printf ',"collection_method":"Read-only GNU find metadata scan with fixed root, root-owner, regular-file, special-permission, xdev, timeout, and result-limit constraints",'
printf '"xdev_enabled":%s,"scan_completed":%s,"suid_count":%s,"sgid_count":%s,"suid_sgid_count":%s,' "$xdev_enabled" "$scan_completed" "$suid_count" "$sgid_count" "$suid_sgid_count"
printf '"sticky_count":%s,"unresolved_count":%s,"scan_error_count":%s,"warning_count":%s,' "$sticky_count" "$unresolved_count" "$scan_error_count" "$warning_count"
printf '"manual_review_required":%s,"verified_unnecessary_suid_count":%s,"verified_unnecessary_sgid_count":%s,"reason_code":' "$manual_review_required" "$verified_unnecessary_suid_count" "$verified_unnecessary_sgid_count"; os_guard_json_quote "$reason_code"
printf ',"os":{"distro":'; os_guard_json_quote "$distro"; printf ',"version_id":'; os_guard_json_quote "$version_id"; printf '}'
printf ',"kernel":'; os_guard_json_quote "$kernel"
printf ',"observed_at":'; os_guard_json_quote "$observed_at"; printf ',"module_version":'; os_guard_json_quote "$module_version"
printf ',"judgment_basis":'; os_guard_json_quote "$judgment_basis"
printf '},"error":%s}\n' "$error_json"
