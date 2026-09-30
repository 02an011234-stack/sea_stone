#!/bin/sh
set -u
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd); . "$SCRIPT_DIR/../lib/common.sh"
distro=${OS_GUARD_DISTRO:-unknown}; version_id=${OS_GUARD_VERSION_ID:-unknown}; module_version=${OS_GUARD_MODULE_VERSION:-unknown}
observed_at=$(os_guard_utc_now); kernel=$(uname -r 2>/dev/null || printf unknown); test_root=${OS_GUARD_TEST_ROOT:-}
status_json=null; review_state=PENDING; error_json=null; reason_code=KISA_U25_ANALYSIS_PENDING; judgment_basis='World-writable regular files have not been evaluated'
scan_scope=root_filesystem_regular_files; xdev_enabled=true; scan_completed=false; world_writable_count=0; approved_count=0; unapproved_count=0
unresolved_count=0; warning_count=0; scan_error_count=0; manual_review_required=false; collection_error=''; record_limit=100000
case "$distro:$version_id" in rocky:9|rocky:9.*|rocky:10|rocky:10.*|ubuntu:22|ubuntu:22.*|ubuntu:24|ubuntu:24.*) ;; *) collection_error=UNSUPPORTED_OS_CONFIGURATION; scan_error_count=1 ;; esac
find_bin=$(command -v find 2>/dev/null || true); timeout_bin=$(command -v timeout 2>/dev/null || true)
if [ -z "$collection_error" ] && { [ -z "$find_bin" ] || [ ! -x "$find_bin" ]; }; then collection_error=FIND_COMMAND_UNUSABLE; scan_error_count=1; fi
if [ -z "$collection_error" ] && { [ -z "$timeout_bin" ] || [ ! -x "$timeout_bin" ]; }; then collection_error=TIMEOUT_COMMAND_UNUSABLE; scan_error_count=1; fi
process_fixture() {
    IFS='|' read -r state found approved unapproved unresolved warnings extra < "$1" || true
    case "${state:-}" in complete|partial_warning|scan_error|timeout) ;; *) collection_error=SCAN_RESULT_PARSE_FAILED; scan_error_count=1; return 0 ;; esac
    for v in "$found" "$approved" "$unapproved" "$unresolved" "$warnings"; do case "$v" in ''|*[!0-9]*) collection_error=SCAN_RESULT_PARSE_FAILED; scan_error_count=1; return 0 ;; esac; done
    world_writable_count=$found; approved_count=$approved; unapproved_count=$unapproved; unresolved_count=$unresolved; warning_count=$warnings
    if [ $((approved_count + unapproved_count)) -gt "$world_writable_count" ]; then collection_error=SCAN_RESULT_PARSE_FAILED; scan_error_count=1
    elif [ "$state" = scan_error ]; then collection_error=FILESYSTEM_SCAN_FAILED; scan_error_count=1
    elif [ "$state" = timeout ]; then collection_error=FILESYSTEM_SCAN_TIMEOUT; scan_error_count=1
    else scan_completed=true; fi
    return 0
}
scan_filesystem() {
    output=$($timeout_bin 10 "$find_bin" / -xdev -type f -perm -0002 -printf '.\n' 2>/dev/null); rc=$?
    [ "$rc" -eq 124 ] && { collection_error=FILESYSTEM_SCAN_TIMEOUT; scan_error_count=1; return; }
    [ "$rc" -eq 0 ] || { collection_error=FILESYSTEM_SCAN_FAILED; scan_error_count=1; return; }
    count=0
    while IFS= read -r marker; do [ -n "$marker" ] || continue; [ "$marker" = . ] || { collection_error=SCAN_RESULT_PARSE_FAILED; scan_error_count=1; return; }; count=$((count + 1)); [ "$count" -le "$record_limit" ] || { collection_error=SCAN_RESULT_LIMIT_EXCEEDED; scan_error_count=1; return; }; done <<EOF
$output
EOF
    world_writable_count=$count; scan_completed=true
}
if [ -z "$collection_error" ]; then
    if [ -n "$test_root" ] && [ -n "${OS_GUARD_TEST_SCAN_FILE:-}" ]; then [ -r "$OS_GUARD_TEST_SCAN_FILE" ] && process_fixture "$OS_GUARD_TEST_SCAN_FILE" || collection_error=FIXTURE_SCAN_UNREADABLE
    else scan_filesystem; fi
fi
if [ "$unapproved_count" -gt 0 ]; then status_json='"VULNERABLE"'; review_state=NOT_REQUIRED; reason_code=KISA_U25_VERIFIED_UNAPPROVED_WORLD_WRITABLE; judgment_basis='A locally verified unapproved world-writable regular file was identified'
elif [ -n "$collection_error" ] || [ "$scan_completed" != true ] || [ "$unresolved_count" -gt 0 ]; then status_json='"UNCHECKABLE"'; review_state=NOT_REQUIRED; reason_code=KISA_U25_SCAN_INCOMPLETE; judgment_basis='The bounded filesystem scan could not be completed or validated'; code=${collection_error:-SCAN_RESULT_UNRESOLVED}; error_json=$(printf '{"code":'; os_guard_json_quote "$code"; printf ',"message":"world-writable file scan failed"}')
elif [ "$world_writable_count" -eq 0 ]; then status_json='"GOOD"'; review_state=NOT_REQUIRED; reason_code=KISA_U25_NONE_FOUND; judgment_basis='The completed bounded scan found no world-writable regular file'
elif [ "$approved_count" -eq "$world_writable_count" ]; then status_json='"GOOD"'; review_state=NOT_REQUIRED; reason_code=KISA_U25_ALL_LOCALLY_APPROVED; judgment_basis='All discovered world-writable regular files are covered by an approved local operational policy'
else status_json=null; review_state=PENDING; manual_review_required=true; reason_code=KISA_U25_REVIEW_REQUIRED; judgment_basis='World-writable regular files were found but their operational necessity is not established by approved local policy'; fi
printf '{"item_id":"U-25","status":%s,"review_state":"%s","current_value":{"scan_scope":' "$status_json" "$review_state"; os_guard_json_quote "$scan_scope"
printf ',"xdev_enabled":%s,"scan_completed":%s,"world_writable_count":%s,"approved_count":%s,"unapproved_count":%s,"unresolved_count":%s,"warning_count":%s,"scan_error_count":%s,"manual_review_required":%s},' "$xdev_enabled" "$scan_completed" "$world_writable_count" "$approved_count" "$unapproved_count" "$unresolved_count" "$warning_count" "$scan_error_count" "$manual_review_required"
printf '"evidence":{"item_id":"U-25","scan_scope":'; os_guard_json_quote "$scan_scope"; printf ',"collection_method":"Read-only fixed find scan for regular files with other-write permission and xdev/timeout/result limits","xdev_enabled":%s,"scan_completed":%s,"world_writable_count":%s,"approved_count":%s,"unapproved_count":%s,"unresolved_count":%s,"warning_count":%s,"scan_error_count":%s,"manual_review_required":%s,"reason_code":' "$xdev_enabled" "$scan_completed" "$world_writable_count" "$approved_count" "$unapproved_count" "$unresolved_count" "$warning_count" "$scan_error_count" "$manual_review_required"; os_guard_json_quote "$reason_code"
printf ',"os":{"distro":'; os_guard_json_quote "$distro"; printf ',"version_id":'; os_guard_json_quote "$version_id"; printf '},"kernel":'; os_guard_json_quote "$kernel"; printf ',"module_version":'; os_guard_json_quote "$module_version"; printf ',"observed_at":'; os_guard_json_quote "$observed_at"; printf ',"judgment_basis":'; os_guard_json_quote "$judgment_basis"; printf '},"error":%s}\n' "$error_json"
