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
scan_root=${test_root:-/}

status_json='null'
review_state='PENDING'
collection_error=''
error_json='null'
reason_code='KISA_U15_SCAN_PENDING'
decision_reason='The root filesystem orphan ownership scan has not completed'

scan_target='/'
scan_scope='root_filesystem_only'
scan_attempted=false
scan_complete=false
orphaned_entry_found=false
observed_match_count=0
first_match_type='none'
find_exit_code=-1

case "$distro:$version_id" in
    rocky:9|rocky:9.*|rocky:10|rocky:10.*|ubuntu:22|ubuntu:22.*|ubuntu:24|ubuntu:24.*) ;;
    *) collection_error='UNSUPPORTED_OS_CONFIGURATION' ;;
esac

find_bin=''
test_find_override=false
if [ -z "$collection_error" ]; then
    if [ -n "$test_root" ] && [ -n "${OS_GUARD_TEST_FIND_BIN:-}" ]; then
        find_bin=$OS_GUARD_TEST_FIND_BIN
        test_find_override=true
    else
        find_bin=$(command -v find 2>/dev/null || true)
    fi
    if [ -z "$find_bin" ]; then
        collection_error='FIND_COMMAND_NOT_FOUND'
    elif [ ! -f "$find_bin" ] || { [ "$test_find_override" = false ] && [ ! -x "$find_bin" ]; }; then
        collection_error='FIND_COMMAND_UNUSABLE'
    fi
fi

scan_output=''
if [ -z "$collection_error" ]; then
    scan_attempted=true
    # KISA U-15 checks the root filesystem for entries whose user or group
    # cannot be resolved. -quit limits sensitive path handling and runtime;
    # only the first matching object's type is retained, never its path.
    scan_output=$("$find_bin" "$scan_root" -xdev \( -nouser -o -nogroup \) -printf '%y\n' -quit 2>/dev/null)
    find_exit_code=$?

    case "$scan_output" in
        '') ;;
        b|c|d|f|l|p|s)
            orphaned_entry_found=true
            observed_match_count=1
            case "$scan_output" in
                b) first_match_type='block_device' ;;
                c) first_match_type='character_device' ;;
                d) first_match_type='directory' ;;
                f) first_match_type='regular_file' ;;
                l) first_match_type='symbolic_link' ;;
                p) first_match_type='fifo' ;;
                s) first_match_type='socket' ;;
            esac
            ;;
        *) collection_error='FIND_OUTPUT_INVALID' ;;
    esac

    if [ "$find_exit_code" -eq 0 ]; then
        scan_complete=true
    fi
fi

if [ "$orphaned_entry_found" = true ]; then
    status_json='"VULNERABLE"'
    review_state='NOT_REQUIRED'
    reason_code='KISA_U15_ORPHANED_OWNER_OR_GROUP_FOUND'
    decision_reason='At least one file or directory on the root filesystem has no resolvable owner or group'
elif [ -n "$collection_error" ]; then
    status_json='"UNCHECKABLE"'
    review_state='NOT_REQUIRED'
    reason_code='KISA_U15_COLLECTION_FAILED'
    decision_reason='The orphan ownership scan could not be performed or its output was invalid'
    error_json=$(printf '{"code":'; os_guard_json_quote "$collection_error"; printf ',"message":"File ownership scan failed"}')
elif [ "$scan_complete" != true ]; then
    status_json='"UNCHECKABLE"'
    review_state='NOT_REQUIRED'
    reason_code='KISA_U15_SCAN_INCOMPLETE'
    decision_reason='No orphaned entry was observed, but the root filesystem scan did not complete successfully'
    error_json='{"code":"FILESYSTEM_SCAN_INCOMPLETE","message":"File ownership scan was incomplete"}'
else
    status_json='"GOOD"'
    review_state='NOT_REQUIRED'
    reason_code='KISA_U15_NO_ORPHANED_OWNER_OR_GROUP'
    decision_reason='The completed root filesystem scan found no file or directory without a resolvable owner or group'
fi

printf '{"item_id":"U-15","status":%s,"review_state":"%s",' "$status_json" "$review_state"
printf '"current_value":{"scan_target":"%s","scan_scope":"%s",' "$scan_target" "$scan_scope"
printf '"scan_attempted":%s,"scan_complete":%s,"orphaned_entry_found":%s,' "$scan_attempted" "$scan_complete" "$orphaned_entry_found"
printf '"observed_match_count":%s,"first_match_type":' "$observed_match_count"; os_guard_json_quote "$first_match_type"
printf ',"find_exit_code":%s},' "$find_exit_code"
printf '"evidence":{"item_id":"U-15","inspection_target":"Root filesystem files and directories",'
printf '"collection_method":"Read-only find scan using -xdev and the -nouser or -nogroup predicates; stop after the first match without exporting paths",'
printf '"assessment_condition":"Any unresolved owner or group is vulnerable; a complete scan with no match is good",'
printf '"scan_success":%s,"observed_summary":{"orphaned_entry_found":%s,"observed_match_count":%s,"first_match_type":' "$scan_complete" "$orphaned_entry_found" "$observed_match_count"
os_guard_json_quote "$first_match_type"; printf '},"reason_code":'; os_guard_json_quote "$reason_code"
printf ',"os":{"distro":'; os_guard_json_quote "$distro"; printf ',"version_id":'; os_guard_json_quote "$version_id"; printf '}'
printf ',"kernel":'; os_guard_json_quote "$kernel"
printf ',"observed_at":'; os_guard_json_quote "$observed_at"; printf ',"module_version":'; os_guard_json_quote "$module_version"
printf ',"decision_reason":'; os_guard_json_quote "$decision_reason"
printf '},"error":%s}\n' "$error_json"
