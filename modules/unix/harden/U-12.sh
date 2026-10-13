#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_content.sh"

HARDEN_ITEM_ID='U-12'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-12.sh"
HARDEN_TARGET_DESCRIPTION='static global shell session timeout configuration'
HARDEN_RISK_LEVEL='MEDIUM'

u12_configuration_files=''
u12_append_profile=false

os_guard_item_validate_content_policy() {
    if [ -z "$content_test_root" ] || \
        [ "$content_test_root" = '/' ] || \
        [ "${OS_GUARD_TEST_POLICY_FIXTURE:-false}" != 'true' ]; then
        os_guard_content_set_error \
            'POLICY_INTEGRATION_REQUIRED' \
            'trusted U-12 session-timeout policy integration is not available'
        return 1
    fi
    if [ "${OS_GUARD_TEST_SESSION_TIMEOUT_POLICY_APPROVED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_SESSION_TIMEOUT_SCOPE:-}" != 'global-supported-shells' ]; then
        os_guard_content_set_error \
            'SESSION_TIMEOUT_POLICY_NOT_APPROVED' \
            'the fixture policy must approve the supported global shell scope'
        return 1
    fi
    if [ "${OS_GUARD_TEST_SESSION_TIMEOUT_EXCEPTIONS:-}" != 'none' ]; then
        os_guard_content_set_error \
            'SESSION_TIMEOUT_EXCEPTIONS_UNSUPPORTED' \
            'account-specific timeout exceptions cannot be applied safely by this module'
        return 1
    fi
    return 0
}

append_u12_file() {
    candidate_path=$1
    if [ -z "$u12_configuration_files" ]; then
        u12_configuration_files=$candidate_path
    else
        u12_configuration_files="$u12_configuration_files
$candidate_path"
    fi
}

collect_u12_files() {
    profile_path="${content_test_root}/etc/profile"
    if [ ! -f "$profile_path" ] || [ -L "$profile_path" ]; then
        os_guard_content_set_error \
            'PROFILE_TARGET_UNSAFE' \
            'the required global profile is missing or symbolic'
        return 1
    fi
    append_u12_file "$profile_path"

    if awk '
        /^[[:space:]]*#/ { next }
        /\/etc\/profile\.d/ && /(^|[;[:space:]])(\.|source)[[:space:]]/ { found=1 }
        END { exit found ? 0 : 1 }
    ' "$profile_path"; then
        for candidate_path in "${content_test_root}/etc/profile.d"/*.sh; do
            [ -e "$candidate_path" ] || continue
            if [ -L "$candidate_path" ] || [ ! -f "$candidate_path" ]; then
                os_guard_content_set_error \
                    'PROFILE_FRAGMENT_UNSAFE' \
                    'a global profile fragment cannot be changed safely'
                return 1
            fi
            append_u12_file "$candidate_path"
        done
    fi

    for candidate_path in \
        "${content_test_root}/etc/csh.cshrc" \
        "${content_test_root}/etc/csh.login"; do
        if [ -e "$candidate_path" ] || [ -L "$candidate_path" ]; then
            if [ -L "$candidate_path" ] || [ ! -f "$candidate_path" ]; then
                os_guard_content_set_error \
                    'CSH_TARGET_UNSAFE' \
                    'a global csh profile cannot be changed safely'
                return 1
            fi
            append_u12_file "$candidate_path"
        fi
    done
    return 0
}

u12_file_has_unsafe_setting() {
    inspected_path=$1
    awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*(export[[:space:]]+)?TMOUT=["\047]?[0-9]+["\047]?([[:space:]]*(;|#|$))/ {
            value=$0
            sub(/^[[:space:]]*(export[[:space:]]+)?TMOUT=["\047]?/, "", value)
            sub(/["\047]?[[:space:]]*(;.*|#.*)?$/, "", value)
            if (value + 0 <= 0 || value + 0 > 600) unsafe=1
        }
        /^[[:space:]]*set[[:space:]]+autologout[[:space:]]*=[[:space:]]*[0-9]+/ {
            value=$0
            sub(/^.*=[[:space:]]*/, "", value)
            sub(/[[:space:]]*(;.*|#.*)?$/, "", value)
            if (value + 0 <= 0 || value + 0 > 10) unsafe=1
        }
        END { exit unsafe ? 0 : 1 }
    ' "$inspected_path"
}

u12_any_timeout_setting() {
    while IFS= read -r inspected_path; do
        if awk '
            /^[[:space:]]*#/ { next }
            /^[[:space:]]*(export[[:space:]]+)?TMOUT=/ { found=1 }
            /^[[:space:]]*set[[:space:]]+autologout[[:space:]]*=/ { found=1 }
            END { exit found ? 0 : 1 }
        ' "$inspected_path"; then
            return 0
        fi
    done <<EOF
$u12_configuration_files
EOF
    return 1
}

os_guard_item_render_content() {
    source_path=$1
    append_timeout=false
    if [ "$u12_append_profile" = true ] && \
        [ "$source_path" = "${content_test_root}/etc/profile" ]; then
        append_timeout=true
    fi

    awk -v append_timeout="$append_timeout" '
        function replace_tmout(line,    prefix,value,suffix) {
            prefix=line
            sub(/TMOUT=.*/, "TMOUT=", prefix)
            value=line
            sub(/^.*TMOUT=["\047]?/, "", value)
            suffix=value
            sub(/^[0-9]+["\047]?/, "", suffix)
            return prefix "600" suffix
        }
        function replace_autologout(line,    prefix,value,suffix) {
            prefix=line
            sub(/=.*/, "=", prefix)
            value=line
            sub(/^.*=[[:space:]]*/, "", value)
            suffix=value
            sub(/^[0-9]+/, "", suffix)
            return prefix " 10" suffix
        }
        {
            output=$0
            if ($0 !~ /^[[:space:]]*#/ &&
                $0 ~ /^[[:space:]]*(export[[:space:]]+)?TMOUT=["\047]?[0-9]+["\047]?/) {
                value=$0
                sub(/^.*TMOUT=["\047]?/, "", value)
                sub(/["\047]?[[:space:]]*(;.*|#.*)?$/, "", value)
                if (value + 0 <= 0 || value + 0 > 600) output=replace_tmout($0)
            } else if ($0 !~ /^[[:space:]]*#/ &&
                       $0 ~ /^[[:space:]]*set[[:space:]]+autologout[[:space:]]*=[[:space:]]*[0-9]+/) {
                value=$0
                sub(/^.*=[[:space:]]*/, "", value)
                sub(/[[:space:]]*(;.*|#.*)?$/, "", value)
                if (value + 0 <= 0 || value + 0 > 10) output=replace_autologout($0)
            }
            print output
        }
        END {
            if (append_timeout == "true") {
                print "TMOUT=600"
                print "export TMOUT"
            }
        }
    ' "$source_path"
}

os_guard_item_discover_content_targets() {
    if ! collect_u12_files; then
        return 1
    fi

    CONTENT_CURRENT_EFFECTIVE_VALUE='not safely logged; see existing CHECK evidence'
    unsafe_count=0
    while IFS= read -r candidate_path; do
        [ -n "$candidate_path" ] || continue
        if u12_file_has_unsafe_setting "$candidate_path"; then
            unsafe_count=$((unsafe_count + 1))
            display_path=${candidate_path#"$content_test_root"}
            os_guard_content_add_target \
                "$candidate_path" "$display_path" \
                'static timeout assignment' \
                'replace only unsafe static timeout value with the KISA maximum' || return 1
        fi
    done <<EOF
$u12_configuration_files
EOF

    if [ "$unsafe_count" -eq 0 ]; then
        if u12_any_timeout_setting; then
            os_guard_content_set_error \
                'TIMEOUT_POLICY_NOT_SAFELY_EDITABLE' \
                'the vulnerable timeout policy is not a supported static assignment'
            return 1
        fi
        u12_append_profile=true
        profile_path="${content_test_root}/etc/profile"
        os_guard_content_add_target \
            "$profile_path" '/etc/profile' 'end of file' \
            'append one static TMOUT=600 export policy' || return 1
    fi
    return 0
}

os_guard_content_run_module "${1:-}"
