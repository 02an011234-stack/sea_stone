#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_content.sh"

HARDEN_ITEM_ID='U-30'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-30.sh"
HARDEN_TARGET_DESCRIPTION='statically resolvable shell UMASK configuration'
HARDEN_RISK_LEVEL='MEDIUM'

u30_files=''
u30_append_profile=false

append_u30_file() {
    candidate_path=$1
    if [ -z "$u30_files" ]; then
        u30_files=$candidate_path
    else
        u30_files="$u30_files
$candidate_path"
    fi
}

collect_u30_files() {
    for candidate_path in \
        "${content_test_root}/etc/profile" \
        "${content_test_root}/etc/login.defs"; do
        if [ -e "$candidate_path" ] || [ -L "$candidate_path" ]; then
            if [ -L "$candidate_path" ] || [ ! -f "$candidate_path" ]; then
                os_guard_content_set_error 'UMASK_TARGET_UNSAFE' 'a UMASK source is not a regular file'
                return 1
            fi
            append_u30_file "$candidate_path"
        fi
    done
    for candidate_path in "${content_test_root}/etc/profile.d"/*.sh; do
        [ -e "$candidate_path" ] || continue
        if [ -L "$candidate_path" ] || [ ! -f "$candidate_path" ]; then
            os_guard_content_set_error 'UMASK_TARGET_UNSAFE' 'a UMASK fragment is not a regular file'
            return 1
        fi
        append_u30_file "$candidate_path"
    done

    passwd_path="${content_test_root}/etc/passwd"
    if [ -r "$passwd_path" ]; then
        while IFS=: read -r account_name password_field account_uid account_gid \
            gecos home_directory login_shell extra_field; do
            [ -n "$account_name" ] || continue
            case "$account_uid" in
                ''|*[!0-9]*)
                    os_guard_content_set_error 'PASSWD_PARSE_FAILED' 'account UID metadata is invalid'
                    return 1
                    ;;
            esac
            for profile_name in .profile .bashrc .bash_profile .kshrc .cshrc .login; do
                candidate_path="${content_test_root}${home_directory}/$profile_name"
                if [ -e "$candidate_path" ] || [ -L "$candidate_path" ]; then
                    if [ -L "$candidate_path" ] || [ ! -f "$candidate_path" ]; then
                        os_guard_content_set_error 'UMASK_TARGET_UNSAFE' 'an account UMASK source is unsafe'
                        return 1
                    fi
                    append_u30_file "$candidate_path"
                fi
            done
        done < "$passwd_path"
    fi
    return 0
}

u30_file_has_unsafe_mask() {
    inspected_path=$1
    awk '
        function octal(value,    digit_index,numeric,digit) {
            numeric=0
            for (digit_index=1; digit_index<=length(value); digit_index++) {
                digit=substr(value,digit_index,1)
                numeric=(numeric*8)+digit
            }
            return numeric
        }
        /^[[:space:]]*#/ { next }
        {
            line=$0
            sub(/[[:space:]]*#.*/, "", line)
            if (line ~ /^[[:space:]]*(umask[[:space:]]+|UMASK[[:space:]]*=)[0-7]+/) {
                value=line
                sub(/^[[:space:]]*(umask[[:space:]]+|UMASK[[:space:]]*=)/, "", value)
                sub(/[[:space:]].*$/, "", value)
                numeric=octal(value)
                if (and(numeric, 18) != 18) unsafe=1
            }
        }
        END { exit unsafe ? 0 : 1 }
    ' "$inspected_path"
}

u30_any_mask_setting() {
    while IFS= read -r inspected_path; do
        if awk '
            /^[[:space:]]*#/ { next }
            /^[[:space:]]*(umask[[:space:]]+|UMASK[[:space:]]*=)/ { found=1 }
            END { exit found ? 0 : 1 }
        ' "$inspected_path"; then
            return 0
        fi
    done <<EOF
$u30_files
EOF
    return 1
}

os_guard_item_render_content() {
    source_path=$1
    append_mask=false
    if [ "$u30_append_profile" = true ] && \
        [ "$source_path" = "${content_test_root}/etc/profile" ]; then
        append_mask=true
    fi

    awk -v append_mask="$append_mask" '
        function octal(value,    digit_index,numeric,digit) {
            numeric=0
            for (digit_index=1; digit_index<=length(value); digit_index++) {
                digit=substr(value,digit_index,1)
                numeric=(numeric*8)+digit
            }
            return numeric
        }
        {
            output=$0
            if ($0 !~ /^[[:space:]]*#/ &&
                match($0, /^[[:space:]]*(umask[[:space:]]+|UMASK[[:space:]]*=)[0-7]+/)) {
                matched=substr($0,RSTART,RLENGTH)
                value=matched
                sub(/^[[:space:]]*(umask[[:space:]]+|UMASK[[:space:]]*=)/,"",value)
                if (and(octal(value),18) != 18) {
                    replacement=matched
                    sub(/[0-7]+$/,"027",replacement)
                    output=substr($0,1,RSTART-1) replacement substr($0,RSTART+RLENGTH)
                }
            }
            print output
        }
        END {
            if (append_mask == "true") print "umask 027"
        }
    ' "$source_path"
}

os_guard_item_discover_content_targets() {
    if ! collect_u30_files; then
        return 1
    fi
    if [ -z "$u30_files" ]; then
        os_guard_content_set_error 'NO_UMASK_SOURCE' 'no safe UMASK configuration source exists'
        return 1
    fi

    CONTENT_CURRENT_EFFECTIVE_VALUE='not safely logged; see existing CHECK evidence'
    unsafe_count=0
    while IFS= read -r candidate_path; do
        [ -n "$candidate_path" ] || continue
        if u30_file_has_unsafe_mask "$candidate_path"; then
            unsafe_count=$((unsafe_count + 1))
            display_path=${candidate_path#"$content_test_root"}
            os_guard_content_add_target \
                "$candidate_path" "$display_path" 'static UMASK assignment' \
                'replace only noncompliant static UMASK values with 027' || return 1
        fi
    done <<EOF
$u30_files
EOF

    if [ "$unsafe_count" -eq 0 ]; then
        if u30_any_mask_setting; then
            os_guard_content_set_error \
                'UMASK_POLICY_NOT_SAFELY_EDITABLE' \
                'the vulnerable UMASK policy is not a supported static assignment'
            return 1
        fi
        profile_path="${content_test_root}/etc/profile"
        if [ ! -f "$profile_path" ] || [ -L "$profile_path" ]; then
            os_guard_content_set_error \
                'PROFILE_TARGET_UNSAFE' \
                'a regular global profile is required to add UMASK safely'
            return 1
        fi
        u30_append_profile=true
        os_guard_content_add_target \
            "$profile_path" '/etc/profile' 'end of file' \
            'append one static umask 027 policy' || return 1
    fi
    return 0
}

os_guard_content_run_module "${1:-}"
