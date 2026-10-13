#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_content.sh"

HARDEN_ITEM_ID='U-14'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-14.sh"
HARDEN_TARGET_DESCRIPTION='statically resolvable effective root login PATH assignment'
HARDEN_RISK_LEVEL='HIGH'

u14_files=''
u14_target_file=''
u14_target_line=''

append_u14_file() {
    candidate_path=$1
    if [ -z "$u14_files" ]; then
        u14_files=$candidate_path
    else
        u14_files="$u14_files
$candidate_path"
    fi
}

append_existing_u14_file() {
    candidate_path=$1
    if [ ! -e "$candidate_path" ] && [ ! -L "$candidate_path" ]; then
        return 0
    fi
    if [ -L "$candidate_path" ] || [ ! -f "$candidate_path" ] || [ ! -r "$candidate_path" ]; then
        os_guard_content_set_error \
            'ROOT_PATH_TARGET_UNSAFE' \
            'a root PATH startup source cannot be changed safely'
        return 1
    fi
    append_u14_file "$candidate_path"
    return 0
}

collect_u14_files() {
    profile_path="${content_test_root}/etc/profile"
    if ! append_existing_u14_file "$profile_path"; then
        return 1
    fi
    if [ ! -f "$profile_path" ]; then
        os_guard_content_set_error 'PROFILE_NOT_FOUND' 'the global profile does not exist'
        return 1
    fi

    if awk '
        /^[[:space:]]*#/ { next }
        /\/etc\/profile\.d/ && /(^|[;[:space:]])(\.|source)[[:space:]]/ { found=1 }
        END { exit found ? 0 : 1 }
    ' "$profile_path"; then
        for candidate_path in "${content_test_root}/etc/profile.d"/*.sh; do
            [ -e "$candidate_path" ] || continue
            append_existing_u14_file "$candidate_path" || return 1
        done
    fi

    passwd_path="${content_test_root}/etc/passwd"
    root_record=$(awk -F: '$1 == "root" { print; exit }' "$passwd_path" 2>/dev/null || true)
    if [ -z "$root_record" ]; then
        os_guard_content_set_error 'ROOT_ACCOUNT_UNRESOLVED' 'the root account startup relationship is unavailable'
        return 1
    fi
    root_home=$(printf '%s\n' "$root_record" | awk -F: '{ print $6 }')
    root_shell=$(printf '%s\n' "$root_record" | awk -F: '{ print $7 }')
    case "$root_home:$root_shell" in
        /root:/bin/bash|/root:/usr/bin/bash)
            for profile_name in .bash_profile .bash_login .profile .bashrc; do
                append_existing_u14_file \
                    "${content_test_root}${root_home}/$profile_name" || return 1
            done
            ;;
        /root:/bin/sh|/root:/usr/bin/sh)
            append_existing_u14_file \
                "${content_test_root}${root_home}/.profile" || return 1
            ;;
        *)
            os_guard_content_set_error \
                'ROOT_STARTUP_RELATIONSHIP_UNRESOLVED' \
                'the root home or shell is nonstandard'
            return 1
            ;;
    esac
    return 0
}

select_u14_effective_assignment() {
    assignment_count=0
    while IFS= read -r candidate_path; do
        [ -n "$candidate_path" ] || continue
        assignment_lines=$(awk '
            /^[[:space:]]*#/ { next }
            /^[[:space:]]*(export[[:space:]]+|readonly[[:space:]]+)?PATH=/ { print NR }
        ' "$candidate_path")
        while IFS= read -r assignment_line; do
            [ -n "$assignment_line" ] || continue
            assignment_count=$((assignment_count + 1))
            u14_target_file=$candidate_path
            u14_target_line=$assignment_line
        done <<EOF
$assignment_lines
EOF
    done <<EOF
$u14_files
EOF

    if [ "$assignment_count" -eq 0 ]; then
        os_guard_content_set_error 'PATH_ASSIGNMENT_NOT_FOUND' 'no static PATH assignment was found'
        return 1
    fi

    selected_line=$(sed -n "${u14_target_line}p" "$u14_target_file")
    selected_value=${selected_line#*=}
    case "$selected_value" in
        *'`'*|*'$('*|*'$'*)
            os_guard_content_set_error \
                'DYNAMIC_PATH_NOT_EDITABLE' \
                'the effective PATH assignment contains dynamic expansion'
            return 1
            ;;
    esac
    return 0
}

os_guard_item_render_content() {
    source_path=$1
    awk -v target_line="$u14_target_line" '
        function sanitize_path(value,    quote,count,component_index,component,result,last_component) {
            quote=""
            if ((substr(value,1,1) == "\"" && substr(value,length(value),1) == "\"") ||
                (substr(value,1,1) == "\047" && substr(value,length(value),1) == "\047")) {
                quote=substr(value,1,1)
                value=substr(value,2,length(value)-2)
            }
            count=split(value,components,":")
            last_component=components[count]
            result=""
            for (component_index=1; component_index<=count; component_index++) {
                component=components[component_index]
                if ((component == "" || component == ".") && component_index < count) continue
                if (result == "") result=component
                else result=result ":" component
            }
            if ((last_component == "" || last_component == ".") && result !~ /(^|:)\.?$/) {
                result=result ":" last_component
            }
            return quote result quote
        }
        {
            if (NR != target_line) {
                print
                next
            }
            prefix=$0
            sub(/=.*/, "=", prefix)
            value=$0
            sub(/^[^=]*=/, "", value)
            print prefix sanitize_path(value)
        }
    ' "$source_path"
}

os_guard_item_discover_content_targets() {
    if ! collect_u14_files || ! select_u14_effective_assignment; then
        return 1
    fi
    CONTENT_CURRENT_EFFECTIVE_VALUE='redacted PATH summary; see existing CHECK evidence'
    display_path=${u14_target_file#"$content_test_root"}
    os_guard_content_add_target \
        "$u14_target_file" "$display_path" \
        "line $u14_target_line" \
        'remove only current-directory elements before the final PATH position'
}

os_guard_content_run_module "${1:-}"
