#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/../lib/common.sh"

distro=${OS_GUARD_DISTRO:-unknown}
version_id=${OS_GUARD_VERSION_ID:-unknown}
module_version=${OS_GUARD_MODULE_VERSION:-unknown}
observed_at=$(os_guard_utc_now)
kernel=$(uname -r 2>/dev/null || printf unknown)
test_root=${OS_GUARD_TEST_ROOT:-}

status_json=null
review_state=PENDING
reason_code=KISA_U30_NOT_EVALUATED
judgment_basis='UMASK sources were not evaluated'
error_json=null

checked_source_count=0
effective_value_count=0
compliant_count=0
noncompliant_count=0
ambiguity_count=0
collection_error=''
effective_mask=''
required_mask_decimal=$((0022))

case "$distro:$version_id" in
    rocky:9|rocky:9.*|rocky:10|rocky:10.*|ubuntu:22|ubuntu:22.*|ubuntu:24|ubuntu:24.*)
        ;;
    *)
        collection_error=UNSUPPORTED_OS_CONFIGURATION
        ;;
esac

is_supported_umask() {
    candidate_mask=$1
    case "$candidate_mask" in
        [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7])
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

evaluate_mask() {
    current_umask=$1

    if ! is_supported_umask "$current_umask"; then
        ambiguity_count=$((ambiguity_count + 1))
        return
    fi

    effective_value_count=$((effective_value_count + 1))
    effective_mask=$current_umask

    # Treat both operands as arithmetic values. The required octal 022 mask is
    # decimal 18 here, which avoids comparing decimal 18 with string "0022".
    current_umask_decimal=$((0$current_umask))
    validation_result=$((current_umask_decimal & required_mask_decimal))

    if [ "$validation_result" -eq "$required_mask_decimal" ]; then
        compliant_count=$((compliant_count + 1))
    else
        noncompliant_count=$((noncompliant_count + 1))
    fi
}

extract_umask_values() {
    printf '%s\n' "$1" | awk '
        {
            remaining=$0
            pattern="(^|[;[:space:]])(umask|UMASK)[[:space:]=]+[^;[:space:]]+"
            while (match(remaining, pattern)) {
                token=substr(remaining, RSTART, RLENGTH)
                sub(/^.*(umask|UMASK)[[:space:]=]+/, "", token)
                print token
                remaining=substr(remaining, RSTART + RLENGTH)
            }
        }
    '
}

parse_source() {
    source_path=$1
    if [ ! -r "$source_path" ]; then
        collection_error=SOURCE_UNREADABLE
        return
    fi

    checked_source_count=$((checked_source_count + 1))
    while IFS= read -r source_line || [ -n "$source_line" ]; do
        clean_line=$(printf '%s\n' "$source_line" | sed 's/[[:space:]]*#.*$//')
        [ -n "$clean_line" ] || continue

        case "$clean_line" in
            *'if '*|*'case '*|*'$('*)
                ambiguity_count=$((ambiguity_count + 1))
                ;;
        esac

        extracted_values=$(extract_umask_values "$clean_line" 2>/dev/null) || {
            collection_error=SOURCE_PARSE_FAILED
            return
        }
        [ -n "$extracted_values" ] || continue

        while IFS= read -r extracted_mask; do
            [ -n "$extracted_mask" ] || continue
            evaluate_mask "$extracted_mask"
        done <<EOF
$extracted_values
EOF
    done < "$source_path"
}

load_fixture_result() {
    fixture_path=$1
    IFS='|' read -r fixture_state fixture_checked fixture_effective \
        fixture_compliant fixture_noncompliant fixture_ambiguous \
        fixture_mask fixture_extra < "$fixture_path" || true

    case "${fixture_state:-}" in
        complete|read_error)
            ;;
        *)
            collection_error=RESULT_PARSE_FAILED
            ;;
    esac

    for numeric_value in \
        "$fixture_checked" "$fixture_effective" "$fixture_compliant" \
        "$fixture_noncompliant" "$fixture_ambiguous"; do
        case "$numeric_value" in
            ''|*[!0-9]*)
                collection_error=RESULT_PARSE_FAILED
                ;;
        esac
    done

    checked_source_count=${fixture_checked:-0}
    effective_value_count=${fixture_effective:-0}
    compliant_count=${fixture_compliant:-0}
    noncompliant_count=${fixture_noncompliant:-0}
    ambiguity_count=${fixture_ambiguous:-0}
    effective_mask=${fixture_mask:-}

    if [ "${fixture_state:-}" = read_error ]; then
        collection_error=SOURCE_READ_FAILED
    fi
}

collect_runtime_sources() {
    source_found=false

    for source_path in \
        "${test_root}/etc/profile" \
        "${test_root}/etc/login.defs"; do
        if [ -e "$source_path" ]; then
            source_found=true
            parse_source "$source_path"
        fi
    done

    for source_path in "${test_root}"/etc/profile.d/*.sh; do
        [ -e "$source_path" ] || continue
        source_found=true
        parse_source "$source_path"
    done

    passwd_path="${test_root}/etc/passwd"
    if [ -r "$passwd_path" ]; then
        while IFS=: read -r account_name password_field account_uid account_gid \
            account_comment home_directory login_shell extra_field; do
            case "$account_uid" in
                ''|*[!0-9]*)
                    collection_error=PASSWD_PARSE_FAILED
                    break
                    ;;
            esac

            for profile_name in \
                .profile .bashrc .bash_profile .kshrc .cshrc .login; do
                source_path="${test_root}${home_directory}/$profile_name"
                if [ -e "$source_path" ]; then
                    source_found=true
                    parse_source "$source_path"
                fi
            done
        done < "$passwd_path"
    fi

    if [ "$source_found" = false ]; then
        collection_error=NO_UMASK_SOURCE
    fi
}

if [ -z "$collection_error" ]; then
    if [ -n "${OS_GUARD_TEST_UMASK_FILE:-}" ]; then
        load_fixture_result "$OS_GUARD_TEST_UMASK_FILE"
    else
        collect_runtime_sources
    fi
fi

if [ -n "$collection_error" ]; then
    status_json='"UNCHECKABLE"'
    review_state=NOT_REQUIRED
    reason_code=KISA_U30_COLLECTION_FAILED
    judgment_basis='Required UMASK sources could not be read or parsed'
    error_json=$(printf '{"code":'; os_guard_json_quote "$collection_error"; printf ',"message":"UMASK collection failed"}')
elif [ "$ambiguity_count" -gt 0 ] || \
    { [ "$effective_value_count" -gt 1 ] && \
      [ "$compliant_count" -gt 0 ] && \
      [ "$noncompliant_count" -gt 0 ]; }; then
    status_json=null
    review_state=PENDING
    reason_code=KISA_U30_EFFECTIVE_VALUE_AMBIGUOUS
    judgment_basis='Conflicting or dynamic startup logic prevents one effective UMASK from being established'
elif [ "$effective_value_count" -eq 0 ]; then
    status_json='"VULNERABLE"'
    review_state=NOT_REQUIRED
    reason_code=KISA_U30_UMASK_NOT_SET
    judgment_basis='No effective UMASK setting was identified in the inspected startup sources'
elif [ "$noncompliant_count" -gt 0 ]; then
    status_json='"VULNERABLE"'
    review_state=NOT_REQUIRED
    reason_code=KISA_U30_MASK_BELOW_REQUIREMENT
    judgment_basis='An effective UMASK does not contain the required 022 mask bits'
else
    status_json='"GOOD"'
    review_state=NOT_REQUIRED
    reason_code=KISA_U30_MASK_COMPLIANT
    judgment_basis='The effective UMASK contains at least the required 022 mask bits'
fi

printf '{"item_id":"U-30","status":%s,"review_state":"%s","current_value":{"checked_source_count":%s,"effective_value_count":%s,"compliant_count":%s,"noncompliant_count":%s,"ambiguity_count":%s,"effective_mask":' \
    "$status_json" "$review_state" "$checked_source_count" \
    "$effective_value_count" "$compliant_count" "$noncompliant_count" \
    "$ambiguity_count"
os_guard_json_quote "$effective_mask"
printf '},"evidence":{"item_id":"U-30","inspection_target":"system and account shell startup UMASK settings","collection_method":"Read-only bounded startup source parsing with octal bit-mask evaluation","checked_source_count":%s,"effective_value_count":%s,"compliant_count":%s,"noncompliant_count":%s,"ambiguity_count":%s,"reason_code":' \
    "$checked_source_count" "$effective_value_count" "$compliant_count" \
    "$noncompliant_count" "$ambiguity_count"
os_guard_json_quote "$reason_code"
printf ',"os":{"distro":'
os_guard_json_quote "$distro"
printf ',"version_id":'
os_guard_json_quote "$version_id"
printf '},"kernel":'
os_guard_json_quote "$kernel"
printf ',"module_version":'
os_guard_json_quote "$module_version"
printf ',"observed_at":'
os_guard_json_quote "$observed_at"
printf ',"judgment_basis":'
os_guard_json_quote "$judgment_basis"
printf '},"error":%s}\n' "$error_json"
