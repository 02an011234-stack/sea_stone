#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/../lib/common.sh"

distro=${OS_GUARD_DISTRO:-unknown}
version_id=${OS_GUARD_VERSION_ID:-unknown}
module_version=${OS_GUARD_MODULE_VERSION:-unknown}
observed_at=$(os_guard_utc_now)
test_root=${OS_GUARD_TEST_ROOT:-}

passwd_path="${test_root}/etc/passwd"
shadow_path="${test_root}/etc/shadow"
login_defs_path="${test_root}/etc/login.defs"

case "$distro" in
    rocky)
        pam_paths="${test_root}/etc/pam.d/system-auth
${test_root}/etc/pam.d/password-auth"
        ;;
    ubuntu)
        pam_paths="${test_root}/etc/pam.d/common-password"
        ;;
    *)
        pam_paths=''
        ;;
esac

collection_error=''
status_json='null'
review_state='PENDING'
manual_review_required=true
error_json='null'
reason_code='KISA_U13_ALGORITHM_ANALYSIS_PENDING'
decision_reason='Password hash algorithms and the future password policy have not been determined'

checked_account_count=0
safe_hash_count=0
weak_hash_count=0
unknown_hash_count=0
locked_or_no_password_count=0
effective_encrypt_method=''
pam_policy_state='UNKNOWN'
policy_conflict_detected=false
current_hash_state='UNKNOWN'
future_password_policy_state='UNKNOWN'
login_encrypt_method=''
login_method_count=0
login_method_conflict=false
pam_unix_count=0
pam_complex=false
authselect_state='not_applicable'

case "$distro" in rocky|ubuntu) ;; *) collection_error='UNSUPPORTED_OS_CONFIGURATION' ;; esac

for required_path in "$passwd_path" "$shadow_path"; do
    if [ -z "$collection_error" ] && [ ! -e "$required_path" ]; then
        collection_error='ACCOUNT_DATABASE_NOT_FOUND'
    elif [ -z "$collection_error" ] && [ ! -r "$required_path" ]; then
        collection_error='ACCOUNT_DATABASE_UNREADABLE'
    fi
done

if [ -z "$collection_error" ] && [ -e "$login_defs_path" ] && [ ! -r "$login_defs_path" ]; then
    collection_error='LOGIN_DEFS_UNREADABLE'
fi

pam_file_count=0
if [ -z "$collection_error" ]; then
    old_ifs=$IFS
    IFS='
'
    for pam_path in $pam_paths; do
        IFS=$old_ifs
        if [ ! -e "$pam_path" ]; then
            collection_error='PAM_CONFIGURATION_NOT_FOUND'
            break
        elif [ ! -r "$pam_path" ]; then
            collection_error='PAM_CONFIGURATION_UNREADABLE'
            break
        fi
        pam_file_count=$((pam_file_count + 1))
        IFS='
'
    done
    IFS=$old_ifs
fi

if [ -z "$collection_error" ]; then
    hash_summary=$(awk -F: '
        function classify(field) {
            if (field == "" || field ~ /^[!*]/) {
                locked++
            } else if (field ~ /^\$(5|6)\$/) {
                safe++
            } else if (field ~ /^\$1\$/ || field ~ /^\$2/) {
                weak++
            } else if (field ~ /^[.\/0-9A-Za-z]{13}$/) {
                weak++
            } else {
                unknown++
            }
        }
        NR == FNR {
            passwd_lines++
            if (NF != 7 || $1 == "" || seen_passwd[$1]++) {
                malformed_passwd++
                next
            }
            passwd_field[$1] = $2
            next
        }
        NR != FNR {
            shadow_lines++
            if (NF != 9 || $1 == "" || seen_shadow[$1]++) {
                malformed_shadow++
                next
            }
            shadow_field[$1] = $2
        }
        END {
            for (name in shadow_field) classify(shadow_field[name])
            for (name in passwd_field) {
                if (passwd_field[name] != "x" && !(name in shadow_field)) {
                    classify(passwd_field[name])
                }
            }
            print "passwd_lines=" passwd_lines + 0
            print "shadow_lines=" shadow_lines + 0
            print "malformed_passwd=" malformed_passwd + 0
            print "malformed_shadow=" malformed_shadow + 0
            print "safe_hash_count=" safe + 0
            print "weak_hash_count=" weak + 0
            print "unknown_hash_count=" unknown + 0
            print "locked_or_no_password_count=" locked + 0
        }
    ' "$passwd_path" "$shadow_path" 2>/dev/null)
    hash_status=$?
    if [ "$hash_status" -ne 0 ]; then
        collection_error='ACCOUNT_DATABASE_PARSE_ERROR'
    else
        passwd_lines=$(printf '%s\n' "$hash_summary" | awk -F= '$1 == "passwd_lines" { print $2 }')
        shadow_lines=$(printf '%s\n' "$hash_summary" | awk -F= '$1 == "shadow_lines" { print $2 }')
        malformed_passwd=$(printf '%s\n' "$hash_summary" | awk -F= '$1 == "malformed_passwd" { print $2 }')
        malformed_shadow=$(printf '%s\n' "$hash_summary" | awk -F= '$1 == "malformed_shadow" { print $2 }')
        safe_hash_count=$(printf '%s\n' "$hash_summary" | awk -F= '$1 == "safe_hash_count" { print $2 }')
        weak_hash_count=$(printf '%s\n' "$hash_summary" | awk -F= '$1 == "weak_hash_count" { print $2 }')
        unknown_hash_count=$(printf '%s\n' "$hash_summary" | awk -F= '$1 == "unknown_hash_count" { print $2 }')
        locked_or_no_password_count=$(printf '%s\n' "$hash_summary" | awk -F= '$1 == "locked_or_no_password_count" { print $2 }')
        checked_account_count=$((safe_hash_count + weak_hash_count + unknown_hash_count))
        if [ "$passwd_lines" -eq 0 ] || [ "$shadow_lines" -eq 0 ] || \
           [ "$malformed_passwd" -gt 0 ] || [ "$malformed_shadow" -gt 0 ]; then
            collection_error='ACCOUNT_DATABASE_PARSE_ERROR'
        fi
    fi
fi

if [ -z "$collection_error" ] && [ -r "$login_defs_path" ]; then
    login_summary=$(awk '
        /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
        toupper($1) == "ENCRYPT_METHOD" {
            value = toupper($2)
            sub(/[[:space:]#].*$/, "", value)
            if (value == "") next
            count++
            seen[value] = 1
            final = value
        }
        END {
            for (value in seen) distinct++
            print "count=" count + 0
            print "distinct=" distinct + 0
            print "method=" final
        }
    ' "$login_defs_path" 2>/dev/null) || collection_error='LOGIN_DEFS_PARSE_ERROR'
    if [ -z "$collection_error" ]; then
        login_method_count=$(printf '%s\n' "$login_summary" | awk -F= '$1 == "count" { print $2 }')
        login_distinct_count=$(printf '%s\n' "$login_summary" | awk -F= '$1 == "distinct" { print $2 }')
        login_encrypt_method=$(printf '%s\n' "$login_summary" | awk -F= '$1 == "method" { print $2 }')
        [ "$login_distinct_count" -gt 1 ] && login_method_conflict=true
    fi
fi

if [ -z "$collection_error" ]; then
    old_ifs=$IFS
    IFS='
'
    # The file list is fixed locally by the supported OS branch above.
    # shellcheck disable=SC2086
    pam_summary=$(awk '
        function basename(value) { sub(/^.*\//, "", value); return tolower(value) }
        /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
        {
            if (tolower($1) == "@include" ||
                ((tolower($1) == "password") &&
                 (tolower($2) == "include" || tolower($2) == "substack")) ||
                $0 ~ /\\[[:space:]]*$/) complex = 1
            if (tolower($1) != "password") next
            module_field = 0
            for (index_field = 2; index_field <= NF; index_field++) {
                if (basename($index_field) == "pam_unix.so") {
                    module_field = index_field
                    break
                }
            }
            if (!module_field) next
            pam_count++
            files[FILENAME] = 1
            algorithm = "implicit"
            for (argument = module_field + 1; argument <= NF; argument++) {
                option = tolower($argument)
                if (option == "sha512" || option == "sha256" || option == "md5" ||
                    option == "blowfish" || option == "bigcrypt" || option == "yescrypt" ||
                    option == "gost_yescrypt") algorithm = option
            }
            if (algorithm == "sha512") sha512++
            else if (algorithm == "sha256") sha256++
            else if (algorithm == "md5" || algorithm == "blowfish" || algorithm == "bigcrypt") weak++
            else if (algorithm == "implicit") implicit++
            else unknown++
        }
        END {
            for (file in files) file_count++
            print "pam_unix_count=" pam_count + 0
            print "pam_file_with_unix_count=" file_count + 0
            print "sha512_count=" sha512 + 0
            print "sha256_count=" sha256 + 0
            print "weak_count=" weak + 0
            print "unknown_count=" unknown + 0
            print "implicit_count=" implicit + 0
            print "complex=" (complex ? "true" : "false")
        }
    ' $pam_paths 2>/dev/null)
    pam_status=$?
    IFS=$old_ifs
    if [ "$pam_status" -ne 0 ]; then
        collection_error='PAM_CONFIGURATION_PARSE_ERROR'
    else
        pam_unix_count=$(printf '%s\n' "$pam_summary" | awk -F= '$1 == "pam_unix_count" { print $2 }')
        pam_file_with_unix_count=$(printf '%s\n' "$pam_summary" | awk -F= '$1 == "pam_file_with_unix_count" { print $2 }')
        pam_sha512_count=$(printf '%s\n' "$pam_summary" | awk -F= '$1 == "sha512_count" { print $2 }')
        pam_sha256_count=$(printf '%s\n' "$pam_summary" | awk -F= '$1 == "sha256_count" { print $2 }')
        pam_weak_count=$(printf '%s\n' "$pam_summary" | awk -F= '$1 == "weak_count" { print $2 }')
        pam_unknown_count=$(printf '%s\n' "$pam_summary" | awk -F= '$1 == "unknown_count" { print $2 }')
        pam_implicit_count=$(printf '%s\n' "$pam_summary" | awk -F= '$1 == "implicit_count" { print $2 }')
        pam_complex=$(printf '%s\n' "$pam_summary" | awk -F= '$1 == "complex" { print $2 }')
    fi
fi

login_policy_state='UNKNOWN'
case "$login_encrypt_method" in
    SHA512|SHA256) login_policy_state='SAFE' ;;
    MD5|DES|BLOWFISH|BIGCRYPT) login_policy_state='WEAK' ;;
    '') login_policy_state='DEFAULT_SHA512' ;;
esac

if [ -z "$collection_error" ]; then
    if [ "$pam_unix_count" -eq 0 ] || [ "$pam_file_with_unix_count" -ne "$pam_file_count" ] || \
       [ "$pam_complex" = true ]; then
        pam_policy_state='UNKNOWN'
    elif [ "$pam_weak_count" -gt 0 ]; then
        pam_policy_state='WEAK'
        effective_encrypt_method='WEAK_PAM_OPTION'
    elif [ "$pam_unknown_count" -gt 0 ]; then
        pam_policy_state='UNKNOWN'
        effective_encrypt_method='UNKNOWN_PAM_OPTION'
    elif [ "$pam_implicit_count" -gt 0 ]; then
        case "$login_policy_state" in
            SAFE)
                pam_policy_state='SAFE'
                effective_encrypt_method=$login_encrypt_method
                ;;
            WEAK)
                pam_policy_state='WEAK'
                effective_encrypt_method=$login_encrypt_method
                ;;
            DEFAULT_SHA512)
                pam_policy_state='SAFE'
                effective_encrypt_method='SHA512_DEFAULT'
                ;;
            *)
                pam_policy_state='UNKNOWN'
                effective_encrypt_method=$login_encrypt_method
                ;;
        esac
    else
        pam_policy_state='SAFE'
        if [ "$pam_sha512_count" -gt 0 ] && [ "$pam_sha256_count" -gt 0 ]; then
            effective_encrypt_method='SHA2_MULTIPLE'
        elif [ "$pam_sha512_count" -gt 0 ]; then
            effective_encrypt_method='SHA512'
        else
            effective_encrypt_method='SHA256'
        fi
    fi

    if { [ "$pam_sha512_count" -gt 0 ] || [ "$pam_sha256_count" -gt 0 ]; } && \
       [ "$login_policy_state" = 'WEAK' ]; then
        policy_conflict_detected=true
    elif [ "$pam_weak_count" -gt 0 ] && { [ "$login_policy_state" = 'SAFE' ] || \
         [ "$login_policy_state" = 'DEFAULT_SHA512' ]; }; then
        policy_conflict_detected=true
    elif [ "$login_method_conflict" = true ]; then
        policy_conflict_detected=true
    fi
fi

if [ "$distro" = 'rocky' ] && [ -z "$test_root" ]; then
    authselect_state='unavailable'
    if authselect_bin=$(command -v authselect 2>/dev/null) && [ -x "$authselect_bin" ]; then
        if "$authselect_bin" current >/dev/null 2>&1; then
            authselect_state='configured'
        else
            authselect_state='not_configured'
        fi
    fi
elif [ "$distro" = 'rocky' ]; then
    authselect_state='fixture_not_queried'
fi

if [ "$weak_hash_count" -gt 0 ]; then
    current_hash_state='WEAK'
elif [ "$unknown_hash_count" -gt 0 ]; then
    current_hash_state='UNKNOWN'
elif [ "$safe_hash_count" -gt 0 ]; then
    current_hash_state='SAFE'
else
    current_hash_state='NO_ACTIVE_PASSWORD_HASH'
fi
future_password_policy_state=$pam_policy_state

if [ -n "$collection_error" ]; then
    status_json='"UNCHECKABLE"'
    review_state='NOT_REQUIRED'
    manual_review_required=false
    reason_code='KISA_U13_COLLECTION_FAILED'
    decision_reason='Password hash or password-generation policy data could not be collected safely'
    error_json=$(printf '{"code":'; os_guard_json_quote "$collection_error"; printf ',"message":"Password algorithm collection or parsing failed"}')
elif [ "$weak_hash_count" -gt 0 ] || [ "$future_password_policy_state" = 'WEAK' ]; then
    status_json='"VULNERABLE"'
    review_state='NOT_REQUIRED'
    manual_review_required=false
    reason_code='KISA_U13_WEAK_ALGORITHM_FOUND'
    decision_reason='A weak active password hash or weak future password-generation policy was confirmed'
elif [ "$unknown_hash_count" -gt 0 ] || [ "$future_password_policy_state" = 'UNKNOWN' ]; then
    status_json='null'
    review_state='PENDING'
    manual_review_required=true
    reason_code='KISA_U13_ALGORITHM_REVIEW_REQUIRED'
    decision_reason='An unknown hash prefix or nonstandard password-generation policy requires review'
else
    status_json='"GOOD"'
    review_state='NOT_REQUIRED'
    manual_review_required=false
    reason_code='KISA_U13_SHA2_OR_STRONGER_CONFIRMED'
    decision_reason='Current active hashes and the effective future password policy meet the SHA-2 requirement'
fi

configuration_paths="$passwd_path
$shadow_path
$login_defs_path
$pam_paths"
configuration_paths_json=$(printf '%s\n' "$configuration_paths" | while IFS= read -r path; do
    [ -n "$path" ] || continue
    printf '%s\n' "${path#"$test_root"}"
done | os_guard_json_array_from_lines)
kernel=$(uname -r 2>/dev/null || true)

printf '{"item_id":"U-13","status":%s,"review_state":"%s",' "$status_json" "$review_state"
printf '"current_value":{"checked_account_count":%s,"safe_hash_count":%s,' "$checked_account_count" "$safe_hash_count"
printf '"weak_hash_count":%s,"unknown_hash_count":%s,' "$weak_hash_count" "$unknown_hash_count"
printf '"locked_or_no_password_count":%s,"effective_encrypt_method":' "$locked_or_no_password_count"
if [ -n "$effective_encrypt_method" ]; then os_guard_json_quote "$effective_encrypt_method"; else printf 'null'; fi
printf ',"login_encrypt_method":'
if [ -n "$login_encrypt_method" ]; then os_guard_json_quote "$login_encrypt_method"; else printf 'null'; fi
printf ',"login_method_count":%s,"pam_policy_state":' "$login_method_count"; os_guard_json_quote "$pam_policy_state"
printf ',"pam_unix_record_count":%s,"pam_complex":%s,' "$pam_unix_count" "$pam_complex"
printf '"authselect_state":'; os_guard_json_quote "$authselect_state"
printf ',"policy_conflict_detected":%s,"current_hash_state":' "$policy_conflict_detected"; os_guard_json_quote "$current_hash_state"
printf ',"future_password_policy_state":'; os_guard_json_quote "$future_password_policy_state"
printf ',"manual_review_required":%s},' "$manual_review_required"
printf '"evidence":{"item_id":"U-13","collection_method":"Aggregate active local password hash prefixes and resolve the local PAM password-generation policy without exporting credentials",'
printf '"configuration_paths":%s,"reason_code":' "$configuration_paths_json"; os_guard_json_quote "$reason_code"
printf ',"os":{"distro":'; os_guard_json_quote "$distro"; printf ',"version_id":'; os_guard_json_quote "$version_id"
printf '},"kernel":'; os_guard_json_quote "$kernel"
printf ',"observed_at":'; os_guard_json_quote "$observed_at"; printf ',"module_version":'; os_guard_json_quote "$module_version"
printf ',"decision_reason":'; os_guard_json_quote "$decision_reason"
printf '},"error":%s}\n' "$error_json"
exit 0
