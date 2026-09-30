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
group_path="${test_root}/etc/group"
pam_path="${test_root}/etc/pam.d/su"
su_path=''
for candidate in "${test_root}/usr/bin/su" "${test_root}/bin/su"; do
    if [ -e "$candidate" ]; then su_path=$candidate; break; fi
done

passwd_present=false; passwd_readable=false; group_present=false; group_readable=false
pam_present=false; pam_readable=false; su_present=false; su_metadata_collected=false
valid_account_count=0; malformed_passwd_entry_count=0; root_only_system=false
pam_wheel_active=false; pam_wheel_valid_count=0; pam_wheel_nonstandard_count=0; pam_complex=false
restriction_group_exists=false; restriction_group_member_count=0
su_mode=''; su_group_matches_policy=false; restriction_method='none'; policy_active=false
status_json='null'; review_state='PENDING'; review_reason=''
reason_code='KISA_U06_REVIEW_REQUIRED'
decision_reason='The effective su restriction policy requires manual review'
collection_error=''; error_json='null'; pam_group=''; su_group=''

[ -e "$passwd_path" ] && passwd_present=true
[ -r "$passwd_path" ] && passwd_readable=true
[ -e "$group_path" ] && group_present=true
[ -r "$group_path" ] && group_readable=true
[ -e "$pam_path" ] && pam_present=true
[ -r "$pam_path" ] && pam_readable=true
[ -n "$su_path" ] && su_present=true

case "$distro" in rocky|ubuntu) ;; *) collection_error='UNSUPPORTED_OS_CONFIGURATION' ;; esac
if [ -z "$collection_error" ] && [ "$passwd_present" != true ]; then
    collection_error='PASSWD_FILE_NOT_FOUND'
elif [ -z "$collection_error" ] && [ "$passwd_readable" != true ]; then
    collection_error='PASSWD_FILE_UNREADABLE'
fi

if [ -z "$collection_error" ]; then
    if counts=$(awk -F: '
        BEGIN { valid=malformed=root_count=nonroot_count=0; root_uid=-1 }
        {
            if (NF != 7 || $1 == "" || $3 !~ /^[0-9]+$/ || $4 !~ /^[0-9]+$/) { malformed++; next }
            valid++
            if ($1 == "root") { root_count++; root_uid=$3+0 } else nonroot_count++
        }
        END { print valid, malformed, root_count, root_uid, nonroot_count }
    ' "$passwd_path" 2>/dev/null); then
        set -- $counts
        if [ "$#" -eq 5 ]; then
            valid_account_count=$1; malformed_passwd_entry_count=$2
            root_count=$3; root_uid=$4; nonroot_count=$5
            if [ "$valid_account_count" -eq 1 ] && [ "$root_count" -eq 1 ] && [ "$root_uid" -eq 0 ] && [ "$nonroot_count" -eq 0 ]; then
                root_only_system=true
            fi
        else
            collection_error='PASSWD_FILE_PARSE_ERROR'
        fi
    else
        collection_error='PASSWD_FILE_READ_ERROR'
    fi
fi
if [ -z "$collection_error" ] && { [ "$valid_account_count" -eq 0 ] || [ "$malformed_passwd_entry_count" -gt 0 ]; }; then
    collection_error='PASSWD_FILE_PARSE_ERROR'
fi

if [ -z "$collection_error" ] && [ "$root_only_system" != true ]; then
    if [ "$su_present" = true ]; then
        if metadata=$(stat -L -c '%G|%a' "$su_path" 2>/dev/null); then
            su_group=${metadata%%|*}; su_mode=${metadata#*|}
            case "$su_mode" in *[!0-7]*|'') collection_error='SU_METADATA_PARSE_ERROR' ;; *) su_metadata_collected=true ;; esac
        else
            collection_error='SU_METADATA_READ_ERROR'
        fi
    fi

    if [ -z "$collection_error" ] && [ "$pam_present" = true ]; then
        if [ "$pam_readable" != true ]; then
            collection_error='PAM_CONFIGURATION_UNREADABLE'
        elif pam_result=$(awk '
            BEGIN { valid=nonstandard=complex=0; selected="" }
            /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
            {
                line=$0; sub(/[[:space:]]*#.*/, "", line)
                if (line ~ /\\[[:space:]]*$/) complex=1
                count=split(line, fields, /[[:space:]]+/); start=1
                while (start <= count && fields[start] == "") start++
                found=0
                for (i=start; i<=count; i++) {
                    module=fields[i]; sub(/^.*\//, "", module)
                    if (tolower(module) == "pam_wheel.so") { found=i; break }
                }
                if (!found) next
                type=tolower(fields[start]); control=tolower(fields[start+1])
                use_uid=0; group=""; unsupported=0
                for (i=found+1; i<=count; i++) {
                    arg=fields[i]
                    if (arg == "use_uid") use_uid=1
                    else if (arg ~ /^group=/) { group=arg; sub(/^group=/, "", group) }
                    else if (arg != "") unsupported=1
                }
                if (type == "auth" && control == "required" && unsupported == 0 && (use_uid || group != "")) {
                    if (group == "") group="wheel"
                    valid++; selected=group
                } else nonstandard++
            }
            END { if (selected == "") selected="-"; print valid "|" nonstandard "|" complex "|" selected }
        ' "$pam_path" 2>/dev/null); then
            old_ifs=$IFS; IFS='|'; set -- $pam_result; IFS=$old_ifs
            if [ "$#" -eq 4 ]; then
                pam_wheel_valid_count=$1; pam_wheel_nonstandard_count=$2
                [ "$3" -eq 1 ] && pam_complex=true
                pam_group=$4; [ "$pam_group" = '-' ] && pam_group=''
                if [ $((pam_wheel_valid_count + pam_wheel_nonstandard_count)) -gt 0 ]; then
                    pam_wheel_active=true
                fi
            else
                collection_error='PAM_CONFIGURATION_PARSE_ERROR'
            fi
        else
            collection_error='PAM_CONFIGURATION_READ_ERROR'
        fi
    fi
fi

group_info() {
    wanted=$1
    awk -F: -v wanted="$wanted" '
        FILENAME == ARGV[1] {
            if (NF == 7 && $1 != "" && $4 ~ /^[0-9]+$/) primary[$1]=$4
            next
        }
        {
            if (NF != 4 || $1 == "" || $3 !~ /^[0-9]+$/) { malformed++; next }
            if ($1 != wanted) next
            found++; gid=$3; count=split($4, listed, ",")
            for (i=1; i<=count; i++) if (listed[i] != "") members[listed[i]]=1
        }
        END {
            if (found == 1) {
                for (account in primary) if (primary[account] == gid) members[account]=1
                for (account in members) member_count++
            }
            print found+0, member_count+0, malformed+0
        }
    ' "$passwd_path" "$group_path" 2>/dev/null
}

if [ -z "$collection_error" ] && [ "$root_only_system" != true ]; then
    if [ "$group_present" != true ]; then
        collection_error='GROUP_FILE_NOT_FOUND'
    elif [ "$group_readable" != true ]; then
        collection_error='GROUP_FILE_UNREADABLE'
    fi
fi

if [ -z "$collection_error" ] && [ "$root_only_system" != true ]; then
    file_policy_good=false
    if [ "$su_metadata_collected" = true ] && [ "$su_mode" = '4750' ]; then
        if info=$(group_info "$su_group"); then
            set -- $info
            if [ "$#" -eq 3 ] && [ "$3" -eq 0 ] && [ "$1" -eq 1 ]; then
                file_policy_good=true; restriction_group_exists=true
                restriction_group_member_count=$2; su_group_matches_policy=true
            elif [ "$#" -ne 3 ] || [ "$3" -gt 0 ]; then
                collection_error='GROUP_FILE_PARSE_ERROR'
            fi
        else
            collection_error='GROUP_FILE_READ_ERROR'
        fi
    fi

    pam_policy_good=false
    if [ -z "$collection_error" ] && [ "$pam_wheel_valid_count" -eq 1 ] && [ "$pam_wheel_nonstandard_count" -eq 0 ]; then
        if info=$(group_info "$pam_group"); then
            set -- $info
            if [ "$#" -eq 3 ] && [ "$3" -eq 0 ]; then
                if [ "$1" -eq 1 ]; then
                    pam_policy_good=true; restriction_group_exists=true
                    restriction_group_member_count=$2
                    [ "$su_group" = "$pam_group" ] && su_group_matches_policy=true
                fi
            else
                collection_error='GROUP_FILE_PARSE_ERROR'
            fi
        else
            collection_error='GROUP_FILE_READ_ERROR'
        fi
    fi

    if [ "$file_policy_good" = true ]; then
        restriction_method='su_file_group_mode_4750'; policy_active=true
    elif [ "$pam_policy_good" = true ]; then
        restriction_method='pam_wheel_required'; policy_active=true
    fi
fi

if [ -n "$collection_error" ]; then
    status_json='"UNCHECKABLE"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U06_COLLECTION_FAILED'
    decision_reason='The su restriction configuration could not be read or parsed safely'
    error_json=$(printf '{"code":'; os_guard_json_quote "$collection_error"; printf ',"message":"su restriction metadata collection or parsing failed"}')
elif [ "$root_only_system" = true ]; then
    status_json='"GOOD"'; review_state='NOT_REQUIRED'; policy_active=true
    restriction_method='root_only_exception'; reason_code='KISA_U06_ROOT_ONLY_EXCEPTION'
    decision_reason='No general user account exists, so the KISA su restriction exception applies'
elif [ "$policy_active" = true ]; then
    status_json='"GOOD"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U06_SU_RESTRICTED_TO_GROUP'
    decision_reason='su use is restricted to members of a configured group'
elif [ "$su_present" != true ]; then
    review_reason='SU_COMMAND_NOT_PRESENT_REQUIRES_REVIEW'
elif [ "$pam_wheel_valid_count" -gt 1 ] || [ "$pam_wheel_nonstandard_count" -gt 0 ] || [ "$pam_complex" = true ]; then
    review_reason='NONSTANDARD_OR_COMPLEX_PAM_POLICY'
else
    status_json='"VULNERABLE"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U06_SU_RESTRICTION_NOT_CONFIGURED'
    decision_reason='No KISA-compliant PAM or su executable group restriction is active'
fi

su_evidence_path='/usr/bin/su'
[ "$su_path" = "${test_root}/bin/su" ] && su_evidence_path='/bin/su'
printf '{"item_id":"U-06","status":%s,"review_state":"%s",' "$status_json" "$review_state"
printf '"current_value":{"su_present":%s,"su_metadata_collected":%s,"su_mode":' "$su_present" "$su_metadata_collected"
if [ -n "$su_mode" ]; then os_guard_json_quote "$su_mode"; else printf 'null'; fi
printf ',"pam_file_present":%s,"pam_file_readable":%s,"pam_wheel_active":%s,' "$pam_present" "$pam_readable" "$pam_wheel_active"
printf '"pam_wheel_valid_count":%s,"pam_wheel_nonstandard_count":%s,"pam_complex":%s,' "$pam_wheel_valid_count" "$pam_wheel_nonstandard_count" "$pam_complex"
printf '"restriction_method":'; os_guard_json_quote "$restriction_method"
printf ',"restriction_group_exists":%s,"restriction_group_member_count":%s,' "$restriction_group_exists" "$restriction_group_member_count"
printf '"su_group_matches_policy":%s,"policy_active":%s,"root_only_system":%s,' "$su_group_matches_policy" "$policy_active" "$root_only_system"
printf '"valid_account_count":%s,"malformed_passwd_entry_count":%s},' "$valid_account_count" "$malformed_passwd_entry_count"
printf '"evidence":{"item_id":"U-06","collection_method":"Inspect su metadata, active PAM restriction records, local group aggregates, and the root-only exception without authenticating or changing accounts",'
printf '"configuration_paths":["%s","/etc/pam.d/su","/etc/group","/etc/passwd"],' "$su_evidence_path"
printf '"reason_code":'; os_guard_json_quote "$reason_code"; printf ',"review_reason":'
if [ -n "$review_reason" ]; then os_guard_json_quote "$review_reason"; else printf 'null'; fi
printf ',"os":{"distro":'; os_guard_json_quote "$distro"; printf ',"version_id":'; os_guard_json_quote "$version_id"
printf '},"observed_at":'; os_guard_json_quote "$observed_at"; printf ',"module_version":'; os_guard_json_quote "$module_version"
printf ',"decision_reason":'; os_guard_json_quote "$decision_reason"
printf '},"error":%s}\n' "$error_json"
exit 0
