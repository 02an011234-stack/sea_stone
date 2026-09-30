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

passwd_present=false; passwd_readable=false; group_present=false; group_readable=false
administrator_group_confirmed=false; administrator_group_gid=''
administrator_group_name_is_root=false; root_account_included=false
valid_passwd_entry_count=0; valid_group_entry_count=0
malformed_passwd_entry_count=0; malformed_group_entry_count=0
primary_gid_member_count=0; explicit_group_member_count=0; duplicate_member_reference_count=0
administrator_group_member_count=0; non_root_administrator_count=0
external_or_unknown_member_count=0; manual_review_target_count=0
manual_review_required=false
status_json='null'; review_state='PENDING'; collection_error=''; error_json='null'
reason_code='KISA_U08_ADMIN_ACCOUNT_NECESSITY_REQUIRES_REVIEW'
decision_reason='Non-root administrator-group membership requires operational necessity review'

[ -e "$passwd_path" ] && passwd_present=true
[ -r "$passwd_path" ] && passwd_readable=true
[ -e "$group_path" ] && group_present=true
[ -r "$group_path" ] && group_readable=true

case "$distro" in rocky|ubuntu) ;; *) collection_error='UNSUPPORTED_OS_CONFIGURATION' ;; esac
if [ -z "$collection_error" ] && [ "$passwd_present" != true ]; then
    collection_error='PASSWD_FILE_NOT_FOUND'
elif [ -z "$collection_error" ] && [ "$passwd_readable" != true ]; then
    collection_error='PASSWD_FILE_UNREADABLE'
elif [ -z "$collection_error" ] && [ "$group_present" != true ]; then
    collection_error='GROUP_FILE_NOT_FOUND'
elif [ -z "$collection_error" ] && [ "$group_readable" != true ]; then
    collection_error='GROUP_FILE_UNREADABLE'
fi

# Account names are used only as in-memory join keys. Only aggregate counts and
# the administrator GID leave awk.
if [ -z "$collection_error" ]; then
    if counts=$(awk -F: '
        FILENAME == ARGV[1] {
            if (NF != 7 || $1 == "" || $3 !~ /^[0-9]+$/ || $4 !~ /^[0-9]+$/) {
                malformed_passwd++; next
            }
            valid_passwd++; accounts[$1]=1; primary_gid[$1]=$4+0
            if ($1 == "root") { root_count++; root_uid=$3+0; root_gid=$4+0 }
            next
        }
        {
            if (NF != 4 || $1 == "" || $3 !~ /^[0-9]+$/) { malformed_group++; next }
            valid_group++
            if ($3+0 != root_gid) next
            admin_group_count++
            if ($1 == "root") name_is_root=1
            count=split($4, listed, ",")
            for (i=1; i<=count; i++) if (listed[i] != "") explicit[listed[i]]=1
        }
        END {
            if (root_count == 1 && admin_group_count == 1) {
                for (account in primary_gid) {
                    if (primary_gid[account] == root_gid) {
                        primary[account]=1; members[account]=1
                    }
                }
                for (account in explicit) {
                    members[account]=1
                    if (account in primary) overlap++
                    if (!(account in accounts)) external++
                }
                for (account in primary) primary_count++
                for (account in explicit) explicit_count++
                for (account in members) {
                    member_count++
                    if (account == "root") root_included=1; else nonroot_count++
                }
            }
            print valid_passwd+0, malformed_passwd+0, root_count+0, root_uid+0, root_gid+0,
                  valid_group+0, malformed_group+0, admin_group_count+0, name_is_root+0,
                  primary_count+0, explicit_count+0, overlap+0, member_count+0,
                  nonroot_count+0, external+0, root_included+0
        }
    ' "$passwd_path" "$group_path" 2>/dev/null); then
        set -- $counts
        if [ "$#" -eq 16 ]; then
            valid_passwd_entry_count=$1; malformed_passwd_entry_count=$2
            root_account_count=$3; root_uid=$4; root_gid=$5
            valid_group_entry_count=$6; malformed_group_entry_count=$7
            admin_group_count=$8; [ "$9" -eq 1 ] && administrator_group_name_is_root=true
            shift 9
            primary_gid_member_count=$1; explicit_group_member_count=$2
            duplicate_member_reference_count=$3; administrator_group_member_count=$4
            non_root_administrator_count=$5; external_or_unknown_member_count=$6
            [ "$7" -eq 1 ] && root_account_included=true
            administrator_group_gid=$root_gid
        else
            collection_error='ACCOUNT_GROUP_PARSE_ERROR'
        fi
    else
        collection_error='ACCOUNT_GROUP_READ_ERROR'
    fi
fi

if [ -z "$collection_error" ] && { [ "$valid_passwd_entry_count" -eq 0 ] || [ "$valid_group_entry_count" -eq 0 ] || [ "$malformed_passwd_entry_count" -gt 0 ] || [ "$malformed_group_entry_count" -gt 0 ]; }; then
    collection_error='ACCOUNT_GROUP_PARSE_ERROR'
elif [ -z "$collection_error" ] && { [ "$root_account_count" -ne 1 ] || [ "$root_uid" -ne 0 ] || [ "$admin_group_count" -ne 1 ] || [ "$root_account_included" != true ]; }; then
    collection_error='ADMINISTRATOR_GROUP_NOT_CONFIRMABLE'
elif [ -z "$collection_error" ]; then
    administrator_group_confirmed=true
fi

if [ -n "$collection_error" ]; then
    status_json='"UNCHECKABLE"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U08_COLLECTION_FAILED'
    decision_reason='The root administrator group or its membership could not be read and parsed safely'
    error_json=$(printf '{"code":'; os_guard_json_quote "$collection_error"; printf ',"message":"Administrator group membership collection or parsing failed"}')
elif [ "$non_root_administrator_count" -eq 0 ] && [ "$administrator_group_name_is_root" = true ]; then
    status_json='"GOOD"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U08_ROOT_ONLY_ADMIN_GROUP'
    decision_reason='Only root is included in the root administrator group'
else
    manual_review_required=true
    manual_review_target_count=$non_root_administrator_count
fi

if [ -n "$administrator_group_gid" ]; then admin_gid_json=$administrator_group_gid; else admin_gid_json='null'; fi

printf '{"item_id":"U-08","status":%s,"review_state":"%s",' "$status_json" "$review_state"
printf '"current_value":{"passwd_file_present":%s,"passwd_file_readable":%s,' "$passwd_present" "$passwd_readable"
printf '"group_file_present":%s,"group_file_readable":%s,"administrator_group_confirmed":%s,' "$group_present" "$group_readable" "$administrator_group_confirmed"
printf '"administrator_group_gid":%s,"administrator_group_name_is_root":%s,' "$admin_gid_json" "$administrator_group_name_is_root"
printf '"administrator_group_member_count":%s,"primary_gid_member_count":%s,' "$administrator_group_member_count" "$primary_gid_member_count"
printf '"explicit_group_member_count":%s,"duplicate_member_reference_count":%s,' "$explicit_group_member_count" "$duplicate_member_reference_count"
printf '"root_account_included":%s,"non_root_administrator_count":%s,' "$root_account_included" "$non_root_administrator_count"
printf '"external_or_unknown_member_count":%s,"manual_review_target_count":%s,' "$external_or_unknown_member_count" "$manual_review_target_count"
printf '"manual_review_required":%s,"valid_passwd_entry_count":%s,' "$manual_review_required" "$valid_passwd_entry_count"
printf '"valid_group_entry_count":%s,"malformed_passwd_entry_count":%s,' "$valid_group_entry_count" "$malformed_passwd_entry_count"
printf '"malformed_group_entry_count":%s},' "$malformed_group_entry_count"
printf '"evidence":{"item_id":"U-08","collection_method":"Join root primary-GID and explicit root-group membership in memory and export aggregate counts only",'
printf '"configuration_paths":["/etc/passwd","/etc/group"],"kisa_basis_type":"ROOT_GROUP_MINIMUM_MEMBERSHIP_REVIEW",'
printf '"reason_code":'; os_guard_json_quote "$reason_code"
printf ',"os":{"distro":'; os_guard_json_quote "$distro"; printf ',"version_id":'; os_guard_json_quote "$version_id"
printf '},"observed_at":'; os_guard_json_quote "$observed_at"; printf ',"module_version":'; os_guard_json_quote "$module_version"
printf ',"decision_reason":'; os_guard_json_quote "$decision_reason"
printf '},"error":%s}\n' "$error_json"
exit 0
