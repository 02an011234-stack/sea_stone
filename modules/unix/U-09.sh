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
nsswitch_path="${test_root}/etc/nsswitch.conf"

passwd_present=false; passwd_readable=false; group_present=false; group_readable=false
valid_passwd_entry_count=0; valid_group_entry_count=0
malformed_passwd_entry_count=0; malformed_group_entry_count=0
unique_primary_gid_count=0; unique_group_gid_count=0
linked_group_gid_count=0; unlinked_group_gid_count=0
missing_primary_group_gid_count=0; duplicate_group_gid_count=0
unknown_explicit_member_reference_count=0
nss_configuration_state='not_found'; external_identity_sources_present=false
status_json='null'; review_state='PENDING'; review_reason=''
reason_code='KISA_U09_REVIEW_REQUIRED'
decision_reason='The account-to-group relationship requires manual review'
collection_error=''; error_json='null'

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

if [ -z "$collection_error" ]; then
    if counts=$(awk -F: '
        FILENAME == ARGV[1] {
            if (NF != 7 || $1 == "" || $3 !~ /^[0-9]+$/ || $4 !~ /^[0-9]+$/) {
                malformed_passwd++; next
            }
            valid_passwd++; accounts[$1]=1; primary_gid[$4+0]=1
            next
        }
        {
            if (NF != 4 || $1 == "" || $3 !~ /^[0-9]+$/) { malformed_group++; next }
            valid_group++; gid=$3+0; group_gid[gid]=1; gid_entries[gid]++
            count=split($4, listed, ",")
            for (i=1; i<=count; i++) {
                if (listed[i] == "") continue
                key=gid SUBSEP listed[i]; explicit[key]=1
                if (!(listed[i] in accounts)) unknown_member_refs[key]=1
            }
        }
        END {
            for (gid in primary_gid) {
                unique_primary++
                if (!(gid in group_gid)) missing_primary++
            }
            for (gid in group_gid) {
                unique_group++
                if (gid_entries[gid] > 1) duplicate_gid++
                connected=(gid in primary_gid)
                if (!connected) {
                    for (key in explicit) {
                        split(key, parts, SUBSEP)
                        if (parts[1] == gid && parts[2] in accounts) { connected=1; break }
                    }
                }
                if (connected) linked++; else unlinked++
            }
            for (key in unknown_member_refs) unknown_refs++
            print valid_passwd+0, malformed_passwd+0, valid_group+0, malformed_group+0,
                  unique_primary+0, unique_group+0, linked+0, unlinked+0,
                  missing_primary+0, duplicate_gid+0, unknown_refs+0
        }
    ' "$passwd_path" "$group_path" 2>/dev/null); then
        set -- $counts
        if [ "$#" -eq 11 ]; then
            valid_passwd_entry_count=$1; malformed_passwd_entry_count=$2
            valid_group_entry_count=$3; malformed_group_entry_count=$4
            unique_primary_gid_count=$5; unique_group_gid_count=$6
            linked_group_gid_count=$7; unlinked_group_gid_count=$8
            missing_primary_group_gid_count=$9
            shift 9
            duplicate_group_gid_count=$1; unknown_explicit_member_reference_count=$2
        else
            collection_error='ACCOUNT_GROUP_RELATION_PARSE_ERROR'
        fi
    else
        collection_error='ACCOUNT_GROUP_RELATION_READ_ERROR'
    fi
fi

if [ -z "$collection_error" ] && { [ "$valid_passwd_entry_count" -eq 0 ] || [ "$valid_group_entry_count" -eq 0 ] || [ "$malformed_passwd_entry_count" -gt 0 ] || [ "$malformed_group_entry_count" -gt 0 ]; }; then
    collection_error='ACCOUNT_GROUP_RELATION_PARSE_ERROR'
fi

# NSS is inspected locally only. No directory lookup or authentication occurs.
if [ -e "$nsswitch_path" ]; then
    if [ -r "$nsswitch_path" ]; then
        if nss_result=$(awk '
            BEGIN { passwd_seen=group_seen=external=0 }
            /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
            {
                line=$0; sub(/[[:space:]]*#.*/, "", line)
                field_count=split(line, fields, /[[:space:]]+/)
                key=fields[1]; sub(/:$/, "", key)
                if (key != "passwd" && key != "group") next
                if (key == "passwd") passwd_seen=1; else group_seen=1
                in_action=0
                for (i=2; i<=field_count; i++) {
                    source=fields[i]
                    if (source == "") continue
                    if (source ~ /^\[/) in_action=1
                    if (!in_action && source != "files") external=1
                    if (source ~ /\]$/) in_action=0
                }
            }
            END { print passwd_seen, group_seen, external }
        ' "$nsswitch_path" 2>/dev/null); then
            set -- $nss_result
            if [ "$#" -eq 3 ] && [ "$1" -eq 1 ] && [ "$2" -eq 1 ]; then
                if [ "$3" -eq 1 ]; then
                    nss_configuration_state='external_or_dynamic'
                    external_identity_sources_present=true
                else
                    nss_configuration_state='local_files_only'
                fi
            else
                nss_configuration_state='parse_warning'
            fi
        else
            nss_configuration_state='read_error'
        fi
    else
        nss_configuration_state='unreadable'
    fi
fi

if [ -n "$collection_error" ]; then
    status_json='"UNCHECKABLE"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U09_COLLECTION_FAILED'
    decision_reason='The local passwd and group relationship could not be read or parsed safely'
    error_json=$(printf '{"code":'; os_guard_json_quote "$collection_error"; printf ',"message":"Account and group relationship collection or parsing failed"}')
elif [ "$nss_configuration_state" != 'local_files_only' ]; then
    review_reason='EXTERNAL_OR_UNKNOWN_NSS_REQUIRES_REVIEW'
elif [ "$missing_primary_group_gid_count" -gt 0 ]; then
    review_reason='PRIMARY_GID_NOT_DEFINED_IN_LOCAL_GROUP'
elif [ "$unlinked_group_gid_count" -gt 0 ]; then
    status_json='"VULNERABLE"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U09_GROUP_GID_WITHOUT_ACCOUNT'
    decision_reason='At least one locally defined group GID is not connected to any local account'
else
    status_json='"GOOD"'; review_state='NOT_REQUIRED'
    reason_code='KISA_U09_ALL_GROUP_GIDS_CONNECTED'
    decision_reason='Every locally defined group GID is connected to at least one local account'
fi

printf '{"item_id":"U-09","status":%s,"review_state":"%s",' "$status_json" "$review_state"
printf '"current_value":{"passwd_file_present":%s,"passwd_file_readable":%s,' "$passwd_present" "$passwd_readable"
printf '"group_file_present":%s,"group_file_readable":%s,' "$group_present" "$group_readable"
printf '"valid_passwd_entry_count":%s,"valid_group_entry_count":%s,' "$valid_passwd_entry_count" "$valid_group_entry_count"
printf '"unique_primary_gid_count":%s,"unique_group_gid_count":%s,' "$unique_primary_gid_count" "$unique_group_gid_count"
printf '"linked_group_gid_count":%s,"unlinked_group_gid_count":%s,' "$linked_group_gid_count" "$unlinked_group_gid_count"
printf '"problem_gid_count":%s,"missing_primary_group_gid_count":%s,' "$unlinked_group_gid_count" "$missing_primary_group_gid_count"
printf '"duplicate_group_gid_count":%s,"unknown_explicit_member_reference_count":%s,' "$duplicate_group_gid_count" "$unknown_explicit_member_reference_count"
printf '"malformed_passwd_entry_count":%s,"malformed_group_entry_count":%s,' "$malformed_passwd_entry_count" "$malformed_group_entry_count"
printf '"nss_configuration_state":'; os_guard_json_quote "$nss_configuration_state"
printf ',"external_identity_sources_present":%s},' "$external_identity_sources_present"
printf '"evidence":{"item_id":"U-09","collection_method":"Compare unique local group GIDs with passwd primary GIDs and valid explicit members without exporting identifiers",'
printf '"configuration_paths":["/etc/passwd","/etc/group","/etc/nsswitch.conf"],"reason_code":'; os_guard_json_quote "$reason_code"
printf ',"review_reason":'; if [ -n "$review_reason" ]; then os_guard_json_quote "$review_reason"; else printf 'null'; fi
printf ',"os":{"distro":'; os_guard_json_quote "$distro"; printf ',"version_id":'; os_guard_json_quote "$version_id"
printf '},"observed_at":'; os_guard_json_quote "$observed_at"; printf ',"module_version":'; os_guard_json_quote "$module_version"
printf ',"decision_reason":'; os_guard_json_quote "$decision_reason"
printf '},"error":%s}\n' "$error_json"
exit 0
