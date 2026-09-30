#!/bin/sh

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=../lib/common.sh
. "$SCRIPT_DIR/../lib/common.sh"

item_id='U-01'
distro=${OS_GUARD_DISTRO:-unknown}
version_id=${OS_GUARD_VERSION_ID:-unknown}
module_version=${OS_GUARD_MODULE_VERSION:-unknown}
sshd_config='/etc/ssh/sshd_config'
pam_login='/etc/pam.d/login'
securetty='/etc/securetty'
inetd_config='/etc/inetd.conf'
xinetd_telnet_config='/etc/xinetd.d/telnet'
observed_at=$(os_guard_utc_now)

json_nullable_boolean() {
    case "$1" in
        true|false) printf '%s' "$1" ;;
        *) printf 'null' ;;
    esac
}

json_nullable_string() {
    if [ -n "$1" ]; then
        os_guard_json_quote "$1"
    else
        printf 'null'
    fi
}

probe_units() {
    probe_process=$1
    shift
    systemd_status_seen=0

    if command -v systemctl >/dev/null 2>&1; then
        for unit_name in "$@"; do
            unit_state=$(systemctl is-active "$unit_name" 2>/dev/null || true)
            case "$unit_state" in
                active|activating|reloading)
                    printf 'active'
                    return
                    ;;
                inactive|failed|deactivating)
                    systemd_status_seen=1
                    ;;
            esac
        done
    fi

    if command -v pgrep >/dev/null 2>&1; then
        case "$probe_process" in
            ssh)
                if pgrep -x sshd >/dev/null 2>&1; then
                    printf 'active'
                    return
                fi
                ;;
            telnet)
                if pgrep -x in.telnetd >/dev/null 2>&1 || \
                   pgrep -x telnetd >/dev/null 2>&1; then
                    printf 'active'
                    return
                fi
                ;;
            inetd)
                if pgrep -x inetd >/dev/null 2>&1 || \
                   pgrep -x inetutils-inetd >/dev/null 2>&1; then
                    printf 'active'
                    return
                fi
                ;;
            xinetd)
                if pgrep -x xinetd >/dev/null 2>&1; then
                    printf 'active'
                    return
                fi
                ;;
        esac
    fi

    if [ "$systemd_status_seen" -eq 1 ]; then
        printf 'inactive'
    else
        printf 'unknown'
    fi
}

case "$distro" in
    rocky)
        ssh_units_lines='sshd.service
sshd.socket
ssh.service
ssh.socket'
        ;;
    ubuntu)
        ssh_units_lines='ssh.service
ssh.socket
sshd.service
sshd.socket'
        ;;
    *)
        ssh_units_lines='sshd.service
ssh.service
sshd.socket
ssh.socket'
        ;;
esac
telnet_units_lines='telnet.socket
telnet.service
telnetd.service
in.telnetd.service'

# Word splitting here is limited to local, fixed unit names defined above.
# shellcheck disable=SC2086
ssh_service_state=$(probe_units ssh $ssh_units_lines)
# shellcheck disable=SC2086
telnet_service_state=$(probe_units telnet $telnet_units_lines)
telnet_activation_source='dedicated_service'
telnet_service_probe_error=''

if [ "$telnet_service_state" != 'active' ]; then
    case "$distro" in
        ubuntu)
            inetd_state=$(probe_units inetd inetutils-inetd.service openbsd-inetd.service inetd.service)
            if [ "$inetd_state" = 'active' ]; then
                if [ -e "$inetd_config" ] && [ ! -r "$inetd_config" ]; then
                    telnet_service_state='unknown'
                    telnet_service_probe_error='INETD_CONFIGURATION_UNREADABLE'
                elif [ -r "$inetd_config" ] && \
                     grep -Eq '^[[:space:]]*telnet[[:space:]]' "$inetd_config" 2>/dev/null; then
                    telnet_service_state='active'
                    telnet_activation_source='inetd_configuration'
                fi
            fi
            ;;
        rocky)
            xinetd_state=$(probe_units xinetd xinetd.service)
            if [ "$xinetd_state" = 'active' ]; then
                if [ -e "$xinetd_telnet_config" ] && [ ! -r "$xinetd_telnet_config" ]; then
                    telnet_service_state='unknown'
                    telnet_service_probe_error='XINETD_CONFIGURATION_UNREADABLE'
                elif [ -r "$xinetd_telnet_config" ] && \
                     grep -Eiq '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)' \
                     "$xinetd_telnet_config" 2>/dev/null; then
                    telnet_service_state='active'
                    telnet_activation_source='xinetd_configuration'
                fi
            fi
            ;;
    esac
fi

include_directives=''
include_present=false
match_condition_present='unknown'
ssh_config_scan='unavailable'
configuration_paths="$sshd_config
$pam_login
$securetty
$inetd_config
$xinetd_telnet_config"

if [ -r "$sshd_config" ]; then
    ssh_config_scan='complete'
    include_directives=$(awk '
        /^[[:space:]]*#/ { next }
        tolower($1) == "include" {
            for (field = 2; field <= NF; field++) print $field
        }
    ' "$sshd_config" 2>/dev/null || true)
    if [ -n "$include_directives" ]; then
        include_present=true
    fi
    if awk '
        /^[[:space:]]*#/ { next }
        tolower($1) == "match" { found = 1 }
        END { exit found ? 0 : 1 }
    ' "$sshd_config" 2>/dev/null; then
        match_condition_present=true
    else
        match_condition_present=false
    fi

    old_ifs=$IFS
    IFS='
'
    for include_pattern in $include_directives; do
        IFS=$old_ifs
        case "$include_pattern" in
            /*) resolved_pattern=$include_pattern ;;
            *) resolved_pattern="/etc/ssh/$include_pattern" ;;
        esac
        # Expansion is restricted to patterns read from the local OpenSSH config.
        # shellcheck disable=SC2086
        for include_path in $resolved_pattern; do
            [ -e "$include_path" ] || continue
            configuration_paths="$configuration_paths
$include_path"
            if [ ! -r "$include_path" ]; then
                ssh_config_scan='unavailable'
                match_condition_present='unknown'
                continue
            fi
            if awk '
                /^[[:space:]]*#/ { next }
                tolower($1) == "match" { found = 1 }
                END { exit found ? 0 : 1 }
            ' "$include_path" 2>/dev/null; then
                match_condition_present=true
            fi
        done
        IFS='
'
    done
    IFS=$old_ifs
fi

include_json=$(printf '%s\n' "$include_directives" | os_guard_json_array_from_lines)
configuration_paths_json=$(printf '%s\n' "$configuration_paths" | os_guard_json_array_from_lines)
ssh_units_json=$(printf '%s\n' "$ssh_units_lines" | os_guard_json_array_from_lines)
telnet_units_json=$(printf '%s\n' "$telnet_units_lines" | os_guard_json_array_from_lines)

sshd_bin=''
permit_root_login=''
permit_source='not_checked'
ssh_restriction='not_applicable'
ssh_error=''

if [ "$ssh_service_state" = 'active' ]; then
    sshd_bin=$(command -v sshd 2>/dev/null || true)
    if [ -z "$sshd_bin" ] || [ ! -x "$sshd_bin" ]; then
        ssh_restriction='unknown'
        ssh_error='OPENSSH_EXECUTABLE_NOT_FOUND'
    elif [ "$ssh_config_scan" != 'complete' ]; then
        ssh_restriction='unknown'
        ssh_error='SSH_CONFIGURATION_UNREADABLE'
    else
        host_name=$(hostname 2>/dev/null || printf 'localhost')
        [ -n "$host_name" ] || host_name='localhost'
        if effective_output=$(
            "$sshd_bin" -T -C "user=root,host=$host_name,addr=127.0.0.1" 2>/dev/null
        ); then
            permit_root_login=$(printf '%s\n' "$effective_output" | awk '
                tolower($1) == "permitrootlogin" { print tolower($2); exit }
            ')
            permit_source='sshd_effective_config'
        fi

        if [ -z "$permit_root_login" ]; then
            ssh_restriction='unknown'
            ssh_error='EFFECTIVE_CONFIG_UNAVAILABLE'
        elif [ "$match_condition_present" = 'true' ]; then
            ssh_restriction='review_required'
        elif [ "$permit_root_login" = 'no' ]; then
            ssh_restriction='blocked'
        else
            ssh_restriction='allowed'
        fi
    fi
elif [ "$ssh_service_state" = 'unknown' ]; then
    ssh_restriction='unknown'
    ssh_error='SSH_SERVICE_STATE_UNAVAILABLE'
fi

pam_securetty_applied='unknown'
securetty_exists=false
securetty_readable=false
securetty_pts_allowed='unknown'
telnet_restriction='not_applicable'
telnet_error=''

if [ "$telnet_service_state" = 'active' ]; then
    if [ -e "$pam_login" ] && [ ! -r "$pam_login" ]; then
        telnet_restriction='unknown'
        telnet_error='PAM_LOGIN_UNREADABLE'
    else
        pam_securetty_applied=false
        if [ -r "$pam_login" ] && grep -Eq \
            '^[[:space:]]*auth[[:space:]]+required[[:space:]]+([^[:space:]]*/)?pam_securetty\.so([[:space:]]|$)' \
            "$pam_login" 2>/dev/null; then
            pam_securetty_applied=true
        fi

        if [ -e "$securetty" ]; then
            securetty_exists=true
            if [ ! -r "$securetty" ]; then
                telnet_restriction='unknown'
                telnet_error='SECURETTY_UNREADABLE'
            else
                securetty_readable=true
                securetty_pts_allowed=false
                if grep -Eq '^[[:space:]]*pts/[^[:space:]#]+' "$securetty" 2>/dev/null; then
                    securetty_pts_allowed=true
                fi
            fi
        else
            securetty_pts_allowed='unknown'
        fi

        if [ -z "$telnet_error" ]; then
            if [ "$pam_securetty_applied" = 'true' ]; then
                if [ "$securetty_exists" = 'false' ] || \
                   [ "$securetty_pts_allowed" = 'false' ]; then
                    telnet_restriction='blocked'
                else
                    telnet_restriction='allowed'
                fi
            else
                telnet_restriction='allowed'
            fi
        fi
    fi
elif [ "$telnet_service_state" = 'unknown' ]; then
    telnet_restriction='unknown'
    telnet_error=$telnet_service_probe_error
    [ -n "$telnet_error" ] || telnet_error='TELNET_SERVICE_STATE_UNAVAILABLE'
fi

status_json='"GOOD"'
review_state='NOT_REQUIRED'
decision_reason='All detected remote terminal services are unused or block direct root login'
error_json='null'

if [ "$ssh_restriction" = 'allowed' ] || [ "$telnet_restriction" = 'allowed' ]; then
    status_json='"VULNERABLE"'
    decision_reason='At least one active remote terminal service permits direct root login'
elif [ "$ssh_restriction" = 'unknown' ] || [ "$telnet_restriction" = 'unknown' ]; then
    status_json='"UNCHECKABLE"'
    decision_reason='An active or potentially active remote terminal service could not be verified'
    error_json=$(
        printf '{"code":"REMOTE_ACCESS_CHECK_UNAVAILABLE","message":"Remote access service or policy state could not be verified","ssh_code":'
        json_nullable_string "$ssh_error"
        printf ',"telnet_code":'
        json_nullable_string "$telnet_error"
        printf '}'
    )
elif [ "$ssh_restriction" = 'review_required' ]; then
    status_json='null'
    review_state='PENDING'
    decision_reason='OpenSSH Match conditions may produce different PermitRootLogin values by connection context'
fi

printf '{'
printf '"item_id":"U-01",'
printf '"status":%s,' "$status_json"
printf '"review_state":"%s",' "$review_state"
printf '"current_value":{'
printf '"ssh":{'
printf '"service_in_use":'
case "$ssh_service_state" in active) printf 'true' ;; inactive) printf 'false' ;; *) printf 'null' ;; esac
printf ',"service_state":'
os_guard_json_quote "$ssh_service_state"
printf ',"permit_root_login":'
json_nullable_string "$permit_root_login"
printf ',"value_source":'
os_guard_json_quote "$permit_source"
printf ',"root_login_restriction":'
os_guard_json_quote "$ssh_restriction"
printf '},"telnet":{'
printf '"service_in_use":'
case "$telnet_service_state" in active) printf 'true' ;; inactive) printf 'false' ;; *) printf 'null' ;; esac
printf ',"service_state":'
os_guard_json_quote "$telnet_service_state"
printf ',"activation_source":'
os_guard_json_quote "$telnet_activation_source"
printf ',"pam_securetty_applied":'
json_nullable_boolean "$pam_securetty_applied"
printf ',"securetty_exists":%s' "$securetty_exists"
printf ',"securetty_readable":%s' "$securetty_readable"
printf ',"pts_entries_allowed":'
json_nullable_boolean "$securetty_pts_allowed"
printf ',"root_login_restriction":'
os_guard_json_quote "$telnet_restriction"
printf '}},'
printf '"evidence":{'
printf '"item_id":"U-01",'
printf '"collection_method":"Service state inspection, OpenSSH effective configuration query, and KISA Telnet PAM/securetty inspection",'
printf '"configuration_paths":%s,' "$configuration_paths_json"
printf '"include_directives":%s,' "$include_json"
printf '"include_present":%s,' "$include_present"
printf '"match_condition_present":'
json_nullable_boolean "$match_condition_present"
printf ',"ssh_service_units":%s,' "$ssh_units_json"
printf '"telnet_service_units":%s,' "$telnet_units_json"
printf '"sshd_executable":'
json_nullable_string "$sshd_bin"
printf ',"os":{"distro":'
os_guard_json_quote "$distro"
printf ',"version_id":'
os_guard_json_quote "$version_id"
printf '},"observed_at":'
os_guard_json_quote "$observed_at"
printf ',"module_version":'
os_guard_json_quote "$module_version"
printf ',"decision_reason":'
os_guard_json_quote "$decision_reason"
printf '},"error":%s}\n' "$error_json"

exit 0
