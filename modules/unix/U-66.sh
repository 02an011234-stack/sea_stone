#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/../lib/common.sh"

distro=${OS_GUARD_DISTRO:-unknown}
version_id=${OS_GUARD_VERSION_ID:-unknown}
module_version=${OS_GUARD_MODULE_VERSION:-unknown}
observed_at=$(os_guard_utc_now)
kernel=$(uname -r 2>/dev/null || printf unknown)
root=${OS_GUARD_TEST_ROOT:-}

status_json=null
review_state=PENDING
error_json=null
active=0
output=0
policy=0
rules=0
complex=0
backend=none
complete=false
err=''

case "$distro:$version_id" in
    rocky:9|rocky:9.*|rocky:10|rocky:10.*|ubuntu:22|ubuntu:22.*|ubuntu:24|ubuntu:24.*) ;;
    *) err=UNSUPPORTED_OS_CONFIGURATION ;;
esac

fixture() {
    IFS='|' read -r state active output policy rules complex backend extra < "$1" || true
    [ "$state" = complete ] && complete=true || err=COLLECTION_FAILED
    for value in "$active" "$output" "$policy" "$rules" "$complex"; do
        case "$value" in ''|*[!0-9]*) err=RESULT_PARSE_FAILED ;; esac
    done
    case "$backend" in rsyslog|journald|syslog|mixed|none) ;; *) err=RESULT_PARSE_FAILED ;; esac
}

last_storage_value() {
    awk '
        /^[[:space:]]*\[/ {
            section=$0
            gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", section)
            next
        }
        section == "Journal" && /^[[:space:]]*Storage[[:space:]]*=/ {
            value=$0
            sub(/^[^=]*=[[:space:]]*/, "", value)
            sub(/[[:space:]]*$/, "", value)
            storage=tolower(value)
        }
        END { print storage }
    '
}

assess_journald_config() {
    config_text=$1
    if ! printf '%s\n' "$config_text" | grep -Eq '^[[:space:]]*\[Journal\][[:space:]]*$'; then
        err=JOURNALD_CONFIG_INVALID
        return 1
    fi
    storage_value=$(printf '%s\n' "$config_text" | last_storage_value)
    if [ "$storage_value" = none ]; then
        rules=0
    else
        rules=$((rules + 1))
    fi
    return 0
}

collect_journald_with_analyzer() {
    analyzer=''
    if [ -n "$root" ] && [ -n "${OS_GUARD_TEST_SYSTEMD_ANALYZE_BIN:-}" ]; then
        analyzer=$OS_GUARD_TEST_SYSTEMD_ANALYZE_BIN
        [ -f "$analyzer" ] && [ -x "$analyzer" ] || return 1
    elif [ -z "$root" ]; then
        analyzer=$(command -v systemd-analyze 2>/dev/null || true)
        [ -n "$analyzer" ] || return 1
    else
        return 1
    fi

    config_text=$($analyzer cat-config systemd/journald.conf 2>/dev/null)
    [ $? -eq 0 ] && [ -n "$config_text" ] || return 1
    assess_journald_config "$config_text"
}

collect_journald_fallback() {
    base=''
    for candidate in \
        "${root}/etc/systemd/journald.conf" \
        "${root}/run/systemd/journald.conf" \
        "${root}/usr/local/lib/systemd/journald.conf" \
        "${root}/usr/lib/systemd/journald.conf" \
        "${root}/lib/systemd/journald.conf"; do
        if [ -e "$candidate" ] || [ -L "$candidate" ]; then
            [ -r "$candidate" ] || { err=JOURNALD_CONFIG_UNREADABLE; return; }
            base=$candidate
            break
        fi
    done

    dropin_count=0
    for directory in \
        "${root}/usr/lib/systemd/journald.conf.d" \
        "${root}/usr/local/lib/systemd/journald.conf.d" \
        "${root}/run/systemd/journald.conf.d" \
        "${root}/etc/systemd/journald.conf.d"; do
        [ -e "$directory" ] || continue
        [ -d "$directory" ] && [ -r "$directory" ] && [ -x "$directory" ] || { err=JOURNALD_CONFIG_UNREADABLE; return; }
        for fragment in "$directory"/*.conf; do
            [ -e "$fragment" ] || [ -L "$fragment" ] || continue
            [ -r "$fragment" ] || { err=JOURNALD_CONFIG_UNREADABLE; return; }
            dropin_count=$((dropin_count + 1))
        done
    done

    if [ -n "$base" ]; then
        config_text=$(cat -- "$base" 2>/dev/null) || { err=JOURNALD_CONFIG_UNREADABLE; return; }
        assess_journald_config "$config_text" || return
    else
        rules=$((rules + 1))
        complex=$((complex + 1))
    fi

    if [ "$dropin_count" -gt 0 ]; then
        complex=$((complex + dropin_count))
        [ "$rules" -gt 0 ] || rules=1
    fi
}

collect_journald_config() {
    if collect_journald_with_analyzer; then return; fi
    [ -z "$err" ] || return
    collect_journald_fallback
}

runtime() {
    systemctl_bin=$(command -v systemctl 2>/dev/null || true)
    [ -n "$systemctl_bin" ] || { err=SYSTEMCTL_UNAVAILABLE; return; }

    rs=0; jr=0; sy=0
    [ "$($systemctl_bin is-active rsyslog.service 2>/dev/null || true)" = active ] && rs=1
    [ "$($systemctl_bin is-active systemd-journald.service 2>/dev/null || true)" = active ] && jr=1
    [ "$($systemctl_bin is-active syslog.service 2>/dev/null || true)" = active ] && sy=1
    active=$((rs + jr + sy))
    if [ "$active" -gt 1 ]; then backend=mixed
    elif [ "$rs" -gt 0 ]; then backend=rsyslog
    elif [ "$jr" -gt 0 ]; then backend=journald
    elif [ "$sy" -gt 0 ]; then backend=syslog
    fi
    if [ "$active" -eq 0 ]; then complete=true; return; fi

    if [ "$rs" -gt 0 ]; then
        rsyslog_conf="${root}/etc/rsyslog.conf"
        [ -r "$rsyslog_conf" ] || { err=RSYSLOG_CONFIG_UNREADABLE; return; }
        rules=$(grep -Eic '^[[:space:]]*[^#$[:space:]][^[:space:]]*\.[^[:space:]]+[[:space:]]+[^[:space:]]+' "$rsyslog_conf" || true)
        include_count=$(grep -Eic '^[[:space:]]*(\$IncludeConfig|include\()[[:space:]]*' "$rsyslog_conf" || true)
        [ "$include_count" -gt 0 ] && complex=$((complex + include_count))
        for fragment in "${root}/etc/rsyslog.d"/*.conf; do
            [ -r "$fragment" ] || continue
            fragment_rules=$(grep -Eic '^[[:space:]]*[^#$[:space:]][^[:space:]]*\.[^[:space:]]+[[:space:]]+[^[:space:]]+' "$fragment" || true)
            rules=$((rules + fragment_rules))
            grep -Eiq '(^|[[:space:]])@@?[^[:space:]]+' "$fragment" && complex=$((complex + 1))
        done
    fi

    if [ "$jr" -gt 0 ]; then
        collect_journald_config
        [ -z "$err" ] || return
    fi

    logroot="${root}/var/log"
    [ -d "$logroot" ] || { err=LOG_DIRECTORY_UNAVAILABLE; return; }
    found=$(find "$logroot" -xdev -type f -size +0c -print -quit 2>/dev/null)
    [ $? -eq 0 ] || { err=LOG_OUTPUT_SCAN_FAILED; return; }
    if [ -z "$found" ] && [ "$jr" -gt 0 ]; then
        for journal_root in "${root}/run/log/journal" "${root}/var/log/journal"; do
            [ -d "$journal_root" ] || continue
            found=$(find "$journal_root" -xdev -type f -size +0c -print -quit 2>/dev/null)
            [ $? -eq 0 ] || { err=LOG_OUTPUT_SCAN_FAILED; return; }
            [ -z "$found" ] || break
        done
    fi
    [ -n "$found" ] && output=1
    found=''
    complete=true
}

if [ -z "$err" ]; then
    if [ -n "${OS_GUARD_TEST_U66_FILE:-}" ]; then fixture "$OS_GUARD_TEST_U66_FILE"
    else runtime
    fi
fi

if [ -n "$err" ] || [ "$complete" != true ]; then
    status_json='"UNCHECKABLE"'; review_state=NOT_REQUIRED; reason=KISA_U66_COLLECTION_FAILED
    basis='Logging service, configuration, or output state could not be collected'
    code=${err:-INCOMPLETE}
    error_json=$(printf '{"code":'; os_guard_json_quote "$code"; printf ',"message":"Logging-policy collection failed"}')
elif [ "$active" -eq 0 ]; then
    status_json='"VULNERABLE"'; review_state=NOT_REQUIRED; reason=KISA_U66_LOGGING_INACTIVE
    basis='No supported system logging backend is active'
elif [ "$output" -eq 0 ]; then
    status_json='"VULNERABLE"'; review_state=NOT_REQUIRED; reason=KISA_U66_LOG_OUTPUT_ABSENT
    basis='The active logging backend has no observable non-empty local log output'
elif [ "$rules" -eq 0 ] && [ "$complex" -eq 0 ]; then
    status_json='"VULNERABLE"'; review_state=NOT_REQUIRED; reason=KISA_U66_REQUIRED_RULES_ABSENT
    basis='No local logging rule or enabled journald storage policy is present'
elif [ "$policy" -gt 0 ] && [ "$complex" -eq 0 ]; then
    status_json='"GOOD"'; review_state=NOT_REQUIRED; reason=KISA_U66_POLICY_VERIFIED
    basis='Logging is active, output is present, and the registered security logging policy is verified'
else
    status_json=null; review_state=PENDING; reason=KISA_U66_POLICY_REVIEW_REQUIRED
    basis='Logging is operational, but organizational policy alignment or complex forwarding requires review'
fi

printf '{"item_id":"U-66","status":%s,"review_state":"%s","current_value":{"logging_active":%s,"logging_backend":' "$status_json" "$review_state" "$active"
os_guard_json_quote "$backend"
printf ',"log_output_present":%s,"policy_verified":%s,"required_rules_present_count":%s,"complex_config_count":%s},' "$output" "$policy" "$rules" "$complex"
printf '"evidence":{"item_id":"U-66","collection_method":"Read-only logging service, aggregate rule, and file-metadata inspection without log content","logging_active":%s,"logging_backend":' "$active"
os_guard_json_quote "$backend"
printf ',"log_output_present":%s,"policy_verified":%s,"required_rules_present_count":%s,"complex_config_count":%s,"reason_code":' "$output" "$policy" "$rules" "$complex"
os_guard_json_quote "$reason"
printf ',"os":{"distro":'; os_guard_json_quote "$distro"; printf ',"version_id":'; os_guard_json_quote "$version_id"; printf '},"kernel":'; os_guard_json_quote "$kernel"
printf ',"module_version":'; os_guard_json_quote "$module_version"; printf ',"observed_at":'; os_guard_json_quote "$observed_at"; printf ',"judgment_basis":'; os_guard_json_quote "$basis"
printf '},"error":%s}\n' "$error_json"
