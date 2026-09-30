#!/bin/sh
set -u
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd); . "$SCRIPT_DIR/../lib/common.sh"
distro=${OS_GUARD_DISTRO:-unknown}; version_id=${OS_GUARD_VERSION_ID:-unknown}; module_version=${OS_GUARD_MODULE_VERSION:-unknown}; observed_at=$(os_guard_utc_now); kernel=$(uname -r 2>/dev/null || printf unknown); root=${OS_GUARD_TEST_ROOT:-}
status_json=null; review_state=PENDING; reason_code=KISA_U29_NOT_EVALUATED; basis='hosts.lpd metadata was not evaluated'; error_json=null
exists=false; checked=false; owner_compliant=false; permission_compliant=false; mode=''; collection_error=''
case "$distro:$version_id" in rocky:9|rocky:9.*|rocky:10|rocky:10.*|ubuntu:22|ubuntu:22.*|ubuntu:24|ubuntu:24.*) ;; *) collection_error=UNSUPPORTED_OS_CONFIGURATION;; esac
target="${root}/etc/hosts.lpd"
if [ -z "$collection_error" ] && [ -n "${OS_GUARD_TEST_U29_FILE:-}" ]; then
  IFS='|' read -r state f_exists f_checked f_owner_ok f_perm_ok identity_conflict extra < "$OS_GUARD_TEST_U29_FILE" || true
  case "$state:$f_exists:$f_checked:$f_owner_ok:$f_perm_ok:$identity_conflict" in complete:true:true:true:true:false) exists=true; checked=true; owner_compliant=true; permission_compliant=true; status_json='"GOOD"'; review_state=NOT_REQUIRED; reason_code=KISA_U29_OWNER_AND_MODE_COMPLIANT; basis='The file is root-owned and its permission is a subset of 0600';; complete:false:false:false:false:false) status_json='"GOOD"'; review_state=NOT_REQUIRED; reason_code=KISA_U29_FILE_ABSENT; basis='The hosts.lpd file does not exist';; complete:true:true:*:*:true) exists=true; checked=true; status_json=null; review_state=PENDING; reason_code=KISA_U29_IDENTITY_CONFLICT; basis='Owner UID and name resolution conflict requires review';; complete:true:true:*:*:false) exists=true; checked=true; owner_compliant=$f_owner_ok; permission_compliant=$f_perm_ok; status_json='"VULNERABLE"'; review_state=NOT_REQUIRED; reason_code=KISA_U29_OWNER_OR_MODE_VIOLATION; basis='The file owner or permission does not meet the KISA requirement';; *) collection_error=FIXTURE_RESULT_INVALID;; esac
elif [ -z "$collection_error" ]; then
  if [ ! -e "$target" ] && [ ! -L "$target" ]; then status_json='"GOOD"'; review_state=NOT_REQUIRED; reason_code=KISA_U29_FILE_ABSENT; basis='The hosts.lpd file does not exist'
  elif [ ! -f "$target" ] || [ -L "$target" ]; then exists=true; status_json=null; review_state=PENDING; reason_code=KISA_U29_NONSTANDARD_FILE_TYPE; basis='The configured path is not a regular non-symbolic file'
  else
    exists=true; stat_bin=$(command -v stat 2>/dev/null || true)
    if [ -z "$stat_bin" ]; then collection_error=STAT_COMMAND_UNUSABLE
    else
      metadata=$($stat_bin -c '%u|%U|%a' -- "$target" 2>/dev/null) || collection_error=STAT_FAILED
      if [ -z "$collection_error" ]; then
        old=$IFS; IFS='|'; set -- $metadata; IFS=$old
        if [ "$#" -ne 3 ] || ! printf '%s|%s|%s\n' "$1" "$2" "$3" | awk -F'|' '$1~/^[0-9]+$/&&$2!=""&&$3~/^[0-7]{3,4}$/{ok=1}END{exit ok?0:1}'; then collection_error=METADATA_PARSE_FAILED
        else uid=$1; owner=$2; mode=$3; checked=true; [ "$uid" -eq 0 ] && [ "$owner" = root ] && owner_compliant=true; mode_value=$((0$mode)); [ $((mode_value & ~0600)) -eq 0 ] && permission_compliant=true
          if { [ "$uid" -eq 0 ] && [ "$owner" != root ]; } || { [ "$uid" -ne 0 ] && [ "$owner" = root ]; }; then status_json=null; review_state=PENDING; reason_code=KISA_U29_IDENTITY_CONFLICT; basis='Owner UID and name resolution conflict requires review'
          elif [ "$owner_compliant" = true ] && [ "$permission_compliant" = true ]; then status_json='"GOOD"'; review_state=NOT_REQUIRED; reason_code=KISA_U29_OWNER_AND_MODE_COMPLIANT; basis='The file is root-owned and its permission is a subset of 0600'
          else status_json='"VULNERABLE"'; review_state=NOT_REQUIRED; reason_code=KISA_U29_OWNER_OR_MODE_VIOLATION; basis='The file owner or permission does not meet the KISA requirement'; fi
        fi
      fi
    fi
  fi
fi
if [ -n "$collection_error" ]; then status_json='"UNCHECKABLE"'; review_state=NOT_REQUIRED; reason_code=KISA_U29_COLLECTION_FAILED; basis='Required file metadata could not be collected'; error_json=$(printf '{"code":'; os_guard_json_quote "$collection_error"; printf ',"message":"hosts.lpd metadata collection failed"}'); fi
printf '{"item_id":"U-29","status":%s,"review_state":"%s","current_value":{"exists":%s,"checked":%s,"owner_compliant":%s,"permission_compliant":%s,"mode":' "$status_json" "$review_state" "$exists" "$checked" "$owner_compliant" "$permission_compliant"; os_guard_json_quote "$mode"
printf '},"evidence":{"item_id":"U-29","inspection_target":"/etc/hosts.lpd metadata","collection_method":"Read-only existence and stat metadata inspection","exists":%s,"checked":%s,"owner_compliant":%s,"permission_compliant":%s,"reason_code":' "$exists" "$checked" "$owner_compliant" "$permission_compliant"; os_guard_json_quote "$reason_code"; printf ',"os":{"distro":'; os_guard_json_quote "$distro"; printf ',"version_id":'; os_guard_json_quote "$version_id"; printf '},"kernel":'; os_guard_json_quote "$kernel"; printf ',"module_version":'; os_guard_json_quote "$module_version"; printf ',"observed_at":'; os_guard_json_quote "$observed_at"; printf ',"judgment_basis":'; os_guard_json_quote "$basis"; printf '},"error":%s}\n' "$error_json"
