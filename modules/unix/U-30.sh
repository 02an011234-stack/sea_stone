#!/bin/sh
set -u
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd); . "$SCRIPT_DIR/../lib/common.sh"
distro=${OS_GUARD_DISTRO:-unknown}; version_id=${OS_GUARD_VERSION_ID:-unknown}; module_version=${OS_GUARD_MODULE_VERSION:-unknown}; observed_at=$(os_guard_utc_now); kernel=$(uname -r 2>/dev/null || printf unknown); root=${OS_GUARD_TEST_ROOT:-}
status_json=null; review_state=PENDING; reason_code=KISA_U30_NOT_EVALUATED; basis='UMASK sources were not evaluated'; error_json=null
checked_source_count=0; effective_value_count=0; compliant_count=0; noncompliant_count=0; ambiguity_count=0; collection_error=''; effective_mask=''
case "$distro:$version_id" in rocky:9|rocky:9.*|rocky:10|rocky:10.*|ubuntu:22|ubuntu:22.*|ubuntu:24|ubuntu:24.*) ;; *) collection_error=UNSUPPORTED_OS_CONFIGURATION;; esac
evaluate_mask(){ value=$1; case "$value" in 0[0-7][0-7]|[0-7][0-7][0-7]) ;; *) ambiguity_count=$((ambiguity_count+1)); return;; esac; effective_value_count=$((effective_value_count+1)); effective_mask=$value; numeric=$((0$value)); if [ $((numeric & 0022)) -eq 0022 ]; then compliant_count=$((compliant_count+1)); else noncompliant_count=$((noncompliant_count+1)); fi; }
parse_source(){ f=$1; [ -r "$f" ] || { collection_error=SOURCE_UNREADABLE; return; }; checked_source_count=$((checked_source_count+1)); while IFS= read -r line || [ -n "$line" ]; do clean=$(printf '%s\n' "$line" | sed 's/[[:space:]]*#.*$//'); [ -n "$clean" ] || continue; case "$clean" in *'if '*|*'case '*|*'$('*) ambiguity_count=$((ambiguity_count+1));; esac; value=$(printf '%s\n' "$clean" | awk 'match($0,/(^|[;[:space:]])(umask|UMASK)[[:space:]=]+([0-7]+)/,m){print m[3]}' 2>/dev/null || true); [ -z "$value" ] || evaluate_mask "$value"; done < "$f"; }
if [ -z "$collection_error" ]; then
 if [ -n "${OS_GUARD_TEST_UMASK_FILE:-}" ]; then
  IFS='|' read -r state checked effective compliant noncompliant ambiguous mask extra < "$OS_GUARD_TEST_UMASK_FILE" || true
  case "${state:-}" in complete|read_error) ;; *) collection_error=RESULT_PARSE_FAILED;; esac
  for v in "$checked" "$effective" "$compliant" "$noncompliant" "$ambiguous"; do case "$v" in ''|*[!0-9]*) collection_error=RESULT_PARSE_FAILED;; esac; done
  checked_source_count=${checked:-0}; effective_value_count=${effective:-0}; compliant_count=${compliant:-0}; noncompliant_count=${noncompliant:-0}; ambiguity_count=${ambiguous:-0}; effective_mask=${mask:-}; [ "${state:-}" = read_error ] && collection_error=SOURCE_READ_FAILED
 else
  found=false; for f in "${root}/etc/profile" "${root}/etc/login.defs"; do if [ -e "$f" ]; then found=true; parse_source "$f"; fi; done
  for f in "${root}"/etc/profile.d/*.sh; do [ -e "$f" ] || continue; found=true; parse_source "$f"; done
  passwd_file="${root}/etc/passwd"; if [ -r "$passwd_file" ]; then while IFS=: read -r n x u g c h s extra; do case "$u" in ''|*[!0-9]*) collection_error=PASSWD_PARSE_FAILED; break;; esac; for name in .profile .bashrc .bash_profile .kshrc .cshrc .login; do f="${root}${h}/$name"; [ -e "$f" ] && { found=true; parse_source "$f"; }; done; done < "$passwd_file"; fi
  [ "$found" = true ] || collection_error=NO_UMASK_SOURCE
 fi
fi
if [ -n "$collection_error" ]; then status_json='"UNCHECKABLE"'; review_state=NOT_REQUIRED; reason_code=KISA_U30_COLLECTION_FAILED; basis='Required UMASK sources could not be read or parsed'; error_json=$(printf '{"code":'; os_guard_json_quote "$collection_error"; printf ',"message":"UMASK collection failed"}')
elif [ "$ambiguity_count" -gt 0 ] || [ "$effective_value_count" -gt 1 ] && [ "$compliant_count" -gt 0 ] && [ "$noncompliant_count" -gt 0 ]; then status_json=null; review_state=PENDING; reason_code=KISA_U30_EFFECTIVE_VALUE_AMBIGUOUS; basis='Conflicting or dynamic startup logic prevents one effective UMASK from being established'
elif [ "$effective_value_count" -eq 0 ]; then status_json='"VULNERABLE"'; review_state=NOT_REQUIRED; reason_code=KISA_U30_UMASK_NOT_SET; basis='No effective UMASK setting was identified in the inspected startup sources'
elif [ "$noncompliant_count" -gt 0 ]; then status_json='"VULNERABLE"'; review_state=NOT_REQUIRED; reason_code=KISA_U30_MASK_BELOW_REQUIREMENT; basis='An effective UMASK does not contain the required 022 mask bits'
else status_json='"GOOD"'; review_state=NOT_REQUIRED; reason_code=KISA_U30_MASK_COMPLIANT; basis='The effective UMASK contains at least the required 022 mask bits'; fi
printf '{"item_id":"U-30","status":%s,"review_state":"%s","current_value":{"checked_source_count":%s,"effective_value_count":%s,"compliant_count":%s,"noncompliant_count":%s,"ambiguity_count":%s,"effective_mask":' "$status_json" "$review_state" "$checked_source_count" "$effective_value_count" "$compliant_count" "$noncompliant_count" "$ambiguity_count"; os_guard_json_quote "$effective_mask"
printf '},"evidence":{"item_id":"U-30","inspection_target":"system and account shell startup UMASK settings","collection_method":"Read-only bounded startup source parsing with octal bit-mask evaluation","checked_source_count":%s,"effective_value_count":%s,"compliant_count":%s,"noncompliant_count":%s,"ambiguity_count":%s,"reason_code":' "$checked_source_count" "$effective_value_count" "$compliant_count" "$noncompliant_count" "$ambiguity_count"; os_guard_json_quote "$reason_code"; printf ',"os":{"distro":'; os_guard_json_quote "$distro"; printf ',"version_id":'; os_guard_json_quote "$version_id"; printf '},"kernel":'; os_guard_json_quote "$kernel"; printf ',"module_version":'; os_guard_json_quote "$module_version"; printf ',"observed_at":'; os_guard_json_quote "$observed_at"; printf ',"judgment_basis":'; os_guard_json_quote "$basis"; printf '},"error":%s}\n' "$error_json"
