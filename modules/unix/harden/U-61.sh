#!/bin/sh
set -u
set -f

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_content.sh"

HARDEN_ITEM_ID='U-61'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-61.sh"
HARDEN_TARGET_DESCRIPTION='one direct SNMP community source restriction'
HARDEN_RISK_LEVEL='HIGH'
HARDEN_SERVICE_RELOAD_REQUIRED=true

u61_configuration_path=''

u61_set_error() {
    os_guard_content_set_error "$1" "$2"
    return 1
}

u61_unit_is_active() {
    systemctl_command=$(command -v systemctl 2>/dev/null || true)
    [ -n "$systemctl_command" ] && \
        [ "$("$systemctl_command" is-active snmpd.service 2>/dev/null || true)" = 'active' ]
}

os_guard_item_validate_content_policy() {
    if [ -z "$content_test_root" ] || \
        [ "$content_test_root" = '/' ] || \
        [ "${OS_GUARD_TEST_POLICY_FIXTURE:-false}" != 'true' ]; then
        u61_set_error \
            'POLICY_INTEGRATION_REQUIRED' \
            'trusted U-61 operating policy integration is not available'
        return 1
    fi
    if [ "${OS_GUARD_TEST_SNMP_ACCESS_POLICY_APPROVED:-false}" != 'true' ] || \
        [ "${OS_GUARD_TEST_SNMP_CONFIGURATION_SOURCE:-}" != 'static-snmpd-conf' ] || \
        [ "${OS_GUARD_TEST_MONITORING_CONNECTIVITY_VERIFIED:-false}" != 'true' ]; then
        u61_set_error \
            'SNMP_ACCESS_POLICY_EVIDENCE_REQUIRED' \
            'approved SNMP source and monitoring-connectivity evidence are required'
        return 1
    fi
    if ! os_guard_harden_ipv4_cidr_is_bounded \
        "${OS_GUARD_TEST_APPROVED_MANAGEMENT_NETWORK:-}"; then
        u61_set_error \
            'SNMP_NETWORK_SCOPE_INVALID' \
            'one bounded approved SNMP management network is required'
        return 1
    fi
    if [ "$content_action" = 'EXECUTE' ] && \
        [ "${OS_GUARD_TEST_RELOAD_APPROVED:-false}" != 'true' ]; then
        u61_set_error \
            'SERVICE_RELOAD_APPROVAL_REQUIRED' \
            'SNMP reload approval is required'
        return 1
    fi
}

u61_direct_community_count() {
    awk '
        $1 ~ /^(rocommunity|rwcommunity|rocommunity6|rwcommunity6)$/ { count++ }
        END { print count+0 }
    ' "$1"
}

os_guard_item_render_content() {
    source_path=$1
    approved_network=$OS_GUARD_TEST_APPROVED_MANAGEMENT_NETWORK
    awk -v network="$approved_network" '
        $1 ~ /^(rocommunity|rwcommunity|rocommunity6|rwcommunity6)$/ {
            suffix=""
            for (field_number=4; field_number<=NF; field_number++) {
                suffix=suffix " " $field_number
            }
            print $1 " " $2 " " network suffix
            next
        }
        { print }
    ' "$source_path"
}

os_guard_item_discover_content_targets() {
    if ! u61_unit_is_active; then
        u61_set_error \
            'SUPPORTED_SNMP_SERVICE_REQUIRED' \
            'the approved snmpd service is not active'
        return 1
    fi
    u61_configuration_path="${content_test_root}/etc/snmp/snmpd.conf"
    if [ ! -f "$u61_configuration_path" ] || [ -L "$u61_configuration_path" ]; then
        u61_set_error \
            'SNMP_CONFIGURATION_AMBIGUOUS' \
            'one regular static snmpd.conf is required'
        return 1
    fi
    if grep -Eiq '^[[:space:]]*(include|includeFile|includeDir|access|group|view)([[:space:]]|$)' "$u61_configuration_path"; then
        u61_set_error \
            'SNMP_COMPLEX_POLICY_NOT_SUPPORTED' \
            'included or VACM SNMP configuration requires manual review'
        return 1
    fi
    if [ "$(u61_direct_community_count "$u61_configuration_path")" -ne 1 ]; then
        u61_set_error \
            'SNMP_ACCESS_RULE_AMBIGUOUS' \
            'exactly one direct community access rule is required'
        return 1
    fi
    if ! awk '
        $1 ~ /^(rocommunity|rwcommunity|rocommunity6|rwcommunity6)$/ &&
        ($3 == "" || $3 == "default" || $3 == "any" || $3 == "ANY" ||
         $3 == "0.0.0.0" || $3 == "0.0.0.0/0" || $3 == "::" || $3 == "::/0") {
            found=1
        }
        END { exit found ? 0 : 1 }
    ' "$u61_configuration_path"; then
        u61_set_error \
            'SNMP_ACCESS_RULE_NOT_ACTIONABLE' \
            'the direct SNMP rule is not an explicitly unrestricted source'
        return 1
    fi

    CONTENT_CURRENT_EFFECTIVE_VALUE='one direct SNMP rule permits an unrestricted source'
    os_guard_content_add_target \
        "$u61_configuration_path" \
        '/etc/snmp/snmpd.conf' \
        'SNMP source restriction' \
        'replace only the unrestricted source with the approved management network'
}

os_guard_item_validate_configuration() {
    if [ "${OS_GUARD_TEST_FORCE_ITEM_SYNTAX_FAILURE:-false}" = 'true' ]; then
        u61_set_error \
            'SNMP_ACCESS_VALIDATION_FAILED' \
            'forced SNMP access-policy validation failure'
        return 1
    fi
    approved_network=$OS_GUARD_TEST_APPROVED_MANAGEMENT_NETWORK
    restricted_count=$(awk -v network="$approved_network" '
        $1 ~ /^(rocommunity|rwcommunity|rocommunity6|rwcommunity6)$/ && $3 == network {
            count++
        }
        END { print count+0 }
    ' "$u61_configuration_path")
    if [ "$restricted_count" -ne 1 ]; then
        u61_set_error \
            'SNMP_ACCESS_VALIDATION_FAILED' \
            'the resulting SNMP source restriction is not unambiguous'
        return 1
    fi
}

os_guard_content_run_module "${1:-}"
