#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_multi.sh"

HARDEN_ITEM_ID='U-63'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-63.sh"
HARDEN_TARGET_DESCRIPTION='sudoers owner and permission metadata'
HARDEN_RISK_LEVEL='HIGH'

os_guard_item_discover_targets() {
    sudoers_path="${multi_test_root}/etc/sudoers"

    if [ ! -e "$sudoers_path" ] && [ ! -L "$sudoers_path" ]; then
        os_guard_multi_set_error 'SUDOERS_NOT_FOUND' 'the sudoers target does not exist'
        return 1
    fi

    os_guard_multi_add_target \
        "$sudoers_path" \
        '/etc/sudoers' \
        'file' \
        '0' \
        'root' \
        '0640' \
        'no permission bit outside the 0640 allowance mask' \
        'NONE'
}

resolve_visudo_command() {
    if [ -n "$multi_test_root" ] && [ -n "${OS_GUARD_TEST_VISUDO_BIN:-}" ]; then
        visudo_command=$OS_GUARD_TEST_VISUDO_BIN
    else
        visudo_command=$(command -v visudo 2>/dev/null || true)
    fi

    if [ -z "$visudo_command" ] || [ ! -x "$visudo_command" ]; then
        os_guard_multi_set_error \
            'VISUDO_COMMAND_UNAVAILABLE' \
            'sudoers syntax validation command is unavailable'
        return 1
    fi

    return 0
}

validate_sudoers_syntax() {
    if ! resolve_visudo_command; then
        return 1
    fi

    sudoers_path="${multi_test_root}/etc/sudoers"
    if ! "$visudo_command" -cf "$sudoers_path" >/dev/null 2>&1; then
        os_guard_multi_set_error \
            'SUDOERS_SYNTAX_INVALID' \
            'sudoers syntax validation failed'
        return 1
    fi

    return 0
}

os_guard_item_pre_execute_validation() {
    validate_sudoers_syntax
}

os_guard_item_post_apply_validation() {
    validate_sudoers_syntax
}

os_guard_multi_run_module "${1:-}"
