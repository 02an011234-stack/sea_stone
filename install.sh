#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export PYTHONPATH="$SCRIPT_DIR/src"
exec /usr/bin/env python3 -m os_guard_agent.installer \
    --source "$SCRIPT_DIR" \
    "$@"
