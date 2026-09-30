#!/bin/sh

os_guard_utc_now() {
    date -u '+%Y-%m-%dT%H:%M:%SZ'
}

os_guard_json_quote() {
    printf '"'
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
    printf '"'
}

os_guard_json_array_from_lines() {
    printf '['
    os_guard_first_item=1
    while IFS= read -r os_guard_line; do
        [ -n "$os_guard_line" ] || continue
        if [ "$os_guard_first_item" -eq 0 ]; then
            printf ','
        fi
        os_guard_json_quote "$os_guard_line"
        os_guard_first_item=0
    done
    printf ']'
}
