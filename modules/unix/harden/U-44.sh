#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULES_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
. "$MODULES_DIR/lib/common.sh"
. "$MODULES_DIR/lib/harden_common.sh"
. "$MODULES_DIR/lib/harden_service.sh"

HARDEN_ITEM_ID='U-44'
HARDEN_CHECK_SCRIPT="$MODULES_DIR/unix/U-44.sh"
HARDEN_TARGET_DESCRIPTION='tftp, talk, and ntalk systemd services and sockets'
HARDEN_SYSTEMD_UNITS='tftp.service
tftp.socket
tftpd.service
talk.service
talk.socket
ntalk.service
ntalk.socket'
HARDEN_LEGACY_FILES='/etc/inetd.conf
/etc/xinetd.d/tftp
/etc/xinetd.d/talk
/etc/xinetd.d/ntalk'
HARDEN_LEGACY_PATTERN='^[[:space:]]*(tftp|talk|ntalk)[[:space:]]|disable[[:space:]]*=[[:space:]]*no'

os_guard_service_run "${1:-}"
