"""Read-only Linux distribution and host information detection."""

from __future__ import annotations

import platform
import shlex
import socket
from pathlib import Path

from .models import OsInfo


def _read_os_release(path: Path) -> tuple[dict[str, str], str | None]:
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return {}, f"cannot read os-release: {exc}"

    values: dict[str, str] = {}
    invalid_lines = 0
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            invalid_lines += 1
            continue

        key, raw_value = line.split("=", 1)
        key = key.strip()
        if not key:
            invalid_lines += 1
            continue
        try:
            parsed = shlex.split(raw_value, posix=True)
        except ValueError:
            invalid_lines += 1
            continue
        values[key] = " ".join(parsed)

    if not values:
        detail = "no valid values"
        if invalid_lines:
            detail += f" ({invalid_lines} invalid lines)"
        return {}, f"cannot parse os-release: {detail}"
    return values, None


def _support_status(distro: str, version_id: str) -> tuple[bool, str | None]:
    version_parts = version_id.split(".", 1)
    major_version = version_parts[0] if version_parts else ""

    if distro == "rocky":
        if major_version in {"9", "10"}:
            return True, None
        return False, f"unsupported Rocky Linux version: {version_id or 'unknown'}"

    if distro == "ubuntu":
        if major_version in {"22", "24"}:
            return True, None
        return False, f"unsupported Ubuntu version: {version_id or 'unknown'}"

    return False, f"unsupported Linux distribution: {distro or 'unknown'}"


def detect_os(os_release_path: Path = Path("/etc/os-release")) -> OsInfo:
    """Detect OS information without changing the host system."""

    values, parse_error = _read_os_release(os_release_path)
    distro = values.get("ID", "").strip().lower()
    version = values.get("VERSION", "").strip()
    version_id = values.get("VERSION_ID", "").strip()

    if parse_error:
        supported = False
        unsupported_reason = parse_error
    elif not distro or not version_id:
        supported = False
        missing = [
            name
            for name, value in (("ID", distro), ("VERSION_ID", version_id))
            if not value
        ]
        unsupported_reason = f"os-release missing required value(s): {', '.join(missing)}"
    else:
        supported, unsupported_reason = _support_status(distro, version_id)

    return OsInfo(
        distro=distro or "unknown",
        version=version or version_id or "unknown",
        version_id=version_id or "unknown",
        kernel=platform.release() or "unknown",
        hostname=socket.gethostname() or "unknown",
        architecture=platform.machine() or "unknown",
        supported=supported,
        unsupported_reason=unsupported_reason,
    )

