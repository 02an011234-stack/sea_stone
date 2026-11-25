"""Secure consumption of Central registration files."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

try:
    import pwd
except ImportError:  # pragma: no cover - Windows test host
    pwd = None  # type: ignore[assignment]

POSIX_RUNTIME = os.name == "posix"


class RegistrationFileError(RuntimeError):
    """Raised when a registration file is unsafe or violates the contract."""


@dataclass(frozen=True)
class RegistrationFile:
    enrollment_id: str
    token: str
    expires_at: str
    server_id: str
    family: str
    schema_version: str
    central_server_url: str
    ca_sha256_fingerprint: str
    enrollment_header: str


def _reject_unsafe_registration_path(path: Path) -> None:
    if ".." in path.parts:
        raise RegistrationFileError("registration file path traversal is not permitted")
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current = current / component
        if current.is_symlink():
            raise RegistrationFileError(
                "registration file path must not contain symbolic links"
            )


def validate_enrollment_runtime(credential_path: Path) -> None:
    """Require installed Enrollment to run as the dedicated service identity."""

    if not POSIX_RUNTIME:
        return
    if pwd is None:
        raise RegistrationFileError("Unix account APIs are unavailable")
    try:
        account = pwd.getpwnam("osguard")
    except KeyError:
        raise RegistrationFileError("osguard service account is unavailable") from None
    if os.geteuid() != account.pw_uid:
        raise RegistrationFileError("Enrollment must run as the osguard service account")

    parent = credential_path.absolute().parent
    try:
        current = Path(parent.anchor)
        for component in parent.parts[1:]:
            current = current / component
            if current.is_symlink():
                raise RegistrationFileError(
                    "operating credential path must not contain symbolic links"
                )
        metadata = os.stat(parent, follow_symlinks=False)
        if not stat.S_ISDIR(metadata.st_mode):
            raise RegistrationFileError("operating credential directory is invalid")
        if metadata.st_uid != account.pw_uid or metadata.st_gid != account.pw_gid:
            raise RegistrationFileError(
                "operating credential directory is not owned by osguard"
            )
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise RegistrationFileError(
                "operating credential directory permissions are too broad"
            )
        if credential_path.exists():
            credential_metadata = os.stat(credential_path, follow_symlinks=False)
            if credential_path.is_symlink() or not stat.S_ISREG(credential_metadata.st_mode):
                raise RegistrationFileError("operating credential path is unsafe")
            if (
                credential_metadata.st_uid != account.pw_uid
                or credential_metadata.st_gid != account.pw_gid
                or stat.S_IMODE(credential_metadata.st_mode) & 0o077
            ):
                raise RegistrationFileError(
                    "existing operating credential ownership or permissions are unsafe"
                )
    except RegistrationFileError:
        raise
    except OSError:
        raise RegistrationFileError(
            "operating credential directory cannot be validated"
        ) from None


def load_registration_file(
    path: Path,
    expected_url: str | None,
    *,
    allowed_owner_uids: set[int] | None = None,
) -> RegistrationFile:
    try:
        _reject_unsafe_registration_path(path)
        if not path.is_file():
            raise RegistrationFileError("registration file is not a regular file")
        metadata = path.stat()
        if metadata.st_size > 64 * 1024:
            raise RegistrationFileError("registration file is too large")
        if os.name == "posix":
            if metadata.st_mode & 0o077:
                raise RegistrationFileError("registration file permissions are too broad")
            accepted_owners = (
                {os.geteuid()}
                if allowed_owner_uids is None
                else allowed_owner_uids
            )
            if metadata.st_uid not in accepted_owners:
                raise RegistrationFileError(
                    "registration file owner is not permitted"
                )
        payload = json.loads(path.read_text(encoding="utf-8"))
    except RegistrationFileError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise RegistrationFileError("registration file is unreadable or invalid") from None
    if not isinstance(payload, Mapping):
        raise RegistrationFileError("registration file root must be an object")

    def required_string(key: str) -> str:
        value: Any = payload.get(key)
        if not isinstance(value, str) or not value.strip():
            raise RegistrationFileError(f"registration field '{key}' is required")
        return value.strip()

    registration = RegistrationFile(
        enrollment_id=required_string("enrollment_id"),
        token=required_string("token"),
        expires_at=required_string("expires_at"),
        server_id=required_string("server_id"),
        family=required_string("family"),
        schema_version=required_string("schema_version"),
        central_server_url=required_string("central_server_url").rstrip("/"),
        ca_sha256_fingerprint=required_string("ca_sha256_fingerprint"),
        enrollment_header=required_string("enrollment_header"),
    )
    if registration.schema_version != "2.0":
        raise RegistrationFileError("unsupported registration schema_version")
    if registration.family != "UNIX":
        raise RegistrationFileError("registration file is not for a Unix Agent")
    if registration.enrollment_header != "X-Enrollment-Token":
        raise RegistrationFileError("unsupported enrollment header")
    if (
        expected_url is not None
        and registration.central_server_url != expected_url.rstrip("/")
    ):
        raise RegistrationFileError("registration Central URL does not match configuration")
    fingerprint = registration.ca_sha256_fingerprint
    if len(fingerprint) != 64 or any(char not in "0123456789abcdef" for char in fingerprint):
        raise RegistrationFileError("registration CA fingerprint is invalid")
    try:
        expiry = datetime.fromisoformat(registration.expires_at.replace("Z", "+00:00"))
    except ValueError:
        raise RegistrationFileError("registration expires_at is invalid") from None
    if expiry.tzinfo is None or expiry.astimezone(timezone.utc) <= datetime.now(timezone.utc):
        raise RegistrationFileError("registration file has expired")
    return registration


def dispose_registration_file(path: Path) -> None:
    """Unlink the consumed file; secure overwrite is not promised by filesystems."""

    try:
        _reject_unsafe_registration_path(path)
        path.unlink()
    except RegistrationFileError:
        raise
    except OSError:
        raise RegistrationFileError("consumed registration file could not be removed") from None
