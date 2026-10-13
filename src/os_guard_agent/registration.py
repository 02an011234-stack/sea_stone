"""Secure consumption of Central registration files."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


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


def load_registration_file(path: Path, expected_url: str) -> RegistrationFile:
    try:
        if path.is_symlink():
            raise RegistrationFileError("registration file must not be a symlink")
        if not path.is_file():
            raise RegistrationFileError("registration file is not a regular file")
        if os.name == "posix" and path.stat().st_mode & 0o077:
            raise RegistrationFileError("registration file permissions are too broad")
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
    if registration.central_server_url != expected_url.rstrip("/"):
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
        if path.is_symlink():
            raise RegistrationFileError("registration file must not be a symlink")
        path.unlink()
    except RegistrationFileError:
        raise
    except OSError:
        raise RegistrationFileError("consumed registration file could not be removed") from None
