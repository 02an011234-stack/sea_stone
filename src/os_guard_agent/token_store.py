"""Restricted local storage for Agent operating credentials."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

from .models import OperatingCredential


class TokenStoreError(RuntimeError):
    """Raised when operating credentials cannot be stored or loaded."""


@dataclass(frozen=True)
class PendingCredentialRotation:
    rotation_id: str
    grace_until: str
    active: OperatingCredential
    previous: OperatingCredential


class TokenStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def save(self, credential: OperatingCredential) -> None:
        self._write_document(asdict(credential))

    def stage_rotation(
        self,
        previous: OperatingCredential,
        active: OperatingCredential,
        *,
        rotation_id: str,
        grace_until: str,
    ) -> None:
        if previous.server_id != active.server_id or previous.agent_id != active.agent_id:
            raise TokenStoreError("credential rotation scope does not match")
        if previous.credential_id == active.credential_id:
            raise TokenStoreError("credential rotation did not issue a new credential")
        self._write_document(
            {
                "schema_version": "2.0",
                "active": asdict(active),
                "rotation": {
                    "state": "PENDING_CONFIRMATION",
                    "rotation_id": rotation_id,
                    "grace_until": grace_until,
                    "previous": asdict(previous),
                },
            }
        )

    def confirm_rotation(self, credential_id: str) -> None:
        pending = self.pending_rotation()
        if pending is None or pending.active.credential_id != credential_id:
            raise TokenStoreError("credential rotation state does not match")
        self.save(pending.active)

    def pending_rotation(self) -> PendingCredentialRotation | None:
        payload = self._read_document()
        if "active" not in payload:
            return None
        if payload.get("schema_version") != "2.0":
            raise TokenStoreError("invalid operating credential file")
        rotation = payload.get("rotation")
        if not isinstance(rotation, Mapping):
            raise TokenStoreError("invalid operating credential file")
        if rotation.get("state") != "PENDING_CONFIRMATION":
            raise TokenStoreError("invalid operating credential file")
        rotation_id = rotation.get("rotation_id")
        grace_until = rotation.get("grace_until")
        if not isinstance(rotation_id, str) or not rotation_id:
            raise TokenStoreError("invalid operating credential file")
        if not isinstance(grace_until, str) or not grace_until:
            raise TokenStoreError("invalid operating credential file")
        return PendingCredentialRotation(
            rotation_id=rotation_id,
            grace_until=grace_until,
            active=self._parse_credential(payload.get("active")),
            previous=self._parse_credential(rotation.get("previous")),
        )

    def _write_document(self, payload: Mapping[str, Any]) -> None:
        parent = self.path.parent
        try:
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if parent.is_symlink():
                raise TokenStoreError("operating credential directory must not be a symlink")
            if os.name == "posix":
                parent.chmod(0o700)
            if self.path.is_symlink():
                raise TokenStoreError("operating credential path must not be a symlink")

            file_descriptor, temporary_name = tempfile.mkstemp(
                dir=parent,
                prefix=f".{self.path.name}.",
            )
            temporary_path = Path(temporary_name)
            try:
                os.chmod(temporary_path, 0o600)
                with os.fdopen(file_descriptor, "w", encoding="utf-8") as output:
                    json.dump(payload, output, separators=(",", ":"))
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temporary_path, self.path)
                os.chmod(self.path, 0o600)
                if os.name == "posix":
                    directory_fd = os.open(parent, os.O_RDONLY)
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
            except Exception:
                try:
                    os.close(file_descriptor)
                except OSError:
                    pass
                temporary_path.unlink(missing_ok=True)
                raise
        except TokenStoreError:
            raise
        except OSError:
            raise TokenStoreError("failed to store operating credentials") from None

    def load(self) -> OperatingCredential:
        payload = self._read_document()
        if "active" in payload:
            return self._parse_credential(payload.get("active"))
        return self._parse_credential(payload)

    def _read_document(self) -> dict[str, Any]:
        try:
            if self.path.is_symlink():
                raise TokenStoreError("operating credential path must not be a symlink")
            if os.name == "posix" and self.path.stat().st_mode & 0o077:
                raise TokenStoreError("operating credential file permissions are too broad")
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except TokenStoreError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise TokenStoreError("failed to load operating credentials") from None

        if not isinstance(payload, dict):
            raise TokenStoreError("invalid operating credential file")
        return payload

    @staticmethod
    def _parse_credential(payload: Any) -> OperatingCredential:
        if not isinstance(payload, Mapping):
            raise TokenStoreError("invalid operating credential file")
        try:
            values = {
                key: payload[key]
                for key in ("server_id", "agent_id", "credential_id", "token", "expires_at")
            }
        except KeyError:
            raise TokenStoreError("invalid operating credential file") from None
        if any(not isinstance(value, str) or not value for value in values.values()):
            raise TokenStoreError("invalid operating credential file")
        return OperatingCredential(**values)

    def clear(self) -> None:
        try:
            self.path.unlink(missing_ok=True)
        except OSError:
            raise TokenStoreError("failed to remove operating credentials") from None
