"""Restricted local storage for Agent operating credentials."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict
from pathlib import Path

from .models import OperatingCredential


class TokenStoreError(RuntimeError):
    """Raised when operating credentials cannot be stored or loaded."""


class TokenStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def save(self, credential: OperatingCredential) -> None:
        parent = self.path.parent
        try:
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if os.name == "posix":
                parent.chmod(0o700)

            file_descriptor, temporary_name = tempfile.mkstemp(
                dir=parent,
                prefix=f".{self.path.name}.",
            )
            temporary_path = Path(temporary_name)
            try:
                os.chmod(temporary_path, 0o600)
                with os.fdopen(file_descriptor, "w", encoding="utf-8") as output:
                    json.dump(asdict(credential), output, separators=(",", ":"))
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temporary_path, self.path)
                os.chmod(self.path, 0o600)
            except Exception:
                try:
                    os.close(file_descriptor)
                except OSError:
                    pass
                temporary_path.unlink(missing_ok=True)
                raise
        except OSError:
            raise TokenStoreError("failed to store operating credentials") from None

    def load(self) -> OperatingCredential:
        try:
            if os.name == "posix" and self.path.stat().st_mode & 0o077:
                raise TokenStoreError("operating credential file permissions are too broad")
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except TokenStoreError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise TokenStoreError("failed to load operating credentials") from None

        if not isinstance(payload, dict):
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

