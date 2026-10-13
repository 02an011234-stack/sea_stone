"""Durable immutable request outbox and ACK journal."""

from __future__ import annotations

import base64
import json
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


class OutboxError(RuntimeError):
    """Raised when durable transfer state cannot be trusted."""


@dataclass(frozen=True)
class OutboxEntry:
    entry_id: str
    sequence: int
    kind: str
    route: str | None
    payload: Mapping[str, Any]
    content: bytes | None
    dependencies: tuple[str, ...]
    path: Path

    @property
    def message_id(self) -> str:
        value = self.payload.get("message_id")
        if not isinstance(value, str) or not value:
            raise OutboxError("outbox entry has no message_id")
        return value


class OutboxStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.pending_dir = root / "pending"
        self.ack_dir = root / "acks"

    def initialize(self) -> None:
        for directory in (self.root, self.pending_dir, self.ack_dir):
            try:
                if directory.is_symlink():
                    raise OutboxError("outbox path must not contain symlinks")
                directory.mkdir(mode=0o700, parents=True, exist_ok=True)
                if os.name == "posix":
                    directory.chmod(0o700)
            except OutboxError:
                raise
            except OSError:
                raise OutboxError("outbox directory is unavailable") from None

    def enqueue(
        self,
        kind: str,
        payload: Mapping[str, Any],
        *,
        route: str | None = None,
        content: bytes | None = None,
        dependencies: tuple[str, ...] = (),
    ) -> OutboxEntry:
        self.initialize()
        message_id = payload.get("message_id")
        if not isinstance(message_id, str) or not message_id:
            raise OutboxError("outbox payload message_id is required")
        entry_id = message_id
        path = self.pending_dir / f"{entry_id}.json"
        if path.exists():
            existing = self._load_entry(path)
            expected_content = content if content is not None else None
            if (
                existing.kind != kind
                or existing.route != route
                or dict(existing.payload) != dict(payload)
                or existing.content != expected_content
                or existing.dependencies != dependencies
            ):
                raise OutboxError("outbox message_id conflicts with existing payload")
            return existing
        sequence = time.time_ns()
        document = {
            "schema_version": "1.0",
            "entry_id": entry_id,
            "sequence": sequence,
            "kind": kind,
            "route": route,
            "payload": dict(payload),
            "content_base64": (
                base64.b64encode(content).decode("ascii") if content is not None else None
            ),
            "dependencies": list(dependencies),
        }
        self._atomic_json(path, document)
        return self._load_entry(path)

    def ready_entries(self) -> tuple[OutboxEntry, ...]:
        self.initialize()
        entries = []
        try:
            paths = tuple(self.pending_dir.glob("*.json"))
        except OSError:
            raise OutboxError("outbox pending entries cannot be listed") from None
        for path in paths:
            entry = self._load_entry(path)
            if all(self.is_acked(dependency) for dependency in entry.dependencies):
                entries.append(entry)
        return tuple(sorted(entries, key=lambda entry: (entry.sequence, entry.entry_id)))

    def has_pending(self) -> bool:
        self.initialize()
        return any(self.pending_dir.glob("*.json"))

    def is_acked(self, message_id: str) -> bool:
        path = self.ack_dir / f"{message_id}.json"
        if not path.exists():
            return False
        try:
            if path.is_symlink():
                raise OutboxError("ACK journal entry must not be a symlink")
            if os.name == "posix" and path.stat().st_mode & 0o077:
                raise OutboxError("ACK journal permissions are too broad")
            document = json.loads(path.read_text(encoding="utf-8"))
        except OutboxError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise OutboxError("ACK journal is corrupt") from None
        if (
            not isinstance(document, Mapping)
            or document.get("schema_version") != "1.0"
            or document.get("message_id") != message_id
            or not isinstance(document.get("ack"), Mapping)
        ):
            raise OutboxError("ACK journal is invalid")
        return True

    def acknowledge(self, entry: OutboxEntry, ack: Mapping[str, Any]) -> None:
        self.initialize()
        ack_path = self.ack_dir / f"{entry.message_id}.json"
        document = {
            "schema_version": "1.0",
            "message_id": entry.message_id,
            "entry_kind": entry.kind,
            "ack": dict(ack),
        }
        if ack_path.exists():
            try:
                existing = json.loads(ack_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                raise OutboxError("ACK journal is corrupt") from None
            if existing != document:
                raise OutboxError("ACK journal conflicts with received ACK")
        else:
            self._atomic_json(ack_path, document)
        try:
            entry.path.unlink(missing_ok=True)
            self._fsync_directory(self.pending_dir)
        except OSError:
            raise OutboxError("acknowledged outbox entry could not be removed") from None

    def discard(self, entry: OutboxEntry) -> None:
        """Remove a request that has never been sent and is no longer valid."""

        if self.is_acked(entry.message_id):
            raise OutboxError("acknowledged outbox entry cannot be discarded")
        try:
            entry.path.unlink(missing_ok=True)
            self._fsync_directory(self.pending_dir)
        except OSError:
            raise OutboxError("outbox entry could not be discarded") from None

    def discard_stale_attempt(self, job_id: str, current_attempt_id: str) -> int:
        """Drop unsent requests from an expired attempt after Central reassigns a job."""

        removed = 0
        self.initialize()
        for path in tuple(self.pending_dir.glob("*.json")):
            entry = self._load_entry(path)
            attempt_id = entry.payload.get("attempt_id")
            if (
                entry.route == job_id
                and isinstance(attempt_id, str)
                and attempt_id != current_attempt_id
            ):
                self.discard(entry)
                removed += 1
        return removed

    def _load_entry(self, path: Path) -> OutboxEntry:
        try:
            if path.is_symlink():
                raise OutboxError("outbox entry must not be a symlink")
            if os.name == "posix" and path.stat().st_mode & 0o077:
                raise OutboxError("outbox entry permissions are too broad")
            document = json.loads(path.read_text(encoding="utf-8"))
        except OutboxError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise OutboxError("outbox entry is corrupt") from None
        if not isinstance(document, Mapping) or document.get("schema_version") != "1.0":
            raise OutboxError("outbox entry is invalid")
        payload = document.get("payload")
        dependencies = document.get("dependencies")
        if not isinstance(payload, Mapping) or not isinstance(dependencies, list):
            raise OutboxError("outbox entry is invalid")
        if any(not isinstance(value, str) or not value for value in dependencies):
            raise OutboxError("outbox entry is invalid")
        encoded_content = document.get("content_base64")
        try:
            content = (
                None
                if encoded_content is None
                else base64.b64decode(encoded_content, validate=True)
            )
        except (ValueError, TypeError):
            raise OutboxError("outbox content is invalid") from None
        entry_id = document.get("entry_id")
        sequence = document.get("sequence")
        kind = document.get("kind")
        route = document.get("route")
        if (
            not isinstance(entry_id, str)
            or not entry_id
            or not isinstance(sequence, int)
            or isinstance(sequence, bool)
            or not isinstance(kind, str)
            or not kind
            or (route is not None and (not isinstance(route, str) or not route))
        ):
            raise OutboxError("outbox entry is invalid")
        return OutboxEntry(
            entry_id,
            sequence,
            kind,
            route,
            dict(payload),
            content,
            tuple(dependencies),
            path,
        )

    def _atomic_json(self, path: Path, document: Mapping[str, Any]) -> None:
        if path.is_symlink():
            raise OutboxError("outbox destination must not be a symlink")
        descriptor = -1
        temporary_path: Path | None = None
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                dir=path.parent,
                prefix=f".{path.name}.",
            )
            temporary_path = Path(temporary_name)
            os.chmod(temporary_path, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                descriptor = -1
                json.dump(document, output, ensure_ascii=False, separators=(",", ":"))
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary_path, path)
            os.chmod(path, 0o600)
            self._fsync_directory(path.parent)
        except (OSError, TypeError, ValueError):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
            raise OutboxError("outbox state could not be stored") from None

    @staticmethod
    def _fsync_directory(directory: Path) -> None:
        if os.name != "posix":
            return
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
