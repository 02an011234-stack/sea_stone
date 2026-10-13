"""Persistent trusted-time and one-time execution Grant state."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from .policy import canonicalize_json, load_strict_json
from .trusted_time import (
    AuthenticatedTimeEvidence,
    TrustedTime,
    TrustedTimeCode,
    TrustedTimeError,
)

EXECUTION_STATE_SCHEMA_VERSION = "1.0"
MAX_STATE_BYTES = 4 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_LOCKS_GUARD = threading.Lock()
_PROCESS_LOCKS: dict[str, threading.Lock] = {}


class ExecutionStateCode(str, Enum):
    STATE_UNAVAILABLE = "STATE_UNAVAILABLE"
    STATE_CORRUPT = "STATE_CORRUPT"
    STATE_WRITE_FAILED = "STATE_WRITE_FAILED"
    STATE_LOCKED = "STATE_LOCKED"
    GRANT_REUSED = "GRANT_REUSED"
    JOB_ATTEMPT_REUSED = "JOB_ATTEMPT_REUSED"


class ExecutionStateError(RuntimeError):
    def __init__(self, code: ExecutionStateCode, message: str) -> None:
        super().__init__(message)
        self.code = code


class PersistentExecutionStateStore:
    """Fail-closed state for authenticated time and consumed Grants.

    Future execution integration must validate first, atomically mark CONSUMED,
    and only then mutate the host. A crash after consumption requires a newly
    issued Grant; this store never changes a consumed record back to reusable.
    """

    def __init__(
        self,
        path: Path,
        *,
        replace_func: Callable[[str | os.PathLike[str], str | os.PathLike[str]], None]
        = os.replace,
    ) -> None:
        self.path = path
        self.lock_path = path.with_name(f".{path.name}.lock")
        self._replace = replace_func
        lock_key = str(path.absolute())
        with _LOCKS_GUARD:
            self._process_lock = _PROCESS_LOCKS.setdefault(lock_key, threading.Lock())

    def initialize(self) -> None:
        self._prepare_parent()
        with self._locked():
            if self.path.exists() or self.path.is_symlink():
                self._load()
                return
            state = {
                "schema_version": EXECUTION_STATE_SCHEMA_VERSION,
                "generation": 0,
                "time_evidence": None,
                "consumed_grants": {},
            }
            self._write(state, expected_identity=None)

    def record_time_evidence(self, evidence: AuthenticatedTimeEvidence) -> None:
        try:
            with self._locked():
                state, identity = self._load()
                previous = state["time_evidence"]
                if previous is not None:
                    if evidence.evidence_id == previous["evidence_id"]:
                        raise TrustedTimeError(
                            TrustedTimeCode.EVIDENCE_REPLAY,
                            "trusted time evidence was already recorded",
                        )
                    previous_observed = _parse_utc(previous["observed_at"])
                    previous_last = _parse_utc(previous["last_trusted_at"])
                    if evidence.observed_at < previous_observed or (
                        evidence.observed_at
                        + timedelta(seconds=evidence.uncertainty_seconds)
                        < previous_last
                    ):
                        raise TrustedTimeError(
                            TrustedTimeCode.TIME_ROLLBACK,
                            "trusted time evidence moves time backwards",
                        )
                state["time_evidence"] = {
                    "evidence_id": evidence.evidence_id,
                    "evidence_hash": evidence.evidence_hash,
                    "source_id": evidence.source_id,
                    "issuer_id": evidence.issuer_id,
                    "signing_key_id": evidence.signing_key_id,
                    "server_id": evidence.server_id,
                    "agent_id": evidence.agent_id,
                    "issued_at": _utc_text(evidence.issued_at),
                    "observed_at": _utc_text(evidence.observed_at),
                    "expires_at": _utc_text(evidence.expires_at),
                    "uncertainty_seconds": evidence.uncertainty_seconds,
                    "received_at": _utc_text(evidence.received_at),
                    "last_trusted_at": _utc_text(evidence.observed_at),
                }
                state["generation"] += 1
                self._write(state, expected_identity=identity)
        except ExecutionStateError as exc:
            raise self._time_state_error(exc) from None

    def derive_trusted_time(
        self,
        *,
        local_now: datetime,
        maximum_evidence_age_seconds: int,
    ) -> TrustedTime:
        try:
            with self._locked():
                state, identity = self._load()
                evidence = state["time_evidence"]
                if evidence is None:
                    raise TrustedTimeError(
                        TrustedTimeCode.TIME_STATE_UNAVAILABLE,
                        "authenticated time evidence is unavailable",
                    )
                received_at = _parse_utc(evidence["received_at"])
                observed_at = _parse_utc(evidence["observed_at"])
                expires_at = _parse_utc(evidence["expires_at"])
                last_trusted_at = _parse_utc(evidence["last_trusted_at"])
                uncertainty = evidence["uncertainty_seconds"]
                elapsed = (local_now - received_at).total_seconds()
                if elapsed < -uncertainty:
                    raise TrustedTimeError(
                        TrustedTimeCode.TIME_ROLLBACK,
                        "local time moved backwards after authenticated evidence",
                    )
                if elapsed > maximum_evidence_age_seconds:
                    raise TrustedTimeError(
                        TrustedTimeCode.EVIDENCE_EXPIRED,
                        "authenticated time evidence is too old",
                    )
                trusted_value = observed_at + timedelta(seconds=max(0.0, elapsed))
                if trusted_value + timedelta(seconds=uncertainty) < last_trusted_at:
                    raise TrustedTimeError(
                        TrustedTimeCode.TIME_ROLLBACK,
                        "derived trusted time moved backwards",
                    )
                if trusted_value >= expires_at:
                    raise TrustedTimeError(
                        TrustedTimeCode.EVIDENCE_EXPIRED,
                        "authenticated time evidence has expired",
                    )
                if trusted_value > last_trusted_at:
                    evidence["last_trusted_at"] = _utc_text(trusted_value)
                    state["generation"] += 1
                    self._write(state, expected_identity=identity)
                return TrustedTime(
                    value=trusted_value,
                    evidence_id=evidence["evidence_id"],
                    source_id=evidence["source_id"],
                    authenticated=True,
                    uncertainty_seconds=uncertainty,
                    evidence_expires_at=expires_at,
                )
        except ExecutionStateError as exc:
            raise self._time_state_error(exc) from None

    @staticmethod
    def _time_state_error(error: ExecutionStateError) -> TrustedTimeError:
        code = {
            ExecutionStateCode.STATE_CORRUPT: TrustedTimeCode.TIME_STATE_CORRUPT,
            ExecutionStateCode.STATE_WRITE_FAILED: TrustedTimeCode.TIME_STATE_WRITE_FAILED,
        }.get(error.code, TrustedTimeCode.TIME_STATE_UNAVAILABLE)
        return TrustedTimeError(code, str(error))

    def consume_grant(
        self,
        *,
        grant_id: str,
        grant_hash: str,
        job_id: str,
        attempt_id: str,
        consumed_at: datetime,
    ) -> None:
        with self._locked():
            state, identity = self._load()
            consumed_grants: dict[str, Any] = state["consumed_grants"]
            self._ensure_grant_available(
                consumed_grants,
                grant_id=grant_id,
                job_id=job_id,
                attempt_id=attempt_id,
            )
            consumed_grants[grant_id] = {
                "grant_hash": grant_hash,
                "job_id": job_id,
                "attempt_id": attempt_id,
                "status": "CONSUMED",
                "consumed_at": _utc_text(consumed_at),
            }
            state["generation"] += 1
            self._write(state, expected_identity=identity)

    def check_grant_available(
        self,
        *,
        grant_id: str,
        job_id: str,
        attempt_id: str,
    ) -> None:
        """Read-only availability check; execution must still consume atomically."""

        with self._locked():
            state, _ = self._load()
            self._ensure_grant_available(
                state["consumed_grants"],
                grant_id=grant_id,
                job_id=job_id,
                attempt_id=attempt_id,
            )

    @staticmethod
    def _ensure_grant_available(
        consumed_grants: Mapping[str, Any],
        *,
        grant_id: str,
        job_id: str,
        attempt_id: str,
    ) -> None:
        if grant_id in consumed_grants:
            raise ExecutionStateError(
                ExecutionStateCode.GRANT_REUSED,
                "execution Grant was already consumed",
            )
        for record in consumed_grants.values():
            if record["job_id"] == job_id and record["attempt_id"] == attempt_id:
                raise ExecutionStateError(
                    ExecutionStateCode.JOB_ATTEMPT_REUSED,
                    "job and attempt already consumed another execution Grant",
                )

    def read_summary(self) -> Mapping[str, Any]:
        with self._locked():
            state, _ = self._load()
        return json.loads(json.dumps(state))

    def _prepare_parent(self) -> None:
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if self.path.parent.is_symlink() or not self.path.parent.is_dir():
                raise OSError
            if os.name == "posix":
                os.chmod(self.path.parent, 0o700)
        except OSError:
            raise ExecutionStateError(
                ExecutionStateCode.STATE_UNAVAILABLE,
                "execution state directory is unavailable",
            ) from None

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self._prepare_parent()
        with self._process_lock:
            descriptor: int | None = None
            try:
                descriptor = os.open(
                    self.lock_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                os.write(descriptor, str(os.getpid()).encode("ascii"))
                os.fsync(descriptor)
            except FileExistsError:
                raise ExecutionStateError(
                    ExecutionStateCode.STATE_LOCKED,
                    "execution state is locked or a previous update was interrupted",
                ) from None
            except OSError:
                raise ExecutionStateError(
                    ExecutionStateCode.STATE_UNAVAILABLE,
                    "execution state lock could not be created",
                ) from None
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            try:
                yield
            finally:
                try:
                    self.lock_path.unlink()
                except OSError:
                    pass

    def _load(self) -> tuple[dict[str, Any], tuple[int, int, int, int]]:
        if self.path.is_symlink():
            self._state_error(ExecutionStateCode.STATE_CORRUPT, "symlink is not allowed")
        try:
            stat_result = self.path.stat()
            if not self.path.is_file() or stat_result.st_size > MAX_STATE_BYTES:
                raise OSError
            if os.name == "posix" and stat_result.st_mode & 0o077:
                self._state_error(
                    ExecutionStateCode.STATE_CORRUPT,
                    "execution state permissions are too broad",
                )
            raw = self.path.read_bytes()
        except FileNotFoundError:
            self._state_error(
                ExecutionStateCode.STATE_UNAVAILABLE,
                "execution state is missing and cannot be recreated implicitly",
            )
        except ExecutionStateError:
            raise
        except OSError:
            self._state_error(
                ExecutionStateCode.STATE_UNAVAILABLE,
                "execution state could not be read",
            )
        try:
            document = load_strict_json(raw)
            self._validate_document(document)
        except (ValueError, TypeError, KeyError):
            self._state_error(
                ExecutionStateCode.STATE_CORRUPT,
                "execution state integrity validation failed",
            )
        identity = (
            stat_result.st_dev,
            stat_result.st_ino,
            stat_result.st_size,
            stat_result.st_mtime_ns,
        )
        return document, identity

    def _write(
        self,
        state: dict[str, Any],
        *,
        expected_identity: tuple[int, int, int, int] | None,
    ) -> None:
        unhashed = dict(state)
        unhashed.pop("state_hash", None)
        state["state_hash"] = hashlib.sha256(canonicalize_json(unhashed)).hexdigest()
        descriptor: int | None = None
        temporary_path: Path | None = None
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
            )
            temporary_path = Path(temporary_name)
            os.chmod(temporary_path, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                descriptor = None
                output.write(canonicalize_json(state))
                output.flush()
                os.fsync(output.fileno())
            if expected_identity is None:
                if self.path.exists() or self.path.is_symlink():
                    self._state_error(
                        ExecutionStateCode.STATE_CORRUPT,
                        "execution state appeared during initialization",
                    )
            elif self._identity() != expected_identity:
                self._state_error(
                    ExecutionStateCode.STATE_CORRUPT,
                    "execution state changed during validation",
                )
            self._replace(temporary_path, self.path)
            temporary_path = None
            os.chmod(self.path, 0o600)
            if os.name == "posix":
                parent_descriptor = os.open(self.path.parent, os.O_RDONLY)
                try:
                    os.fsync(parent_descriptor)
                finally:
                    os.close(parent_descriptor)
        except ExecutionStateError:
            raise
        except OSError:
            self._state_error(
                ExecutionStateCode.STATE_WRITE_FAILED,
                "execution state update failed",
            )
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if temporary_path is not None:
                try:
                    temporary_path.unlink()
                except OSError:
                    pass

    def _identity(self) -> tuple[int, int, int, int]:
        try:
            result = self.path.stat()
        except OSError:
            return (-1, -1, -1, -1)
        return (result.st_dev, result.st_ino, result.st_size, result.st_mtime_ns)

    @staticmethod
    def _validate_document(document: Any) -> None:
        if not isinstance(document, dict) or set(document) != {
            "schema_version",
            "generation",
            "time_evidence",
            "consumed_grants",
            "state_hash",
        }:
            raise ValueError("invalid execution state fields")
        if document["schema_version"] != EXECUTION_STATE_SCHEMA_VERSION:
            raise ValueError("unsupported execution state schema")
        if not isinstance(document["generation"], int) or document["generation"] < 0:
            raise ValueError("invalid execution state generation")
        state_hash = document["state_hash"]
        if not isinstance(state_hash, str) or not _SHA256.fullmatch(state_hash):
            raise ValueError("invalid execution state hash")
        unhashed = dict(document)
        unhashed.pop("state_hash")
        if hashlib.sha256(canonicalize_json(unhashed)).hexdigest() != state_hash:
            raise ValueError("execution state hash mismatch")
        PersistentExecutionStateStore._validate_time(document["time_evidence"])
        PersistentExecutionStateStore._validate_grants(document["consumed_grants"])

    @staticmethod
    def _validate_time(evidence: Any) -> None:
        if evidence is None:
            return
        expected = {
            "evidence_id",
            "evidence_hash",
            "source_id",
            "issuer_id",
            "signing_key_id",
            "server_id",
            "agent_id",
            "issued_at",
            "observed_at",
            "expires_at",
            "uncertainty_seconds",
            "received_at",
            "last_trusted_at",
        }
        if not isinstance(evidence, dict) or set(evidence) != expected:
            raise ValueError("invalid time state")
        for field in (
            "evidence_id",
            "source_id",
            "issuer_id",
            "signing_key_id",
            "server_id",
            "agent_id",
        ):
            if not isinstance(evidence[field], str) or not evidence[field]:
                raise ValueError("invalid time identity")
        if not isinstance(evidence["evidence_hash"], str) or not _SHA256.fullmatch(
            evidence["evidence_hash"]
        ):
            raise ValueError("invalid evidence hash")
        for field in (
            "issued_at",
            "observed_at",
            "expires_at",
            "received_at",
            "last_trusted_at",
        ):
            _parse_utc(evidence[field])
        uncertainty = evidence["uncertainty_seconds"]
        if not isinstance(uncertainty, int) or uncertainty < 0:
            raise ValueError("invalid time uncertainty")

    @staticmethod
    def _validate_grants(grants: Any) -> None:
        if not isinstance(grants, dict):
            raise ValueError("invalid consumed Grants")
        job_attempts: set[tuple[str, str]] = set()
        for grant_id, record in grants.items():
            if not isinstance(grant_id, str) or not grant_id:
                raise ValueError("invalid Grant ID")
            if not isinstance(record, dict) or set(record) != {
                "grant_hash",
                "job_id",
                "attempt_id",
                "status",
                "consumed_at",
            }:
                raise ValueError("invalid consumed Grant")
            if not isinstance(record["grant_hash"], str) or not _SHA256.fullmatch(
                record["grant_hash"]
            ):
                raise ValueError("invalid Grant hash")
            if record["status"] != "CONSUMED":
                raise ValueError("invalid Grant status")
            for field in ("job_id", "attempt_id"):
                if not isinstance(record[field], str) or not record[field]:
                    raise ValueError("invalid Grant binding")
            _parse_utc(record["consumed_at"])
            binding = (record["job_id"], record["attempt_id"])
            if binding in job_attempts:
                raise ValueError("duplicate job and attempt consumption")
            job_attempts.add(binding)

    @staticmethod
    def _state_error(code: ExecutionStateCode, message: str) -> None:
        raise ExecutionStateError(code, message)


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _parse_utc(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("invalid UTC timestamp")
    return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
