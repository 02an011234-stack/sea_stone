"""Persistent, fail-closed policy anti-rollback and revocation state."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from .policy import (
    PolicyStateError,
    PolicyValidationCode,
    RevocationState,
    canonicalize_json,
    load_strict_json,
)

STORE_SCHEMA_VERSION = "1.0"
MAX_STORE_BYTES = 4 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_LOCKS_GUARD = threading.Lock()
_PROCESS_LOCKS: dict[str, threading.Lock] = {}


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        raise PolicyStateError(
            PolicyValidationCode.POLICY_STATE_CORRUPT,
            "policy state timestamp must include a timezone",
        )
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _parse_utc(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("invalid UTC timestamp")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    return parsed.astimezone(timezone.utc)


class PersistentPolicyVersionStore:
    """JSON state store with atomic replacement and cooperative process locking.

    The store protects against corruption, accidental truncation, replay through
    the Agent interface, and concurrent cooperative writers.  It cannot defend
    against an administrator who can delete or restore both the state and its
    surrounding trusted installation state.
    """

    persistent = True
    revocation_persistent = True

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
        key = str(path.absolute())
        with _LOCKS_GUARD:
            self._process_lock = _PROCESS_LOCKS.setdefault(key, threading.Lock())

    def initialize(self) -> None:
        """Explicitly provision a new store; never silently recreates one."""

        self._prepare_parent()
        with self._locked():
            if self.path.exists() or self.path.is_symlink():
                self._load()
                return
            state = {
                "schema_version": STORE_SCHEMA_VERSION,
                "generation": 0,
                "policies": {},
                "revocation": None,
            }
            self._write(state, expected_identity=None)

    def check_and_record(
        self,
        policy_id: str,
        policy_version: int,
        policy_hash: str,
        *,
        issuer_id: str = "",
        server_id: str = "",
        agent_id: str = "",
        signing_key_id: str = "",
        verified_at: datetime | None = None,
        require_current_revocation: bool = False,
    ) -> PolicyValidationCode | None:
        verified_at = verified_at or datetime.now(timezone.utc)
        verified_text = _utc_text(verified_at)
        with self._locked():
            state, identity = self._load()
            revocation = state["revocation"]
            if require_current_revocation:
                revocation_error = self._check_current_revocation(
                    revocation, server_id, verified_at
                )
                if revocation_error is not None:
                    return revocation_error
            if revocation is not None:
                if signing_key_id in revocation["revoked_signing_key_ids"]:
                    return PolicyValidationCode.SIGNING_KEY_REVOKED
                if self._policy_is_revoked(
                    revocation, policy_id, policy_version, policy_hash
                ):
                    return PolicyValidationCode.POLICY_REVOKED

            policies: dict[str, Any] = state["policies"]
            existing = policies.get(policy_id)
            if existing is not None:
                latest_version = existing["latest_version"]
                latest_hash = existing["latest_hash"]
                if policy_version < latest_version:
                    return PolicyValidationCode.POLICY_DOWNGRADE
                if policy_version == latest_version:
                    if policy_hash != latest_hash:
                        return PolicyValidationCode.POLICY_VERSION_CONFLICT
                    return PolicyValidationCode.POLICY_DUPLICATE

                if (
                    existing["issuer_id"] != issuer_id
                    or existing["server_id"] != server_id
                    or existing["agent_id"] != agent_id
                ):
                    return PolicyValidationCode.POLICY_VERSION_CONFLICT
                existing["latest_version"] = policy_version
                existing["latest_hash"] = policy_hash
                existing["last_verified_at"] = verified_text
                existing["history"].append(
                    {
                        "policy_version": policy_version,
                        "policy_hash": policy_hash,
                        "verified_at": verified_text,
                    }
                )
            else:
                policies[policy_id] = {
                    "latest_version": policy_version,
                    "latest_hash": policy_hash,
                    "issuer_id": issuer_id,
                    "server_id": server_id,
                    "agent_id": agent_id,
                    "registered_at": verified_text,
                    "last_verified_at": verified_text,
                    "revoked": self._policy_is_revoked(
                        revocation, policy_id, policy_version, policy_hash
                    )
                    if revocation is not None
                    else False,
                    "revocation_version": (
                        revocation["revocation_version"] if revocation is not None else None
                    ),
                    "history": [
                        {
                            "policy_version": policy_version,
                            "policy_hash": policy_hash,
                            "verified_at": verified_text,
                        }
                    ],
                }
            state["generation"] += 1
            self._write(state, expected_identity=identity)
        return None

    def record_revocation(
        self, state: RevocationState, *, verified_at: datetime
    ) -> PolicyValidationCode | None:
        verified_text = _utc_text(verified_at)
        with self._locked():
            document, identity = self._load()
            existing = document["revocation"]
            if existing is not None:
                if state.signing_key_id in existing["revoked_signing_key_ids"]:
                    return PolicyValidationCode.SIGNING_KEY_REVOKED
                if (
                    state.revocation_list_id != existing["revocation_list_id"]
                    or state.issuer_id != existing["issuer_id"]
                    or state.server_id != existing["server_id"]
                ):
                    return PolicyValidationCode.REVOCATION_VERSION_CONFLICT
                current_version = existing["revocation_version"]
                current_hash = existing["revocation_hash"]
                if state.revocation_version < current_version:
                    return PolicyValidationCode.REVOCATION_REPLAY
                if state.revocation_version == current_version:
                    if state.revocation_hash != current_hash:
                        return PolicyValidationCode.REVOCATION_VERSION_CONFLICT
                    return PolicyValidationCode.REVOCATION_DUPLICATE

            revocation = {
                "revocation_list_id": state.revocation_list_id,
                "revocation_version": state.revocation_version,
                "revocation_hash": state.revocation_hash,
                "issuer_id": state.issuer_id,
                "server_id": state.server_id,
                "signing_key_id": state.signing_key_id,
                "issued_at": _utc_text(state.issued_at),
                "valid_from": _utc_text(state.valid_from),
                "expires_at": _utc_text(state.expires_at),
                "verified_at": verified_text,
                "revoked_policies": [
                    {
                        "policy_id": item.policy_id,
                        "policy_version": item.policy_version,
                        "policy_hash": item.policy_hash,
                    }
                    for item in state.revoked_policies
                ],
                "revoked_signing_key_ids": list(state.revoked_signing_key_ids),
            }
            document["revocation"] = revocation
            for policy_id, policy in document["policies"].items():
                policy["revoked"] = self._policy_is_revoked(
                    revocation,
                    policy_id,
                    policy["latest_version"],
                    policy["latest_hash"],
                )
                policy["revocation_version"] = state.revocation_version
            document["generation"] += 1
            self._write(document, expected_identity=identity)
        return None

    def check_execution_binding(
        self,
        *,
        policy_id: str,
        policy_version: int,
        policy_hash: str,
        issuer_id: str,
        server_id: str,
        agent_id: str,
        policy_signing_key_id: str,
        grant_signing_key_id: str,
        verified_at: datetime,
    ) -> PolicyValidationCode | None:
        """Confirm that execution still targets the latest, non-revoked policy."""

        with self._locked():
            state, _ = self._load()
            revocation = state["revocation"]
            revocation_error = self._check_current_revocation(
                revocation,
                server_id,
                verified_at,
            )
            if revocation_error is not None:
                return revocation_error
            assert revocation is not None
            if (
                policy_signing_key_id in revocation["revoked_signing_key_ids"]
                or grant_signing_key_id in revocation["revoked_signing_key_ids"]
            ):
                return PolicyValidationCode.SIGNING_KEY_REVOKED
            if self._policy_is_revoked(
                revocation,
                policy_id,
                policy_version,
                policy_hash,
            ):
                return PolicyValidationCode.POLICY_REVOKED

            policy = state["policies"].get(policy_id)
            if policy is None:
                return PolicyValidationCode.POLICY_STATE_UNAVAILABLE
            if policy["latest_version"] != policy_version:
                return PolicyValidationCode.POLICY_DOWNGRADE
            if policy["latest_hash"] != policy_hash:
                return PolicyValidationCode.POLICY_VERSION_CONFLICT
            if (
                policy["issuer_id"] != issuer_id
                or policy["server_id"] != server_id
                or policy["agent_id"] != agent_id
            ):
                return PolicyValidationCode.POLICY_VERSION_CONFLICT
            if policy["revoked"]:
                return PolicyValidationCode.POLICY_REVOKED
        return None

    def read_summary(self) -> Mapping[str, Any]:
        """Return a sanitized copy for diagnostics and tests."""

        with self._locked():
            state, _ = self._load()
        return json.loads(json.dumps(state))

    @staticmethod
    def _check_current_revocation(
        revocation: Mapping[str, Any] | None,
        server_id: str,
        now: datetime,
    ) -> PolicyValidationCode | None:
        if revocation is None or revocation["server_id"] != server_id:
            return PolicyValidationCode.REVOCATION_STATE_UNAVAILABLE
        if now < _parse_utc(revocation["valid_from"]):
            return PolicyValidationCode.REVOCATION_NOT_YET_VALID
        if now >= _parse_utc(revocation["expires_at"]):
            return PolicyValidationCode.REVOCATION_EXPIRED
        return None

    @staticmethod
    def _policy_is_revoked(
        revocation: Mapping[str, Any],
        policy_id: str,
        policy_version: int,
        policy_hash: str,
    ) -> bool:
        for item in revocation["revoked_policies"]:
            if item["policy_id"] != policy_id:
                continue
            if item["policy_version"] is not None and item["policy_version"] != policy_version:
                continue
            if item["policy_hash"] is not None and item["policy_hash"] != policy_hash:
                continue
            return True
        return False

    def _prepare_parent(self) -> None:
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if self.path.parent.is_symlink() or not self.path.parent.is_dir():
                raise OSError
            if os.name == "posix":
                os.chmod(self.path.parent, 0o700)
        except OSError:
            raise PolicyStateError(
                PolicyValidationCode.POLICY_STATE_UNAVAILABLE,
                "policy state directory is unavailable",
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
                raise PolicyStateError(
                    PolicyValidationCode.POLICY_STATE_LOCKED,
                    "policy state is locked or a previous update was interrupted",
                ) from None
            except OSError:
                raise PolicyStateError(
                    PolicyValidationCode.POLICY_STATE_UNAVAILABLE,
                    "policy state lock could not be created",
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
                    # A missing/unremovable lock fails future operations closed.
                    pass

    def _load(self) -> tuple[dict[str, Any], tuple[int, int, int, int]]:
        if self.path.is_symlink():
            raise PolicyStateError(
                PolicyValidationCode.POLICY_STATE_CORRUPT,
                "policy state symlink is not allowed",
            )
        try:
            stat_result = self.path.stat()
            if not self.path.is_file():
                raise OSError
            if stat_result.st_size > MAX_STORE_BYTES:
                raise PolicyStateError(
                    PolicyValidationCode.POLICY_STATE_CORRUPT,
                    "policy state exceeds the safe size limit",
                )
            if os.name == "posix" and stat_result.st_mode & 0o077:
                raise PolicyStateError(
                    PolicyValidationCode.POLICY_STATE_CORRUPT,
                    "policy state permissions are too broad",
                )
            raw = self.path.read_bytes()
        except FileNotFoundError:
            raise PolicyStateError(
                PolicyValidationCode.POLICY_STATE_UNAVAILABLE,
                "policy state is missing and must not be recreated implicitly",
            ) from None
        except PolicyStateError:
            raise
        except OSError:
            raise PolicyStateError(
                PolicyValidationCode.POLICY_STATE_UNAVAILABLE,
                "policy state could not be read",
            ) from None
        try:
            document = load_strict_json(raw)
            self._validate_document(document)
        except (ValueError, TypeError, KeyError):
            raise PolicyStateError(
                PolicyValidationCode.POLICY_STATE_CORRUPT,
                "policy state integrity validation failed",
            ) from None
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
        state_without_hash = dict(state)
        state_without_hash.pop("state_hash", None)
        state["state_hash"] = hashlib.sha256(
            canonicalize_json(state_without_hash)
        ).hexdigest()
        temporary_path: Path | None = None
        descriptor: int | None = None
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
                    raise PolicyStateError(
                        PolicyValidationCode.POLICY_STATE_CORRUPT,
                        "policy state appeared during initialization",
                    )
            elif self._identity() != expected_identity:
                raise PolicyStateError(
                    PolicyValidationCode.POLICY_STATE_CORRUPT,
                    "policy state changed during validation",
                )
            self._replace(temporary_path, self.path)
            temporary_path = None
            os.chmod(self.path, 0o600)
            if os.name == "posix":
                directory_descriptor = os.open(self.path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_descriptor)
                finally:
                    os.close(directory_descriptor)
        except PolicyStateError:
            raise
        except OSError:
            raise PolicyStateError(
                PolicyValidationCode.POLICY_STATE_WRITE_FAILED,
                "policy state update failed",
            ) from None
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
            stat_result = self.path.stat()
        except OSError:
            return (-1, -1, -1, -1)
        return (
            stat_result.st_dev,
            stat_result.st_ino,
            stat_result.st_size,
            stat_result.st_mtime_ns,
        )

    @staticmethod
    def _validate_document(document: Any) -> None:
        if not isinstance(document, dict) or set(document) != {
            "schema_version",
            "generation",
            "policies",
            "revocation",
            "state_hash",
        }:
            raise ValueError("invalid state fields")
        if document["schema_version"] != STORE_SCHEMA_VERSION:
            raise ValueError("unsupported state schema")
        if not isinstance(document["generation"], int) or document["generation"] < 0:
            raise ValueError("invalid state generation")
        if not isinstance(document["policies"], dict):
            raise ValueError("invalid policy state")
        state_hash = document["state_hash"]
        if not isinstance(state_hash, str) or not _SHA256.fullmatch(state_hash):
            raise ValueError("invalid state hash")
        unhashed = dict(document)
        unhashed.pop("state_hash")
        expected_hash = hashlib.sha256(canonicalize_json(unhashed)).hexdigest()
        if state_hash != expected_hash:
            raise ValueError("state hash mismatch")
        for policy_id, policy in document["policies"].items():
            PersistentPolicyVersionStore._validate_policy_entry(policy_id, policy)
        revocation = document["revocation"]
        if revocation is not None:
            PersistentPolicyVersionStore._validate_revocation_entry(revocation)

    @staticmethod
    def _validate_policy_entry(policy_id: Any, policy: Any) -> None:
        if not isinstance(policy_id, str) or not policy_id:
            raise ValueError("invalid policy ID")
        expected = {
            "latest_version",
            "latest_hash",
            "issuer_id",
            "server_id",
            "agent_id",
            "registered_at",
            "last_verified_at",
            "revoked",
            "revocation_version",
            "history",
        }
        if not isinstance(policy, dict) or set(policy) != expected:
            raise ValueError("invalid policy entry")
        if not isinstance(policy["latest_version"], int) or policy["latest_version"] < 1:
            raise ValueError("invalid latest version")
        if not isinstance(policy["latest_hash"], str) or not _SHA256.fullmatch(policy["latest_hash"]):
            raise ValueError("invalid latest hash")
        for field in ("issuer_id", "server_id", "agent_id"):
            if not isinstance(policy[field], str) or not policy[field]:
                raise ValueError("invalid policy identity")
        _parse_utc(policy["registered_at"])
        _parse_utc(policy["last_verified_at"])
        if not isinstance(policy["revoked"], bool):
            raise ValueError("invalid revoked state")
        if policy["revocation_version"] is not None and (
            not isinstance(policy["revocation_version"], int)
            or policy["revocation_version"] < 1
        ):
            raise ValueError("invalid policy revocation version")
        history = policy["history"]
        if not isinstance(history, list) or not history:
            raise ValueError("invalid policy history")
        previous_version = 0
        for item in history:
            if not isinstance(item, dict) or set(item) != {
                "policy_version",
                "policy_hash",
                "verified_at",
            }:
                raise ValueError("invalid history entry")
            if not isinstance(item["policy_version"], int) or item["policy_version"] <= previous_version:
                raise ValueError("history versions are not increasing")
            if not isinstance(item["policy_hash"], str) or not _SHA256.fullmatch(item["policy_hash"]):
                raise ValueError("invalid history hash")
            _parse_utc(item["verified_at"])
            previous_version = item["policy_version"]
        if previous_version != policy["latest_version"] or history[-1]["policy_hash"] != policy["latest_hash"]:
            raise ValueError("latest policy state does not match history")

    @staticmethod
    def _validate_revocation_entry(revocation: Any) -> None:
        expected = {
            "revocation_list_id",
            "revocation_version",
            "revocation_hash",
            "issuer_id",
            "server_id",
            "signing_key_id",
            "issued_at",
            "valid_from",
            "expires_at",
            "verified_at",
            "revoked_policies",
            "revoked_signing_key_ids",
        }
        if not isinstance(revocation, dict) or set(revocation) != expected:
            raise ValueError("invalid revocation state")
        for field in (
            "revocation_list_id",
            "issuer_id",
            "server_id",
            "signing_key_id",
        ):
            if not isinstance(revocation[field], str) or not revocation[field]:
                raise ValueError("invalid revocation identity")
        if not isinstance(revocation["revocation_version"], int) or revocation["revocation_version"] < 1:
            raise ValueError("invalid revocation version")
        if not isinstance(revocation["revocation_hash"], str) or not _SHA256.fullmatch(revocation["revocation_hash"]):
            raise ValueError("invalid revocation hash")
        for field in ("issued_at", "valid_from", "expires_at", "verified_at"):
            _parse_utc(revocation[field])
        if not isinstance(revocation["revoked_policies"], list):
            raise ValueError("invalid revoked policies")
        for item in revocation["revoked_policies"]:
            if not isinstance(item, dict) or set(item) != {
                "policy_id",
                "policy_version",
                "policy_hash",
            }:
                raise ValueError("invalid revoked policy")
            if not isinstance(item["policy_id"], str) or not item["policy_id"]:
                raise ValueError("invalid revoked policy ID")
            if item["policy_version"] is not None and (
                not isinstance(item["policy_version"], int) or item["policy_version"] < 1
            ):
                raise ValueError("invalid revoked policy version")
            if item["policy_hash"] is not None and (
                not isinstance(item["policy_hash"], str) or not _SHA256.fullmatch(item["policy_hash"])
            ):
                raise ValueError("invalid revoked policy hash")
        keys = revocation["revoked_signing_key_ids"]
        if not isinstance(keys, list) or any(not isinstance(key, str) or not key for key in keys):
            raise ValueError("invalid revoked signing keys")
