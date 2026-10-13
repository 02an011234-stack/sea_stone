"""Authenticated time evidence and fail-closed trusted clock interfaces."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Mapping, Protocol

from cryptography.exceptions import InvalidSignature

from .policy import (
    POLICY_SCHEMA_VERSION,
    SAFE_INTEGER_LIMIT,
    SIGNATURE_ALGORITHM,
    TrustedPolicyKeyStore,
    canonicalize_json,
    load_strict_json,
)

LOGGER = logging.getLogger(__name__)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class TrustedTimeCode(str, Enum):
    VALID = "VALID"
    INVALID_EVIDENCE = "INVALID_EVIDENCE"
    UNSUPPORTED_SCHEMA = "UNSUPPORTED_SCHEMA"
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"
    UNTRUSTED_KEY = "UNTRUSTED_KEY"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    ISSUER_MISMATCH = "ISSUER_MISMATCH"
    SOURCE_NOT_ALLOWED = "SOURCE_NOT_ALLOWED"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    UNCERTAINTY_TOO_HIGH = "UNCERTAINTY_TOO_HIGH"
    LOCAL_CLOCK_OUT_OF_BOUNDS = "LOCAL_CLOCK_OUT_OF_BOUNDS"
    EVIDENCE_NOT_YET_VALID = "EVIDENCE_NOT_YET_VALID"
    EVIDENCE_EXPIRED = "EVIDENCE_EXPIRED"
    EVIDENCE_REPLAY = "EVIDENCE_REPLAY"
    TIME_ROLLBACK = "TIME_ROLLBACK"
    TIME_STATE_UNAVAILABLE = "TIME_STATE_UNAVAILABLE"
    TIME_STATE_CORRUPT = "TIME_STATE_CORRUPT"
    TIME_STATE_WRITE_FAILED = "TIME_STATE_WRITE_FAILED"


@dataclass(frozen=True)
class AuthenticatedTimeEvidence:
    evidence_id: str
    evidence_hash: str
    source_id: str
    issuer_id: str
    signing_key_id: str
    server_id: str
    agent_id: str
    issued_at: datetime
    observed_at: datetime
    expires_at: datetime
    uncertainty_seconds: int
    received_at: datetime


@dataclass(frozen=True)
class TrustedTime:
    value: datetime
    evidence_id: str
    source_id: str
    authenticated: bool
    uncertainty_seconds: int
    evidence_expires_at: datetime


@dataclass(frozen=True)
class TimeEvidenceValidationResult:
    valid: bool
    code: TrustedTimeCode
    message: str
    evidence: AuthenticatedTimeEvidence | None = None


class TrustedTimeError(RuntimeError):
    def __init__(self, code: TrustedTimeCode, message: str) -> None:
        super().__init__(message)
        self.code = code


class TrustedTimeProvider(Protocol):
    def current_time(self) -> TrustedTime: ...


class TrustedTimeStateStore(Protocol):
    def record_time_evidence(self, evidence: AuthenticatedTimeEvidence) -> None: ...

    def derive_trusted_time(
        self,
        *,
        local_now: datetime,
        maximum_evidence_age_seconds: int,
    ) -> TrustedTime: ...


class SignedTimeEvidenceVerifier:
    """Verify test-fixture time evidence signed by a locally trusted time key."""

    _ENVELOPE_FIELDS = {
        "time_schema_version",
        "signature_algorithm",
        "signing_key_id",
        "payload_sha256",
        "signature",
        "payload",
    }
    _PAYLOAD_FIELDS = {
        "evidence_id",
        "source_id",
        "issuer_id",
        "server_id",
        "agent_id",
        "issued_at",
        "observed_at",
        "expires_at",
        "uncertainty_seconds",
    }

    def __init__(
        self,
        trusted_keys: TrustedPolicyKeyStore,
        state_store: TrustedTimeStateStore,
        *,
        allowed_source_ids: frozenset[str],
        maximum_uncertainty_seconds: int,
        maximum_local_clock_delta_seconds: int,
        local_clock: Callable[[], datetime] | None = None,
    ) -> None:
        if maximum_uncertainty_seconds < 0 or maximum_local_clock_delta_seconds < 0:
            raise ValueError("trusted time bounds must not be negative")
        if not allowed_source_ids:
            raise ValueError("at least one trusted time source is required")
        self._trusted_keys = trusted_keys
        self._state_store = state_store
        self._allowed_source_ids = allowed_source_ids
        self._maximum_uncertainty_seconds = maximum_uncertainty_seconds
        self._maximum_local_clock_delta_seconds = maximum_local_clock_delta_seconds
        self._local_clock = local_clock or (lambda: datetime.now(timezone.utc))

    def validate_and_record(
        self,
        document: str | bytes,
        *,
        server_id: str,
        agent_id: str,
    ) -> TimeEvidenceValidationResult:
        try:
            raw = load_strict_json(document)
            evidence = self._verify(raw, server_id=server_id, agent_id=agent_id)
            self._state_store.record_time_evidence(evidence)
        except TrustedTimeError as exc:
            LOGGER.warning("Trusted time evidence rejected (reason=%s)", exc.code.value)
            return TimeEvidenceValidationResult(False, exc.code, str(exc))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError, KeyError):
            LOGGER.warning(
                "Trusted time evidence rejected (reason=%s)",
                TrustedTimeCode.INVALID_EVIDENCE.value,
            )
            return TimeEvidenceValidationResult(
                False,
                TrustedTimeCode.INVALID_EVIDENCE,
                "trusted time evidence is invalid",
            )
        LOGGER.info(
            "Trusted time evidence accepted (evidence_id=%s, source_id=%s)",
            evidence.evidence_id,
            evidence.source_id,
        )
        return TimeEvidenceValidationResult(
            True,
            TrustedTimeCode.VALID,
            "trusted time evidence is valid",
            evidence,
        )

    def _verify(
        self, raw: Any, *, server_id: str, agent_id: str
    ) -> AuthenticatedTimeEvidence:
        if not isinstance(raw, dict) or set(raw) != self._ENVELOPE_FIELDS:
            self._fail(TrustedTimeCode.INVALID_EVIDENCE, "time envelope is invalid")
        schema = self._string(raw, "time_schema_version")
        if schema != POLICY_SCHEMA_VERSION:
            self._fail(TrustedTimeCode.UNSUPPORTED_SCHEMA, "time schema is not supported")
        algorithm = self._string(raw, "signature_algorithm")
        if algorithm != SIGNATURE_ALGORITHM:
            self._fail(
                TrustedTimeCode.UNSUPPORTED_ALGORITHM,
                "time signature algorithm is not allowed",
            )
        key_id = self._identifier(raw, "signing_key_id")
        public_key = self._trusted_keys.get(key_id)
        if public_key is None or not self._trusted_keys.usage_is_allowed(key_id, "time"):
            self._fail(TrustedTimeCode.UNTRUSTED_KEY, "time signing key is not trusted")
        payload = raw.get("payload")
        if not isinstance(payload, dict) or set(payload) != self._PAYLOAD_FIELDS:
            self._fail(TrustedTimeCode.INVALID_EVIDENCE, "time payload is invalid")
        payload_hash = self._string(raw, "payload_sha256").lower()
        if not _SHA256.fullmatch(payload_hash):
            self._fail(TrustedTimeCode.INVALID_EVIDENCE, "time hash is invalid")
        if hashlib.sha256(canonicalize_json(payload)).hexdigest() != payload_hash:
            self._fail(TrustedTimeCode.INVALID_EVIDENCE, "time hash does not match")
        signed_fields = {
            "time_schema_version": schema,
            "signature_algorithm": algorithm,
            "signing_key_id": key_id,
            "payload_sha256": payload_hash,
            "payload": payload,
        }
        try:
            signature = base64.b64decode(self._string(raw, "signature"), validate=True)
            public_key.verify(signature, canonicalize_json(signed_fields))
        except (ValueError, InvalidSignature):
            self._fail(TrustedTimeCode.INVALID_SIGNATURE, "time signature is invalid")
        issuer_id = self._identifier(payload, "issuer_id")
        if not self._trusted_keys.issuer_is_allowed(key_id, issuer_id):
            self._fail(TrustedTimeCode.ISSUER_MISMATCH, "time issuer is not authorized")
        source_id = self._identifier(payload, "source_id")
        if source_id not in self._allowed_source_ids:
            self._fail(TrustedTimeCode.SOURCE_NOT_ALLOWED, "time source is not allowed")
        if (
            self._identifier(payload, "server_id") != server_id
            or self._identifier(payload, "agent_id") != agent_id
        ):
            self._fail(TrustedTimeCode.SCOPE_MISMATCH, "time evidence scope mismatch")
        uncertainty = payload.get("uncertainty_seconds")
        if (
            not isinstance(uncertainty, int)
            or isinstance(uncertainty, bool)
            or uncertainty < 0
            or uncertainty > SAFE_INTEGER_LIMIT
        ):
            self._fail(TrustedTimeCode.INVALID_EVIDENCE, "time uncertainty is invalid")
        if uncertainty > self._maximum_uncertainty_seconds:
            self._fail(
                TrustedTimeCode.UNCERTAINTY_TOO_HIGH,
                "time evidence uncertainty exceeds the local limit",
            )
        issued_at = self._timestamp(payload, "issued_at")
        observed_at = self._timestamp(payload, "observed_at")
        expires_at = self._timestamp(payload, "expires_at")
        if issued_at > observed_at or observed_at >= expires_at:
            self._fail(TrustedTimeCode.INVALID_EVIDENCE, "time lifecycle is invalid")
        received_at = self._local_now()
        allowed_delta = self._maximum_local_clock_delta_seconds + uncertainty
        delta = abs((received_at - observed_at).total_seconds())
        if delta > allowed_delta:
            self._fail(
                TrustedTimeCode.LOCAL_CLOCK_OUT_OF_BOUNDS,
                "local clock differs too far from authenticated time evidence",
            )
        if received_at < issued_at:
            self._fail(
                TrustedTimeCode.EVIDENCE_NOT_YET_VALID,
                "time evidence has not been issued yet",
            )
        if received_at >= expires_at:
            self._fail(TrustedTimeCode.EVIDENCE_EXPIRED, "time evidence has expired")
        return AuthenticatedTimeEvidence(
            evidence_id=self._identifier(payload, "evidence_id"),
            evidence_hash=payload_hash,
            source_id=source_id,
            issuer_id=issuer_id,
            signing_key_id=key_id,
            server_id=server_id,
            agent_id=agent_id,
            issued_at=issued_at,
            observed_at=observed_at,
            expires_at=expires_at,
            uncertainty_seconds=uncertainty,
            received_at=received_at,
        )

    def _local_now(self) -> datetime:
        current = self._local_clock()
        if current.tzinfo is None:
            self._fail(
                TrustedTimeCode.TIME_STATE_UNAVAILABLE,
                "local clock must include a timezone",
            )
        return current.astimezone(timezone.utc)

    @staticmethod
    def _string(raw: Mapping[str, Any], field_name: str) -> str:
        value = raw.get(field_name)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"invalid time field: {field_name}")
        return value.strip()

    @classmethod
    def _identifier(cls, raw: Mapping[str, Any], field_name: str) -> str:
        value = cls._string(raw, field_name)
        if not _IDENTIFIER.fullmatch(value):
            raise ValueError(f"invalid time identifier: {field_name}")
        return value

    @staticmethod
    def _timestamp(raw: Mapping[str, Any], field_name: str) -> datetime:
        value = raw.get(field_name)
        if not isinstance(value, str) or not value.endswith("Z"):
            raise ValueError("time timestamp must be UTC")
        try:
            return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
        except ValueError:
            raise ValueError("time timestamp is invalid") from None

    @staticmethod
    def _fail(code: TrustedTimeCode, message: str) -> None:
        raise TrustedTimeError(code, message)


class PersistentTrustedTimeProvider:
    """Derive current trusted time from persisted authenticated evidence."""

    def __init__(
        self,
        state_store: TrustedTimeStateStore,
        *,
        maximum_evidence_age_seconds: int,
        local_clock: Callable[[], datetime] | None = None,
    ) -> None:
        if maximum_evidence_age_seconds <= 0:
            raise ValueError("maximum evidence age must be greater than zero")
        self._state_store = state_store
        self._maximum_evidence_age_seconds = maximum_evidence_age_seconds
        self._local_clock = local_clock or (lambda: datetime.now(timezone.utc))

    def current_time(self) -> TrustedTime:
        local_now = self._local_clock()
        if local_now.tzinfo is None:
            raise TrustedTimeError(
                TrustedTimeCode.TIME_STATE_UNAVAILABLE,
                "local clock must include a timezone",
            )
        return self._state_store.derive_trusted_time(
            local_now=local_now.astimezone(timezone.utc),
            maximum_evidence_age_seconds=self._maximum_evidence_age_seconds,
        )
