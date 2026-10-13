"""Signed, one-time HARDEN execution Grant verification.

Validation and consumption are intentionally separate from actual module execution.
Even a valid consumed Grant never enables operational HARDEN in this release.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature

from .execution_state import ExecutionStateCode, ExecutionStateError, PersistentExecutionStateStore
from .models import Action
from .policy import (
    POLICY_SCHEMA_VERSION,
    SIGNATURE_ALGORITHM,
    PolicyStateError,
    PolicyValidationCode,
    PolicyValidationResult,
    PolicyVersionStore,
    TrustedPolicyKeyStore,
    canonicalize_json,
    load_strict_json,
)
from .trusted_time import TrustedTimeError, TrustedTimeProvider

LOGGER = logging.getLogger(__name__)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_UCODE = re.compile(r"^U-(0[1-9]|[1-5][0-9]|6[0-7])$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class GrantValidationCode(str, Enum):
    VALID = "VALID"
    MALFORMED_JSON = "MALFORMED_JSON"
    INVALID_ENVELOPE = "INVALID_ENVELOPE"
    UNSUPPORTED_SCHEMA = "UNSUPPORTED_SCHEMA"
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"
    UNTRUSTED_SIGNING_KEY = "UNTRUSTED_SIGNING_KEY"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    HASH_MISMATCH = "HASH_MISMATCH"
    ISSUER_MISMATCH = "ISSUER_MISMATCH"
    INVALID_PAYLOAD = "INVALID_PAYLOAD"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    JOB_BINDING_MISMATCH = "JOB_BINDING_MISMATCH"
    ITEM_ACTION_MISMATCH = "ITEM_ACTION_MISMATCH"
    POLICY_BINDING_MISMATCH = "POLICY_BINDING_MISMATCH"
    PREVIEW_BINDING_MISMATCH = "PREVIEW_BINDING_MISMATCH"
    MODULE_BINDING_MISMATCH = "MODULE_BINDING_MISMATCH"
    GRANT_NOT_YET_VALID = "GRANT_NOT_YET_VALID"
    GRANT_EXPIRED = "GRANT_EXPIRED"
    TRUSTED_TIME_UNAVAILABLE = "TRUSTED_TIME_UNAVAILABLE"
    POLICY_STATE_REJECTED = "POLICY_STATE_REJECTED"
    SIGNING_KEY_REVOKED = "SIGNING_KEY_REVOKED"
    POLICY_REVOKED = "POLICY_REVOKED"
    GRANT_REUSED = "GRANT_REUSED"
    JOB_ATTEMPT_REUSED = "JOB_ATTEMPT_REUSED"
    EXECUTION_STATE_UNAVAILABLE = "EXECUTION_STATE_UNAVAILABLE"


@dataclass(frozen=True)
class ExecutionGrantPayload:
    grant_id: str
    approval_id: str
    issuer_id: str
    server_id: str
    agent_id: str
    job_id: str
    attempt_id: str
    action: Action
    item_id: str
    policy_id: str
    policy_version: int
    policy_hash: str
    preview_id: str
    state_fingerprint: str
    manifest_id: str
    module_version: str
    not_before: datetime
    expires_at: datetime
    single_use: bool


@dataclass(frozen=True)
class ExecutionGrantEnvelope:
    grant_schema_version: str
    signature_algorithm: str
    signing_key_id: str
    payload_sha256: str
    signature: str
    payload: ExecutionGrantPayload


@dataclass(frozen=True)
class GrantValidationContext:
    server_id: str
    agent_id: str
    grant_id: str
    approval_id: str
    job_id: str
    attempt_id: str
    action: Action
    item_id: str
    policy_result: PolicyValidationResult
    preview_id: str
    state_fingerprint: str
    manifest_id: str
    module_version: str


@dataclass(frozen=True)
class GrantValidationResult:
    valid: bool
    consumed: bool
    code: GrantValidationCode
    message: str
    grant: ExecutionGrantEnvelope | None = None
    operational_use_allowed: bool = False


class _GrantFailure(ValueError):
    def __init__(self, code: GrantValidationCode, message: str) -> None:
        super().__init__(message)
        self.code = code


class SignedExecutionGrantVerifier:
    """Verify and durably consume a one-time Grant without executing HARDEN."""

    _ENVELOPE_FIELDS = {
        "grant_schema_version",
        "signature_algorithm",
        "signing_key_id",
        "payload_sha256",
        "signature",
        "payload",
    }
    _PAYLOAD_FIELDS = {
        "grant_id",
        "approval_id",
        "issuer_id",
        "server_id",
        "agent_id",
        "job_id",
        "attempt_id",
        "action",
        "item_id",
        "policy_id",
        "policy_version",
        "policy_hash",
        "preview_id",
        "state_fingerprint",
        "manifest_id",
        "module_version",
        "not_before",
        "expires_at",
        "single_use",
    }

    def __init__(
        self,
        trusted_keys: TrustedPolicyKeyStore,
        trusted_time: TrustedTimeProvider,
        policy_store: PolicyVersionStore,
        execution_state: PersistentExecutionStateStore,
    ) -> None:
        self._trusted_keys = trusted_keys
        self._trusted_time = trusted_time
        self._policy_store = policy_store
        self._execution_state = execution_state

    def validate_and_consume(
        self,
        document: str | bytes,
        context: GrantValidationContext,
    ) -> GrantValidationResult:
        return self._validate(document, context, consume=True)

    def validate(
        self,
        document: str | bytes,
        context: GrantValidationContext,
    ) -> GrantValidationResult:
        """Read-only pre-validation; a future execution must validate and consume again."""

        return self._validate(document, context, consume=False)

    def _validate(
        self,
        document: str | bytes,
        context: GrantValidationContext,
        *,
        consume: bool,
    ) -> GrantValidationResult:
        try:
            raw = load_strict_json(document)
            envelope, grant_hash = self._verify_envelope(raw)
            now = self._trusted_now()
            self._validate_binding(envelope, context, now)
            self._validate_current_policy(envelope, context, now)
            if consume:
                self._execution_state.consume_grant(
                    grant_id=envelope.payload.grant_id,
                    grant_hash=grant_hash,
                    job_id=envelope.payload.job_id,
                    attempt_id=envelope.payload.attempt_id,
                    consumed_at=now,
                )
            else:
                self._execution_state.check_grant_available(
                    grant_id=envelope.payload.grant_id,
                    job_id=envelope.payload.job_id,
                    attempt_id=envelope.payload.attempt_id,
                )
        except _GrantFailure as exc:
            return self._failure(exc.code, str(exc))
        except ExecutionStateError as exc:
            code = {
                ExecutionStateCode.GRANT_REUSED: GrantValidationCode.GRANT_REUSED,
                ExecutionStateCode.JOB_ATTEMPT_REUSED: GrantValidationCode.JOB_ATTEMPT_REUSED,
            }.get(exc.code, GrantValidationCode.EXECUTION_STATE_UNAVAILABLE)
            return self._failure(code, str(exc))
        except PolicyStateError as exc:
            return self._failure(
                GrantValidationCode.POLICY_STATE_REJECTED,
                f"policy state rejected Grant ({exc.code.value})",
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError, KeyError):
            return self._failure(
                GrantValidationCode.MALFORMED_JSON,
                "execution Grant document is invalid",
            )

        if consume:
            LOGGER.info(
                "Execution Grant validated and consumed for simulation only "
                "(grant_id=%s, job_id=%s)",
                envelope.payload.grant_id,
                envelope.payload.job_id,
            )
        else:
            LOGGER.info(
                "Execution Grant pre-validated without consumption "
                "(grant_id=%s, job_id=%s)",
                envelope.payload.grant_id,
                envelope.payload.job_id,
            )
        return GrantValidationResult(
            valid=True,
            consumed=consume,
            code=GrantValidationCode.VALID,
            message=(
                "execution Grant is valid and permanently consumed"
                if consume
                else "execution Grant is valid but not consumed or authorized for use"
            ),
            grant=envelope,
            operational_use_allowed=False,
        )

    def _verify_envelope(self, raw: Any) -> tuple[ExecutionGrantEnvelope, str]:
        if not isinstance(raw, dict) or set(raw) != self._ENVELOPE_FIELDS:
            self._fail(GrantValidationCode.INVALID_ENVELOPE, "Grant envelope is invalid")
        schema = self._string(raw, "grant_schema_version")
        if schema != POLICY_SCHEMA_VERSION:
            self._fail(GrantValidationCode.UNSUPPORTED_SCHEMA, "Grant schema is unsupported")
        algorithm = self._string(raw, "signature_algorithm")
        if algorithm != SIGNATURE_ALGORITHM:
            self._fail(
                GrantValidationCode.UNSUPPORTED_ALGORITHM,
                "Grant signature algorithm is not allowed",
            )
        key_id = self._identifier(raw, "signing_key_id")
        public_key = self._trusted_keys.get(key_id)
        if public_key is None or not self._trusted_keys.usage_is_allowed(key_id, "grant"):
            self._fail(
                GrantValidationCode.UNTRUSTED_SIGNING_KEY,
                "Grant signing key is not trusted for approval use",
            )
        payload = raw.get("payload")
        if not isinstance(payload, dict) or set(payload) != self._PAYLOAD_FIELDS:
            self._fail(GrantValidationCode.INVALID_PAYLOAD, "Grant payload is invalid")
        payload_hash = self._string(raw, "payload_sha256").lower()
        if not _SHA256.fullmatch(payload_hash):
            self._fail(GrantValidationCode.INVALID_PAYLOAD, "Grant hash is invalid")
        if hashlib.sha256(canonicalize_json(payload)).hexdigest() != payload_hash:
            self._fail(GrantValidationCode.HASH_MISMATCH, "Grant payload hash does not match")
        signed_fields = {
            "grant_schema_version": schema,
            "signature_algorithm": algorithm,
            "signing_key_id": key_id,
            "payload_sha256": payload_hash,
            "payload": payload,
        }
        try:
            signature = base64.b64decode(self._string(raw, "signature"), validate=True)
            public_key.verify(signature, canonicalize_json(signed_fields))
        except (ValueError, InvalidSignature):
            self._fail(GrantValidationCode.INVALID_SIGNATURE, "Grant signature is invalid")
        issuer_id = self._identifier(payload, "issuer_id")
        if not self._trusted_keys.issuer_is_allowed(key_id, issuer_id):
            self._fail(GrantValidationCode.ISSUER_MISMATCH, "Grant issuer is not authorized")
        parsed_payload = self._parse_payload(payload)
        envelope = ExecutionGrantEnvelope(
            grant_schema_version=schema,
            signature_algorithm=algorithm,
            signing_key_id=key_id,
            payload_sha256=payload_hash,
            signature=self._string(raw, "signature"),
            payload=parsed_payload,
        )
        return envelope, hashlib.sha256(canonicalize_json(signed_fields)).hexdigest()

    def _parse_payload(self, raw: Mapping[str, Any]) -> ExecutionGrantPayload:
        try:
            action = Action(self._string(raw, "action"))
        except ValueError:
            self._fail(GrantValidationCode.INVALID_PAYLOAD, "Grant action is invalid")
        item_id = self._string(raw, "item_id")
        policy_hash = self._string(raw, "policy_hash").lower()
        state_fingerprint = self._string(raw, "state_fingerprint").lower()
        policy_version = raw.get("policy_version")
        single_use = raw.get("single_use")
        if action is not Action.HARDEN or not _UCODE.fullmatch(item_id):
            self._fail(GrantValidationCode.INVALID_PAYLOAD, "Grant authority is invalid")
        if not _SHA256.fullmatch(policy_hash) or not _SHA256.fullmatch(state_fingerprint):
            self._fail(GrantValidationCode.INVALID_PAYLOAD, "Grant digest is invalid")
        if not isinstance(policy_version, int) or isinstance(policy_version, bool) or policy_version < 1:
            self._fail(GrantValidationCode.INVALID_PAYLOAD, "Grant policy version is invalid")
        if single_use is not True:
            self._fail(GrantValidationCode.INVALID_PAYLOAD, "Grant must be single use")
        not_before = self._timestamp(raw, "not_before")
        expires_at = self._timestamp(raw, "expires_at")
        if not_before >= expires_at:
            self._fail(GrantValidationCode.INVALID_PAYLOAD, "Grant lifecycle is invalid")
        return ExecutionGrantPayload(
            grant_id=self._identifier(raw, "grant_id"),
            approval_id=self._identifier(raw, "approval_id"),
            issuer_id=self._identifier(raw, "issuer_id"),
            server_id=self._identifier(raw, "server_id"),
            agent_id=self._identifier(raw, "agent_id"),
            job_id=self._identifier(raw, "job_id"),
            attempt_id=self._identifier(raw, "attempt_id"),
            action=action,
            item_id=item_id,
            policy_id=self._identifier(raw, "policy_id"),
            policy_version=policy_version,
            policy_hash=policy_hash,
            preview_id=self._identifier(raw, "preview_id"),
            state_fingerprint=state_fingerprint,
            manifest_id=self._identifier(raw, "manifest_id"),
            module_version=self._identifier(raw, "module_version"),
            not_before=not_before,
            expires_at=expires_at,
            single_use=single_use,
        )

    def _trusted_now(self) -> datetime:
        try:
            trusted = self._trusted_time.current_time()
        except TrustedTimeError as exc:
            self._fail(
                GrantValidationCode.TRUSTED_TIME_UNAVAILABLE,
                f"trusted time rejected Grant ({exc.code.value})",
            )
        if not trusted.authenticated or trusted.value.tzinfo is None:
            self._fail(
                GrantValidationCode.TRUSTED_TIME_UNAVAILABLE,
                "authenticated trusted time is unavailable",
            )
        return trusted.value.astimezone(timezone.utc)

    def _validate_binding(
        self,
        envelope: ExecutionGrantEnvelope,
        context: GrantValidationContext,
        now: datetime,
    ) -> None:
        payload = envelope.payload
        if now < payload.not_before:
            self._fail(GrantValidationCode.GRANT_NOT_YET_VALID, "Grant is not yet valid")
        if now >= payload.expires_at:
            self._fail(GrantValidationCode.GRANT_EXPIRED, "Grant has expired")
        if payload.server_id != context.server_id or payload.agent_id != context.agent_id:
            self._fail(GrantValidationCode.SCOPE_MISMATCH, "Grant Agent or Server scope differs")
        if payload.grant_id != context.grant_id or payload.approval_id != context.approval_id:
            self._fail(GrantValidationCode.SCOPE_MISMATCH, "Grant approval identity differs")
        if payload.job_id != context.job_id or payload.attempt_id != context.attempt_id:
            self._fail(GrantValidationCode.JOB_BINDING_MISMATCH, "Grant job binding differs")
        if payload.action is not context.action or payload.item_id != context.item_id:
            self._fail(GrantValidationCode.ITEM_ACTION_MISMATCH, "Grant item or action differs")
        if payload.preview_id != context.preview_id or payload.state_fingerprint != context.state_fingerprint:
            self._fail(GrantValidationCode.PREVIEW_BINDING_MISMATCH, "Grant preview binding differs")
        if payload.manifest_id != context.manifest_id or payload.module_version != context.module_version:
            self._fail(GrantValidationCode.MODULE_BINDING_MISMATCH, "Grant module binding differs")

    def _validate_current_policy(
        self,
        envelope: ExecutionGrantEnvelope,
        context: GrantValidationContext,
        now: datetime,
    ) -> None:
        result = context.policy_result
        payload = envelope.payload
        if not result.valid or result.policy is None or result.policy_hash is None:
            self._fail(GrantValidationCode.POLICY_BINDING_MISMATCH, "validated policy is unavailable")
        policy = result.policy
        if (
            payload.policy_id != policy.payload.policy_id
            or payload.policy_version != policy.payload.policy_version
            or payload.policy_hash != result.policy_hash
        ):
            self._fail(GrantValidationCode.POLICY_BINDING_MISMATCH, "Grant policy binding differs")
        if now < policy.payload.valid_from or now >= policy.payload.expires_at:
            self._fail(GrantValidationCode.POLICY_BINDING_MISMATCH, "bound policy is not currently valid")
        if payload.item_id not in policy.payload.target.u_codes or Action.HARDEN not in policy.payload.target.actions:
            self._fail(GrantValidationCode.POLICY_BINDING_MISMATCH, "policy does not authorize this item")
        state_error = self._policy_store.check_execution_binding(
            policy_id=payload.policy_id,
            policy_version=payload.policy_version,
            policy_hash=payload.policy_hash,
            issuer_id=policy.payload.issuer_id,
            server_id=payload.server_id,
            agent_id=payload.agent_id,
            policy_signing_key_id=policy.signing_key_id,
            grant_signing_key_id=envelope.signing_key_id,
            verified_at=now,
        )
        if state_error is PolicyValidationCode.SIGNING_KEY_REVOKED:
            self._fail(GrantValidationCode.SIGNING_KEY_REVOKED, "Grant or policy signing key is revoked")
        if state_error is PolicyValidationCode.POLICY_REVOKED:
            self._fail(GrantValidationCode.POLICY_REVOKED, "bound policy is revoked")
        if state_error is not None:
            self._fail(
                GrantValidationCode.POLICY_STATE_REJECTED,
                f"current policy state rejected Grant ({state_error.value})",
            )

    @staticmethod
    def _string(raw: Mapping[str, Any], field_name: str) -> str:
        value = raw.get(field_name)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"invalid Grant field: {field_name}")
        return value.strip()

    @classmethod
    def _identifier(cls, raw: Mapping[str, Any], field_name: str) -> str:
        value = cls._string(raw, field_name)
        if not _IDENTIFIER.fullmatch(value):
            raise ValueError(f"invalid Grant identifier: {field_name}")
        return value

    @staticmethod
    def _timestamp(raw: Mapping[str, Any], field_name: str) -> datetime:
        value = raw.get(field_name)
        if not isinstance(value, str) or not value.endswith("Z"):
            raise ValueError("Grant timestamp must be UTC")
        try:
            return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
        except ValueError:
            raise ValueError("Grant timestamp is invalid") from None

    @staticmethod
    def _failure(code: GrantValidationCode, message: str) -> GrantValidationResult:
        LOGGER.warning("Execution Grant rejected (reason=%s)", code.value)
        return GrantValidationResult(False, False, code, message)

    @staticmethod
    def _fail(code: GrantValidationCode, message: str) -> None:
        raise _GrantFailure(code, message)
