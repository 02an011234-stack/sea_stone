"""Verification of signed policy and signing-key revocation state."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidSignature

from .policy import (
    POLICY_SCHEMA_VERSION,
    SAFE_INTEGER_LIMIT,
    SIGNATURE_ALGORITHM,
    PolicyStateError,
    PolicyValidationCode,
    PolicyVersionStore,
    RevocationState,
    RevocationValidationResult,
    RevokedPolicy,
    TrustedPolicyKeyStore,
    canonicalize_json,
    load_strict_json,
)
from .trusted_time import TrustedTimeProvider

LOGGER = logging.getLogger(__name__)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")


class SignedRevocationVerifier:
    """Validate signed revocation fixtures and persist monotonic state."""

    _ENVELOPE_FIELDS = {
        "revocation_schema_version",
        "signature_algorithm",
        "signing_key_id",
        "payload_sha256",
        "signature",
        "payload",
    }
    _PAYLOAD_FIELDS = {
        "revocation_list_id",
        "revocation_version",
        "issuer_id",
        "server_id",
        "issued_at",
        "valid_from",
        "expires_at",
        "revoked_policies",
        "revoked_signing_key_ids",
    }
    _REVOKED_POLICY_FIELDS = {"policy_id", "policy_version", "policy_hash"}

    def __init__(
        self,
        trusted_keys: TrustedPolicyKeyStore,
        state_store: PolicyVersionStore,
        *,
        clock: Callable[[], datetime] | None = None,
        trusted_time_provider: TrustedTimeProvider | None = None,
    ) -> None:
        self._trusted_keys = trusted_keys
        self._state_store = state_store
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._trusted_time_provider = trusted_time_provider

    def validate_and_record(
        self,
        document: str | bytes,
        *,
        server_id: str,
        clock_trusted: bool,
        accept_duplicate: bool = False,
    ) -> RevocationValidationResult:
        try:
            raw = load_strict_json(document)
            state = self._verify(raw, server_id=server_id, clock_trusted=clock_trusted)
            result_code = self._state_store.record_revocation(
                state, verified_at=self._trusted_now(clock_trusted)
            )
            if result_code is not None and not (
                accept_duplicate
                and result_code is PolicyValidationCode.REVOCATION_DUPLICATE
            ):
                return self._failure(result_code, self._state_error_message(result_code))
        except PolicyStateError as exc:
            LOGGER.error("Revocation state update failed (reason=%s)", exc.code.value)
            return self._failure(exc.code, str(exc))
        except _RevocationFailure as exc:
            return self._failure(exc.code, str(exc))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError, KeyError):
            return self._failure(
                PolicyValidationCode.INVALID_REVOCATION,
                "revocation document is invalid",
            )
        LOGGER.info(
            "Signed revocation state accepted (list_id=%s, version=%s)",
            state.revocation_list_id,
            state.revocation_version,
        )
        return RevocationValidationResult(
            True,
            PolicyValidationCode.VALID,
            "revocation signature and scope are valid",
            state,
        )

    def _verify(
        self,
        raw: Any,
        *,
        server_id: str,
        clock_trusted: bool,
    ) -> RevocationState:
        if not isinstance(raw, dict) or set(raw) != self._ENVELOPE_FIELDS:
            raise ValueError("invalid revocation envelope")
        schema_version = self._required_string(raw, "revocation_schema_version")
        if schema_version != POLICY_SCHEMA_VERSION:
            raise ValueError("unsupported revocation schema")
        algorithm = self._required_string(raw, "signature_algorithm")
        if algorithm != SIGNATURE_ALGORITHM:
            raise ValueError("unsupported revocation signature algorithm")
        key_id = self._identifier(raw, "signing_key_id")
        public_key = self._trusted_keys.get(key_id)
        if public_key is None or not self._trusted_keys.usage_is_allowed(
            key_id, "revocation"
        ):
            raise ValueError("untrusted revocation signing key")
        payload = raw.get("payload")
        if not isinstance(payload, dict) or set(payload) != self._PAYLOAD_FIELDS:
            raise ValueError("invalid revocation payload")
        payload_bytes = canonicalize_json(payload)
        payload_hash = self._required_string(raw, "payload_sha256").lower()
        if not _HASH.fullmatch(payload_hash):
            raise ValueError("invalid revocation hash")
        if hashlib.sha256(payload_bytes).hexdigest() != payload_hash:
            raise ValueError("revocation hash mismatch")
        signed_fields = {
            "revocation_schema_version": schema_version,
            "signature_algorithm": algorithm,
            "signing_key_id": key_id,
            "payload_sha256": payload_hash,
            "payload": payload,
        }
        try:
            signature = base64.b64decode(
                self._required_string(raw, "signature"), validate=True
            )
            public_key.verify(signature, canonicalize_json(signed_fields))
        except (ValueError, InvalidSignature):
            raise ValueError("revocation signature is invalid") from None

        issuer_id = self._identifier(payload, "issuer_id")
        if not self._trusted_keys.issuer_is_allowed(key_id, issuer_id):
            raise ValueError("revocation issuer does not match trusted key")
        payload_server_id = self._identifier(payload, "server_id")
        if payload_server_id != server_id:
            raise ValueError("revocation server scope mismatch")
        version = payload.get("revocation_version")
        if (
            not isinstance(version, int)
            or isinstance(version, bool)
            or version < 1
            or version > SAFE_INTEGER_LIMIT
        ):
            raise ValueError("invalid revocation version")
        issued_at = self._timestamp(payload, "issued_at")
        valid_from = self._timestamp(payload, "valid_from")
        expires_at = self._timestamp(payload, "expires_at")
        if issued_at > expires_at or valid_from >= expires_at:
            raise ValueError("invalid revocation lifecycle")
        now = self._trusted_now(clock_trusted)
        if now < issued_at or now < valid_from:
            raise _RevocationFailure(
                PolicyValidationCode.REVOCATION_NOT_YET_VALID,
                "revocation validity period has not started",
            )
        if now >= expires_at:
            raise _RevocationFailure(
                PolicyValidationCode.REVOCATION_EXPIRED,
                "revocation state has expired",
            )
        revoked_policies = self._parse_revoked_policies(payload["revoked_policies"])
        revoked_keys = self._identifier_array(
            payload["revoked_signing_key_ids"], allow_empty=True
        )
        return RevocationState(
            revocation_list_id=self._identifier(payload, "revocation_list_id"),
            revocation_version=version,
            revocation_hash=payload_hash,
            issuer_id=issuer_id,
            server_id=payload_server_id,
            signing_key_id=key_id,
            issued_at=issued_at,
            valid_from=valid_from,
            expires_at=expires_at,
            revoked_policies=revoked_policies,
            revoked_signing_key_ids=revoked_keys,
        )

    def _parse_revoked_policies(self, raw: Any) -> tuple[RevokedPolicy, ...]:
        if not isinstance(raw, list):
            raise ValueError("invalid revoked policy list")
        result: list[RevokedPolicy] = []
        identities: set[tuple[str, int | None, str | None]] = set()
        for item in raw:
            if not isinstance(item, dict) or set(item) != self._REVOKED_POLICY_FIELDS:
                raise ValueError("invalid revoked policy entry")
            policy_id = self._identifier(item, "policy_id")
            policy_version = item.get("policy_version")
            if policy_version is not None and (
                not isinstance(policy_version, int)
                or isinstance(policy_version, bool)
                or policy_version < 1
            ):
                raise ValueError("invalid revoked policy version")
            policy_hash = item.get("policy_hash")
            if policy_hash is not None and (
                not isinstance(policy_hash, str)
                or not _HASH.fullmatch(policy_hash)
            ):
                raise ValueError("invalid revoked policy hash")
            identity = (policy_id, policy_version, policy_hash)
            if identity in identities:
                raise ValueError("duplicate revoked policy entry")
            identities.add(identity)
            result.append(RevokedPolicy(*identity))
        return tuple(result)

    def _trusted_now(self, clock_trusted: bool) -> datetime:
        if self._trusted_time_provider is not None:
            try:
                trusted_time = self._trusted_time_provider.current_time()
            except (RuntimeError, OSError, ValueError):
                raise _RevocationFailure(
                    PolicyValidationCode.UNTRUSTED_CLOCK,
                    "authenticated Agent time is unavailable",
                ) from None
            if not trusted_time.authenticated or trusted_time.value.tzinfo is None:
                raise _RevocationFailure(
                    PolicyValidationCode.UNTRUSTED_CLOCK,
                    "authenticated Agent time is unavailable",
                )
            return trusted_time.value.astimezone(timezone.utc)
        if not clock_trusted:
            raise _RevocationFailure(
                PolicyValidationCode.UNTRUSTED_CLOCK,
                "Agent time is not trusted for revocation validation",
            )
        now = self._clock()
        if now.tzinfo is None:
            raise _RevocationFailure(
                PolicyValidationCode.UNTRUSTED_CLOCK,
                "revocation validation clock must include a timezone",
            )
        return now.astimezone(timezone.utc)

    @staticmethod
    def _required_string(raw: Mapping[str, Any], field_name: str) -> str:
        value = raw.get(field_name)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"invalid revocation field: {field_name}")
        return value.strip()

    @classmethod
    def _identifier(cls, raw: Mapping[str, Any], field_name: str) -> str:
        value = cls._required_string(raw, field_name)
        if not _IDENTIFIER.fullmatch(value):
            raise ValueError(f"invalid revocation identifier: {field_name}")
        return value

    @staticmethod
    def _identifier_array(raw: Any, *, allow_empty: bool) -> tuple[str, ...]:
        if not isinstance(raw, list) or (not raw and not allow_empty):
            raise ValueError("invalid revocation identifier list")
        if any(not isinstance(value, str) or not _IDENTIFIER.fullmatch(value) for value in raw):
            raise ValueError("invalid revocation identifier")
        if len(set(raw)) != len(raw):
            raise ValueError("duplicate revocation identifier")
        return tuple(raw)

    @staticmethod
    def _timestamp(raw: Mapping[str, Any], field_name: str) -> datetime:
        value = raw.get(field_name)
        if not isinstance(value, str) or not value.endswith("Z"):
            raise ValueError("revocation timestamp must be UTC")
        try:
            return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
        except ValueError:
            raise ValueError("invalid revocation timestamp") from None

    @staticmethod
    def _state_error_message(code: PolicyValidationCode) -> str:
        return {
            PolicyValidationCode.REVOCATION_REPLAY: "older revocation state was rejected",
            PolicyValidationCode.REVOCATION_VERSION_CONFLICT: "revocation version conflicts with persisted state",
            PolicyValidationCode.REVOCATION_DUPLICATE: "duplicate revocation state was rejected",
            PolicyValidationCode.SIGNING_KEY_REVOKED: "revocation signer was already revoked",
            PolicyValidationCode.POLICY_STATE_UNAVAILABLE: "persistent revocation state is unavailable",
        }.get(code, "revocation state was rejected")

    @staticmethod
    def _failure(
        code: PolicyValidationCode, message: str
    ) -> RevocationValidationResult:
        LOGGER.warning("Signed revocation state rejected (reason=%s)", code.value)
        return RevocationValidationResult(False, code, message)


class _RevocationFailure(ValueError):
    def __init__(self, code: PolicyValidationCode, message: str) -> None:
        super().__init__(message)
        self.code = code
