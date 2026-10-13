"""Offline verification for signed OS Guard operating policies.

This module deliberately has no API or HARDEN integration.  A successfully
verified policy is still not authorized for operational use until persistent
anti-rollback state, revocation synchronization, and a trusted clock exist.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Mapping, Protocol, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from .models import Action, OsInfo

if TYPE_CHECKING:
    from .trusted_time import TrustedTimeProvider

POLICY_SCHEMA_VERSION = "1.0"
SIGNATURE_ALGORITHM = "Ed25519"
SAFE_INTEGER_LIMIT = 9_007_199_254_740_991
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_UCODE = re.compile(r"^U-(0[1-9]|[1-5][0-9]|6[0-7])$")
_HOSTNAME = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)
LOGGER = logging.getLogger(__name__)


class PolicyValidationCode(str, Enum):
    VALID = "VALID"
    MALFORMED_JSON = "MALFORMED_JSON"
    DUPLICATE_JSON_KEY = "DUPLICATE_JSON_KEY"
    UNSUPPORTED_SCHEMA_VERSION = "UNSUPPORTED_SCHEMA_VERSION"
    INVALID_ENVELOPE = "INVALID_ENVELOPE"
    UNSUPPORTED_SIGNATURE_ALGORITHM = "UNSUPPORTED_SIGNATURE_ALGORITHM"
    UNTRUSTED_SIGNING_KEY = "UNTRUSTED_SIGNING_KEY"
    ISSUER_MISMATCH = "ISSUER_MISMATCH"
    SIGNING_KEY_REVOKED = "SIGNING_KEY_REVOKED"
    INVALID_HASH = "INVALID_HASH"
    HASH_MISMATCH = "HASH_MISMATCH"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    INVALID_PAYLOAD = "INVALID_PAYLOAD"
    UNSUPPORTED_POLICY_TYPE = "UNSUPPORTED_POLICY_TYPE"
    INVALID_POLICY_VALUES = "INVALID_POLICY_VALUES"
    UNTRUSTED_CLOCK = "UNTRUSTED_CLOCK"
    POLICY_NOT_YET_VALID = "POLICY_NOT_YET_VALID"
    POLICY_EXPIRED = "POLICY_EXPIRED"
    SERVER_SCOPE_MISMATCH = "SERVER_SCOPE_MISMATCH"
    AGENT_SCOPE_MISMATCH = "AGENT_SCOPE_MISMATCH"
    OS_SCOPE_MISMATCH = "OS_SCOPE_MISMATCH"
    U_CODE_SCOPE_INVALID = "U_CODE_SCOPE_INVALID"
    ACTION_SCOPE_INVALID = "ACTION_SCOPE_INVALID"
    MANIFEST_SCOPE_MISMATCH = "MANIFEST_SCOPE_MISMATCH"
    MODULE_VERSION_SCOPE_MISMATCH = "MODULE_VERSION_SCOPE_MISMATCH"
    POLICY_REVOKED = "POLICY_REVOKED"
    POLICY_DOWNGRADE = "POLICY_DOWNGRADE"
    POLICY_VERSION_CONFLICT = "POLICY_VERSION_CONFLICT"
    POLICY_IDENTITY_MISMATCH = "POLICY_IDENTITY_MISMATCH"
    POLICY_DUPLICATE = "POLICY_DUPLICATE"
    POLICY_STATE_UNAVAILABLE = "POLICY_STATE_UNAVAILABLE"
    POLICY_STATE_CORRUPT = "POLICY_STATE_CORRUPT"
    POLICY_STATE_WRITE_FAILED = "POLICY_STATE_WRITE_FAILED"
    POLICY_STATE_LOCKED = "POLICY_STATE_LOCKED"
    REVOCATION_STATE_UNAVAILABLE = "REVOCATION_STATE_UNAVAILABLE"
    REVOCATION_NOT_YET_VALID = "REVOCATION_NOT_YET_VALID"
    REVOCATION_EXPIRED = "REVOCATION_EXPIRED"
    REVOCATION_REPLAY = "REVOCATION_REPLAY"
    REVOCATION_VERSION_CONFLICT = "REVOCATION_VERSION_CONFLICT"
    REVOCATION_DUPLICATE = "REVOCATION_DUPLICATE"
    INVALID_REVOCATION = "INVALID_REVOCATION"


@dataclass(frozen=True)
class PolicyTarget:
    server_id: str
    agent_ids: tuple[str, ...]
    supported_os: Mapping[str, tuple[str, ...]]
    u_codes: tuple[str, ...]
    actions: tuple[Action, ...]
    manifest_ids: tuple[str, ...]
    module_versions: tuple[str, ...]


@dataclass(frozen=True)
class PolicyPayload:
    policy_id: str
    policy_version: int
    policy_type: str
    issuer_id: str
    approved_by: str
    approved_at: datetime
    issued_at: datetime
    valid_from: datetime
    expires_at: datetime
    target: PolicyTarget
    values: Mapping[str, Any]


@dataclass(frozen=True)
class PolicyEnvelope:
    policy_schema_version: str
    signature_algorithm: str
    signing_key_id: str
    payload_sha256: str
    signature: str
    payload: PolicyPayload


@dataclass(frozen=True)
class PolicyValidationContext:
    server_id: str
    agent_id: str
    os_info: OsInfo
    manifest_id: str
    module_version: str
    allowed_u_codes: frozenset[str]
    allowed_actions: frozenset[Action]
    clock_trusted: bool = False


@dataclass(frozen=True)
class PolicyValidationResult:
    valid: bool
    code: PolicyValidationCode
    message: str
    policy: PolicyEnvelope | None = None
    policy_hash: str | None = None
    operational_use_allowed: bool = False
    operational_limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class RevokedPolicy:
    policy_id: str
    policy_version: int | None
    policy_hash: str | None


@dataclass(frozen=True)
class RevocationState:
    revocation_list_id: str
    revocation_version: int
    revocation_hash: str
    issuer_id: str
    server_id: str
    signing_key_id: str
    issued_at: datetime
    valid_from: datetime
    expires_at: datetime
    revoked_policies: tuple[RevokedPolicy, ...]
    revoked_signing_key_ids: tuple[str, ...]


@dataclass(frozen=True)
class RevocationValidationResult:
    valid: bool
    code: PolicyValidationCode
    message: str
    state: RevocationState | None = None


class PolicyVersionStore(Protocol):
    """Anti-rollback state. Production use requires a persistent implementation."""

    @property
    def persistent(self) -> bool: ...

    @property
    def revocation_persistent(self) -> bool: ...

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
    ) -> PolicyValidationCode | None: ...

    def record_revocation(
        self, state: RevocationState, *, verified_at: datetime
    ) -> PolicyValidationCode | None: ...

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
    ) -> PolicyValidationCode | None: ...


class InMemoryPolicyVersionStore:
    """Process-local replay protection for tests and first-stage validation only."""

    persistent = False
    revocation_persistent = False

    def __init__(self) -> None:
        self._versions: dict[str, tuple[int, str]] = {}

    def check_and_record(
        self,
        policy_id: str,
        policy_version: int,
        policy_hash: str,
        **_: Any,
    ) -> PolicyValidationCode | None:
        previous = self._versions.get(policy_id)
        if previous is not None:
            previous_version, previous_hash = previous
            if policy_version < previous_version:
                return PolicyValidationCode.POLICY_DOWNGRADE
            if policy_version == previous_version:
                if policy_hash != previous_hash:
                    return PolicyValidationCode.POLICY_VERSION_CONFLICT
                return PolicyValidationCode.POLICY_DUPLICATE
        self._versions[policy_id] = (policy_version, policy_hash)
        return None

    def record_revocation(
        self, state: RevocationState, *, verified_at: datetime
    ) -> PolicyValidationCode | None:
        del state, verified_at
        return PolicyValidationCode.POLICY_STATE_UNAVAILABLE

    def check_execution_binding(self, **_: Any) -> PolicyValidationCode | None:
        return PolicyValidationCode.POLICY_STATE_UNAVAILABLE


class TrustedPolicyKeyStore:
    """Trusted Ed25519 keys provisioned locally, never obtained from policy JSON."""

    def __init__(
        self,
        keys: Mapping[str, Ed25519PublicKey],
        issuers_by_key: Mapping[str, frozenset[str]],
        usages_by_key: Mapping[str, frozenset[str]] | None = None,
    ) -> None:
        self._keys = dict(keys)
        self._issuers_by_key = dict(issuers_by_key)
        self._usages_by_key = (
            dict(usages_by_key)
            if usages_by_key is not None
            else {key_id: frozenset({"policy"}) for key_id in keys}
        )
        if set(self._keys) != set(self._issuers_by_key):
            raise ValueError("every trusted policy key must have an issuer binding")
        if set(self._keys) != set(self._usages_by_key):
            raise ValueError("every trusted policy key must have an allowed usage")
        if any(not issuers for issuers in self._issuers_by_key.values()):
            raise ValueError("trusted policy key issuer binding must not be empty")
        if any(
            not usages
            or not usages.issubset({"policy", "revocation", "time", "grant"})
            for usages in self._usages_by_key.values()
        ):
            raise ValueError("trusted policy key usage is invalid")

    def get(self, key_id: str) -> Ed25519PublicKey | None:
        return self._keys.get(key_id)

    def issuer_is_allowed(self, key_id: str, issuer_id: str) -> bool:
        return issuer_id in self._issuers_by_key.get(key_id, frozenset())

    def usage_is_allowed(self, key_id: str, usage: str) -> bool:
        return usage in self._usages_by_key.get(key_id, frozenset())

    @classmethod
    def from_directory(
        cls,
        directory: Path,
        issuers_by_key: Mapping[str, frozenset[str]],
        usages_by_key: Mapping[str, frozenset[str]] | None = None,
    ) -> "TrustedPolicyKeyStore":
        keys: dict[str, Ed25519PublicKey] = {}
        try:
            entries = tuple(directory.iterdir())
        except OSError as exc:
            raise ValueError("trusted policy key directory is unavailable") from exc
        for path in entries:
            if path.suffix != ".pem" or path.is_symlink() or not path.is_file():
                continue
            key_id = path.stem
            if not _IDENTIFIER.fullmatch(key_id):
                raise ValueError("trusted policy key filename is invalid")
            try:
                loaded = load_pem_public_key(path.read_bytes())
            except (OSError, ValueError, TypeError) as exc:
                raise ValueError("trusted policy public key is invalid") from exc
            if not isinstance(loaded, Ed25519PublicKey):
                raise ValueError("trusted policy key is not Ed25519")
            if key_id in keys:
                raise ValueError("duplicate trusted policy key ID")
            keys[key_id] = loaded
        return cls(keys, issuers_by_key, usages_by_key)


class _PolicyFailure(ValueError):
    def __init__(self, code: PolicyValidationCode, message: str) -> None:
        super().__init__(message)
        self.code = code


class _DuplicateKey(ValueError):
    pass


class PolicyStateError(RuntimeError):
    """Raised when anti-rollback state cannot be trusted or safely updated."""

    def __init__(self, code: PolicyValidationCode, message: str) -> None:
        super().__init__(message)
        self.code = code


def load_strict_json(document: str | bytes) -> Any:
    """Parse JSON while rejecting duplicate keys and non-standard numbers."""

    def pairs_hook(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _DuplicateKey(key)
            result[key] = value
        return result

    def reject_constant(_: str) -> None:
        raise ValueError("non-finite JSON number")

    return json.loads(
        document,
        object_pairs_hook=pairs_hook,
        parse_constant=reject_constant,
    )


def canonicalize_json(value: Any) -> bytes:
    """Return RFC 8785 canonical bytes for the policy data domain.

    Policies intentionally reject floating-point numbers.  Integers are limited
    to the interoperable I-JSON range, so their JSON spelling is already the
    ECMAScript/RFC 8785 spelling.
    """

    def serialize(item: Any) -> str:
        if item is None:
            return "null"
        if item is True:
            return "true"
        if item is False:
            return "false"
        if isinstance(item, int):
            if abs(item) > SAFE_INTEGER_LIMIT:
                raise ValueError("integer is outside the I-JSON safe range")
            return str(item)
        if isinstance(item, float):
            raise ValueError("floating-point policy values are not supported")
        if isinstance(item, str):
            if any(0xD800 <= ord(character) <= 0xDFFF for character in item):
                raise ValueError("lone Unicode surrogate is not valid I-JSON")
            return json.dumps(item, ensure_ascii=False, separators=(",", ":"))
        if isinstance(item, list):
            return "[" + ",".join(serialize(entry) for entry in item) + "]"
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise ValueError("JSON object keys must be strings")
            ordered_keys = sorted(item, key=lambda key: key.encode("utf-16-be"))
            return "{" + ",".join(
                f"{serialize(key)}:{serialize(item[key])}" for key in ordered_keys
            ) + "}"
        raise ValueError("unsupported JSON value")

    return serialize(value).encode("utf-8")


class PolicyVerifier:
    _ENVELOPE_FIELDS = frozenset(
        {
            "policy_schema_version",
            "signature_algorithm",
            "signing_key_id",
            "payload_sha256",
            "signature",
            "payload",
        }
    )
    _PAYLOAD_FIELDS = frozenset(
        {
            "policy_id",
            "policy_version",
            "policy_type",
            "issuer_id",
            "approved_by",
            "approved_at",
            "issued_at",
            "valid_from",
            "expires_at",
            "target",
            "values",
        }
    )
    _TARGET_FIELDS = frozenset(
        {
            "server_id",
            "agent_ids",
            "supported_os",
            "u_codes",
            "actions",
            "manifest_ids",
            "module_versions",
        }
    )
    _POLICY_U_CODES = {
        "SNMP_ACCESS_CONTROL": frozenset({"U-61"}),
        "LOGIN_WARNING_MESSAGE": frozenset({"U-62"}),
        "SECURITY_PATCH_MANAGEMENT": frozenset({"U-64"}),
        "NTP_TIME_SYNCHRONIZATION": frozenset({"U-65"}),
        "SYSTEM_LOGGING": frozenset({"U-66"}),
    }

    def __init__(
        self,
        trusted_keys: TrustedPolicyKeyStore,
        version_store: PolicyVersionStore,
        *,
        clock: Callable[[], datetime] | None = None,
        revoked_policy_ids: frozenset[str] = frozenset(),
        revoked_policy_hashes: frozenset[str] = frozenset(),
        revoked_key_ids: frozenset[str] = frozenset(),
        revocation_state_current: bool = False,
        require_current_revocation: bool = False,
        trusted_time_provider: TrustedTimeProvider | None = None,
    ) -> None:
        self._trusted_keys = trusted_keys
        self._version_store = version_store
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._revoked_policy_ids = revoked_policy_ids
        self._revoked_policy_hashes = revoked_policy_hashes
        self._revoked_key_ids = revoked_key_ids
        self._revocation_state_current = revocation_state_current
        self._require_current_revocation = require_current_revocation
        self._trusted_time_provider = trusted_time_provider

    def validate(
        self,
        document: str | bytes,
        context: PolicyValidationContext,
        *,
        accept_duplicate: bool = False,
        expected_policy_id: str | None = None,
        expected_policy_version: int | None = None,
    ) -> PolicyValidationResult:
        try:
            raw = load_strict_json(document)
        except _DuplicateKey:
            return self._failure(
                PolicyValidationCode.DUPLICATE_JSON_KEY,
                "policy JSON contains a duplicate object key",
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
            return self._failure(
                PolicyValidationCode.MALFORMED_JSON, "policy document is invalid JSON"
            )

        try:
            envelope, policy_hash = self._verify_envelope(raw)
            if (
                expected_policy_id is not None
                and envelope.payload.policy_id != expected_policy_id
            ) or (
                expected_policy_version is not None
                and envelope.payload.policy_version != expected_policy_version
            ):
                raise _PolicyFailure(
                    PolicyValidationCode.POLICY_IDENTITY_MISMATCH,
                    "policy identity differs from the requested policy",
                )
            validation_time = self._validate_context(envelope, policy_hash, context)
            version_error = self._version_store.check_and_record(
                envelope.payload.policy_id,
                envelope.payload.policy_version,
                policy_hash,
                issuer_id=envelope.payload.issuer_id,
                server_id=context.server_id,
                agent_id=context.agent_id,
                signing_key_id=envelope.signing_key_id,
                verified_at=validation_time,
                require_current_revocation=self._require_current_revocation,
            )
            if version_error is not None and not (
                accept_duplicate
                and version_error is PolicyValidationCode.POLICY_DUPLICATE
            ):
                raise _PolicyFailure(version_error, self._version_message(version_error))
        except _PolicyFailure as exc:
            return self._failure(exc.code, str(exc))
        except PolicyStateError as exc:
            LOGGER.error("Operating policy state rejected (reason=%s)", exc.code.value)
            return self._failure(exc.code, str(exc))
        except (ValueError, TypeError):
            return self._failure(
                PolicyValidationCode.INVALID_PAYLOAD,
                "policy payload could not be validated",
            )

        limitations: list[str] = []
        if not self._version_store.persistent:
            limitations.append("persistent anti-rollback state is not configured")
        if not self._revocation_state_current:
            limitations.append("policy and signing-key revocation state is not current")
        if not self._version_store.revocation_persistent:
            limitations.append("verified revocation state is not persisted")
        # Reserved for a later execution grant verifier and API integration.
        limitations.append("HARDEN execution authorization is not implemented")
        result = PolicyValidationResult(
            valid=True,
            code=PolicyValidationCode.VALID,
            message="policy signature and scope are valid",
            policy=envelope,
            policy_hash=policy_hash,
            operational_use_allowed=False,
            operational_limitations=tuple(limitations),
        )
        LOGGER.info(
            "Operating policy accepted for validation only (policy_id=%s, version=%s)",
            envelope.payload.policy_id,
            envelope.payload.policy_version,
        )
        return result

    def _verify_envelope(
        self, raw: Any
    ) -> tuple[PolicyEnvelope, str]:
        if not isinstance(raw, dict) or frozenset(raw) != self._ENVELOPE_FIELDS:
            raise _PolicyFailure(
                PolicyValidationCode.INVALID_ENVELOPE,
                "policy envelope fields are invalid",
            )
        schema_version = self._required_string(raw, "policy_schema_version")
        if schema_version != POLICY_SCHEMA_VERSION:
            raise _PolicyFailure(
                PolicyValidationCode.UNSUPPORTED_SCHEMA_VERSION,
                "policy schema version is not supported",
            )
        algorithm = self._required_string(raw, "signature_algorithm")
        if algorithm != SIGNATURE_ALGORITHM:
            raise _PolicyFailure(
                PolicyValidationCode.UNSUPPORTED_SIGNATURE_ALGORITHM,
                "policy signature algorithm is not allowed",
            )
        key_id = self._identifier(raw, "signing_key_id")
        if key_id in self._revoked_key_ids:
            raise _PolicyFailure(
                PolicyValidationCode.SIGNING_KEY_REVOKED,
                "policy signing key has been revoked",
            )
        key = self._trusted_keys.get(key_id)
        if key is None or not self._trusted_keys.usage_is_allowed(key_id, "policy"):
            raise _PolicyFailure(
                PolicyValidationCode.UNTRUSTED_SIGNING_KEY,
                "policy signing key is not locally trusted",
            )
        payload_raw = raw.get("payload")
        if not isinstance(payload_raw, dict):
            raise _PolicyFailure(
                PolicyValidationCode.INVALID_PAYLOAD, "policy payload must be an object"
            )
        try:
            payload_bytes = canonicalize_json(payload_raw)
        except ValueError:
            raise _PolicyFailure(
                PolicyValidationCode.INVALID_PAYLOAD,
                "policy payload is outside the supported RFC 8785 data domain",
            ) from None
        declared_hash = self._required_string(raw, "payload_sha256").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", declared_hash):
            raise _PolicyFailure(
                PolicyValidationCode.INVALID_HASH, "policy payload hash is invalid"
            )
        actual_hash = hashlib.sha256(payload_bytes).hexdigest()
        if declared_hash != actual_hash:
            raise _PolicyFailure(
                PolicyValidationCode.HASH_MISMATCH,
                "policy payload hash does not match canonical payload",
            )
        signed_fields = {
            "policy_schema_version": schema_version,
            "signature_algorithm": algorithm,
            "signing_key_id": key_id,
            "payload_sha256": declared_hash,
            "payload": payload_raw,
        }
        try:
            signature = base64.b64decode(
                self._required_string(raw, "signature"), validate=True
            )
        except (ValueError, TypeError):
            raise _PolicyFailure(
                PolicyValidationCode.INVALID_SIGNATURE,
                "policy signature encoding is invalid",
            ) from None
        try:
            key.verify(signature, canonicalize_json(signed_fields))
        except InvalidSignature:
            raise _PolicyFailure(
                PolicyValidationCode.INVALID_SIGNATURE,
                "policy signature verification failed",
            ) from None
        payload = self._parse_payload(payload_raw)
        if not self._trusted_keys.issuer_is_allowed(key_id, payload.issuer_id):
            raise _PolicyFailure(
                PolicyValidationCode.ISSUER_MISMATCH,
                "policy issuer is not authorized for the signing key",
            )
        envelope = PolicyEnvelope(
            policy_schema_version=schema_version,
            signature_algorithm=algorithm,
            signing_key_id=key_id,
            payload_sha256=declared_hash,
            signature=self._required_string(raw, "signature"),
            payload=payload,
        )
        return envelope, actual_hash

    def _parse_payload(self, raw: Mapping[str, Any]) -> PolicyPayload:
        if frozenset(raw) != self._PAYLOAD_FIELDS:
            raise _PolicyFailure(
                PolicyValidationCode.INVALID_PAYLOAD, "policy payload fields are invalid"
            )
        policy_id = self._identifier(raw, "policy_id")
        policy_version = raw.get("policy_version")
        if (
            not isinstance(policy_version, int)
            or isinstance(policy_version, bool)
            or policy_version < 1
            or policy_version > SAFE_INTEGER_LIMIT
        ):
            raise _PolicyFailure(
                PolicyValidationCode.INVALID_PAYLOAD,
                "policy version must be a positive integer",
            )
        policy_type = self._required_string(raw, "policy_type")
        if policy_type not in self._POLICY_U_CODES:
            raise _PolicyFailure(
                PolicyValidationCode.UNSUPPORTED_POLICY_TYPE,
                "policy type is not supported",
            )
        target_raw = raw.get("target")
        if not isinstance(target_raw, dict) or frozenset(target_raw) != self._TARGET_FIELDS:
            raise _PolicyFailure(
                PolicyValidationCode.INVALID_PAYLOAD, "policy target fields are invalid"
            )
        target = self._parse_target(target_raw)
        if frozenset(target.u_codes) != self._POLICY_U_CODES[policy_type]:
            raise _PolicyFailure(
                PolicyValidationCode.U_CODE_SCOPE_INVALID,
                "policy type and U-code scope do not match",
            )
        values = raw.get("values")
        if not isinstance(values, dict):
            raise _PolicyFailure(
                PolicyValidationCode.INVALID_POLICY_VALUES,
                "policy values must be an object",
            )
        self._validate_policy_values(policy_type, values)
        valid_from = self._timestamp(raw, "valid_from")
        expires_at = self._timestamp(raw, "expires_at")
        issued_at = self._timestamp(raw, "issued_at")
        approved_at = self._timestamp(raw, "approved_at")
        if not (approved_at <= issued_at <= expires_at) or valid_from >= expires_at:
            raise _PolicyFailure(
                PolicyValidationCode.INVALID_PAYLOAD,
                "policy lifecycle timestamps are inconsistent",
            )
        return PolicyPayload(
            policy_id=policy_id,
            policy_version=policy_version,
            policy_type=policy_type,
            issuer_id=self._identifier(raw, "issuer_id"),
            approved_by=self._identifier(raw, "approved_by"),
            approved_at=approved_at,
            issued_at=issued_at,
            valid_from=valid_from,
            expires_at=expires_at,
            target=target,
            values=dict(values),
        )

    def _parse_target(self, raw: Mapping[str, Any]) -> PolicyTarget:
        supported_os = raw.get("supported_os")
        if not isinstance(supported_os, dict) or not supported_os:
            raise _PolicyFailure(
                PolicyValidationCode.INVALID_PAYLOAD, "supported_os is invalid"
            )
        normalized_os: dict[str, tuple[str, ...]] = {}
        allowed_os_versions = {"rocky": {"9", "10"}, "ubuntu": {"22", "24"}}
        for distro, versions in supported_os.items():
            if distro not in {"rocky", "ubuntu"}:
                raise _PolicyFailure(
                    PolicyValidationCode.INVALID_PAYLOAD,
                    "policy contains an unsupported OS family",
                )
            normalized_versions = self._string_tuple(versions, "supported_os")
            if not set(normalized_versions).issubset(allowed_os_versions[distro]):
                raise _PolicyFailure(
                    PolicyValidationCode.INVALID_PAYLOAD,
                    "policy contains an unsupported OS version",
                )
            normalized_os[distro] = normalized_versions
        try:
            actions = tuple(Action(action) for action in self._string_tuple(raw.get("actions"), "actions"))
        except ValueError:
            raise _PolicyFailure(
                PolicyValidationCode.ACTION_SCOPE_INVALID,
                "policy contains an unknown action",
            ) from None
        if not actions or any(action is not Action.HARDEN for action in actions):
            raise _PolicyFailure(
                PolicyValidationCode.ACTION_SCOPE_INVALID,
                "operating policy action scope must be HARDEN",
            )
        u_codes = self._string_tuple(raw.get("u_codes"), "u_codes")
        if any(not _UCODE.fullmatch(code) for code in u_codes):
            raise _PolicyFailure(
                PolicyValidationCode.U_CODE_SCOPE_INVALID, "policy U-code is invalid"
            )
        return PolicyTarget(
            server_id=self._identifier(raw, "server_id"),
            agent_ids=self._identifier_tuple(raw.get("agent_ids"), "agent_ids"),
            supported_os=normalized_os,
            u_codes=u_codes,
            actions=actions,
            manifest_ids=self._identifier_tuple(raw.get("manifest_ids"), "manifest_ids"),
            module_versions=self._identifier_tuple(raw.get("module_versions"), "module_versions"),
        )

    def _validate_context(
        self,
        envelope: PolicyEnvelope,
        policy_hash: str,
        context: PolicyValidationContext,
    ) -> datetime:
        payload = envelope.payload
        target = payload.target
        if payload.policy_id in self._revoked_policy_ids or policy_hash in self._revoked_policy_hashes:
            raise _PolicyFailure(
                PolicyValidationCode.POLICY_REVOKED, "policy has been revoked"
            )
        if self._trusted_time_provider is not None:
            try:
                trusted_time = self._trusted_time_provider.current_time()
            except (RuntimeError, OSError, ValueError):
                raise _PolicyFailure(
                    PolicyValidationCode.UNTRUSTED_CLOCK,
                    "authenticated Agent time is unavailable",
                ) from None
            if not trusted_time.authenticated:
                raise _PolicyFailure(
                    PolicyValidationCode.UNTRUSTED_CLOCK,
                    "authenticated Agent time is unavailable",
                )
            now = trusted_time.value
        else:
            if not context.clock_trusted:
                raise _PolicyFailure(
                    PolicyValidationCode.UNTRUSTED_CLOCK,
                    "Agent time is not trusted for policy validity checks",
                )
            now = self._clock()
        if now.tzinfo is None:
            raise _PolicyFailure(
                PolicyValidationCode.UNTRUSTED_CLOCK,
                "policy validation clock must include a timezone",
            )
        now = now.astimezone(timezone.utc)
        if now < payload.valid_from:
            raise _PolicyFailure(
                PolicyValidationCode.POLICY_NOT_YET_VALID,
                "policy validity period has not started",
            )
        if now >= payload.expires_at:
            raise _PolicyFailure(
                PolicyValidationCode.POLICY_EXPIRED, "policy has expired"
            )
        if target.server_id != context.server_id:
            raise _PolicyFailure(
                PolicyValidationCode.SERVER_SCOPE_MISMATCH,
                "policy is not scoped to this server",
            )
        if context.agent_id not in target.agent_ids:
            raise _PolicyFailure(
                PolicyValidationCode.AGENT_SCOPE_MISMATCH,
                "policy is not scoped to this Agent",
            )
        if not context.os_info.supported:
            raise _PolicyFailure(
                PolicyValidationCode.OS_SCOPE_MISMATCH,
                "local OS is not supported for operating policy use",
            )
        major_version = context.os_info.version_id.split(".", 1)[0]
        if major_version not in target.supported_os.get(context.os_info.distro, ()):
            raise _PolicyFailure(
                PolicyValidationCode.OS_SCOPE_MISMATCH,
                "policy is not scoped to the detected OS",
            )
        if not set(target.u_codes).issubset(context.allowed_u_codes):
            raise _PolicyFailure(
                PolicyValidationCode.U_CODE_SCOPE_INVALID,
                "policy contains a U-code outside the local allowlist",
            )
        if not set(target.actions).issubset(context.allowed_actions):
            raise _PolicyFailure(
                PolicyValidationCode.ACTION_SCOPE_INVALID,
                "policy contains an action outside the local allowlist",
            )
        if context.manifest_id not in target.manifest_ids:
            raise _PolicyFailure(
                PolicyValidationCode.MANIFEST_SCOPE_MISMATCH,
                "policy is not scoped to the local manifest",
            )
        if context.module_version not in target.module_versions:
            raise _PolicyFailure(
                PolicyValidationCode.MODULE_VERSION_SCOPE_MISMATCH,
                "policy is not scoped to the local module version",
            )
        return now

    def _validate_policy_values(self, policy_type: str, values: Mapping[str, Any]) -> None:
        validators = {
            "SNMP_ACCESS_CONTROL": self._validate_snmp_values,
            "LOGIN_WARNING_MESSAGE": self._validate_banner_values,
            "SECURITY_PATCH_MANAGEMENT": self._validate_patch_values,
            "NTP_TIME_SYNCHRONIZATION": self._validate_ntp_values,
            "SYSTEM_LOGGING": self._validate_logging_values,
        }
        try:
            validators[policy_type](values)
        except _PolicyFailure as exc:
            if exc.code is PolicyValidationCode.INVALID_PAYLOAD:
                raise _PolicyFailure(
                    PolicyValidationCode.INVALID_POLICY_VALUES, str(exc)
                ) from None
            raise

    def _validate_snmp_values(self, values: Mapping[str, Any]) -> None:
        self._exact_fields(values, {"approved_management_networks"})
        networks = self._string_tuple(values.get("approved_management_networks"), "approved_management_networks")
        try:
            for network in networks:
                ipaddress.ip_network(network, strict=True)
        except ValueError:
            self._invalid_values("approved SNMP management network is invalid")

    def _validate_banner_values(self, values: Mapping[str, Any]) -> None:
        self._exact_fields(values, {"approved_banner_text"})
        banner = values.get("approved_banner_text")
        if not isinstance(banner, str) or not banner.strip() or len(banner) > 4096 or "\x00" in banner:
            self._invalid_values("approved login banner is invalid")

    def _validate_patch_values(self, values: Mapping[str, Any]) -> None:
        self._exact_fields(
            values,
            {"change_window_start", "change_window_end", "reboot_approved", "service_impact_approved"},
        )
        start = self._value_timestamp(values, "change_window_start")
        end = self._value_timestamp(values, "change_window_end")
        if start >= end:
            self._invalid_values("patch change window is invalid")
        for field_name in ("reboot_approved", "service_impact_approved"):
            if not isinstance(values.get(field_name), bool):
                self._invalid_values("patch approval values must be boolean")

    def _validate_ntp_values(self, values: Mapping[str, Any]) -> None:
        self._exact_fields(values, {"approved_time_sources"})
        sources = self._string_tuple(values.get("approved_time_sources"), "approved_time_sources")
        for source in sources:
            try:
                ipaddress.ip_address(source)
            except ValueError:
                if not _HOSTNAME.fullmatch(source):
                    self._invalid_values("approved time source is invalid")

    def _validate_logging_values(self, values: Mapping[str, Any]) -> None:
        self._exact_fields(
            values,
            {"retention_days", "remote_forwarding_required", "collector_refs"},
        )
        retention_days = values.get("retention_days")
        if (
            not isinstance(retention_days, int)
            or isinstance(retention_days, bool)
            or not 1 <= retention_days <= 3650
        ):
            self._invalid_values("log retention_days is invalid")
        if not isinstance(values.get("remote_forwarding_required"), bool):
            self._invalid_values("remote_forwarding_required must be boolean")
        self._identifier_tuple(values.get("collector_refs"), "collector_refs", allow_empty=True)

    @staticmethod
    def _exact_fields(values: Mapping[str, Any], expected: set[str]) -> None:
        if set(values) != expected:
            PolicyVerifier._invalid_values("policy value fields are invalid")

    @staticmethod
    def _invalid_values(message: str) -> None:
        raise _PolicyFailure(PolicyValidationCode.INVALID_POLICY_VALUES, message)

    @staticmethod
    def _required_string(raw: Mapping[str, Any], field_name: str) -> str:
        value = raw.get(field_name)
        if not isinstance(value, str) or not value.strip():
            raise _PolicyFailure(
                PolicyValidationCode.INVALID_PAYLOAD,
                f"policy field '{field_name}' is invalid",
            )
        return value.strip()

    @classmethod
    def _identifier(cls, raw: Mapping[str, Any], field_name: str) -> str:
        value = cls._required_string(raw, field_name)
        if not _IDENTIFIER.fullmatch(value):
            raise _PolicyFailure(
                PolicyValidationCode.INVALID_PAYLOAD,
                f"policy field '{field_name}' is not a valid identifier",
            )
        return value

    @staticmethod
    def _string_tuple(value: Any, field_name: str) -> tuple[str, ...]:
        if not isinstance(value, list) or not value:
            raise _PolicyFailure(
                PolicyValidationCode.INVALID_PAYLOAD,
                f"policy field '{field_name}' must be a non-empty array",
            )
        if any(not isinstance(item, str) or not item.strip() for item in value):
            raise _PolicyFailure(
                PolicyValidationCode.INVALID_PAYLOAD,
                f"policy field '{field_name}' contains an invalid string",
            )
        normalized = tuple(item.strip() for item in value)
        if len(set(normalized)) != len(normalized):
            raise _PolicyFailure(
                PolicyValidationCode.INVALID_PAYLOAD,
                f"policy field '{field_name}' contains duplicates",
            )
        return normalized

    @classmethod
    def _identifier_tuple(
        cls, value: Any, field_name: str, *, allow_empty: bool = False
    ) -> tuple[str, ...]:
        if allow_empty and value == []:
            return ()
        result = cls._string_tuple(value, field_name)
        if any(not _IDENTIFIER.fullmatch(item) for item in result):
            raise _PolicyFailure(
                PolicyValidationCode.INVALID_PAYLOAD,
                f"policy field '{field_name}' contains an invalid identifier",
            )
        return result

    @classmethod
    def _timestamp(cls, raw: Mapping[str, Any], field_name: str) -> datetime:
        return cls._parse_timestamp(cls._required_string(raw, field_name), field_name)

    @classmethod
    def _value_timestamp(cls, raw: Mapping[str, Any], field_name: str) -> datetime:
        value = raw.get(field_name)
        if not isinstance(value, str):
            cls._invalid_values(f"policy value '{field_name}' is invalid")
        try:
            return cls._parse_timestamp(value, field_name)
        except _PolicyFailure:
            cls._invalid_values(f"policy value '{field_name}' is invalid")
        raise AssertionError("unreachable")

    @staticmethod
    def _parse_timestamp(value: str, field_name: str) -> datetime:
        if not value.endswith("Z"):
            raise _PolicyFailure(
                PolicyValidationCode.INVALID_PAYLOAD,
                f"policy timestamp '{field_name}' must be UTC",
            )
        try:
            parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        except ValueError:
            raise _PolicyFailure(
                PolicyValidationCode.INVALID_PAYLOAD,
                f"policy timestamp '{field_name}' is invalid",
            ) from None
        if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
            raise _PolicyFailure(
                PolicyValidationCode.INVALID_PAYLOAD,
                f"policy timestamp '{field_name}' must be UTC",
            )
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _version_message(code: PolicyValidationCode) -> str:
        return {
            PolicyValidationCode.POLICY_DOWNGRADE: "policy version downgrade was rejected",
            PolicyValidationCode.POLICY_VERSION_CONFLICT: "policy ID and version have a conflicting hash",
            PolicyValidationCode.POLICY_DUPLICATE: "duplicate policy was rejected",
            PolicyValidationCode.POLICY_REVOKED: "policy has been revoked",
            PolicyValidationCode.SIGNING_KEY_REVOKED: "policy signing key has been revoked",
            PolicyValidationCode.REVOCATION_STATE_UNAVAILABLE: "current revocation state is unavailable",
            PolicyValidationCode.REVOCATION_NOT_YET_VALID: "revocation state is not yet valid",
            PolicyValidationCode.REVOCATION_EXPIRED: "revocation state has expired",
        }.get(code, "policy state validation failed")

    @staticmethod
    def _failure(code: PolicyValidationCode, message: str) -> PolicyValidationResult:
        LOGGER.warning("Operating policy rejected (reason=%s)", code.value)
        return PolicyValidationResult(False, code, message)
