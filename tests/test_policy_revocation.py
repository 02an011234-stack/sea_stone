from __future__ import annotations

import base64
import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from os_guard_agent.models import Action, OsInfo
from os_guard_agent.policy import (
    PolicyValidationCode,
    PolicyValidationContext,
    PolicyVerifier,
    TrustedPolicyKeyStore,
    canonicalize_json,
)
from os_guard_agent.policy_revocation import SignedRevocationVerifier
from os_guard_agent.policy_store import PersistentPolicyVersionStore


NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def signing_material():
    policy_key = Ed25519PrivateKey.generate()
    revocation_key = Ed25519PrivateKey.generate()
    key_store = TrustedPolicyKeyStore(
        {
            "policy-key": policy_key.public_key(),
            "revocation-key": revocation_key.public_key(),
        },
        {
            "policy-key": frozenset({"central-policy-service"}),
            "revocation-key": frozenset({"central-policy-service"}),
        },
        {
            "policy-key": frozenset({"policy"}),
            "revocation-key": frozenset({"revocation"}),
        },
    )
    return policy_key, revocation_key, key_store


@pytest.fixture
def state_store(tmp_path: Path) -> PersistentPolicyVersionStore:
    store = PersistentPolicyVersionStore(tmp_path / "policy-state.json")
    store.initialize()
    return store


@pytest.fixture
def context() -> PolicyValidationContext:
    return PolicyValidationContext(
        server_id="server-1",
        agent_id="agent-1",
        os_info=OsInfo(
            distro="ubuntu",
            version="Ubuntu 22.04",
            version_id="22.04",
            kernel="test-kernel",
            hostname="test-host",
            architecture="x86_64",
            supported=True,
        ),
        manifest_id="manifest-unix-67-v1",
        module_version="unix-2026.1",
        allowed_u_codes=frozenset({"U-61"}),
        allowed_actions=frozenset({Action.HARDEN}),
        clock_trusted=True,
    )


def policy_payload(version: int = 1) -> dict:
    return {
        "policy_id": "policy-1",
        "policy_version": version,
        "policy_type": "SNMP_ACCESS_CONTROL",
        "issuer_id": "central-policy-service",
        "approved_by": "security-admin-1",
        "approved_at": "2026-01-14T08:00:00Z",
        "issued_at": "2026-01-14T09:00:00Z",
        "valid_from": "2026-01-15T00:00:00Z",
        "expires_at": "2026-02-15T00:00:00Z",
        "target": {
            "server_id": "server-1",
            "agent_ids": ["agent-1"],
            "supported_os": {"ubuntu": ["22", "24"]},
            "u_codes": ["U-61"],
            "actions": ["HARDEN"],
            "manifest_ids": ["manifest-unix-67-v1"],
            "module_versions": ["unix-2026.1"],
        },
        "values": {"approved_management_networks": ["10.0.0.0/8"]},
    }


def sign_policy(private_key: Ed25519PrivateKey, payload: dict) -> tuple[bytes, str]:
    policy_hash = hashlib.sha256(canonicalize_json(payload)).hexdigest()
    signed = {
        "policy_schema_version": "1.0",
        "signature_algorithm": "Ed25519",
        "signing_key_id": "policy-key",
        "payload_sha256": policy_hash,
        "payload": payload,
    }
    envelope = {
        **signed,
        "signature": base64.b64encode(
            private_key.sign(canonicalize_json(signed))
        ).decode("ascii"),
    }
    return json.dumps(envelope).encode(), policy_hash


def revocation_payload(
    *,
    version: int = 1,
    revoked_policies: list[dict] | None = None,
    revoked_keys: list[str] | None = None,
    valid_from: str = "2026-01-15T00:00:00Z",
    expires_at: str = "2026-01-16T00:00:00Z",
) -> dict:
    return {
        "revocation_list_id": "server-1-policy-revocations",
        "revocation_version": version,
        "issuer_id": "central-policy-service",
        "server_id": "server-1",
        "issued_at": "2026-01-14T23:00:00Z",
        "valid_from": valid_from,
        "expires_at": expires_at,
        "revoked_policies": revoked_policies or [],
        "revoked_signing_key_ids": revoked_keys or [],
    }


def sign_revocation(
    private_key: Ed25519PrivateKey,
    payload: dict,
    *,
    key_id: str = "revocation-key",
) -> bytes:
    payload_hash = hashlib.sha256(canonicalize_json(payload)).hexdigest()
    signed = {
        "revocation_schema_version": "1.0",
        "signature_algorithm": "Ed25519",
        "signing_key_id": key_id,
        "payload_sha256": payload_hash,
        "payload": payload,
    }
    envelope = {
        **signed,
        "signature": base64.b64encode(
            private_key.sign(canonicalize_json(signed))
        ).decode("ascii"),
    }
    return json.dumps(envelope).encode()


def revocation_verifier(key_store, store, *, now=NOW):
    return SignedRevocationVerifier(key_store, store, clock=lambda: now)


def policy_verifier(key_store, store, *, now=NOW):
    return PolicyVerifier(
        key_store,
        store,
        clock=lambda: now,
        revocation_state_current=True,
        require_current_revocation=True,
    )


def record_empty_revocation(key, key_store, store, *, version=1, now=NOW):
    document = sign_revocation(key, revocation_payload(version=version))
    return revocation_verifier(key_store, store, now=now).validate_and_record(
        document, server_id="server-1", clock_trusted=True
    )


def test_signed_revocation_state_is_verified_and_persisted(
    signing_material, state_store
) -> None:
    _, revocation_key, key_store = signing_material
    result = record_empty_revocation(revocation_key, key_store, state_store)
    assert result.valid
    summary = state_store.read_summary()["revocation"]
    assert summary["revocation_version"] == 1
    assert summary["issuer_id"] == "central-policy-service"
    assert summary["server_id"] == "server-1"


def test_policy_acceptance_requires_current_revocation_state(
    signing_material, state_store, context
) -> None:
    policy_key, _, key_store = signing_material
    document, _ = sign_policy(policy_key, policy_payload())
    result = policy_verifier(key_store, state_store).validate(document, context)
    assert not result.valid
    assert result.code is PolicyValidationCode.REVOCATION_STATE_UNAVAILABLE


def test_first_policy_acceptance_and_restart_downgrade_block(
    signing_material, state_store, context
) -> None:
    policy_key, revocation_key, key_store = signing_material
    assert record_empty_revocation(revocation_key, key_store, state_store).valid
    version_two, _ = sign_policy(policy_key, policy_payload(version=2))
    assert policy_verifier(key_store, state_store).validate(version_two, context).valid
    restarted = PersistentPolicyVersionStore(state_store.path)
    version_one, _ = sign_policy(policy_key, policy_payload(version=1))
    result = policy_verifier(key_store, restarted).validate(version_one, context)
    assert result.code is PolicyValidationCode.POLICY_DOWNGRADE


def test_same_policy_revalidation_is_explicit_duplicate(
    signing_material, state_store, context
) -> None:
    policy_key, revocation_key, key_store = signing_material
    assert record_empty_revocation(revocation_key, key_store, state_store).valid
    document, _ = sign_policy(policy_key, policy_payload())
    verifier = policy_verifier(key_store, state_store)
    assert verifier.validate(document, context).valid
    assert verifier.validate(document, context).code is PolicyValidationCode.POLICY_DUPLICATE


def test_same_version_changed_payload_is_conflict(
    signing_material, state_store, context
) -> None:
    policy_key, revocation_key, key_store = signing_material
    assert record_empty_revocation(revocation_key, key_store, state_store).valid
    first_payload = policy_payload()
    first, _ = sign_policy(policy_key, first_payload)
    assert policy_verifier(key_store, state_store).validate(first, context).valid
    changed = copy.deepcopy(first_payload)
    changed["approved_by"] = "security-admin-2"
    conflict, _ = sign_policy(policy_key, changed)
    result = policy_verifier(key_store, state_store).validate(conflict, context)
    assert result.code is PolicyValidationCode.POLICY_VERSION_CONFLICT


def test_revoked_policy_id_version_and_hash_is_blocked(
    signing_material, state_store, context
) -> None:
    policy_key, revocation_key, key_store = signing_material
    document, policy_hash = sign_policy(policy_key, policy_payload())
    revoked = [{
        "policy_id": "policy-1",
        "policy_version": 1,
        "policy_hash": policy_hash,
    }]
    revocation = sign_revocation(
        revocation_key, revocation_payload(revoked_policies=revoked)
    )
    assert revocation_verifier(key_store, state_store).validate_and_record(
        revocation, server_id="server-1", clock_trusted=True
    ).valid
    result = policy_verifier(key_store, state_store).validate(document, context)
    assert result.code is PolicyValidationCode.POLICY_REVOKED


def test_revoked_signing_key_blocks_policy(
    signing_material, state_store, context
) -> None:
    policy_key, revocation_key, key_store = signing_material
    revocation = sign_revocation(
        revocation_key, revocation_payload(revoked_keys=["policy-key"])
    )
    assert revocation_verifier(key_store, state_store).validate_and_record(
        revocation, server_id="server-1", clock_trusted=True
    ).valid
    document, _ = sign_policy(policy_key, policy_payload())
    result = policy_verifier(key_store, state_store).validate(document, context)
    assert result.code is PolicyValidationCode.SIGNING_KEY_REVOKED


def test_expired_revocation_document_is_rejected(signing_material, state_store) -> None:
    _, revocation_key, key_store = signing_material
    payload = revocation_payload(expires_at="2026-01-15T12:00:00Z")
    result = revocation_verifier(key_store, state_store).validate_and_record(
        sign_revocation(revocation_key, payload),
        server_id="server-1",
        clock_trusted=True,
    )
    assert result.code is PolicyValidationCode.REVOCATION_EXPIRED


def test_persisted_revocation_expiry_blocks_policy(
    signing_material, state_store, context
) -> None:
    policy_key, revocation_key, key_store = signing_material
    early = datetime(2026, 1, 15, 11, 0, tzinfo=timezone.utc)
    payload = revocation_payload(expires_at="2026-01-15T12:00:00Z")
    assert revocation_verifier(key_store, state_store, now=early).validate_and_record(
        sign_revocation(revocation_key, payload),
        server_id="server-1",
        clock_trusted=True,
    ).valid
    document, _ = sign_policy(policy_key, policy_payload())
    result = policy_verifier(key_store, state_store, now=NOW).validate(document, context)
    assert result.code is PolicyValidationCode.REVOCATION_EXPIRED


def test_invalid_revocation_signature_is_rejected(signing_material, state_store) -> None:
    _, _, key_store = signing_material
    foreign_key = Ed25519PrivateKey.generate()
    document = sign_revocation(foreign_key, revocation_payload())
    result = revocation_verifier(key_store, state_store).validate_and_record(
        document, server_id="server-1", clock_trusted=True
    )
    assert result.code is PolicyValidationCode.INVALID_REVOCATION
    assert state_store.read_summary()["revocation"] is None


def test_policy_signing_key_cannot_sign_revocation_state(
    signing_material, state_store
) -> None:
    policy_key, _, key_store = signing_material
    document = sign_revocation(
        policy_key,
        revocation_payload(),
        key_id="policy-key",
    )
    result = revocation_verifier(key_store, state_store).validate_and_record(
        document, server_id="server-1", clock_trusted=True
    )
    assert result.code is PolicyValidationCode.INVALID_REVOCATION


def test_older_revocation_version_is_replay(signing_material, state_store) -> None:
    _, revocation_key, key_store = signing_material
    assert record_empty_revocation(
        revocation_key, key_store, state_store, version=2
    ).valid
    older = sign_revocation(revocation_key, revocation_payload(version=1))
    result = revocation_verifier(key_store, state_store).validate_and_record(
        older, server_id="server-1", clock_trusted=True
    )
    assert result.code is PolicyValidationCode.REVOCATION_REPLAY


def test_same_revocation_version_different_hash_conflicts(
    signing_material, state_store
) -> None:
    _, revocation_key, key_store = signing_material
    assert record_empty_revocation(revocation_key, key_store, state_store).valid
    changed = revocation_payload(revoked_keys=["policy-key"])
    result = revocation_verifier(key_store, state_store).validate_and_record(
        sign_revocation(revocation_key, changed),
        server_id="server-1",
        clock_trusted=True,
    )
    assert result.code is PolicyValidationCode.REVOCATION_VERSION_CONFLICT


def test_duplicate_revocation_is_rejected(signing_material, state_store) -> None:
    _, revocation_key, key_store = signing_material
    document = sign_revocation(revocation_key, revocation_payload())
    verifier = revocation_verifier(key_store, state_store)
    assert verifier.validate_and_record(
        document, server_id="server-1", clock_trusted=True
    ).valid
    result = verifier.validate_and_record(
        document, server_id="server-1", clock_trusted=True
    )
    assert result.code is PolicyValidationCode.REVOCATION_DUPLICATE


def test_revocation_server_scope_is_enforced(signing_material, state_store) -> None:
    _, revocation_key, key_store = signing_material
    payload = revocation_payload()
    payload["server_id"] = "server-2"
    result = revocation_verifier(key_store, state_store).validate_and_record(
        sign_revocation(revocation_key, payload),
        server_id="server-1",
        clock_trusted=True,
    )
    assert result.code is PolicyValidationCode.INVALID_REVOCATION


def test_revocation_issuer_must_match_trusted_key(signing_material, state_store) -> None:
    _, revocation_key, key_store = signing_material
    payload = revocation_payload()
    payload["issuer_id"] = "untrusted-policy-service"
    result = revocation_verifier(key_store, state_store).validate_and_record(
        sign_revocation(revocation_key, payload),
        server_id="server-1",
        clock_trusted=True,
    )
    assert result.code is PolicyValidationCode.INVALID_REVOCATION


def test_revocation_requires_trusted_clock(signing_material, state_store) -> None:
    _, revocation_key, key_store = signing_material
    result = revocation_verifier(key_store, state_store).validate_and_record(
        sign_revocation(revocation_key, revocation_payload()),
        server_id="server-1",
        clock_trusted=False,
    )
    assert result.code is PolicyValidationCode.UNTRUSTED_CLOCK


def test_corrupt_persistent_state_blocks_policy_validation(
    signing_material, state_store, context
) -> None:
    policy_key, _, key_store = signing_material
    state_store.path.write_text("corrupt", encoding="utf-8")
    document, _ = sign_policy(policy_key, policy_payload())
    result = policy_verifier(key_store, state_store).validate(document, context)
    assert result.code is PolicyValidationCode.POLICY_STATE_CORRUPT


def test_operational_use_remains_disabled(
    signing_material, state_store, context
) -> None:
    policy_key, revocation_key, key_store = signing_material
    assert record_empty_revocation(revocation_key, key_store, state_store).valid
    document, _ = sign_policy(policy_key, policy_payload())
    result = policy_verifier(key_store, state_store).validate(document, context)
    assert result.valid
    assert result.operational_use_allowed is False
    assert "HARDEN execution authorization is not implemented" in result.operational_limitations


def test_rejection_audit_log_does_not_include_document_values(
    signing_material, state_store, context, caplog
) -> None:
    _, _, key_store = signing_material
    marker = "TOP_SECRET_POLICY_VALUE"
    document = json.dumps({"secret": marker}).encode()
    result = policy_verifier(key_store, state_store).validate(document, context)
    assert not result.valid
    assert marker not in caplog.text
