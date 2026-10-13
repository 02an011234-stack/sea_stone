from __future__ import annotations

import base64
import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from os_guard_agent.execution_state import PersistentExecutionStateStore
from os_guard_agent.policy import TrustedPolicyKeyStore, canonicalize_json
from os_guard_agent.trusted_time import (
    PersistentTrustedTimeProvider,
    SignedTimeEvidenceVerifier,
    TrustedTimeCode,
    TrustedTimeError,
)

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def material(tmp_path: Path):
    key = Ed25519PrivateKey.generate()
    keys = TrustedPolicyKeyStore(
        {"time-key": key.public_key()},
        {"time-key": frozenset({"central-time-service"})},
        {"time-key": frozenset({"time"})},
    )
    state = PersistentExecutionStateStore(tmp_path / "execution-state.json")
    state.initialize()
    return key, keys, state


def payload(**changes) -> dict:
    result = {
        "evidence_id": "time-evidence-1",
        "source_id": "signed-server-time",
        "issuer_id": "central-time-service",
        "server_id": "server-1",
        "agent_id": "agent-1",
        "issued_at": "2026-01-15T11:59:00Z",
        "observed_at": "2026-01-15T12:00:00Z",
        "expires_at": "2026-01-15T12:10:00Z",
        "uncertainty_seconds": 2,
    }
    result.update(changes)
    return result


def signed(key, body=None, *, key_id="time-key") -> bytes:
    body = copy.deepcopy(body or payload())
    digest = hashlib.sha256(canonicalize_json(body)).hexdigest()
    authenticated = {
        "time_schema_version": "1.0",
        "signature_algorithm": "Ed25519",
        "signing_key_id": key_id,
        "payload_sha256": digest,
        "payload": body,
    }
    return json.dumps(
        {
            **authenticated,
            "signature": base64.b64encode(
                key.sign(canonicalize_json(authenticated))
            ).decode(),
        }
    ).encode()


def verifier(keys, state, *, now=NOW):
    return SignedTimeEvidenceVerifier(
        keys,
        state,
        allowed_source_ids=frozenset({"signed-server-time"}),
        maximum_uncertainty_seconds=5,
        maximum_local_clock_delta_seconds=30,
        local_clock=lambda: now,
    )


def test_signed_time_is_verified_persisted_and_restored(material) -> None:
    key, keys, state = material
    result = verifier(keys, state).validate_and_record(
        signed(key), server_id="server-1", agent_id="agent-1"
    )
    assert result.valid
    restarted = PersistentExecutionStateStore(state.path)
    trusted = PersistentTrustedTimeProvider(
        restarted,
        maximum_evidence_age_seconds=300,
        local_clock=lambda: NOW + timedelta(seconds=10),
    ).current_time()
    assert trusted.authenticated
    assert trusted.value == NOW + timedelta(seconds=10)


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"source_id": "unknown-time-source"}, TrustedTimeCode.SOURCE_NOT_ALLOWED),
        ({"server_id": "other-server"}, TrustedTimeCode.SCOPE_MISMATCH),
        ({"agent_id": "other-agent"}, TrustedTimeCode.SCOPE_MISMATCH),
        ({"uncertainty_seconds": 30}, TrustedTimeCode.UNCERTAINTY_TOO_HIGH),
        ({"observed_at": "2026-01-15T12:05:00Z"}, TrustedTimeCode.LOCAL_CLOCK_OUT_OF_BOUNDS),
    ],
)
def test_time_evidence_scope_and_bounds_fail_closed(material, change, code) -> None:
    key, keys, state = material
    result = verifier(keys, state).validate_and_record(
        signed(key, payload(**change)), server_id="server-1", agent_id="agent-1"
    )
    assert not result.valid
    assert result.code is code


def test_wrong_signature_and_wrong_key_usage_are_rejected(material) -> None:
    key, _, state = material
    foreign = Ed25519PrivateKey.generate()
    keys = TrustedPolicyKeyStore(
        {"time-key": key.public_key()},
        {"time-key": frozenset({"central-time-service"})},
        {"time-key": frozenset({"policy"})},
    )
    assert verifier(keys, state).validate_and_record(
        signed(key), server_id="server-1", agent_id="agent-1"
    ).code is TrustedTimeCode.UNTRUSTED_KEY
    valid_keys = TrustedPolicyKeyStore(
        {"time-key": key.public_key()},
        {"time-key": frozenset({"central-time-service"})},
        {"time-key": frozenset({"time"})},
    )
    result = verifier(valid_keys, state).validate_and_record(
        signed(foreign), server_id="server-1", agent_id="agent-1"
    )
    assert result.code is TrustedTimeCode.INVALID_SIGNATURE


def test_tampering_and_replay_are_rejected(material) -> None:
    key, keys, state = material
    document = signed(key)
    changed = json.loads(document)
    changed["payload"]["observed_at"] = "2026-01-15T12:00:01Z"
    assert verifier(keys, state).validate_and_record(
        json.dumps(changed).encode(), server_id="server-1", agent_id="agent-1"
    ).code is TrustedTimeCode.INVALID_EVIDENCE
    assert verifier(keys, state).validate_and_record(
        document, server_id="server-1", agent_id="agent-1"
    ).valid
    assert verifier(keys, state).validate_and_record(
        document, server_id="server-1", agent_id="agent-1"
    ).code is TrustedTimeCode.EVIDENCE_REPLAY


def test_missing_corrupt_expired_and_rollback_time_fail_closed(material) -> None:
    key, keys, state = material
    provider = PersistentTrustedTimeProvider(
        state, maximum_evidence_age_seconds=300, local_clock=lambda: NOW
    )
    with pytest.raises(TrustedTimeError) as missing:
        provider.current_time()
    assert missing.value.code is TrustedTimeCode.TIME_STATE_UNAVAILABLE
    assert verifier(keys, state).validate_and_record(
        signed(key), server_id="server-1", agent_id="agent-1"
    ).valid
    rollback = PersistentTrustedTimeProvider(
        state,
        maximum_evidence_age_seconds=300,
        local_clock=lambda: NOW - timedelta(seconds=10),
    )
    with pytest.raises(TrustedTimeError) as backwards:
        rollback.current_time()
    assert backwards.value.code is TrustedTimeCode.TIME_ROLLBACK
    expired = PersistentTrustedTimeProvider(
        state,
        maximum_evidence_age_seconds=30,
        local_clock=lambda: NOW + timedelta(seconds=31),
    )
    with pytest.raises(TrustedTimeError) as old:
        expired.current_time()
    assert old.value.code is TrustedTimeCode.EVIDENCE_EXPIRED
    state.path.write_text("{}", encoding="utf-8")
    with pytest.raises(TrustedTimeError) as corrupt:
        provider.current_time()
    assert corrupt.value.code is TrustedTimeCode.TIME_STATE_CORRUPT
