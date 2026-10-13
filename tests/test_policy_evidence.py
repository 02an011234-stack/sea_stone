from __future__ import annotations

import base64
import copy
import hashlib
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from os_guard_agent.execution_state import PersistentExecutionStateStore
from os_guard_agent.api_client import PolicyEvidenceConnectionError
from os_guard_agent.grant import GrantValidationContext, SignedExecutionGrantVerifier
from os_guard_agent.models import Action, OperatingCredential, OsInfo
from os_guard_agent.policy import (
    PolicyValidationCode,
    PolicyValidationContext,
    PolicyValidationResult,
    PolicyVerifier,
    TrustedPolicyKeyStore,
    canonicalize_json,
)
from os_guard_agent.policy_evidence import (
    PolicyEvidenceCode,
    PolicyEvidenceReceiver,
    PolicyEvidenceRequest,
)
from os_guard_agent.policy_revocation import SignedRevocationVerifier
from os_guard_agent.policy_store import PersistentPolicyVersionStore
from os_guard_agent.trusted_time import (
    PersistentTrustedTimeProvider,
    SignedTimeEvidenceVerifier,
)

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
POLICY_HASH_PLACEHOLDER = "0" * 64
FINGERPRINT = "f" * 64


def sign_envelope(key, schema_field, key_id, payload) -> bytes:
    digest = hashlib.sha256(canonicalize_json(payload)).hexdigest()
    signed = {
        schema_field: "1.0",
        "signature_algorithm": "Ed25519",
        "signing_key_id": key_id,
        "payload_sha256": digest,
        "payload": copy.deepcopy(payload),
    }
    return json.dumps(
        {
            **signed,
            "signature": base64.b64encode(key.sign(canonicalize_json(signed))).decode(),
        }
    ).encode()


class FixtureApi:
    def __init__(self, documents) -> None:
        self.documents = documents
        self.calls = []
        self.time_sequence = 0

    def fetch_trusted_time_evidence(self, credential):
        self.calls.append("time")
        self.time_sequence += 1
        return self.documents["time"](self.time_sequence)

    def fetch_policy_revocation(self, credential):
        self.calls.append("revocation")
        return self.documents["revocation"]

    def fetch_operating_policy(self, credential, policy_id, policy_version):
        self.calls.append(("policy", policy_id, policy_version))
        return self.documents["policy"]

    def fetch_execution_grant(self, credential, grant_id):
        self.calls.append(("grant", grant_id))
        return self.documents["grant"]


@pytest.fixture
def setup(tmp_path: Path):
    keys = {
        name: Ed25519PrivateKey.generate()
        for name in ("time-key", "revocation-key", "policy-key", "grant-key")
    }
    trust = TrustedPolicyKeyStore(
        {name: key.public_key() for name, key in keys.items()},
        {
            "time-key": frozenset({"central-time-service"}),
            "revocation-key": frozenset({"central-policy-service"}),
            "policy-key": frozenset({"central-policy-service"}),
            "grant-key": frozenset({"central-approval-service"}),
        },
        {
            "time-key": frozenset({"time"}),
            "revocation-key": frozenset({"revocation"}),
            "policy-key": frozenset({"policy"}),
            "grant-key": frozenset({"grant"}),
        },
    )
    policy_store = PersistentPolicyVersionStore(tmp_path / "policy-state.json")
    policy_store.initialize()
    execution_store = PersistentExecutionStateStore(tmp_path / "execution-state.json")
    execution_store.initialize()
    provider = PersistentTrustedTimeProvider(
        execution_store,
        maximum_evidence_age_seconds=300,
        local_clock=lambda: NOW,
    )
    time_verifier = SignedTimeEvidenceVerifier(
        trust,
        execution_store,
        allowed_source_ids=frozenset({"signed-server-time"}),
        maximum_uncertainty_seconds=5,
        maximum_local_clock_delta_seconds=30,
        local_clock=lambda: NOW,
    )
    revocation_verifier = SignedRevocationVerifier(
        trust,
        policy_store,
        trusted_time_provider=provider,
    )
    policy_verifier = PolicyVerifier(
        trust,
        policy_store,
        trusted_time_provider=provider,
        revocation_state_current=True,
        require_current_revocation=True,
    )
    grant_verifier = SignedExecutionGrantVerifier(
        trust,
        provider,
        policy_store,
        execution_store,
    )
    policy_payload = {
        "policy_id": "policy-1",
        "policy_version": 1,
        "policy_type": "SNMP_ACCESS_CONTROL",
        "issuer_id": "central-policy-service",
        "approved_by": "security-admin-1",
        "approved_at": "2026-01-14T08:00:00Z",
        "issued_at": "2026-01-14T09:00:00Z",
        "valid_from": "2026-01-15T00:00:00Z",
        "expires_at": "2026-01-16T00:00:00Z",
        "target": {
            "server_id": "server-1",
            "agent_ids": ["agent-1"],
            "supported_os": {"ubuntu": ["22", "24"], "rocky": ["9", "10"]},
            "u_codes": ["U-61"],
            "actions": ["HARDEN"],
            "manifest_ids": ["manifest-unix-67-v1"],
            "module_versions": ["unix-2026.1"],
        },
        "values": {"approved_management_networks": ["10.0.0.0/8"]},
    }
    policy_hash = hashlib.sha256(canonicalize_json(policy_payload)).hexdigest()

    def time_document(sequence):
        return sign_envelope(
            keys["time-key"],
            "time_schema_version",
            "time-key",
            {
                "evidence_id": f"time-{sequence}",
                "source_id": "signed-server-time",
                "issuer_id": "central-time-service",
                "server_id": "server-1",
                "agent_id": "agent-1",
                "issued_at": "2026-01-15T11:59:00Z",
                "observed_at": "2026-01-15T12:00:00Z",
                "expires_at": "2026-01-15T12:10:00Z",
                "uncertainty_seconds": 1,
            },
        )

    documents = {
        "time": time_document,
        "revocation": sign_envelope(
            keys["revocation-key"],
            "revocation_schema_version",
            "revocation-key",
            {
                "revocation_list_id": "revocations-1",
                "revocation_version": 1,
                "issuer_id": "central-policy-service",
                "server_id": "server-1",
                "issued_at": "2026-01-15T11:00:00Z",
                "valid_from": "2026-01-15T11:00:00Z",
                "expires_at": "2026-01-15T13:00:00Z",
                "revoked_policies": [],
                "revoked_signing_key_ids": [],
            },
        ),
        "policy": sign_envelope(
            keys["policy-key"],
            "policy_schema_version",
            "policy-key",
            policy_payload,
        ),
        "grant": sign_envelope(
            keys["grant-key"],
            "grant_schema_version",
            "grant-key",
            {
                "grant_id": "grant-1",
                "approval_id": "approval-1",
                "issuer_id": "central-approval-service",
                "server_id": "server-1",
                "agent_id": "agent-1",
                "job_id": "job-1",
                "attempt_id": "attempt-1",
                "action": "HARDEN",
                "item_id": "U-61",
                "policy_id": "policy-1",
                "policy_version": 1,
                "policy_hash": policy_hash,
                "preview_id": "preview-1",
                "state_fingerprint": FINGERPRINT,
                "manifest_id": "manifest-unix-67-v1",
                "module_version": "unix-2026.1",
                "not_before": "2026-01-15T11:59:00Z",
                "expires_at": "2026-01-15T12:05:00Z",
                "single_use": True,
            },
        ),
    }
    api = FixtureApi(documents)
    receiver = PolicyEvidenceReceiver(
        api,
        time_verifier,
        revocation_verifier,
        policy_verifier,
        grant_verifier,
    )
    policy_context = PolicyValidationContext(
        server_id="server-1",
        agent_id="agent-1",
        os_info=OsInfo(
            "ubuntu", "Ubuntu 22.04", "22.04", "kernel", "host", "x86_64", True
        ),
        manifest_id="manifest-unix-67-v1",
        module_version="unix-2026.1",
        allowed_u_codes=frozenset({"U-61"}),
        allowed_actions=frozenset({Action.HARDEN}),
        clock_trusted=False,
    )
    placeholder = PolicyValidationResult(
        False,
        PolicyValidationCode.INVALID_PAYLOAD,
        "not yet fetched",
        policy_hash=POLICY_HASH_PLACEHOLDER,
    )
    grant_context = GrantValidationContext(
        server_id="server-1",
        agent_id="agent-1",
        grant_id="grant-1",
        approval_id="approval-1",
        job_id="job-1",
        attempt_id="attempt-1",
        action=Action.HARDEN,
        item_id="U-61",
        policy_result=placeholder,
        preview_id="preview-1",
        state_fingerprint=FINGERPRINT,
        manifest_id="manifest-unix-67-v1",
        module_version="unix-2026.1",
    )
    return {
        "api": api,
        "documents": documents,
        "receiver": receiver,
        "policy_context": policy_context,
        "grant_context": grant_context,
        "execution_store": execution_store,
        "policy_store": policy_store,
        "keys": keys,
        "credential": OperatingCredential(
            "server-1", "agent-1", "credential-1", "secret-token", "expiry"
        ),
    }


def receive(setup, *, with_grant=True):
    return setup["receiver"].receive_and_validate(
        setup["credential"],
        PolicyEvidenceRequest("policy-1", 1, "grant-1" if with_grant else None),
        setup["policy_context"],
        setup["grant_context"] if with_grant else None,
    )


@pytest.mark.parametrize(
    "request_values",
    [
        ("../policy", 1, None),
        ("policy-1", 0, None),
        ("policy-1", 1, "../grant"),
    ],
)
def test_evidence_request_identifiers_are_locally_validated(request_values) -> None:
    with pytest.raises(ValueError):
        PolicyEvidenceRequest(*request_values)


def test_full_read_only_evidence_pipeline_validates_without_consuming_grant(setup) -> None:
    result = receive(setup)
    assert result.valid
    assert result.code is PolicyEvidenceCode.VALID
    assert result.policy_result.valid
    assert result.grant_result.valid
    assert not result.grant_result.consumed
    assert not result.operational_use_allowed
    assert setup["execution_store"].read_summary()["consumed_grants"] == {}
    assert setup["api"].calls == [
        "time",
        "revocation",
        ("policy", "policy-1", 1),
        ("grant", "grant-1"),
    ]


def test_repeated_current_revocation_and_policy_are_idempotent_for_staging(setup) -> None:
    assert receive(setup).valid
    assert receive(setup).valid
    assert setup["execution_store"].read_summary()["consumed_grants"] == {}


def test_policy_only_staging_does_not_fetch_grant(setup) -> None:
    result = receive(setup, with_grant=False)
    assert result.valid
    assert result.grant_result is None
    assert not any(isinstance(call, tuple) and call[0] == "grant" for call in setup["api"].calls)


def test_credential_and_validation_context_mismatch_stops_before_network(setup) -> None:
    wrong_context = replace(setup["policy_context"], agent_id="other-agent")
    result = setup["receiver"].receive_and_validate(
        setup["credential"],
        PolicyEvidenceRequest("policy-1", 1),
        wrong_context,
    )
    assert result.code is PolicyEvidenceCode.CONTEXT_MISMATCH
    assert setup["api"].calls == []


@pytest.mark.parametrize(
    ("document_name", "expected_code"),
    [
        ("time", PolicyEvidenceCode.TIME_EVIDENCE_REJECTED),
        ("revocation", PolicyEvidenceCode.REVOCATION_REJECTED),
        ("policy", PolicyEvidenceCode.POLICY_REJECTED),
        ("grant", PolicyEvidenceCode.GRANT_REJECTED),
    ],
)
def test_invalid_signed_evidence_fails_at_its_validation_stage(
    setup, document_name, expected_code
) -> None:
    if document_name == "time":
        setup["documents"]["time"] = lambda _sequence: b"{}"
    else:
        setup["documents"][document_name] = b"{}"
    result = receive(setup)
    assert not result.valid
    assert result.code is expected_code
    assert not result.operational_use_allowed
    assert setup["execution_store"].read_summary()["consumed_grants"] == {}


def test_logs_do_not_expose_token_or_signed_documents(setup, caplog) -> None:
    signature = json.loads(setup["documents"]["policy"])["signature"]
    receive(setup)
    assert "secret-token" not in caplog.text
    assert signature not in caplog.text
    assert "approved_management_networks" not in caplog.text


def test_unexpected_policy_identity_is_rejected_before_persistence(setup) -> None:
    original = json.loads(setup["documents"]["policy"])["payload"]
    original["policy_id"] = "other-policy"
    setup["documents"]["policy"] = sign_envelope(
        setup["keys"]["policy-key"],
        "policy_schema_version",
        "policy-key",
        original,
    )
    result = receive(setup)
    assert result.code is PolicyEvidenceCode.POLICY_REJECTED
    assert setup["policy_store"].read_summary()["policies"] == {}


def test_fetch_failure_is_sanitized_and_fails_closed(setup) -> None:
    def fail(_credential):
        raise PolicyEvidenceConnectionError("trusted time evidence connection failed")

    setup["api"].fetch_trusted_time_evidence = fail
    result = receive(setup)
    assert result.code is PolicyEvidenceCode.FETCH_FAILED
    assert not result.operational_use_allowed
    assert "secret-token" not in result.message
