from __future__ import annotations

import base64
import copy
import hashlib
import json
import threading
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from os_guard_agent.execution_state import PersistentExecutionStateStore
from os_guard_agent.grant import (
    GrantValidationCode,
    GrantValidationContext,
    SignedExecutionGrantVerifier,
)
from os_guard_agent.models import Action
from os_guard_agent.policy import (
    PolicyEnvelope,
    PolicyPayload,
    PolicyTarget,
    PolicyValidationCode,
    PolicyValidationResult,
    RevokedPolicy,
    RevocationState,
    TrustedPolicyKeyStore,
    canonicalize_json,
)
from os_guard_agent.policy_store import PersistentPolicyVersionStore
from os_guard_agent.trusted_time import TrustedTime, TrustedTimeCode, TrustedTimeError

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
POLICY_HASH = "a" * 64
FINGERPRINT = "b" * 64


class FixedTrustedTime:
    def __init__(self, value=NOW, *, available=True) -> None:
        self.value = value
        self.available = available

    def current_time(self) -> TrustedTime:
        if not self.available:
            raise TrustedTimeError(
                TrustedTimeCode.TIME_STATE_UNAVAILABLE,
                "test trusted time unavailable",
            )
        return TrustedTime(
            value=self.value,
            evidence_id="time-1",
            source_id="signed-server-time",
            authenticated=True,
            uncertainty_seconds=1,
            evidence_expires_at=NOW + timedelta(hours=1),
        )


@pytest.fixture
def environment(tmp_path: Path):
    policy_key = Ed25519PrivateKey.generate()
    grant_key = Ed25519PrivateKey.generate()
    keys = TrustedPolicyKeyStore(
        {
            "policy-key": policy_key.public_key(),
            "grant-key": grant_key.public_key(),
        },
        {
            "policy-key": frozenset({"central-policy-service"}),
            "grant-key": frozenset({"central-approval-service"}),
        },
        {
            "policy-key": frozenset({"policy"}),
            "grant-key": frozenset({"grant"}),
        },
    )
    policy_store = PersistentPolicyVersionStore(tmp_path / "policy-state.json")
    policy_store.initialize()
    revocation = RevocationState(
        revocation_list_id="revocations-1",
        revocation_version=1,
        revocation_hash="c" * 64,
        issuer_id="central-policy-service",
        server_id="server-1",
        signing_key_id="revocation-key",
        issued_at=NOW - timedelta(hours=1),
        valid_from=NOW - timedelta(hours=1),
        expires_at=NOW + timedelta(hours=1),
        revoked_policies=(),
        revoked_signing_key_ids=(),
    )
    assert policy_store.record_revocation(revocation, verified_at=NOW) is None
    assert policy_store.check_and_record(
        "policy-1",
        1,
        POLICY_HASH,
        issuer_id="central-policy-service",
        server_id="server-1",
        agent_id="agent-1",
        signing_key_id="policy-key",
        verified_at=NOW,
        require_current_revocation=True,
    ) is None
    execution_state = PersistentExecutionStateStore(tmp_path / "execution-state.json")
    execution_state.initialize()
    target = PolicyTarget(
        server_id="server-1",
        agent_ids=("agent-1",),
        supported_os={"ubuntu": ("22", "24"), "rocky": ("9", "10")},
        u_codes=("U-61",),
        actions=(Action.HARDEN,),
        manifest_ids=("manifest-unix-67-v1",),
        module_versions=("unix-2026.1",),
    )
    policy_payload = PolicyPayload(
        policy_id="policy-1",
        policy_version=1,
        policy_type="SNMP_ACCESS_CONTROL",
        issuer_id="central-policy-service",
        approved_by="security-admin-1",
        approved_at=NOW - timedelta(days=1),
        issued_at=NOW - timedelta(hours=2),
        valid_from=NOW - timedelta(hours=1),
        expires_at=NOW + timedelta(hours=1),
        target=target,
        values={"approved_management_networks": ["10.0.0.0/8"]},
    )
    policy = PolicyEnvelope(
        policy_schema_version="1.0",
        signature_algorithm="Ed25519",
        signing_key_id="policy-key",
        payload_sha256=POLICY_HASH,
        signature="not-persisted-or-logged",
        payload=policy_payload,
    )
    policy_result = PolicyValidationResult(
        valid=True,
        code=PolicyValidationCode.VALID,
        message="valid",
        policy=policy,
        policy_hash=POLICY_HASH,
        operational_use_allowed=False,
    )
    context = GrantValidationContext(
        server_id="server-1",
        agent_id="agent-1",
        grant_id="grant-1",
        approval_id="approval-1",
        job_id="job-1",
        attempt_id="attempt-1",
        action=Action.HARDEN,
        item_id="U-61",
        policy_result=policy_result,
        preview_id="preview-1",
        state_fingerprint=FINGERPRINT,
        manifest_id="manifest-unix-67-v1",
        module_version="unix-2026.1",
    )
    return {
        "policy_key": policy_key,
        "grant_key": grant_key,
        "keys": keys,
        "policy_store": policy_store,
        "execution_state": execution_state,
        "context": context,
        "policy_result": policy_result,
        "tmp_path": tmp_path,
    }


def grant_payload(**changes) -> dict:
    result = {
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
        "policy_hash": POLICY_HASH,
        "preview_id": "preview-1",
        "state_fingerprint": FINGERPRINT,
        "manifest_id": "manifest-unix-67-v1",
        "module_version": "unix-2026.1",
        "not_before": "2026-01-15T11:59:00Z",
        "expires_at": "2026-01-15T12:05:00Z",
        "single_use": True,
    }
    result.update(changes)
    return result


def signed_grant(key, body=None, *, key_id="grant-key") -> bytes:
    body = copy.deepcopy(body or grant_payload())
    digest = hashlib.sha256(canonicalize_json(body)).hexdigest()
    signed = {
        "grant_schema_version": "1.0",
        "signature_algorithm": "Ed25519",
        "signing_key_id": key_id,
        "payload_sha256": digest,
        "payload": body,
    }
    return json.dumps(
        {
            **signed,
            "signature": base64.b64encode(key.sign(canonicalize_json(signed))).decode(),
        }
    ).encode()


def verifier(environment, *, trusted_time=None, execution_state=None):
    return SignedExecutionGrantVerifier(
        environment["keys"],
        trusted_time or FixedTrustedTime(),
        environment["policy_store"],
        execution_state or environment["execution_state"],
    )


def test_valid_grant_is_verified_consumed_but_never_operationally_enabled(environment) -> None:
    result = verifier(environment).validate_and_consume(
        signed_grant(environment["grant_key"]), environment["context"]
    )
    assert result.valid and result.consumed
    assert result.code is GrantValidationCode.VALID
    assert not result.operational_use_allowed
    summary = environment["execution_state"].read_summary()
    assert summary["consumed_grants"]["grant-1"]["status"] == "CONSUMED"
    assert "signature" not in json.dumps(summary).lower()


def test_invalid_signature_field_tampering_and_unknown_key_are_rejected(environment) -> None:
    foreign = Ed25519PrivateKey.generate()
    bad_signature = verifier(environment).validate_and_consume(
        signed_grant(foreign), environment["context"]
    )
    assert bad_signature.code is GrantValidationCode.INVALID_SIGNATURE
    changed = json.loads(signed_grant(environment["grant_key"]))
    changed["payload"]["preview_id"] = "changed-preview"
    tampered = verifier(environment).validate_and_consume(
        json.dumps(changed).encode(), environment["context"]
    )
    assert tampered.code is GrantValidationCode.HASH_MISMATCH
    unknown = verifier(environment).validate_and_consume(
        signed_grant(foreign, key_id="foreign-key"), environment["context"]
    )
    assert unknown.code is GrantValidationCode.UNTRUSTED_SIGNING_KEY


def test_key_usage_is_separated(environment) -> None:
    wrong_keys = TrustedPolicyKeyStore(
        {"grant-key": environment["grant_key"].public_key()},
        {"grant-key": frozenset({"central-approval-service"})},
        {"grant-key": frozenset({"policy"})},
    )
    check = SignedExecutionGrantVerifier(
        wrong_keys,
        FixedTrustedTime(),
        environment["policy_store"],
        environment["execution_state"],
    )
    result = check.validate_and_consume(
        signed_grant(environment["grant_key"]), environment["context"]
    )
    assert result.code is GrantValidationCode.UNTRUSTED_SIGNING_KEY


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"server_id": "other-server"}, GrantValidationCode.SCOPE_MISMATCH),
        ({"agent_id": "other-agent"}, GrantValidationCode.SCOPE_MISMATCH),
        ({"grant_id": "other-grant"}, GrantValidationCode.SCOPE_MISMATCH),
        ({"approval_id": "other-approval"}, GrantValidationCode.SCOPE_MISMATCH),
        ({"job_id": "other-job"}, GrantValidationCode.JOB_BINDING_MISMATCH),
        ({"attempt_id": "other-attempt"}, GrantValidationCode.JOB_BINDING_MISMATCH),
        ({"item_id": "U-62"}, GrantValidationCode.ITEM_ACTION_MISMATCH),
        ({"policy_version": 2}, GrantValidationCode.POLICY_BINDING_MISMATCH),
        ({"policy_hash": "d" * 64}, GrantValidationCode.POLICY_BINDING_MISMATCH),
        ({"preview_id": "other-preview"}, GrantValidationCode.PREVIEW_BINDING_MISMATCH),
        ({"state_fingerprint": "d" * 64}, GrantValidationCode.PREVIEW_BINDING_MISMATCH),
        ({"manifest_id": "other-manifest"}, GrantValidationCode.MODULE_BINDING_MISMATCH),
        ({"module_version": "unix-2026.2"}, GrantValidationCode.MODULE_BINDING_MISMATCH),
    ],
)
def test_all_execution_authority_bindings_must_match(environment, change, code) -> None:
    result = verifier(environment).validate_and_consume(
        signed_grant(environment["grant_key"], grant_payload(**change)),
        environment["context"],
    )
    assert not result.valid
    assert result.code is code


def test_invalid_action_single_use_and_lifecycle_are_rejected(environment) -> None:
    for change in (
        {"action": "CHECK"},
        {"single_use": False},
        {"not_before": "2026-01-15T12:10:00Z"},
    ):
        result = verifier(environment).validate_and_consume(
            signed_grant(environment["grant_key"], grant_payload(**change)),
            environment["context"],
        )
        assert result.code is GrantValidationCode.INVALID_PAYLOAD


def test_not_yet_valid_expired_and_untrusted_time_are_rejected(environment) -> None:
    future = verifier(environment).validate_and_consume(
        signed_grant(
            environment["grant_key"],
            grant_payload(not_before="2026-01-15T12:01:00Z"),
        ),
        environment["context"],
    )
    assert future.code is GrantValidationCode.GRANT_NOT_YET_VALID
    expired = verifier(
        environment, trusted_time=FixedTrustedTime(NOW + timedelta(minutes=6))
    ).validate_and_consume(
        signed_grant(environment["grant_key"]), environment["context"]
    )
    assert expired.code is GrantValidationCode.GRANT_EXPIRED
    unavailable = verifier(
        environment, trusted_time=FixedTrustedTime(available=False)
    ).validate_and_consume(
        signed_grant(environment["grant_key"]), environment["context"]
    )
    assert unavailable.code is GrantValidationCode.TRUSTED_TIME_UNAVAILABLE


def test_grant_reuse_and_restart_reuse_are_blocked(environment) -> None:
    document = signed_grant(environment["grant_key"])
    assert verifier(environment).validate_and_consume(document, environment["context"]).valid
    restarted = PersistentExecutionStateStore(environment["execution_state"].path)
    result = verifier(environment, execution_state=restarted).validate_and_consume(
        document, environment["context"]
    )
    assert result.code is GrantValidationCode.GRANT_REUSED


def test_same_job_attempt_cannot_use_a_second_grant(environment) -> None:
    assert verifier(environment).validate_and_consume(
        signed_grant(environment["grant_key"]), environment["context"]
    ).valid
    result = verifier(environment).validate_and_consume(
        signed_grant(environment["grant_key"], grant_payload(grant_id="grant-2")),
        replace(environment["context"], grant_id="grant-2"),
    )
    assert result.code is GrantValidationCode.JOB_ATTEMPT_REUSED


def test_concurrent_consumption_has_exactly_one_success(environment) -> None:
    document = signed_grant(environment["grant_key"])
    results = []

    def consume() -> None:
        results.append(
            verifier(environment).validate_and_consume(document, environment["context"])
        )

    threads = [threading.Thread(target=consume) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(result.valid for result in results) == 1
    assert {result.code for result in results} == {
        GrantValidationCode.VALID,
        GrantValidationCode.GRANT_REUSED,
    }


def test_corrupt_and_write_failed_execution_state_fail_closed(environment) -> None:
    environment["execution_state"].path.write_text("{}", encoding="utf-8")
    corrupt = verifier(environment).validate_and_consume(
        signed_grant(environment["grant_key"]), environment["context"]
    )
    assert corrupt.code is GrantValidationCode.EXECUTION_STATE_UNAVAILABLE

    new_path = environment["tmp_path"] / "write-failure.json"
    good = PersistentExecutionStateStore(new_path)
    good.initialize()

    def fail_replace(source, destination):
        del source, destination
        raise OSError("simulated failure")

    failing = PersistentExecutionStateStore(new_path, replace_func=fail_replace)
    failed = verifier(environment, execution_state=failing).validate_and_consume(
        signed_grant(environment["grant_key"]), environment["context"]
    )
    assert failed.code is GrantValidationCode.EXECUTION_STATE_UNAVAILABLE


def test_policy_change_and_revoked_grant_key_block_approval(environment) -> None:
    assert environment["policy_store"].check_and_record(
        "policy-1",
        2,
        "d" * 64,
        issuer_id="central-policy-service",
        server_id="server-1",
        agent_id="agent-1",
        signing_key_id="policy-key",
        verified_at=NOW,
    ) is None
    changed = verifier(environment).validate_and_consume(
        signed_grant(environment["grant_key"]), environment["context"]
    )
    assert changed.code is GrantValidationCode.POLICY_STATE_REJECTED


def test_revoked_grant_key_is_rejected(environment) -> None:
    revoked = RevocationState(
        revocation_list_id="revocations-1",
        revocation_version=2,
        revocation_hash="d" * 64,
        issuer_id="central-policy-service",
        server_id="server-1",
        signing_key_id="revocation-key",
        issued_at=NOW,
        valid_from=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(hours=1),
        revoked_policies=(),
        revoked_signing_key_ids=("grant-key",),
    )
    assert environment["policy_store"].record_revocation(revoked, verified_at=NOW) is None
    result = verifier(environment).validate_and_consume(
        signed_grant(environment["grant_key"]), environment["context"]
    )
    assert result.code is GrantValidationCode.SIGNING_KEY_REVOKED


def test_revoked_policy_is_rejected(environment) -> None:
    revoked = RevocationState(
        revocation_list_id="revocations-1",
        revocation_version=2,
        revocation_hash="e" * 64,
        issuer_id="central-policy-service",
        server_id="server-1",
        signing_key_id="revocation-key",
        issued_at=NOW,
        valid_from=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(hours=1),
        revoked_policies=(),
        revoked_signing_key_ids=(),
    )
    revoked = replace(
        revoked,
        revoked_policies=(RevokedPolicy("policy-1", 1, POLICY_HASH),),
    )
    assert environment["policy_store"].record_revocation(revoked, verified_at=NOW) is None
    result = verifier(environment).validate_and_consume(
        signed_grant(environment["grant_key"]), environment["context"]
    )
    assert result.code is GrantValidationCode.POLICY_REVOKED


def test_logs_do_not_expose_signature_or_policy_values(environment, caplog) -> None:
    document = signed_grant(environment["grant_key"])
    signature = json.loads(document)["signature"]
    verifier(environment).validate_and_consume(document, environment["context"])
    text = caplog.text
    assert signature not in text
    assert "approved_management_networks" not in text
