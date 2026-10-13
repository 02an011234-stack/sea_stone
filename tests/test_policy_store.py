from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

from os_guard_agent.policy import PolicyStateError, PolicyValidationCode
from os_guard_agent.policy_store import PersistentPolicyVersionStore


NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
HASH_A = "a" * 64
HASH_B = "b" * 64


def initialized_store(tmp_path: Path, **kwargs) -> PersistentPolicyVersionStore:
    store = PersistentPolicyVersionStore(tmp_path / "policy-state.json", **kwargs)
    store.initialize()
    return store


def accept(
    store: PersistentPolicyVersionStore,
    *,
    policy_id: str = "policy-1",
    version: int = 1,
    policy_hash: str = HASH_A,
):
    return store.check_and_record(
        policy_id,
        version,
        policy_hash,
        issuer_id="central-policy-service",
        server_id="server-1",
        agent_id="agent-1",
        signing_key_id="policy-key-1",
        verified_at=NOW,
    )


def test_persistent_store_records_minimal_policy_metadata(tmp_path: Path) -> None:
    store = initialized_store(tmp_path)
    assert accept(store) is None
    summary = store.read_summary()
    record = summary["policies"]["policy-1"]
    assert record["latest_version"] == 1
    assert record["latest_hash"] == HASH_A
    assert record["issuer_id"] == "central-policy-service"
    assert record["server_id"] == "server-1"
    assert record["agent_id"] == "agent-1"
    assert record["registered_at"] == "2026-01-15T12:00:00Z"
    serialized = json.dumps(summary)
    assert "approved_management_networks" not in serialized
    assert "token" not in serialized.lower()
    assert "secret" not in serialized.lower()


def test_agent_restart_restores_state_and_blocks_downgrade(tmp_path: Path) -> None:
    path = tmp_path / "policy-state.json"
    first = PersistentPolicyVersionStore(path)
    first.initialize()
    assert accept(first, version=2, policy_hash=HASH_B) is None
    restarted = PersistentPolicyVersionStore(path)
    assert (
        accept(restarted, version=1, policy_hash=HASH_A)
        is PolicyValidationCode.POLICY_DOWNGRADE
    )


def test_same_version_same_hash_is_duplicate(tmp_path: Path) -> None:
    store = initialized_store(tmp_path)
    assert accept(store) is None
    assert accept(store) is PolicyValidationCode.POLICY_DUPLICATE


def test_same_version_different_hash_is_conflict(tmp_path: Path) -> None:
    store = initialized_store(tmp_path)
    assert accept(store, policy_hash=HASH_A) is None
    assert (
        accept(store, policy_hash=HASH_B)
        is PolicyValidationCode.POLICY_VERSION_CONFLICT
    )


def test_new_version_appends_history_without_payload(tmp_path: Path) -> None:
    store = initialized_store(tmp_path)
    assert accept(store, version=1, policy_hash=HASH_A) is None
    assert accept(store, version=2, policy_hash=HASH_B) is None
    record = store.read_summary()["policies"]["policy-1"]
    assert [item["policy_version"] for item in record["history"]] == [1, 2]
    assert record["latest_version"] == 2


def test_missing_initialized_store_fails_closed(tmp_path: Path) -> None:
    store = PersistentPolicyVersionStore(tmp_path / "missing.json")
    with pytest.raises(PolicyStateError) as error:
        accept(store)
    assert error.value.code is PolicyValidationCode.POLICY_STATE_UNAVAILABLE


@pytest.mark.parametrize(
    "replacement",
    [b"not-json", b'{"schema_version":"1.0"}', b'{"a":1,"a":2}'],
)
def test_corrupt_store_is_rejected(tmp_path: Path, replacement: bytes) -> None:
    store = initialized_store(tmp_path)
    store.path.write_bytes(replacement)
    with pytest.raises(PolicyStateError) as error:
        accept(store)
    assert error.value.code is PolicyValidationCode.POLICY_STATE_CORRUPT


def test_state_hash_tampering_is_rejected(tmp_path: Path) -> None:
    store = initialized_store(tmp_path)
    raw = json.loads(store.path.read_text(encoding="utf-8"))
    raw["generation"] += 1
    store.path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(PolicyStateError) as error:
        accept(store)
    assert error.value.code is PolicyValidationCode.POLICY_STATE_CORRUPT


def test_symlink_store_path_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "policy-state.json"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable")
    store = PersistentPolicyVersionStore(link)
    with pytest.raises(PolicyStateError) as error:
        accept(store)
    assert error.value.code is PolicyValidationCode.POLICY_STATE_CORRUPT


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits required")
def test_broad_store_permissions_are_rejected(tmp_path: Path) -> None:
    store = initialized_store(tmp_path)
    store.path.chmod(0o644)
    with pytest.raises(PolicyStateError) as error:
        accept(store)
    assert error.value.code is PolicyValidationCode.POLICY_STATE_CORRUPT


def test_atomic_replace_failure_preserves_previous_state(tmp_path: Path) -> None:
    path = tmp_path / "policy-state.json"
    good = PersistentPolicyVersionStore(path)
    good.initialize()
    assert accept(good) is None
    original = path.read_bytes()

    def fail_replace(source, destination):
        del source, destination
        raise OSError("simulated interruption")

    failing = PersistentPolicyVersionStore(path, replace_func=fail_replace)
    with pytest.raises(PolicyStateError) as error:
        accept(failing, version=2, policy_hash=HASH_B)
    assert error.value.code is PolicyValidationCode.POLICY_STATE_WRITE_FAILED
    assert path.read_bytes() == original
    assert not list(tmp_path.glob(".policy-state.json.*"))


def test_permission_failure_is_reported_without_partial_state(
    tmp_path: Path, monkeypatch
) -> None:
    store = PersistentPolicyVersionStore(tmp_path / "policy-state.json")

    def deny_chmod(path, mode):
        del path, mode
        raise PermissionError("simulated permission denial")

    monkeypatch.setattr("os_guard_agent.policy_store.os.chmod", deny_chmod)
    with pytest.raises(PolicyStateError) as error:
        store.initialize()
    assert error.value.code in {
        PolicyValidationCode.POLICY_STATE_UNAVAILABLE,
        PolicyValidationCode.POLICY_STATE_WRITE_FAILED,
    }
    assert not store.path.exists()


def test_stale_lock_fails_closed(tmp_path: Path) -> None:
    store = initialized_store(tmp_path)
    store.lock_path.write_text("interrupted", encoding="ascii")
    with pytest.raises(PolicyStateError) as error:
        accept(store)
    assert error.value.code is PolicyValidationCode.POLICY_STATE_LOCKED


def test_state_drift_before_replace_is_rejected(tmp_path: Path, monkeypatch) -> None:
    store = initialized_store(tmp_path)
    monkeypatch.setattr(store, "_identity", lambda: (-1, -1, -1, -1))
    with pytest.raises(PolicyStateError) as error:
        accept(store)
    assert error.value.code is PolicyValidationCode.POLICY_STATE_CORRUPT


def test_concurrent_threads_are_serialized_without_lost_updates(tmp_path: Path) -> None:
    store = initialized_store(tmp_path)
    barrier = threading.Barrier(3)
    results: list[PolicyValidationCode | None] = []
    errors: list[Exception] = []

    def worker(policy_id: str, policy_hash: str) -> None:
        try:
            barrier.wait()
            independent_store = PersistentPolicyVersionStore(store.path)
            results.append(
                accept(
                    independent_store,
                    policy_id=policy_id,
                    policy_hash=policy_hash,
                )
            )
        except Exception as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    threads = [
        threading.Thread(target=worker, args=("policy-a", HASH_A)),
        threading.Thread(target=worker, args=("policy-b", HASH_B)),
    ]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=5)
    assert errors == []
    assert results == [None, None]
    assert set(store.read_summary()["policies"]) == {"policy-a", "policy-b"}


def test_store_file_mode_is_private_on_posix(tmp_path: Path) -> None:
    store = initialized_store(tmp_path)
    if os.name == "posix":
        assert store.path.stat().st_mode & 0o077 == 0
        assert store.path.parent.stat().st_mode & 0o077 == 0
