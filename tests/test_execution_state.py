from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from os_guard_agent.execution_state import (
    ExecutionStateCode,
    ExecutionStateError,
    PersistentExecutionStateStore,
)

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)


def test_missing_state_is_not_recreated_implicitly(tmp_path: Path) -> None:
    store = PersistentExecutionStateStore(tmp_path / "missing.json")
    with pytest.raises(ExecutionStateError) as error:
        store.consume_grant(
            grant_id="grant-1",
            grant_hash="a" * 64,
            job_id="job-1",
            attempt_id="attempt-1",
            consumed_at=NOW,
        )
    assert error.value.code is ExecutionStateCode.STATE_UNAVAILABLE


def test_symlink_state_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "execution-state.json"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable")
    store = PersistentExecutionStateStore(link)
    with pytest.raises(ExecutionStateError) as error:
        store.initialize()
    assert error.value.code is ExecutionStateCode.STATE_CORRUPT


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits required")
def test_broad_state_permissions_are_rejected(tmp_path: Path) -> None:
    store = PersistentExecutionStateStore(tmp_path / "execution-state.json")
    store.initialize()
    store.path.chmod(0o644)
    with pytest.raises(ExecutionStateError) as error:
        store.read_summary()
    assert error.value.code is ExecutionStateCode.STATE_CORRUPT


def test_state_contains_no_grant_signature_or_payload(tmp_path: Path) -> None:
    store = PersistentExecutionStateStore(tmp_path / "execution-state.json")
    store.initialize()
    store.consume_grant(
        grant_id="grant-1",
        grant_hash="a" * 64,
        job_id="job-1",
        attempt_id="attempt-1",
        consumed_at=NOW,
    )
    text = store.path.read_text(encoding="utf-8").lower()
    assert "signature" not in text
    assert "policy_values" not in text
    assert "token" not in text
