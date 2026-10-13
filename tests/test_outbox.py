from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from os_guard_agent.outbox import OutboxError, OutboxStore


def test_outbox_survives_restart_and_dependency_waits_for_ack() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir) / "outbox"
        store = OutboxStore(root)
        first = store.enqueue("evidence", {"message_id": "message-1"}, content=b"{}")
        store.enqueue(
            "result",
            {"message_id": "message-2"},
            route="job-1",
            dependencies=("message-1",),
        )

        restarted = OutboxStore(root)
        assert [entry.message_id for entry in restarted.ready_entries()] == ["message-1"]
        restarted.acknowledge(first, {"evidence_id": "evidence-1"})
        assert [entry.message_id for entry in restarted.ready_entries()] == ["message-2"]
        assert restarted.is_acked("message-1")


def test_same_message_with_different_payload_is_rejected() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        store = OutboxStore(Path(temp_dir) / "outbox")
        store.enqueue("result", {"message_id": "same", "value": 1})
        with pytest.raises(OutboxError):
            store.enqueue("result", {"message_id": "same", "value": 2})


def test_corrupt_outbox_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        store = OutboxStore(Path(temp_dir) / "outbox")
        store.initialize()
        (store.pending_dir / "broken.json").write_text("not-json", encoding="utf-8")
        with pytest.raises(OutboxError):
            store.ready_entries()


def test_new_attempt_discards_only_stale_unsent_requests_for_same_job() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        store = OutboxStore(Path(temp_dir) / "outbox")
        store.enqueue(
            "result",
            {"message_id": "old", "attempt_id": "attempt-old"},
            route="job-1",
        )
        store.enqueue(
            "result",
            {"message_id": "current", "attempt_id": "attempt-new"},
            route="job-1",
        )
        store.enqueue(
            "result",
            {"message_id": "other", "attempt_id": "attempt-other"},
            route="job-2",
        )
        assert store.discard_stale_attempt("job-1", "attempt-new") == 1
        assert {entry.message_id for entry in store.ready_entries()} == {
            "current",
            "other",
        }
