from __future__ import annotations

import tempfile
import time
from pathlib import Path

from os_guard_agent.agent import Agent
from os_guard_agent.config import AgentConfig
from os_guard_agent.models import (
    Action,
    CheckResult,
    EvidenceUploadResponse,
    OperatingCredential,
    OsInfo,
    ResultStatus,
    ResultUploadResponse,
    ReviewState,
    Task,
    TaskAuthorization,
    TaskEventResponse,
)
from os_guard_agent.module_runner import ExecutionPlan, PlannedModule
from os_guard_agent.outbox import OutboxStore
from os_guard_agent.check_transport import enqueue_check_result, enqueue_event, flush_outbox
from os_guard_agent.api_client import ConnectionError
from os_guard_agent.models import TaskEvent


def task() -> Task:
    return Task(
        schema_version="2.0",
        job_id="job-1",
        scan_run_id="run-1",
        server_id="server-1",
        agent_id="agent-1",
        action=Action.CHECK,
        scan_scope="PARTIAL",
        attempt_id="attempt-1",
        planned_item_count=1,
        manifest_id="manifest-unix-67-v1",
        criteria_snapshot_id="criteria-1",
        lease_until="2099-01-01T00:00:00Z",
        expires_at="2099-01-01T01:00:00Z",
        authorization=TaskAuthorization(None, None),
        item_ids=("U-01",),
        module_version="unix-2026.1",
        lease_duration_sec=120,
        lease_deadline_monotonic=time.monotonic() + 120,
    )


class FakeRunner:
    def execute_check(self, _module):
        return CheckResult(
            item_id="U-01",
            status=ResultStatus.GOOD,
            review_state=ReviewState.NOT_REQUIRED,
            current_value={"password_protected": True},
            evidence={
                "item_id": "U-01",
                "module_version": "unix-2026.1",
                "observed_at": "2026-10-13T00:00:00Z",
                "reason_code": "KISA_U01_COMPLIANT",
                "password_protected": True,
                "os": {"distro": "ubuntu", "version_id": "22.04"},
            },
            error=None,
        )


class FakeClient:
    def __init__(self):
        self.calls = []

    def send_task_event_payload(self, _credential, _job_id, payload):
        self.calls.append(("event", payload["event"]))
        return TaskEventResponse(
            payload["message_id"],
            "2026-10-13T00:00:00Z",
            "2026-10-13T00:02:00Z",
            "2026-10-13T00:00:00Z",
            120,
            time.monotonic() + 120,
        )

    def upload_evidence(self, _credential, metadata, content):
        self.calls.append(("evidence", metadata["item_id"]))
        return EvidenceUploadResponse(
            metadata["evidence_id"], metadata["sha256"], len(content)
        )

    def upload_result(self, _credential, _job_id, payload):
        self.calls.append(("result", payload["item_id"]))
        return ResultUploadResponse((payload["result_id"],), (), "2026-10-13T00:00:00Z")


class FailingClient(FakeClient):
    def upload_evidence(self, _credential, _metadata, _content):
        raise ConnectionError("evidence connection failed")


def test_partial_check_executes_local_module_and_acks_before_completion() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        config = AgentConfig(
            central_server_url="https://central.example/agent-api/v2",
            agent_id=None,
            log_path=Path(temp_dir) / "agent.log",
            outbox_path=Path(temp_dir) / "outbox",
        )
        outbox = OutboxStore(config.outbox_path)
        client = FakeClient()
        check_task = task()
        plan = ExecutionPlan(
            "job-1",
            "manifest-unix-67-v1",
            (PlannedModule("U-01", Path("U-01.sh"), Action.CHECK),),
        )
        Agent(config)._run_check_task(
            check_task,
            plan,
            FakeRunner(),  # type: ignore[arg-type]
            outbox,
            client,  # type: ignore[arg-type]
            OperatingCredential("server-1", "agent-1", "cred-1", "token", "expiry"),
            OsInfo("ubuntu", "22.04", "22.04", "kernel", "host", "x86_64", True),
        )

        assert client.calls == [
            ("event", "STARTED"),
            ("evidence", "U-01"),
            ("result", "U-01"),
            ("event", "COMPLETED"),
        ]
        assert not outbox.has_pending()
        assert len(tuple(outbox.ack_dir.glob("*.json"))) == 4


def test_failed_event_is_durable_and_acknowledged() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        outbox = OutboxStore(Path(temp_dir) / "outbox")
        enqueue_event(
            outbox,
            task(),
            TaskEvent.FAILED,
            processed_item_count=0,
            error={"code": "LOCAL_EXECUTION_ABORTED", "message": "CHECK aborted"},
        )
        client = FakeClient()
        count = flush_outbox(
            outbox,
            client,  # type: ignore[arg-type]
            OperatingCredential("server-1", "agent-1", "cred-1", "token", "expiry"),
        )
        assert count == 1
        assert client.calls == [("event", "FAILED")]
        assert not outbox.has_pending()


def test_network_failure_retains_exact_transfer_and_restart_recovers() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir) / "outbox"
        outbox = OutboxStore(root)
        result = FakeRunner().execute_check(None)
        enqueue_check_result(outbox, task(), result)
        operating_credential = OperatingCredential(
            "server-1", "agent-1", "cred-1", "token", "expiry"
        )
        try:
            flush_outbox(outbox, FailingClient(), operating_credential)  # type: ignore[arg-type]
        except ConnectionError:
            pass
        else:
            raise AssertionError("network failure was not propagated")
        pending_before_restart = tuple(
            (entry.message_id, dict(entry.payload), entry.content)
            for entry in outbox.ready_entries()
        )
        assert pending_before_restart

        restarted = OutboxStore(root)
        recovered_client = FakeClient()
        assert flush_outbox(
            restarted,
            recovered_client,  # type: ignore[arg-type]
            operating_credential,
        ) == 2
        assert not restarted.has_pending()
