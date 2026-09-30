from __future__ import annotations

import json
import socket
import unittest
from datetime import datetime, timedelta, timezone

from os_guard_agent.api_client import (
    ApiClient,
    AuthenticationError,
    ConnectionError,
    InvalidTaskError,
    ServerError,
    TaskClaimError,
    TaskConflictError,
    UnsupportedTaskError,
)
from os_guard_agent.models import Action, OperatingCredential

from test_api_client import FakeResponse


def credential() -> OperatingCredential:
    return OperatingCredential("srv-1", "agt-1", "cred-1", "secret-token", "expiry")


def future_time(minutes: int = 5) -> str:
    return (
        (datetime.now(timezone.utc) + timedelta(minutes=minutes))
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def valid_job() -> dict:
    return {
        "schema_version": "2.0",
        "job_id": "job-1",
        "scan_run_id": "run-1",
        "server_id": "srv-1",
        "agent_id": "agt-1",
        "action": "CHECK",
        "scan_scope": "FULL",
        "attempt_id": "attempt-1",
        "planned_item_count": 67,
        "manifest_id": "manifest-unix-67-v1",
        "criteria_snapshot_id": "criteria-1",
        "lease_until": future_time(2),
        "expires_at": future_time(5),
        "authorization": {"grant_id": None, "approval_id": None},
    }


def client_with(payload: object, status: int = 200) -> ApiClient:
    return ApiClient(
        "https://central.example/agent-api/v2",
        opener=lambda *_args, **_kwargs: FakeResponse(payload, status=status),
    )


class TaskClaimTests(unittest.TestCase):
    def test_check_task_received_with_bearer_auth(self) -> None:
        captured = {}

        def opener(request, **_kwargs):
            captured["request"] = request
            return FakeResponse(valid_job(), status=200)

        task = ApiClient(
            "https://central.example/agent-api/v2", opener=opener
        ).claim_task(credential())
        self.assertIsNotNone(task)
        assert task is not None
        self.assertEqual(task.action, Action.CHECK)
        self.assertEqual(task.planned_item_count, 67)
        self.assertEqual(task.manifest_id, "manifest-unix-67-v1")
        self.assertEqual(captured["request"].get_header("Authorization"), "Bearer secret-token")
        self.assertEqual(
            captured["request"].full_url,
            "https://central.example/agent-api/v2/tasks/claim",
        )
        request_payload = json.loads(captured["request"].data)
        self.assertEqual(request_payload["capabilities"], ["CHECK"])

    def test_no_task_204(self) -> None:
        self.assertIsNone(client_with({}, status=204).claim_task(credential()))

    def test_invalid_schema_version(self) -> None:
        job = valid_job()
        job["schema_version"] = "1.0"
        with self.assertRaises(InvalidTaskError):
            client_with(job).claim_task(credential())

    def test_different_agent_id(self) -> None:
        job = valid_job()
        job["agent_id"] = "agt-other"
        with self.assertRaises(InvalidTaskError):
            client_with(job).claim_task(credential())

    def test_missing_required_field(self) -> None:
        for field in (
            "server_id",
            "job_id",
            "attempt_id",
            "manifest_id",
            "criteria_snapshot_id",
        ):
            with self.subTest(field=field):
                job = valid_job()
                del job[field]
                with self.assertRaises(InvalidTaskError):
                    client_with(job).claim_task(credential())

    def test_expired_lease(self) -> None:
        job = valid_job()
        job["lease_until"] = future_time(-1)
        with self.assertRaisesRegex(InvalidTaskError, "lease has expired"):
            client_with(job).claim_task(credential())

    def test_expired_job(self) -> None:
        job = valid_job()
        job["expires_at"] = future_time(-1)
        with self.assertRaisesRegex(InvalidTaskError, "task has expired"):
            client_with(job).claim_task(credential())

    def test_unsupported_action(self) -> None:
        for action in ("HARDEN", "RECHECK", "ROLLBACK"):
            with self.subTest(action=action):
                job = valid_job()
                job["action"] = action
                with self.assertRaises(UnsupportedTaskError):
                    client_with(job).claim_task(credential())

    def test_authentication_errors(self) -> None:
        for status in (401, 403):
            with self.subTest(status=status):
                with self.assertRaises(AuthenticationError):
                    client_with({"error": "secret-token"}, status).claim_task(credential())

    def test_server_error(self) -> None:
        with self.assertRaises(ServerError):
            client_with({}, 503).claim_task(credential())

    def test_bad_request_and_conflict(self) -> None:
        with self.assertRaises(TaskClaimError):
            client_with({}, 400).claim_task(credential())
        with self.assertRaises(TaskConflictError):
            client_with({}, 409).claim_task(credential())

    def test_timeout_and_network_errors_are_sanitized(self) -> None:
        for error in (socket.timeout("secret-token"), OSError("secret-token")):
            with self.subTest(error=type(error).__name__):
                def opener(*_args, _error=error, **_kwargs):
                    raise _error

                client = ApiClient("https://central.example/agent-api/v2", opener=opener)
                with self.assertRaises(ConnectionError) as caught:
                    client.claim_task(credential())
                self.assertNotIn("secret-token", str(caught.exception))

    def test_command_and_script_fields_are_rejected(self) -> None:
        for field in ("command", "shell", "script", "script_body", "powershell", "executable"):
            with self.subTest(field=field):
                job = valid_job()
                job[field] = "do-not-run"
                with self.assertRaises(InvalidTaskError):
                    client_with(job).claim_task(credential())

        nested_job = valid_job()
        nested_job["metadata"] = {"options": {"shell_command": "do-not-run"}}
        with self.assertRaises(InvalidTaskError):
            client_with(nested_job).claim_task(credential())


if __name__ == "__main__":
    unittest.main()
