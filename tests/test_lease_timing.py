from __future__ import annotations

import json
from unittest.mock import patch

from os_guard_agent.api_client import ApiClient
from os_guard_agent.models import OperatingCredential, TaskEvent

from test_api_client import FakeResponse
from test_task_claim import valid_job


def credential() -> OperatingCredential:
    return OperatingCredential("srv-1", "agt-1", "cred-1", "secret-token", "expiry")


def test_claim_uses_monotonic_deadline_and_subtracts_round_trip() -> None:
    client = ApiClient(
        "https://central.example/agent-api/v2",
        opener=lambda *_args, **_kwargs: FakeResponse(valid_job(), status=200),
    )
    with patch("os_guard_agent.api_client.time.monotonic", side_effect=[100.0, 102.0]):
        task = client.claim_task(credential())

    assert task is not None
    assert task.lease_deadline_monotonic == 220.0
    assert task.lease_is_valid(219.999)
    assert not task.lease_is_valid(220.0)


def test_event_ack_refreshes_monotonic_deadline_without_using_wall_clock() -> None:
    task = ApiClient._parse_task(
        json.dumps(valid_job()).encode(),
        "agt-1",
        response_monotonic=10.0,
    )
    captured = {}

    def opener(request, **_kwargs):
        captured["payload"] = json.loads(request.data)
        return FakeResponse(
            {
                "accepted_message_id": captured["payload"]["message_id"],
                "received_at": "2026-10-13T00:00:00Z",
                "server_time": "2026-10-13T00:00:00Z",
                "lease_until": "2026-10-13T00:02:00Z",
                "lease_duration_sec": 120.0,
            },
            status=200,
        )

    client = ApiClient("https://central.example/agent-api/v2", opener=opener)
    with patch("os_guard_agent.api_client.time.monotonic", side_effect=[50.0, 51.5]):
        response = client.send_task_event(credential(), task, TaskEvent.LEASE_RENEWAL)

    assert response.lease_deadline_monotonic == 170.0
    assert captured["payload"]["requested_lease_until"] is None


def test_claim_rejects_duration_consumed_by_round_trip() -> None:
    job = valid_job()
    job["lease_duration_sec"] = 1.0
    client = ApiClient(
        "https://central.example/agent-api/v2",
        opener=lambda *_args, **_kwargs: FakeResponse(job, status=200),
    )
    with patch("os_guard_agent.api_client.time.monotonic", side_effect=[10.0, 12.0]):
        try:
            client.claim_task(credential())
        except Exception as exc:
            assert "lease has expired" in str(exc)
        else:
            raise AssertionError("expired lease was accepted")
