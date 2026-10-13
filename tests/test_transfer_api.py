from __future__ import annotations

import hashlib
import json

from os_guard_agent.api_client import ApiClient
from os_guard_agent.models import OperatingCredential

from test_api_client import FakeResponse


def credential() -> OperatingCredential:
    return OperatingCredential("server-1", "agent-1", "cred-1", "secret-token", "expiry")


def test_evidence_multipart_contract_and_ack() -> None:
    captured = {}
    content = b'{"password_protected":true}'
    metadata = {
        "schema_version": "2.0",
        "message_id": "evidence-message-1",
        "sent_at": "2026-10-13T00:00:00Z",
        "agent_id": "agent-1",
        "evidence_id": "evidence-1",
        "server_id": "server-1",
        "scan_run_id": "run-1",
        "attempt_id": "attempt-1",
        "item_id": "U-01",
        "collector_id": "U-01.collect.v1",
        "captured_at": "2026-10-13T00:00:00Z",
        "redacted": True,
        "media_type": "application/json",
        "sha256": hashlib.sha256(content).hexdigest(),
        "byte_length": len(content),
    }

    def opener(request, **_kwargs):
        captured["request"] = request
        return FakeResponse(
            {
                "evidence_id": "evidence-1",
                "received_at": "2026-10-13T00:00:01Z",
                "sha256": metadata["sha256"],
                "byte_length": len(content),
            },
            status=201,
        )

    response = ApiClient(
        "https://central.example/agent-api/v2", opener=opener
    ).upload_evidence(credential(), metadata, content)

    request = captured["request"]
    assert response.evidence_id == "evidence-1"
    assert request.full_url.endswith("/evidence-uploads")
    assert request.get_header("Authorization") == "Bearer secret-token"
    assert request.get_header("Content-type").startswith("multipart/form-data; boundary=")
    assert content in request.data
    assert b'"password_protected":true' in request.data


def test_result_ack_must_contain_the_submitted_result_id() -> None:
    payload = {
        "message_id": "result-message-1",
        "result_id": "result-1",
        "item_id": "U-01",
    }
    captured = {}

    def opener(request, **_kwargs):
        captured["payload"] = json.loads(request.data)
        return FakeResponse(
            {
                "accepted_ids": [],
                "duplicate_ids": ["result-1"],
                "received_at": "2026-10-13T00:00:01Z",
            },
            status=200,
        )

    response = ApiClient(
        "https://central.example/agent-api/v2", opener=opener
    ).upload_result(credential(), "job-1", payload)

    assert response.duplicate_ids == ("result-1",)
    assert captured["payload"] == payload
