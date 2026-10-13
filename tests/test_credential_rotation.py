from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from os_guard_agent.agent import Agent
from os_guard_agent.api_client import ApiClient, CredentialRotationError
from os_guard_agent.config import AgentConfig
from os_guard_agent.models import CredentialRotation, HeartbeatResponse, OperatingCredential
from os_guard_agent.token_store import TokenStore

from test_api_client import FakeResponse


def old_credential() -> OperatingCredential:
    return OperatingCredential("server-1", "agent-1", "old-cred", "old-secret", "old-expiry")


def new_credential() -> OperatingCredential:
    return OperatingCredential("server-1", "agent-1", "new-cred", "new-secret", "new-expiry")


def rotation() -> CredentialRotation:
    return CredentialRotation(
        credential=new_credential(),
        rotation_id="rotation-1",
        old_credential_id="old-cred",
        grace_until="2026-10-13T00:05:00Z",
        confirmation="FIRST_SUCCESSFUL_AGENT_REQUEST",
    )


def test_rotation_api_contract_and_response() -> None:
    captured = {}

    def opener(request, **_kwargs):
        captured["request"] = request
        return FakeResponse(
            {
                "credential_id": "new-cred",
                "token": "new-secret",
                "expires_at": "new-expiry",
                "rotation_id": "rotation-1",
                "old_credential_id": "old-cred",
                "grace_until": "2026-10-13T00:05:00Z",
                "confirmation": "FIRST_SUCCESSFUL_AGENT_REQUEST",
            },
            status=201,
        )

    result = ApiClient(
        "https://central.example/agent-api/v2", opener=opener
    ).rotate_credential(old_credential())
    payload = json.loads(captured["request"].data)

    assert result.credential == new_credential()
    assert payload["credential_id"] == "old-cred"
    assert payload["agent_id"] == "agent-1"
    assert captured["request"].get_header("Authorization") == "Bearer old-secret"


def test_rotation_response_loss_does_not_change_stored_old_credential() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        store = TokenStore(Path(temp_dir) / "credentials.json")
        store.save(old_credential())

        def timeout(*_args, **_kwargs):
            raise TimeoutError("contains-new-secret")

        client = ApiClient("https://central.example/agent-api/v2", opener=timeout)
        with pytest.raises(CredentialRotationError):
            client.rotate_credential(store.load())
        assert store.load() == old_credential()


def test_staged_rotation_survives_restart_and_confirmation_drops_old_secret() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "credentials.json"
        store = TokenStore(path)
        store.save(old_credential())
        store.stage_rotation(
            old_credential(),
            new_credential(),
            rotation_id="rotation-1",
            grace_until="2026-10-13T00:05:00Z",
        )

        restarted = TokenStore(path)
        assert restarted.load() == new_credential()
        assert restarted.pending_rotation().previous == old_credential()  # type: ignore[union-attr]
        restarted.confirm_rotation("new-cred")
        assert restarted.pending_rotation() is None
        assert restarted.load() == new_credential()
        assert "old-secret" not in path.read_text(encoding="utf-8")


def test_agent_saves_new_credential_before_first_new_authenticated_request() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "credentials.json"
        TokenStore(path).save(old_credential())
        config = AgentConfig(
            central_server_url="https://central.example/agent-api/v2",
            agent_id=None,
            log_path=Path(temp_dir) / "agent.log",
            token_store_path=path,
        )
        observed = {}

        def heartbeat(credential, _payload):
            observed["stored"] = TokenStore(path).load()
            observed["used"] = credential
            return HeartbeatResponse("2026-10-13T00:00:00Z", 30)

        with patch("os_guard_agent.agent.ApiClient") as client_class:
            client_class.return_value.rotate_credential.return_value = rotation()
            client_class.return_value.send_heartbeat.side_effect = heartbeat
            result = Agent(config).rotate_credential()

        assert observed["stored"] == new_credential()
        assert observed["used"] == new_credential()
        assert result == new_credential()
        assert TokenStore(path).pending_rotation() is None
