from __future__ import annotations

import json
import socket
import ssl
import tempfile
import unittest
import urllib.error
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from os_guard_agent import MODULE_VERSION
from os_guard_agent.agent import Agent
from os_guard_agent.api_client import (
    ApiClient,
    AuthenticationError,
    ConnectionError,
    ServerError,
)
from os_guard_agent.config import AgentConfig
from os_guard_agent.models import Heartbeat, HeartbeatResponse, OperatingCredential
from os_guard_agent.token_store import TokenStore

from test_api_client import FakeResponse


def credential() -> OperatingCredential:
    return OperatingCredential("srv-1", "agt-1", "cred-1", "secret-token", "expiry")


def heartbeat() -> Heartbeat:
    return Heartbeat.ready(
        agent_id="agt-1",
        agent_version="0.1.0",
        module_version=MODULE_VERSION,
        inventory_version="inv-1",
    )


class HeartbeatApiTests(unittest.TestCase):
    def test_heartbeat_request_contract_and_bearer_header(self) -> None:
        captured = {}

        def opener(request, **kwargs):
            captured["request"] = request
            captured.update(kwargs)
            return FakeResponse(
                {"received_at": "2026-09-22T00:00:01Z", "poll_after_sec": 30},
                status=200,
            )

        client = ApiClient("https://central.example/agent-api/v2", opener=opener)
        response = client.send_heartbeat(credential(), heartbeat())
        request = captured["request"]
        payload = json.loads(request.data)

        self.assertEqual(response.poll_after_sec, 30)
        self.assertEqual(request.full_url, "https://central.example/agent-api/v2/heartbeat")
        self.assertEqual(request.get_header("Authorization"), "Bearer secret-token")
        self.assertEqual(
            set(payload),
            {
                "schema_version",
                "message_id",
                "sent_at",
                "agent_id",
                "agent_version",
                "module_version",
                "inventory_version",
                "active_job_id",
                "health",
                "pending_result_count",
            },
        )
        self.assertEqual(payload["health"], "READY")
        self.assertIsNone(payload["active_job_id"])
        self.assertEqual(payload["pending_result_count"], 0)
        self.assertEqual(captured["context"].verify_mode, ssl.CERT_REQUIRED)

    def test_message_id_is_unique_and_sent_at_is_utc(self) -> None:
        first = heartbeat()
        second = heartbeat()
        self.assertNotEqual(first.message_id, second.message_id)
        self.assertTrue(first.sent_at.endswith("Z"))
        self.assertIsNotNone(datetime.fromisoformat(first.sent_at.replace("Z", "+00:00")).tzinfo)

    def test_timeout(self) -> None:
        def opener(*_args, **_kwargs):
            raise socket.timeout("secret-token")

        client = ApiClient("https://central.example/agent-api/v2", opener=opener)
        with self.assertRaisesRegex(ConnectionError, "timed out"):
            client.send_heartbeat(credential(), heartbeat())

    def test_authentication_errors_are_distinct(self) -> None:
        for status in (401, 403):
            with self.subTest(status=status):
                client = ApiClient(
                    "https://central.example/agent-api/v2",
                    opener=lambda *_args, _status=status, **_kwargs: FakeResponse(
                        {"error": "secret-token"}, status=_status
                    ),
                )
                with self.assertRaises(AuthenticationError) as caught:
                    client.send_heartbeat(credential(), heartbeat())
                self.assertNotIn("secret-token", str(caught.exception))

    def test_server_error(self) -> None:
        client = ApiClient(
            "https://central.example/agent-api/v2",
            opener=lambda *_args, **_kwargs: FakeResponse({}, status=503),
        )
        with self.assertRaises(ServerError):
            client.send_heartbeat(credential(), heartbeat())


class HeartbeatLoopTests(unittest.TestCase):
    def test_network_error_does_not_stop_agent(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = AgentConfig(
                central_server_url="https://central.example/agent-api/v2",
                agent_id=None,
                log_path=Path(temp_dir) / "agent.log",
                token_store_path=Path(temp_dir) / "credentials.json",
                heartbeat_interval_seconds=0.001,
                inventory_version="inv-1",
            )
            TokenStore(config.token_store_path).save(credential())
            agent = Agent(config)
            calls = 0

            def send_heartbeat(_credential, _heartbeat):
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise ConnectionError("heartbeat connection failed")
                agent.stop()
                return HeartbeatResponse("2026-09-22T00:00:01Z", 30)

            with (
                patch("os_guard_agent.agent.ApiClient") as client_class,
                patch("os_guard_agent.agent.detect_os") as detect,
            ):
                detect.return_value.distro = "rocky"
                detect.return_value.version_id = "9"
                detect.return_value.kernel = "test"
                detect.return_value.architecture = "x86_64"
                detect.return_value.supported = True
                client_class.return_value.send_heartbeat.side_effect = send_heartbeat
                with self.assertLogs("os_guard_agent.agent", level="WARNING") as logs:
                    self.assertEqual(agent.run(), 0)

            self.assertEqual(calls, 2)
            self.assertNotIn("secret-token", " ".join(logs.output))

    def test_failure_log_does_not_expose_token(self) -> None:
        def opener(*_args, **_kwargs):
            raise socket.timeout("secret-token")

        client = ApiClient("https://central.example/agent-api/v2", opener=opener)
        with self.assertRaises(ConnectionError) as caught:
            client.send_heartbeat(credential(), heartbeat())
        self.assertNotIn("secret-token", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
