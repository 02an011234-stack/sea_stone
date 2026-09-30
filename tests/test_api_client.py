from __future__ import annotations

import json
import logging
import ssl
import unittest
import urllib.error

from os_guard_agent.api_client import ApiClient, EnrollmentError, InvalidEnrollmentResponse
from os_guard_agent.log_config import SecretRedactionFilter
from os_guard_agent.models import EnrollmentRequest, OperatingCredential


class FakeResponse:
    def __init__(self, payload: object, status: int = 201) -> None:
        self.status = status
        self.body = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self) -> bytes:
        return self.body

    def getcode(self) -> int:
        return self.status


def enrollment_request() -> EnrollmentRequest:
    return EnrollmentRequest(
        agent_version="0.1.0",
        hostname="rocky-test",
        distro="rocky",
        version="9.4",
        version_id="9.4",
        kernel="5.14.0",
        architecture="x86_64",
    )


class ApiClientTests(unittest.TestCase):
    def test_enrollment_success_and_header(self) -> None:
        captured = {}

        def opener(request, **kwargs):
            captured["request"] = request
            captured.update(kwargs)
            return FakeResponse(
                {
                    "server_id": "srv-1",
                    "agent_id": "agt-1",
                    "credential_id": "cred-1",
                    "token": "operating-secret",
                    "expires_at": "2026-10-01T00:00:00Z",
                }
            )

        client = ApiClient("https://central.example/agent-api/v2", opener=opener)
        credential = client.enroll("enrollment-secret", enrollment_request())

        self.assertEqual(credential.agent_id, "agt-1")
        self.assertEqual(captured["request"].get_method(), "POST")
        self.assertEqual(
            captured["request"].get_header("X-enrollment-token"), "enrollment-secret"
        )
        self.assertEqual(captured["timeout"], 10.0)

    def test_enrollment_http_failure_is_sanitized(self) -> None:
        client = ApiClient(
            "https://central.example/agent-api/v2",
            opener=lambda *_args, **_kwargs: FakeResponse(
                {"error": "secret-token"}, status=401
            ),
        )
        with self.assertRaises(EnrollmentError) as caught:
            client.enroll("secret-token", enrollment_request())
        self.assertNotIn("secret-token", str(caught.exception))

    def test_invalid_enrollment_response(self) -> None:
        client = ApiClient(
            "https://central.example/agent-api/v2",
            opener=lambda *_args, **_kwargs: FakeResponse({"agent_id": "agt-1"}),
        )
        with self.assertRaises(InvalidEnrollmentResponse):
            client.enroll("enrollment-secret", enrollment_request())

    def test_connection_error_is_sanitized(self) -> None:
        def opener(*_args, **_kwargs):
            raise urllib.error.URLError("connection failed with secret-token")

        client = ApiClient("https://central.example/agent-api/v2", opener=opener)
        with self.assertRaises(EnrollmentError) as caught:
            client.enroll("secret-token", enrollment_request())
        self.assertEqual(str(caught.exception), "enrollment connection failed")

    def test_tls_verification_is_enabled(self) -> None:
        captured = {}

        def opener(_request, **kwargs):
            captured.update(kwargs)
            return FakeResponse(
                {
                    "server_id": "srv-1",
                    "agent_id": "agt-1",
                    "credential_id": "cred-1",
                    "token": "token-1",
                    "expires_at": "2026-10-01T00:00:00Z",
                }
            )

        client = ApiClient("https://central.example/agent-api/v2", opener=opener)
        client.enroll("enrollment-secret", enrollment_request())
        context = captured["context"]
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)

    def test_bearer_authorization_header(self) -> None:
        credential = OperatingCredential("srv", "agt", "cred", "token-1", "expiry")
        self.assertEqual(
            ApiClient.authorization_headers(credential),
            {"Authorization": "Bearer token-1"},
        )

    def test_tokens_are_not_exposed_by_repr_or_log_filter(self) -> None:
        credential = OperatingCredential("srv", "agt", "cred", "token-1", "expiry")
        self.assertNotIn("token-1", repr(credential))

        record = logging.LogRecord(
            "test", logging.ERROR, "", 0, "token=token-1 Bearer token-2", (), None
        )
        SecretRedactionFilter().filter(record)
        self.assertNotIn("token-1", record.msg)
        self.assertNotIn("token-2", record.msg)


if __name__ == "__main__":
    unittest.main()
