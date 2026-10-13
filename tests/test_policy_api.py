from __future__ import annotations

import socket
import ssl
import urllib.error

import pytest

from os_guard_agent.api_client import (
    MAX_POLICY_EVIDENCE_BYTES,
    ApiClient,
    InvalidPolicyEvidenceResponse,
    PolicyEvidenceAuthenticationError,
    PolicyEvidenceConnectionError,
    PolicyEvidenceServerError,
    PolicyEvidenceUnavailableError,
)
from os_guard_agent.models import OperatingCredential


class EvidenceResponse:
    def __init__(
        self,
        body: bytes = b'{"signed":"document"}',
        *,
        status: int = 200,
        content_type: str = "application/json",
    ) -> None:
        self.body = body
        self.status = status
        self.headers = {"Content-Type": content_type}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, limit: int = -1) -> bytes:
        return self.body if limit < 0 else self.body[:limit]

    def getcode(self) -> int:
        return self.status


@pytest.fixture
def credential() -> OperatingCredential:
    return OperatingCredential("server-1", "agent-1", "credential-1", "secret-token", "expiry")


def test_all_policy_security_get_contracts_use_bearer_no_store_and_tls(credential) -> None:
    requests = []

    def opener(request, **kwargs):
        requests.append((request, kwargs))
        return EvidenceResponse()

    client = ApiClient("https://central.example/agent-api/v2", opener=opener)
    client.fetch_trusted_time_evidence(credential)
    client.fetch_policy_revocation(credential)
    client.fetch_operating_policy(credential, "policy-1", 3)
    client.fetch_execution_grant(credential, "grant-1")

    assert [request.full_url for request, _ in requests] == [
        "https://central.example/agent-api/v2/policy-security/time-evidence",
        "https://central.example/agent-api/v2/policy-security/revocations/current",
        "https://central.example/agent-api/v2/policy-security/policies/policy-1/versions/3",
        "https://central.example/agent-api/v2/policy-security/grants/grant-1",
    ]
    for request, kwargs in requests:
        assert request.get_method() == "GET"
        assert request.data is None
        assert request.get_header("Authorization") == "Bearer secret-token"
        assert request.get_header("Cache-control") == "no-store"
        assert kwargs["context"].verify_mode == ssl.CERT_REQUIRED
        assert kwargs["context"].check_hostname


@pytest.mark.parametrize("status", [204, 404, 409, 410])
def test_absent_conflicting_or_gone_evidence_fails_closed(credential, status) -> None:
    client = ApiClient(
        "https://central.example/agent-api/v2",
        opener=lambda *_args, **_kwargs: EvidenceResponse(status=status),
    )
    with pytest.raises(PolicyEvidenceUnavailableError):
        client.fetch_policy_revocation(credential)


@pytest.mark.parametrize("status", [401, 403])
def test_policy_evidence_authentication_error_is_distinct_and_sanitized(
    credential, status
) -> None:
    client = ApiClient(
        "https://central.example/agent-api/v2",
        opener=lambda *_args, **_kwargs: EvidenceResponse(status=status),
    )
    with pytest.raises(PolicyEvidenceAuthenticationError) as error:
        client.fetch_trusted_time_evidence(credential)
    assert "secret-token" not in str(error.value)


@pytest.mark.parametrize("status", [429, 500, 503])
def test_retryable_server_status_is_not_treated_as_evidence(credential, status) -> None:
    client = ApiClient(
        "https://central.example/agent-api/v2",
        opener=lambda *_args, **_kwargs: EvidenceResponse(status=status),
    )
    with pytest.raises(PolicyEvidenceServerError):
        client.fetch_execution_grant(credential, "grant-1")


@pytest.mark.parametrize(
    ("body", "content_type"),
    [
        pytest.param(b"", "application/json", id="empty"),
        pytest.param(b"{}", "text/plain", id="wrong-media-type"),
        pytest.param(
            b"x" * (MAX_POLICY_EVIDENCE_BYTES + 1),
            "application/json",
            id="oversized",
        ),
    ],
)
def test_response_framing_is_rejected(credential, body, content_type) -> None:
    client = ApiClient(
        "https://central.example/agent-api/v2",
        opener=lambda *_args, **_kwargs: EvidenceResponse(
            body, content_type=content_type
        ),
    )
    with pytest.raises(InvalidPolicyEvidenceResponse):
        client.fetch_operating_policy(credential, "policy-1", 1)


@pytest.mark.parametrize(
    ("policy_id", "version"),
    [("../policy", 1), ("policy/1", 1), ("policy-1", 0), ("policy-1", True)],
)
def test_path_identifiers_and_versions_are_locally_validated(
    credential, policy_id, version
) -> None:
    client = ApiClient("https://central.example/agent-api/v2", opener=lambda *_a, **_k: None)
    with pytest.raises(ValueError):
        client.fetch_operating_policy(credential, policy_id, version)


def test_timeout_and_network_details_are_sanitized(credential) -> None:
    def timeout(*_args, **_kwargs):
        raise socket.timeout("secret-token")

    client = ApiClient("https://central.example/agent-api/v2", opener=timeout)
    with pytest.raises(PolicyEvidenceConnectionError) as error:
        client.fetch_trusted_time_evidence(credential)
    assert str(error.value) == "trusted time evidence request timed out"

    def network(*_args, **_kwargs):
        raise urllib.error.URLError("secret-token")

    client = ApiClient("https://central.example/agent-api/v2", opener=network)
    with pytest.raises(PolicyEvidenceConnectionError) as error:
        client.fetch_policy_revocation(credential)
    assert "secret-token" not in str(error.value)
