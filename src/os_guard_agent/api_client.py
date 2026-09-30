"""HTTPS client for OS Guard Agent enrollment."""

from __future__ import annotations

import json
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from .models import (
    Action,
    EnrollmentRequest,
    Heartbeat,
    HeartbeatResponse,
    OperatingCredential,
    Task,
    TaskAuthorization,
)

FORBIDDEN_EXECUTION_FIELD_FRAGMENTS = (
    "command",
    "shell",
    "script",
    "powershell",
    "executable",
    "argv",
)


class ApiClientError(RuntimeError):
    """Base error for sanitized Agent API failures."""


class EnrollmentError(ApiClientError):
    """Raised when enrollment cannot be completed."""


class InvalidEnrollmentResponse(EnrollmentError):
    """Raised when the enrollment response is incomplete or malformed."""


class HeartbeatError(ApiClientError):
    """Raised when a heartbeat cannot be accepted."""


class AuthenticationError(HeartbeatError):
    """Raised when operating credentials are rejected."""


class ServerError(HeartbeatError):
    """Raised when the central server returns a server-side error."""


class ConnectionError(HeartbeatError):
    """Raised for sanitized timeout and network failures."""


class TaskClaimError(ApiClientError):
    """Raised when task claiming fails."""


class InvalidTaskError(TaskClaimError):
    """Raised when a claimed task fails local validation."""


class UnsupportedTaskError(InvalidTaskError):
    """Raised when a valid but not-yet-supported action is claimed."""


class TaskConflictError(TaskClaimError):
    """Raised when the central server reports a claim conflict."""


class ApiClient:
    def __init__(
        self,
        base_url: str,
        timeout_seconds: float = 10.0,
        *,
        opener: Callable[..., Any] = urllib.request.urlopen,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        if not base_url.startswith("https://"):
            raise ValueError("Agent API base URL must use HTTPS")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")

        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self._opener = opener
        self.ssl_context = ssl_context or ssl.create_default_context()
        if self.ssl_context.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError("TLS certificate verification must be enabled")
        if not self.ssl_context.check_hostname:
            raise ValueError("TLS hostname verification must be enabled")

    def enroll(
        self,
        enrollment_token: str,
        enrollment: EnrollmentRequest,
    ) -> OperatingCredential:
        if not enrollment_token:
            raise EnrollmentError("enrollment token is required")

        request = urllib.request.Request(
            f"{self.base_url}/enrollments",
            data=json.dumps(asdict(enrollment)).encode("utf-8"),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-Enrollment-Token": enrollment_token,
            },
            method="POST",
        )

        try:
            with self._opener(
                request,
                timeout=self.timeout_seconds,
                context=self.ssl_context,
            ) as response:
                status = getattr(response, "status", response.getcode())
                body = response.read()
        except urllib.error.HTTPError as exc:
            raise EnrollmentError(f"enrollment rejected with HTTP status {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, socket.timeout, OSError):
            raise EnrollmentError("enrollment connection failed") from None

        if status < 200 or status >= 300:
            raise EnrollmentError(f"enrollment rejected with HTTP status {status}")
        return self._parse_enrollment_response(body)

    @staticmethod
    def _parse_enrollment_response(body: bytes) -> OperatingCredential:
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise InvalidEnrollmentResponse("invalid enrollment response") from None

        if not isinstance(payload, Mapping):
            raise InvalidEnrollmentResponse("invalid enrollment response")

        fields: dict[str, str] = {}
        for key in ("server_id", "agent_id", "credential_id", "token", "expires_at"):
            value = payload.get(key)
            if not isinstance(value, str) or not value.strip():
                raise InvalidEnrollmentResponse("invalid enrollment response")
            fields[key] = value.strip()
        return OperatingCredential(**fields)

    @staticmethod
    def authorization_headers(credential: OperatingCredential) -> dict[str, str]:
        return {"Authorization": f"Bearer {credential.token}"}

    def send_heartbeat(
        self,
        credential: OperatingCredential,
        heartbeat: Heartbeat,
    ) -> HeartbeatResponse:
        request = urllib.request.Request(
            f"{self.base_url}/heartbeat",
            data=json.dumps(heartbeat.to_dict()).encode("utf-8"),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                **self.authorization_headers(credential),
            },
            method="POST",
        )

        try:
            with self._opener(
                request,
                timeout=self.timeout_seconds,
                context=self.ssl_context,
            ) as response:
                status = getattr(response, "status", response.getcode())
                body = response.read()
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = b""
        except (TimeoutError, socket.timeout):
            raise ConnectionError("heartbeat request timed out") from None
        except (urllib.error.URLError, OSError):
            raise ConnectionError("heartbeat connection failed") from None

        if status in {401, 403}:
            raise AuthenticationError(f"heartbeat authentication failed with HTTP status {status}")
        if 500 <= status <= 599:
            raise ServerError(f"heartbeat server error with HTTP status {status}")
        if status < 200 or status >= 300:
            raise HeartbeatError(f"heartbeat rejected with HTTP status {status}")

        try:
            payload = json.loads(body.decode("utf-8"))
            received_at = payload["received_at"]
            poll_after_sec = payload.get("poll_after_sec")
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
            raise HeartbeatError("invalid heartbeat response") from None
        if not isinstance(received_at, str) or not received_at:
            raise HeartbeatError("invalid heartbeat response")
        if poll_after_sec is not None and (
            not isinstance(poll_after_sec, int) or isinstance(poll_after_sec, bool)
        ):
            raise HeartbeatError("invalid heartbeat response")
        return HeartbeatResponse(received_at, poll_after_sec)

    def claim_task(self, credential: OperatingCredential) -> Task | None:
        request = urllib.request.Request(
            f"{self.base_url}/tasks/claim",
            data=json.dumps(
                {"agent_id": credential.agent_id, "capabilities": [Action.CHECK.value]}
            ).encode("utf-8"),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                **self.authorization_headers(credential),
            },
            method="POST",
        )

        try:
            with self._opener(
                request,
                timeout=self.timeout_seconds,
                context=self.ssl_context,
            ) as response:
                status = getattr(response, "status", response.getcode())
                body = response.read()
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = b""
        except (TimeoutError, socket.timeout):
            raise ConnectionError("task claim request timed out") from None
        except (urllib.error.URLError, OSError):
            raise ConnectionError("task claim connection failed") from None

        if status == 204:
            return None
        if status in {401, 403}:
            raise AuthenticationError(f"task claim authentication failed with HTTP status {status}")
        if status == 409:
            raise TaskConflictError("task claim conflict")
        if 500 <= status <= 599:
            raise ServerError(f"task claim server error with HTTP status {status}")
        if status == 400:
            raise TaskClaimError("task claim request rejected with HTTP status 400")
        if status != 200:
            raise TaskClaimError(f"task claim rejected with HTTP status {status}")

        return self._parse_task(body, credential.agent_id)

    @classmethod
    def _parse_task(cls, body: bytes, current_agent_id: str) -> Task:
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise InvalidTaskError("invalid task response") from None
        if not isinstance(payload, Mapping):
            raise InvalidTaskError("invalid task response")
        cls._reject_execution_fields(payload)

        def required_string(key: str) -> str:
            value = payload.get(key)
            if not isinstance(value, str) or not value.strip():
                raise InvalidTaskError(f"task field '{key}' is required")
            return value.strip()

        schema_version = required_string("schema_version")
        if schema_version != "2.0":
            raise InvalidTaskError("unsupported task schema_version")

        agent_id = required_string("agent_id")
        if agent_id != current_agent_id:
            raise InvalidTaskError("task agent_id does not match this Agent")

        action_value = required_string("action")
        try:
            action = Action(action_value)
        except ValueError:
            raise InvalidTaskError("task action is not allowed") from None
        if action is not Action.CHECK:
            raise UnsupportedTaskError(f"task action is not supported: {action.value}")

        scan_scope = required_string("scan_scope")
        planned_item_count = payload.get("planned_item_count")
        if (
            not isinstance(planned_item_count, int)
            or isinstance(planned_item_count, bool)
            or planned_item_count < 1
        ):
            raise InvalidTaskError("task planned_item_count is invalid")
        if scan_scope == "FULL" and planned_item_count != 67:
            raise InvalidTaskError("Unix FULL CHECK must contain 67 planned items")

        lease_until = required_string("lease_until")
        expires_at = required_string("expires_at")
        now = datetime.now(timezone.utc)
        if cls._parse_utc_deadline(lease_until, "lease_until") <= now:
            raise InvalidTaskError("task lease has expired")
        if cls._parse_utc_deadline(expires_at, "expires_at") <= now:
            raise InvalidTaskError("task has expired")

        raw_authorization = payload.get("authorization")
        if not isinstance(raw_authorization, Mapping):
            raise InvalidTaskError("task authorization is required")
        grant_id = cls._optional_string(raw_authorization.get("grant_id"), "grant_id")
        approval_id = cls._optional_string(
            raw_authorization.get("approval_id"), "approval_id"
        )

        return Task(
            schema_version=schema_version,
            job_id=required_string("job_id"),
            scan_run_id=required_string("scan_run_id"),
            server_id=required_string("server_id"),
            agent_id=agent_id,
            action=action,
            scan_scope=scan_scope,
            attempt_id=required_string("attempt_id"),
            planned_item_count=planned_item_count,
            manifest_id=required_string("manifest_id"),
            criteria_snapshot_id=required_string("criteria_snapshot_id"),
            lease_until=lease_until,
            expires_at=expires_at,
            authorization=TaskAuthorization(grant_id, approval_id),
        )

    @staticmethod
    def _parse_utc_deadline(value: str, field_name: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise InvalidTaskError(f"task field '{field_name}' is invalid") from None
        if parsed.tzinfo is None:
            raise InvalidTaskError(f"task field '{field_name}' must include a timezone")
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _optional_string(value: Any, field_name: str) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not value.strip():
            raise InvalidTaskError(f"task authorization '{field_name}' is invalid")
        return value.strip()

    @classmethod
    def _reject_execution_fields(cls, value: Any) -> None:
        if isinstance(value, Mapping):
            for key, nested_value in value.items():
                normalized_key = str(key).lower().replace("-", "_")
                if any(
                    fragment in normalized_key
                    for fragment in FORBIDDEN_EXECUTION_FIELD_FRAGMENTS
                ):
                    raise InvalidTaskError("task contains a forbidden execution field")
                cls._reject_execution_fields(nested_value)
        elif isinstance(value, list):
            for nested_value in value:
                cls._reject_execution_fields(nested_value)
