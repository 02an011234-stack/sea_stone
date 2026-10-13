"""HTTPS client for OS Guard Agent enrollment."""

from __future__ import annotations

import json
import hashlib
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import asdict
from datetime import datetime, timezone
from re import fullmatch
from typing import Any, Callable, Mapping
from urllib.parse import quote
from uuid import uuid4

from . import MODULE_VERSION, __version__
from .models import (
    Action,
    CredentialRotation,
    EnrollmentRequest,
    EvidenceUploadResponse,
    Heartbeat,
    HeartbeatResponse,
    Inventory,
    InventoryResponse,
    OperatingCredential,
    ResultUploadResponse,
    Task,
    TaskAuthorization,
    TaskEvent,
    TaskEventResponse,
)

FORBIDDEN_EXECUTION_FIELD_FRAGMENTS = (
    "command",
    "shell",
    "script",
    "powershell",
    "executable",
    "argv",
)
MAX_POLICY_EVIDENCE_BYTES = 1024 * 1024


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


class CredentialRotationError(ApiClientError):
    """Raised when a credential rotation cannot be completed safely."""


class InvalidCredentialRotationResponse(CredentialRotationError):
    """Raised when a rotation response is incomplete or malformed."""


class InventoryError(ApiClientError):
    """Raised when an inventory snapshot cannot be accepted."""


class TaskEventError(ApiClientError):
    """Raised when a task event cannot be accepted."""


class TransferError(ApiClientError):
    """Raised when Evidence, Result, or Event transfer is not acknowledged."""


class PolicyEvidenceApiError(ApiClientError):
    """Base error for sanitized, read-only policy evidence retrieval."""


class PolicyEvidenceAuthenticationError(PolicyEvidenceApiError):
    """Raised when operating credentials cannot retrieve policy evidence."""


class PolicyEvidenceUnavailableError(PolicyEvidenceApiError):
    """Raised when required policy evidence is absent or no longer available."""


class PolicyEvidenceServerError(PolicyEvidenceApiError):
    """Raised when the central policy evidence service fails."""


class PolicyEvidenceConnectionError(PolicyEvidenceApiError):
    """Raised for sanitized timeout and network failures during evidence GETs."""


class InvalidPolicyEvidenceResponse(PolicyEvidenceApiError):
    """Raised when response framing is unsafe or violates the API contract."""


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

    @staticmethod
    def _operation_envelope(agent_id: str) -> dict[str, str]:
        return {
            "schema_version": "2.0",
            "message_id": str(uuid4()),
            "sent_at": datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "agent_id": agent_id,
        }

    def rotate_credential(
        self,
        credential: OperatingCredential,
    ) -> CredentialRotation:
        payload = {
            **self._operation_envelope(credential.agent_id),
            "credential_id": credential.credential_id,
        }
        request = urllib.request.Request(
            f"{self.base_url}/credentials/rotate",
            data=json.dumps(payload).encode("utf-8"),
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
            raise CredentialRotationError("credential rotation request timed out") from None
        except (urllib.error.URLError, OSError):
            raise CredentialRotationError("credential rotation connection failed") from None

        if status in {401, 403}:
            raise CredentialRotationError(
                f"credential rotation authentication failed with HTTP status {status}"
            )
        if status == 409:
            raise CredentialRotationError("credential rotation state conflicts")
        if status != 201:
            raise CredentialRotationError(
                f"credential rotation rejected with HTTP status {status}"
            )
        return self._parse_rotation_response(body, credential)

    @staticmethod
    def _parse_rotation_response(
        body: bytes,
        previous: OperatingCredential,
    ) -> CredentialRotation:
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise InvalidCredentialRotationResponse(
                "invalid credential rotation response"
            ) from None
        if not isinstance(payload, Mapping):
            raise InvalidCredentialRotationResponse("invalid credential rotation response")

        def required_string(key: str) -> str:
            value = payload.get(key)
            if not isinstance(value, str) or not value.strip():
                raise InvalidCredentialRotationResponse(
                    "invalid credential rotation response"
                )
            return value.strip()

        old_credential_id = required_string("old_credential_id")
        if old_credential_id != previous.credential_id:
            raise InvalidCredentialRotationResponse(
                "credential rotation response does not match the old credential"
            )
        new_credential = OperatingCredential(
            server_id=previous.server_id,
            agent_id=previous.agent_id,
            credential_id=required_string("credential_id"),
            token=required_string("token"),
            expires_at=required_string("expires_at"),
        )
        if new_credential.credential_id == previous.credential_id:
            raise InvalidCredentialRotationResponse(
                "credential rotation response did not issue a new credential"
            )
        confirmation = required_string("confirmation")
        if confirmation != "FIRST_SUCCESSFUL_AGENT_REQUEST":
            raise InvalidCredentialRotationResponse(
                "credential rotation confirmation mode is unsupported"
            )
        return CredentialRotation(
            credential=new_credential,
            rotation_id=required_string("rotation_id"),
            old_credential_id=old_credential_id,
            grace_until=required_string("grace_until"),
            confirmation=confirmation,
        )

    def send_inventory(
        self,
        credential: OperatingCredential,
        inventory: Inventory,
    ) -> InventoryResponse:
        if inventory.agent_id != credential.agent_id:
            raise InventoryError("inventory agent_id does not match the credential")
        request = urllib.request.Request(
            f"{self.base_url}/inventory",
            data=json.dumps(
                inventory.to_dict(), ensure_ascii=False, separators=(",", ":")
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
            raise ConnectionError("inventory request timed out") from None
        except (urllib.error.URLError, OSError):
            raise ConnectionError("inventory connection failed") from None

        if status in {401, 403}:
            raise AuthenticationError(
                f"inventory authentication failed with HTTP status {status}"
            )
        if 500 <= status <= 599:
            raise ServerError(f"inventory server error with HTTP status {status}")
        if status != 200:
            raise InventoryError(f"inventory rejected with HTTP status {status}")
        try:
            payload = json.loads(body.decode("utf-8"))
            inventory_version = payload["inventory_version"]
            received_at = payload["received_at"]
            duplicate = payload["duplicate"]
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
            raise InventoryError("invalid inventory response") from None
        if inventory_version != inventory.inventory_version:
            raise InventoryError("inventory response version does not match request")
        if not isinstance(received_at, str) or not received_at:
            raise InventoryError("invalid inventory response")
        if not isinstance(duplicate, bool):
            raise InventoryError("invalid inventory response")
        return InventoryResponse(inventory_version, received_at, duplicate)

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
        payload = {
            **self._operation_envelope(credential.agent_id),
            "capabilities": [Action.CHECK.value],
            "agent_version": __version__,
            "module_version": MODULE_VERSION,
        }
        request = urllib.request.Request(
            f"{self.base_url}/tasks/claim",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                **self.authorization_headers(credential),
            },
            method="POST",
        )

        request_started = time.monotonic()
        try:
            with self._opener(
                request,
                timeout=self.timeout_seconds,
                context=self.ssl_context,
            ) as response:
                status = getattr(response, "status", response.getcode())
                body = response.read()
                response_received = time.monotonic()
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

        return self._parse_task(
            body,
            credential.agent_id,
            round_trip_seconds=max(0.0, response_received - request_started),
            response_monotonic=response_received,
        )

    def send_task_event(
        self,
        credential: OperatingCredential,
        task: Task,
        event: TaskEvent,
        *,
        processed_item_count: int = 0,
        error: Mapping[str, Any] | None = None,
    ) -> TaskEventResponse:
        if task.agent_id != credential.agent_id:
            raise TaskEventError("task agent_id does not match the credential")
        if processed_item_count < 0:
            raise ValueError("processed_item_count must not be negative")
        payload: dict[str, Any] = {
            **self._operation_envelope(credential.agent_id),
            "attempt_id": task.attempt_id,
            "event": event.value,
            "processed_item_count": processed_item_count,
            "requested_lease_until": None,
            "error": error,
        }
        return self.send_task_event_payload(credential, task.job_id, payload)

    def send_task_event_payload(
        self,
        credential: OperatingCredential,
        job_id: str,
        payload: Mapping[str, Any],
    ) -> TaskEventResponse:
        message_id = payload.get("message_id")
        if not isinstance(message_id, str) or not message_id:
            raise TaskEventError("task event message_id is required")
        request = urllib.request.Request(
            f"{self.base_url}/tasks/{quote(job_id, safe='')}/events",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                **self.authorization_headers(credential),
            },
            method="POST",
        )
        request_started = time.monotonic()
        try:
            with self._opener(
                request,
                timeout=self.timeout_seconds,
                context=self.ssl_context,
            ) as response:
                status = getattr(response, "status", response.getcode())
                body = response.read()
                response_received = time.monotonic()
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = b""
        except (TimeoutError, socket.timeout):
            raise ConnectionError("task event request timed out") from None
        except (urllib.error.URLError, OSError):
            raise ConnectionError("task event connection failed") from None

        if status in {401, 403}:
            raise AuthenticationError(
                f"task event authentication failed with HTTP status {status}"
            )
        if status == 409:
            raise TaskConflictError("task event state conflicts")
        if 500 <= status <= 599:
            raise ServerError(f"task event server error with HTTP status {status}")
        if status != 200:
            raise TaskEventError(f"task event rejected with HTTP status {status}")
        return self._parse_task_event_response(
            body,
            expected_message_id=message_id,
            round_trip_seconds=max(0.0, response_received - request_started),
            response_monotonic=response_received,
        )

    def upload_evidence(
        self,
        credential: OperatingCredential,
        metadata: Mapping[str, Any],
        content: bytes,
    ) -> EvidenceUploadResponse:
        if len(content) > 1024 * 1024:
            raise TransferError("evidence exceeds the one MiB limit")
        expected_hash = hashlib.sha256(content).hexdigest()
        if metadata.get("sha256") != expected_hash or metadata.get("byte_length") != len(content):
            raise TransferError("evidence metadata does not match content")
        message_id = metadata.get("message_id")
        if not isinstance(message_id, str) or not message_id:
            raise TransferError("evidence message_id is required")
        boundary = f"os-guard-{message_id}"
        metadata_bytes = json.dumps(
            metadata, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        body = b"".join(
            (
                f"--{boundary}\r\n".encode(),
                b'Content-Disposition: form-data; name="metadata"\r\n',
                b"Content-Type: application/json; charset=utf-8\r\n\r\n",
                metadata_bytes,
                b"\r\n",
                f"--{boundary}\r\n".encode(),
                b'Content-Disposition: form-data; name="file"; filename="evidence.json"\r\n',
                b"Content-Type: application/json\r\n\r\n",
                content,
                b"\r\n",
                f"--{boundary}--\r\n".encode(),
            )
        )
        request = urllib.request.Request(
            f"{self.base_url}/evidence-uploads",
            data=body,
            headers={
                "Accept": "application/json",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                **self.authorization_headers(credential),
            },
            method="POST",
        )
        status, response_body = self._send_transfer(request, "evidence upload")
        if status != 201:
            raise TransferError(f"evidence upload rejected with HTTP status {status}")
        try:
            response = json.loads(response_body.decode("utf-8"))
            evidence_id = response["evidence_id"]
            returned_hash = response["sha256"]
            byte_length = response["byte_length"]
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
            raise TransferError("invalid evidence upload response") from None
        if (
            evidence_id != metadata.get("evidence_id")
            or returned_hash != expected_hash
            or byte_length != len(content)
        ):
            raise TransferError("evidence upload ACK does not match request")
        return EvidenceUploadResponse(
            evidence_id=evidence_id,
            sha256=returned_hash,
            byte_length=byte_length,
            received_at=response.get("received_at"),
            duplicate=response.get("duplicate", False) is True,
        )

    def upload_result(
        self,
        credential: OperatingCredential,
        job_id: str,
        payload: Mapping[str, Any],
    ) -> ResultUploadResponse:
        result_id = payload.get("result_id")
        if not isinstance(result_id, str) or not result_id:
            raise TransferError("result_id is required")
        request = urllib.request.Request(
            f"{self.base_url}/tasks/{quote(job_id, safe='')}/results",
            data=json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                **self.authorization_headers(credential),
            },
            method="POST",
        )
        status, response_body = self._send_transfer(request, "result upload")
        if status != 200:
            raise TransferError(f"result upload rejected with HTTP status {status}")
        try:
            response = json.loads(response_body.decode("utf-8"))
            accepted = tuple(response["accepted_ids"])
            duplicates = tuple(response["duplicate_ids"])
            received_at = response["received_at"]
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
            raise TransferError("invalid result upload response") from None
        if result_id not in accepted and result_id not in duplicates:
            raise TransferError("result upload ACK does not contain result_id")
        return ResultUploadResponse(accepted, duplicates, received_at)

    def _send_transfer(
        self,
        request: urllib.request.Request,
        operation: str,
    ) -> tuple[int, bytes]:
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
            raise ConnectionError(f"{operation} timed out") from None
        except (urllib.error.URLError, OSError):
            raise ConnectionError(f"{operation} connection failed") from None
        if status in {401, 403}:
            raise AuthenticationError(
                f"{operation} authentication failed with HTTP status {status}"
            )
        if 500 <= status <= 599:
            raise ServerError(f"{operation} server error with HTTP status {status}")
        return status, body

    def fetch_trusted_time_evidence(
        self,
        credential: OperatingCredential,
    ) -> bytes:
        return self._fetch_signed_evidence(
            credential,
            "/policy-security/time-evidence",
            "trusted time evidence",
        )

    def fetch_policy_revocation(
        self,
        credential: OperatingCredential,
    ) -> bytes:
        return self._fetch_signed_evidence(
            credential,
            "/policy-security/revocations/current",
            "policy revocation evidence",
        )

    def fetch_operating_policy(
        self,
        credential: OperatingCredential,
        policy_id: str,
        policy_version: int,
    ) -> bytes:
        safe_policy_id = self._policy_identifier(policy_id, "policy_id")
        if (
            not isinstance(policy_version, int)
            or isinstance(policy_version, bool)
            or policy_version < 1
        ):
            raise ValueError("policy_version must be a positive integer")
        return self._fetch_signed_evidence(
            credential,
            "/policy-security/policies/"
            f"{quote(safe_policy_id, safe='')}/versions/{policy_version}",
            "operating policy",
        )

    def fetch_execution_grant(
        self,
        credential: OperatingCredential,
        grant_id: str,
    ) -> bytes:
        safe_grant_id = self._policy_identifier(grant_id, "grant_id")
        return self._fetch_signed_evidence(
            credential,
            f"/policy-security/grants/{quote(safe_grant_id, safe='')}",
            "execution Grant",
        )

    def _fetch_signed_evidence(
        self,
        credential: OperatingCredential,
        path: str,
        evidence_name: str,
    ) -> bytes:
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            headers={
                "Accept": "application/json",
                "Cache-Control": "no-store",
                **self.authorization_headers(credential),
            },
            method="GET",
        )
        try:
            with self._opener(
                request,
                timeout=self.timeout_seconds,
                context=self.ssl_context,
            ) as response:
                status = getattr(response, "status", response.getcode())
                content_type = response.headers.get("Content-Type", "")
                body = response.read(MAX_POLICY_EVIDENCE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            status = exc.code
            content_type = ""
            body = b""
        except (TimeoutError, socket.timeout):
            raise PolicyEvidenceConnectionError(
                f"{evidence_name} request timed out"
            ) from None
        except (urllib.error.URLError, OSError):
            raise PolicyEvidenceConnectionError(
                f"{evidence_name} connection failed"
            ) from None

        if status in {401, 403}:
            raise PolicyEvidenceAuthenticationError(
                f"{evidence_name} authentication failed with HTTP status {status}"
            )
        if status in {204, 404, 410}:
            raise PolicyEvidenceUnavailableError(f"{evidence_name} is unavailable")
        if status == 409:
            raise PolicyEvidenceUnavailableError(f"{evidence_name} state conflicts")
        if status == 429 or 500 <= status <= 599:
            raise PolicyEvidenceServerError(
                f"{evidence_name} service failed with HTTP status {status}"
            )
        if status != 200:
            raise PolicyEvidenceApiError(
                f"{evidence_name} rejected with HTTP status {status}"
            )
        if content_type.split(";", 1)[0].strip().lower() != "application/json":
            raise InvalidPolicyEvidenceResponse(
                f"{evidence_name} response content type is invalid"
            )
        if not body or len(body) > MAX_POLICY_EVIDENCE_BYTES:
            raise InvalidPolicyEvidenceResponse(
                f"{evidence_name} response size is invalid"
            )
        return body

    @staticmethod
    def _policy_identifier(value: str, field_name: str) -> str:
        if not isinstance(value, str) or not fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value
        ):
            raise ValueError(f"{field_name} is invalid")
        return value

    @classmethod
    def _parse_task(
        cls,
        body: bytes,
        current_agent_id: str,
        *,
        round_trip_seconds: float = 0.0,
        response_monotonic: float | None = None,
    ) -> Task:
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
        if scan_scope not in {"FULL", "PARTIAL"}:
            raise InvalidTaskError("task scan_scope is invalid")
        planned_item_count = payload.get("planned_item_count")
        if (
            not isinstance(planned_item_count, int)
            or isinstance(planned_item_count, bool)
            or planned_item_count < 1
        ):
            raise InvalidTaskError("task planned_item_count is invalid")
        item_ids = cls._string_list(payload.get("item_ids"), "item_ids")
        completed_item_ids = cls._string_list(
            payload.get("completed_item_ids"), "completed_item_ids", allow_empty=True
        )
        if len(item_ids) != len(set(item_ids)):
            raise InvalidTaskError("task item_ids contains duplicates")
        if len(completed_item_ids) != len(set(completed_item_ids)):
            raise InvalidTaskError("task completed_item_ids contains duplicates")
        if not set(completed_item_ids).issubset(item_ids):
            raise InvalidTaskError("task completed_item_ids is outside item_ids")
        if planned_item_count != len(item_ids):
            raise InvalidTaskError("task planned_item_count does not match item_ids")
        if scan_scope == "FULL" and planned_item_count != 67:
            raise InvalidTaskError("Unix FULL CHECK must contain 67 planned items")

        lease_until = required_string("lease_until")
        expires_at = required_string("expires_at")
        server_time = required_string("server_time")
        server_datetime = cls._parse_utc_deadline(server_time, "server_time")
        lease_datetime = cls._parse_utc_deadline(lease_until, "lease_until")
        expires_datetime = cls._parse_utc_deadline(expires_at, "expires_at")
        lease_duration = payload.get("lease_duration_sec")
        if (
            not isinstance(lease_duration, (int, float))
            or isinstance(lease_duration, bool)
        ):
            raise InvalidTaskError("task lease_duration_sec is invalid")
        if (
            lease_duration <= 0
            or lease_datetime <= server_datetime
            or lease_duration <= round_trip_seconds
        ):
            raise InvalidTaskError("task lease has expired")
        if expires_datetime <= server_datetime:
            raise InvalidTaskError("task has expired")
        response_monotonic = (
            time.monotonic() if response_monotonic is None else response_monotonic
        )
        safe_duration = float(lease_duration) - max(0.0, round_trip_seconds)
        lease_deadline_monotonic = response_monotonic + safe_duration

        module_version = required_string("module_version")
        if module_version != MODULE_VERSION:
            raise InvalidTaskError("task module_version does not match this Agent")
        simulation = payload.get("simulation")
        if not isinstance(simulation, bool):
            raise InvalidTaskError("task simulation flag is invalid")
        if simulation:
            raise InvalidTaskError("simulation tasks are not accepted by this Agent")
        settings = payload.get("settings")
        if not isinstance(settings, Mapping) or settings:
            raise InvalidTaskError("CHECK task settings must be empty")
        backup_id = cls._optional_string(payload.get("backup_id"), "backup_id")
        if backup_id is not None:
            raise InvalidTaskError("CHECK task backup_id must be null")
        execution_phase = required_string("execution_phase")
        if execution_phase != "CHECK":
            raise InvalidTaskError("task execution_phase is invalid")

        raw_authorization = payload.get("authorization")
        if not isinstance(raw_authorization, Mapping):
            raise InvalidTaskError("task authorization is required")
        grant_id = cls._optional_string(raw_authorization.get("grant_id"), "grant_id")
        approval_id = cls._optional_string(
            raw_authorization.get("approval_id"), "approval_id"
        )
        if grant_id is not None or approval_id is not None:
            raise InvalidTaskError("CHECK task authorization must be empty")

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
            item_ids=item_ids,
            completed_item_ids=completed_item_ids,
            module_version=module_version,
            server_time=server_time,
            lease_duration_sec=float(lease_duration),
            lease_deadline_monotonic=lease_deadline_monotonic,
            simulation=simulation,
            settings=dict(settings),
            backup_id=backup_id,
            execution_phase=execution_phase,
        )

    @classmethod
    def _parse_task_event_response(
        cls,
        body: bytes,
        *,
        expected_message_id: str,
        round_trip_seconds: float,
        response_monotonic: float,
    ) -> TaskEventResponse:
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise TaskEventError("invalid task event response") from None
        if not isinstance(payload, Mapping):
            raise TaskEventError("invalid task event response")

        def required_string(key: str) -> str:
            value = payload.get(key)
            if not isinstance(value, str) or not value.strip():
                raise TaskEventError("invalid task event response")
            return value.strip()

        accepted_message_id = required_string("accepted_message_id")
        if accepted_message_id != expected_message_id:
            raise TaskEventError("task event ACK does not match the request")
        server_time = required_string("server_time")
        lease_until = required_string("lease_until")
        received_at = required_string("received_at")
        try:
            server_datetime = cls._parse_utc_deadline(server_time, "server_time")
            cls._parse_utc_deadline(received_at, "received_at")
            lease_datetime = cls._parse_utc_deadline(lease_until, "lease_until")
        except InvalidTaskError:
            raise TaskEventError("invalid task event response") from None
        duration = payload.get("lease_duration_sec")
        if (
            not isinstance(duration, (int, float))
            or isinstance(duration, bool)
            or duration < 0
        ):
            raise TaskEventError("invalid task event response")
        safe_duration = max(0.0, float(duration) - max(0.0, round_trip_seconds))
        if duration > 0 and lease_datetime <= server_datetime:
            raise TaskEventError("invalid task event response")
        return TaskEventResponse(
            accepted_message_id=accepted_message_id,
            received_at=received_at,
            lease_until=lease_until,
            server_time=server_time,
            lease_duration_sec=float(duration),
            lease_deadline_monotonic=response_monotonic + safe_duration,
        )

    @staticmethod
    def _string_list(
        value: Any,
        field_name: str,
        *,
        allow_empty: bool = False,
    ) -> tuple[str, ...]:
        if not isinstance(value, list) or (not value and not allow_empty):
            raise InvalidTaskError(f"task field '{field_name}' is invalid")
        if any(not isinstance(item, str) or not item.strip() for item in value):
            raise InvalidTaskError(f"task field '{field_name}' is invalid")
        return tuple(item.strip() for item in value)

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
