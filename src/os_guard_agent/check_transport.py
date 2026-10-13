"""Canonical CHECK Evidence/Result/Event transport with durable retries."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Mapping
from uuid import uuid4

from .api_client import ApiClient
from .models import CheckResult, OperatingCredential, ResultStatus, ReviewState, Task, TaskEvent
from .outbox import OutboxEntry, OutboxStore


class CheckTransportError(RuntimeError):
    """Raised when a local result cannot satisfy the Central contract."""


STATUS_MAP = {
    ResultStatus.GOOD: "PASS",
    ResultStatus.VULNERABLE: "FAIL",
    ResultStatus.NOT_APPLICABLE: "NA",
    ResultStatus.UNCHECKABLE: "UNABLE",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def envelope(agent_id: str) -> dict[str, str]:
    return {
        "schema_version": "2.0",
        "message_id": str(uuid4()),
        "sent_at": utc_now(),
        "agent_id": agent_id,
    }


def enqueue_event(
    outbox: OutboxStore,
    task: Task,
    event: TaskEvent,
    *,
    processed_item_count: int,
    dependencies: tuple[str, ...] = (),
    error: Mapping[str, Any] | None = None,
) -> OutboxEntry:
    payload: dict[str, Any] = {
        **envelope(task.agent_id),
        "attempt_id": task.attempt_id,
        "event": event.value,
        "processed_item_count": processed_item_count,
        "requested_lease_until": None,
        "error": None if error is None else dict(error),
    }
    return outbox.enqueue(
        "event",
        payload,
        route=task.job_id,
        dependencies=dependencies,
    )


def enqueue_check_result(
    outbox: OutboxStore,
    task: Task,
    result: CheckResult,
    *,
    evidence_message_id: str | None = None,
    evidence_id: str | None = None,
    result_message_id: str | None = None,
    result_id: str | None = None,
) -> str:
    if result.review_state is ReviewState.CONFIRMED:
        raise CheckTransportError("Agent cannot submit CONFIRMED review_state")
    canonical_status = None if result.status is None else STATUS_MAP[result.status]
    if result.status is None and result.review_state is not ReviewState.PENDING:
        raise CheckTransportError("null status requires PENDING review_state")
    if result.status is not None and result.review_state is not ReviewState.NOT_REQUIRED:
        raise CheckTransportError("automatic status requires NOT_REQUIRED review_state")

    observed_at = result.evidence.get("observed_at")
    if not isinstance(observed_at, str) or not observed_at:
        observed_at = utc_now()
    reason_code = result.evidence.get("reason_code")
    if not isinstance(reason_code, str) or not reason_code:
        reason_code = _fallback_reason_code(result)

    evidence_id = evidence_id or str(uuid4())
    evidence_payload = dict(result.evidence)
    _reject_obvious_secret_values(evidence_payload)
    evidence_bytes = json.dumps(
        evidence_payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(evidence_bytes) > 1024 * 1024:
        raise CheckTransportError("evidence exceeds the one MiB limit")
    evidence_metadata: dict[str, Any] = {
        **envelope(task.agent_id),
        "evidence_id": evidence_id,
        "server_id": task.server_id,
        "scan_run_id": task.scan_run_id,
        "attempt_id": task.attempt_id,
        "item_id": result.item_id,
        "collector_id": f"{result.item_id}.collect.v1",
        "captured_at": observed_at,
        "redacted": True,
        "media_type": "application/json",
        "sha256": hashlib.sha256(evidence_bytes).hexdigest(),
        "byte_length": len(evidence_bytes),
    }
    if evidence_message_id is not None:
        evidence_metadata["message_id"] = evidence_message_id
    evidence_entry = outbox.enqueue(
        "evidence",
        evidence_metadata,
        route=task.job_id,
        content=evidence_bytes,
    )

    auto_stage_state = "FAILED" if result.error is not None else "COMPLETED"
    if auto_stage_state == "FAILED" and canonical_status != "UNABLE":
        raise CheckTransportError("failed collection must have UNCHECKABLE status")
    result_payload: dict[str, Any] = {
        **envelope(task.agent_id),
        "server_id": task.server_id,
        "job_id": task.job_id,
        "scan_run_id": task.scan_run_id,
        "attempt_id": task.attempt_id,
        "result_id": result_id or str(uuid4()),
        "item_id": result.item_id,
        "criteria_snapshot_id": task.criteria_snapshot_id,
        "status": canonical_status,
        "review_state": result.review_state.value,
        "auto_stage_state": auto_stage_state,
        "reason_code": reason_code,
        "observed_at": observed_at,
        "evidence_ids": [evidence_id],
        "current_value": dict(result.current_value),
        "error": None if result.error is None else dict(result.error),
    }
    if result_message_id is not None:
        result_payload["message_id"] = result_message_id
    result_entry = outbox.enqueue(
        "result",
        result_payload,
        route=task.job_id,
        dependencies=(evidence_entry.message_id,),
    )
    return result_entry.message_id


def flush_outbox(
    outbox: OutboxStore,
    client: ApiClient,
    credential: OperatingCredential,
) -> int:
    """Send ready entries once; failures retain the immutable entry for retry."""

    acknowledged = 0
    while True:
        ready = outbox.ready_entries()
        if not ready:
            return acknowledged
        progress = False
        for entry in ready:
            ack = _send_entry(client, credential, entry)
            outbox.acknowledge(entry, ack)
            acknowledged += 1
            progress = True
        if not progress:
            return acknowledged


def _send_entry(
    client: ApiClient,
    credential: OperatingCredential,
    entry: OutboxEntry,
) -> Mapping[str, Any]:
    if entry.kind == "evidence":
        if entry.content is None:
            raise CheckTransportError("evidence outbox entry has no content")
        return asdict(client.upload_evidence(credential, entry.payload, entry.content))
    if entry.kind == "result":
        if entry.route is None:
            raise CheckTransportError("result outbox entry has no job route")
        return asdict(client.upload_result(credential, entry.route, entry.payload))
    if entry.kind == "event":
        if entry.route is None:
            raise CheckTransportError("event outbox entry has no job route")
        return asdict(client.send_task_event_payload(credential, entry.route, entry.payload))
    raise CheckTransportError("unknown outbox entry kind")


def _fallback_reason_code(result: CheckResult) -> str:
    item = result.item_id.replace("-", "_")
    if result.status is ResultStatus.GOOD:
        suffix = "COMPLIANT"
    elif result.status is ResultStatus.VULNERABLE:
        suffix = "NON_COMPLIANT"
    elif result.status is ResultStatus.NOT_APPLICABLE:
        suffix = "NOT_APPLICABLE"
    elif result.status is ResultStatus.UNCHECKABLE:
        suffix = "COLLECTION_FAILED"
    else:
        suffix = "REVIEW_REQUIRED"
    return f"KISA_{item}_{suffix}"


def _reject_obvious_secret_values(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = str(key).lower()
            if normalized in {"token", "credential", "private_key", "secret"}:
                raise CheckTransportError("evidence contains a forbidden secret field")
            if normalized in {"password_protected", "password_policy_enabled"}:
                if not isinstance(nested, bool):
                    raise CheckTransportError("safe password policy field must be boolean")
            _reject_obvious_secret_values(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_obvious_secret_values(nested)
    elif isinstance(value, str):
        lowered = value.lower()
        if "-----begin private key-----" in lowered or lowered.startswith("bearer "):
            raise CheckTransportError("evidence contains an obvious secret value")
