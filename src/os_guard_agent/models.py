"""Shared Agent data models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping
from uuid import uuid4


class Action(str, Enum):
    CHECK = "CHECK"
    HARDEN = "HARDEN"
    RECHECK = "RECHECK"
    ROLLBACK = "ROLLBACK"


class ResultStatus(str, Enum):
    GOOD = "GOOD"
    VULNERABLE = "VULNERABLE"
    NOT_APPLICABLE = "N/A"
    UNCHECKABLE = "UNCHECKABLE"


class ReviewState(str, Enum):
    PENDING = "PENDING"
    CONFIRMED = "CONFIRMED"
    NOT_REQUIRED = "NOT_REQUIRED"


@dataclass(frozen=True)
class OsInfo:
    distro: str
    version: str
    version_id: str
    kernel: str
    hostname: str
    architecture: str
    supported: bool
    unsupported_reason: str | None = None


@dataclass(frozen=True)
class EnrollmentRequest:
    agent_version: str
    hostname: str
    distro: str
    version: str
    version_id: str
    kernel: str
    architecture: str


@dataclass(frozen=True)
class OperatingCredential:
    server_id: str
    agent_id: str
    credential_id: str
    token: str = field(repr=False)
    expires_at: str


class AgentHealth(str, Enum):
    READY = "READY"
    BUSY = "BUSY"
    DEGRADED = "DEGRADED"


@dataclass(frozen=True)
class Heartbeat:
    schema_version: str
    message_id: str
    sent_at: str
    agent_id: str
    agent_version: str
    module_version: str
    inventory_version: str
    active_job_id: str | None
    health: AgentHealth
    pending_result_count: int

    @classmethod
    def ready(
        cls,
        *,
        agent_id: str,
        agent_version: str,
        module_version: str,
        inventory_version: str,
    ) -> "Heartbeat":
        return cls(
            schema_version="2.0",
            message_id=str(uuid4()),
            sent_at=datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            agent_id=agent_id,
            agent_version=agent_version,
            module_version=module_version,
            inventory_version=inventory_version,
            active_job_id=None,
            health=AgentHealth.READY,
            pending_result_count=0,
        )

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["health"] = self.health.value
        return payload


@dataclass(frozen=True)
class HeartbeatResponse:
    received_at: str
    poll_after_sec: int | None = None


@dataclass(frozen=True)
class TaskAuthorization:
    grant_id: str | None
    approval_id: str | None


@dataclass(frozen=True)
class Task:
    schema_version: str
    job_id: str
    scan_run_id: str
    server_id: str
    agent_id: str
    action: Action
    scan_scope: str
    attempt_id: str
    planned_item_count: int
    manifest_id: str
    criteria_snapshot_id: str
    lease_until: str
    expires_at: str
    authorization: TaskAuthorization


@dataclass(frozen=True)
class CheckResult:
    item_id: str
    status: ResultStatus | None
    review_state: ReviewState
    current_value: Mapping[str, Any]
    evidence: Mapping[str, Any]
    error: Mapping[str, Any] | None = None
