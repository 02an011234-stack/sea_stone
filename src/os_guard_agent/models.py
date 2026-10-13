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
    schema_version: str
    message_id: str
    sent_at: str
    enrollment_id: str
    agent_version: str
    hostname: str
    os: Mapping[str, str]
    capabilities: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        enrollment_id: str,
        agent_version: str,
        os_info: OsInfo,
    ) -> "EnrollmentRequest":
        return cls(
            schema_version="2.0",
            message_id=str(uuid4()),
            sent_at=datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            enrollment_id=enrollment_id,
            hostname=os_info.hostname,
            agent_version=agent_version,
            os={
                "family": "UNIX",
                "distribution": os_info.distro,
                "version": os_info.version_id,
                "name": os_info.version,
                "version_id": os_info.version_id,
                "kernel": os_info.kernel,
                "architecture": os_info.architecture,
            },
            capabilities=(Action.CHECK.value,),
        )


@dataclass(frozen=True)
class OperatingCredential:
    server_id: str
    agent_id: str
    credential_id: str
    token: str = field(repr=False)
    expires_at: str


@dataclass(frozen=True)
class CredentialRotation:
    credential: OperatingCredential
    rotation_id: str
    old_credential_id: str
    grace_until: str
    confirmation: str


class AgentHealth(str, Enum):
    READY = "READY"
    BUSY = "BUSY"
    DEGRADED = "DEGRADED"
    ERROR = "ERROR"


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


class CollectionStatus(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class CollectionError:
    code: str
    message: str


@dataclass(frozen=True)
class CollectionResult:
    status: CollectionStatus
    error: CollectionError | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "error": asdict(self.error) if self.error is not None else None,
        }


@dataclass(frozen=True)
class Inventory:
    schema_version: str
    message_id: str
    sent_at: str
    agent_id: str
    inventory_version: str
    hostname: str
    os: Mapping[str, Any]
    roles: tuple[str, ...]
    services: tuple[Mapping[str, Any], ...]
    platform: str
    agent_version: str
    module_version: str
    manifest_id: str
    collection: Mapping[str, CollectionResult]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "message_id": self.message_id,
            "sent_at": self.sent_at,
            "agent_id": self.agent_id,
            "inventory_version": self.inventory_version,
            "hostname": self.hostname,
            "os": dict(self.os),
            "roles": list(self.roles),
            "services": [dict(service) for service in self.services],
            "platform": self.platform,
            "agent_version": self.agent_version,
            "module_version": self.module_version,
            "manifest_id": self.manifest_id,
            "collection": {
                name: result.to_dict() for name, result in self.collection.items()
            },
        }


@dataclass(frozen=True)
class InventoryResponse:
    inventory_version: str
    received_at: str
    duplicate: bool


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
    item_ids: tuple[str, ...] = ()
    completed_item_ids: tuple[str, ...] = ()
    module_version: str = ""
    server_time: str = ""
    lease_duration_sec: float = 0.0
    lease_deadline_monotonic: float | None = field(default=None, repr=False)
    simulation: bool = False
    settings: Mapping[str, Any] = field(default_factory=dict)
    backup_id: str | None = None
    execution_phase: str = "CHECK"

    def lease_is_valid(self, monotonic_now: float) -> bool:
        return (
            self.lease_deadline_monotonic is not None
            and monotonic_now < self.lease_deadline_monotonic
        )


class TaskEvent(str, Enum):
    STARTED = "STARTED"
    PROGRESS = "PROGRESS"
    LEASE_RENEWAL = "LEASE_RENEWAL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class TaskEventResponse:
    accepted_message_id: str
    received_at: str
    lease_until: str
    server_time: str
    lease_duration_sec: float
    lease_deadline_monotonic: float


@dataclass(frozen=True)
class EvidenceUploadResponse:
    evidence_id: str
    sha256: str
    byte_length: int
    received_at: str | None = None
    duplicate: bool = False


@dataclass(frozen=True)
class ResultUploadResponse:
    accepted_ids: tuple[str, ...]
    duplicate_ids: tuple[str, ...]
    received_at: str


@dataclass(frozen=True)
class CheckResult:
    item_id: str
    status: ResultStatus | None
    review_state: ReviewState
    current_value: Mapping[str, Any]
    evidence: Mapping[str, Any]
    error: Mapping[str, Any] | None = None
