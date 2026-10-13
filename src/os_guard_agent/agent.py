"""Agent process skeleton."""

from __future__ import annotations

import logging
import threading
import time
from uuid import uuid4

from . import MODULE_VERSION, __version__
from .api_client import ApiClient, ApiClientError, HeartbeatError
from .config import AgentConfig
from .check_transport import (
    CheckTransportError,
    enqueue_check_result,
    enqueue_event,
    flush_outbox,
    utc_now,
)
from .inventory import build_inventory
from .manifest import ManifestError, load_manifest
from .models import (
    CheckResult,
    EnrollmentRequest,
    Heartbeat,
    OperatingCredential,
    ResultStatus,
    ReviewState,
    Task,
    TaskEvent,
)
from .module_runner import ExecutionPlan, ModuleExecutionError, ModuleRunner
from .os_detect import detect_os
from .outbox import OutboxError, OutboxStore
from .token_store import TokenStore, TokenStoreError

LOGGER = logging.getLogger(__name__)


class Agent:
    """Agent lifecycle for authenticated read-only CHECK communication."""

    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self._stop_event = threading.Event()
        self.claimed_task: Task | None = None
        self.execution_plan: ExecutionPlan | None = None

    def enroll(
        self,
        enrollment_id: str,
        enrollment_token: str,
        expected_server_id: str | None = None,
    ) -> OperatingCredential:
        os_info = detect_os()
        request = EnrollmentRequest.create(
            enrollment_id=enrollment_id,
            agent_version=__version__,
            os_info=os_info,
        )
        credential = ApiClient(
            self.config.central_server_url,
            self.config.request_timeout_seconds,
        ).enroll(enrollment_token, request)
        if expected_server_id is not None and credential.server_id != expected_server_id:
            raise ApiClientError(
                "Enrollment response server_id does not match registration file"
            )
        TokenStore(self.config.token_store_path).save(credential)
        LOGGER.info(
            "Agent enrollment completed (server_id=%s, agent_id=%s, credential_id=%s)",
            credential.server_id,
            credential.agent_id,
            credential.credential_id,
        )
        return credential

    def rotate_credential(self) -> OperatingCredential:
        """Stage a new credential before using it to trigger Central confirmation."""

        store = TokenStore(self.config.token_store_path)
        previous = store.load()
        client = ApiClient(
            self.config.central_server_url,
            self.config.request_timeout_seconds,
        )
        rotation = client.rotate_credential(previous)
        store.stage_rotation(
            previous,
            rotation.credential,
            rotation_id=rotation.rotation_id,
            grace_until=rotation.grace_until,
        )
        inventory = build_inventory(rotation.credential.agent_id, detect_os())
        heartbeat = Heartbeat.ready(
            agent_id=rotation.credential.agent_id,
            agent_version=__version__,
            module_version=MODULE_VERSION,
            inventory_version=inventory.inventory_version,
        )
        client.send_heartbeat(rotation.credential, heartbeat)
        store.confirm_rotation(rotation.credential.credential_id)
        LOGGER.info(
            "Operating credential rotation confirmed (credential_id=%s)",
            rotation.credential.credential_id,
        )
        return rotation.credential

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> int:
        token_store = TokenStore(self.config.token_store_path)
        try:
            credential = token_store.load()
            pending_rotation = token_store.pending_rotation()
        except TokenStoreError as exc:
            LOGGER.error("Agent credentials unavailable: %s", exc)
            return 1

        os_info = detect_os()
        LOGGER.info(
            "OS Guard Unix Agent %s initialized (agent_id=%s)",
            __version__,
            credential.agent_id,
        )
        LOGGER.info(
            "Detected OS distro=%s version_id=%s kernel=%s architecture=%s supported=%s",
            os_info.distro,
            os_info.version_id,
            os_info.kernel,
            os_info.architecture,
            os_info.supported,
        )
        if not os_info.supported:
            LOGGER.warning("Unsupported OS: %s", os_info.unsupported_reason)

        client = ApiClient(
            self.config.central_server_url,
            self.config.request_timeout_seconds,
        )
        inventory = build_inventory(credential.agent_id, os_info)
        outbox = OutboxStore(self.config.outbox_path)
        try:
            outbox.initialize()
        except OutboxError as exc:
            LOGGER.error("Transfer outbox unavailable: %s", exc)
            return 1
        inventory_pending = True
        next_heartbeat = time.monotonic()
        next_claim = time.monotonic()
        while not self._stop_event.is_set():
            now = time.monotonic()
            if now >= next_heartbeat:
                heartbeat = Heartbeat.ready(
                    agent_id=credential.agent_id,
                    agent_version=__version__,
                    module_version=MODULE_VERSION,
                    inventory_version=inventory.inventory_version,
                )
                try:
                    client.send_heartbeat(credential, heartbeat)
                    LOGGER.info("Heartbeat accepted (message_id=%s)", heartbeat.message_id)
                    if pending_rotation is not None:
                        try:
                            token_store.confirm_rotation(credential.credential_id)
                        except TokenStoreError as exc:
                            LOGGER.error(
                                "Credential rotation confirmation could not be stored: %s",
                                exc,
                            )
                            return 1
                        pending_rotation = None
                        LOGGER.info(
                            "Pending credential rotation confirmed (credential_id=%s)",
                            credential.credential_id,
                        )
                    if inventory_pending:
                        client.send_inventory(credential, inventory)
                        inventory_pending = False
                        LOGGER.info(
                            "Inventory accepted (inventory_version=%s)",
                            inventory.inventory_version,
                        )
                except HeartbeatError as exc:
                    LOGGER.warning("Heartbeat failed: %s", exc)
                except ApiClientError as exc:
                    LOGGER.warning("Inventory failed: %s", exc)
                next_heartbeat = time.monotonic() + self.config.heartbeat_interval_seconds

            if self._stop_event.is_set():
                break

            transfer_failed = False
            try:
                flushed = flush_outbox(outbox, client, credential)
                if flushed:
                    LOGGER.info("Recovered and acknowledged %d outbox request(s)", flushed)
            except (ApiClientError, OutboxError, CheckTransportError) as exc:
                LOGGER.warning("Pending transfer retry failed: %s", exc)
                transfer_failed = True
                next_claim = time.monotonic() + self.config.task_claim_interval_seconds

            now = time.monotonic()
            if now >= next_claim and self.claimed_task is None and not transfer_failed:
                try:
                    task = client.claim_task(credential)
                    if task is not None:
                        removed = outbox.discard_stale_attempt(
                            task.job_id,
                            task.attempt_id,
                        )
                        if removed:
                            LOGGER.info(
                                "Discarded %d stale-attempt outbox request(s) (job_id=%s)",
                                removed,
                                task.job_id,
                            )
                        manifest = load_manifest(
                            self.config.manifest_path, task.manifest_id, os_info
                        )
                        execution_plan = ModuleRunner(manifest, os_info).prepare_task(task)
                        self.claimed_task = task
                        self.execution_plan = execution_plan
                        LOGGER.info(
                            "Validated CHECK task claimed (job_id=%s, attempt_id=%s, manifest_id=%s)",
                            task.job_id,
                            task.attempt_id,
                            task.manifest_id,
                        )
                        self._run_check_task(
                            task,
                            execution_plan,
                            ModuleRunner(manifest, os_info),
                            outbox,
                            client,
                            credential,
                            os_info,
                        )
                        self.claimed_task = None
                        self.execution_plan = None
                except (ApiClientError, ManifestError) as exc:
                    LOGGER.warning("Task claim failed: %s", exc)
                    self.claimed_task = None
                    self.execution_plan = None
                except (OutboxError, CheckTransportError) as exc:
                    LOGGER.warning("CHECK transfer deferred: %s", exc)
                    self.claimed_task = None
                    self.execution_plan = None
                next_claim = time.monotonic() + self.config.task_claim_interval_seconds

            wait_until = next_heartbeat
            if self.claimed_task is None:
                wait_until = min(wait_until, next_claim)
            wait_seconds = max(0.0, wait_until - time.monotonic())
            self._stop_event.wait(wait_seconds)

        LOGGER.info("Heartbeat loop stopped")
        return 0

    def _run_check_task(
        self,
        task: Task,
        plan: ExecutionPlan,
        runner: ModuleRunner,
        outbox: OutboxStore,
        client: ApiClient,
        credential: OperatingCredential,
        os_info,
    ) -> None:
        enqueue_event(
            outbox,
            task,
            TaskEvent.STARTED,
            processed_item_count=0,
        )
        flush_outbox(outbox, client, credential)

        transfer_ids = {
            module.item_id: {
                "evidence_message_id": str(uuid4()),
                "evidence_id": str(uuid4()),
                "result_message_id": str(uuid4()),
                "result_id": str(uuid4()),
            }
            for module in plan.modules
        }
        result_dependencies = tuple(
            transfer_ids[module.item_id]["result_message_id"] for module in plan.modules
        )
        completion_entry = enqueue_event(
            outbox,
            task,
            TaskEvent.COMPLETED,
            processed_item_count=task.planned_item_count,
            dependencies=result_dependencies,
        )

        processed = len(task.completed_item_ids)
        for module in plan.modules:
            if self._stop_event.is_set():
                outbox.discard(completion_entry)
                return
            if not task.lease_is_valid(time.monotonic()):
                LOGGER.warning(
                    "CHECK lease expired before item execution (job_id=%s, item_id=%s)",
                    task.job_id,
                    module.item_id,
                )
                outbox.discard(completion_entry)
                return
            try:
                result = runner.execute_check(module)
            except ModuleExecutionError:
                result = CheckResult(
                    item_id=module.item_id,
                    status=ResultStatus.UNCHECKABLE,
                    review_state=ReviewState.NOT_REQUIRED,
                    current_value={},
                    evidence={
                        "item_id": module.item_id,
                        "reason_code": f"KISA_{module.item_id.replace('-', '_')}_COLLECTION_FAILED",
                        "observed_at": utc_now(),
                        "module_version": MODULE_VERSION,
                        "os": {
                            "distro": os_info.distro,
                            "version_id": os_info.version_id,
                        },
                    },
                    error={
                        "code": "MODULE_EXECUTION_FAILED",
                        "message": "Local CHECK module execution failed",
                    },
                )
            ids = transfer_ids[module.item_id]
            try:
                enqueue_check_result(outbox, task, result, **ids)
            except CheckTransportError:
                outbox.discard(completion_entry)
                enqueue_event(
                    outbox,
                    task,
                    TaskEvent.FAILED,
                    processed_item_count=processed,
                    error={
                        "code": "RESULT_CONTRACT_INVALID",
                        "message": "Local CHECK result could not be safely transmitted",
                    },
                )
                flush_outbox(outbox, client, credential)
                raise
            flush_outbox(outbox, client, credential)
            processed += 1
            LOGGER.info(
                "CHECK result acknowledged (job_id=%s, item_id=%s, processed=%d)",
                task.job_id,
                module.item_id,
                processed,
            )

        flush_outbox(outbox, client, credential)
        LOGGER.info(
            "CHECK completion acknowledged (job_id=%s, attempt_id=%s)",
            task.job_id,
            task.attempt_id,
        )
