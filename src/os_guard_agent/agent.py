"""Agent process skeleton."""

from __future__ import annotations

import logging
import threading
import time

from . import MODULE_VERSION, __version__
from .api_client import ApiClient, ApiClientError, HeartbeatError
from .config import AgentConfig
from .manifest import ManifestError, load_manifest
from .models import EnrollmentRequest, Heartbeat, OperatingCredential, Task
from .module_runner import ExecutionPlan, ModuleRunner
from .os_detect import detect_os
from .token_store import TokenStore, TokenStoreError

LOGGER = logging.getLogger(__name__)


class Agent:
    """Minimal Agent lifecycle without remote communication."""

    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self._stop_event = threading.Event()
        self.claimed_task: Task | None = None
        self.execution_plan: ExecutionPlan | None = None

    def enroll(self, enrollment_token: str) -> OperatingCredential:
        os_info = detect_os()
        request = EnrollmentRequest(
            agent_version=__version__,
            hostname=os_info.hostname,
            distro=os_info.distro,
            version=os_info.version,
            version_id=os_info.version_id,
            kernel=os_info.kernel,
            architecture=os_info.architecture,
        )
        credential = ApiClient(
            self.config.central_server_url,
            self.config.request_timeout_seconds,
        ).enroll(enrollment_token, request)
        TokenStore(self.config.token_store_path).save(credential)
        LOGGER.info(
            "Agent enrollment completed (server_id=%s, agent_id=%s, credential_id=%s)",
            credential.server_id,
            credential.agent_id,
            credential.credential_id,
        )
        return credential

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> int:
        try:
            credential = TokenStore(self.config.token_store_path).load()
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
        next_heartbeat = time.monotonic()
        next_claim = time.monotonic()
        while not self._stop_event.is_set():
            now = time.monotonic()
            if now >= next_heartbeat:
                heartbeat = Heartbeat.ready(
                    agent_id=credential.agent_id,
                    agent_version=__version__,
                    module_version=MODULE_VERSION,
                    inventory_version=self.config.inventory_version,
                )
                try:
                    client.send_heartbeat(credential, heartbeat)
                    LOGGER.info("Heartbeat accepted (message_id=%s)", heartbeat.message_id)
                except HeartbeatError as exc:
                    LOGGER.warning("Heartbeat failed: %s", exc)
                next_heartbeat = time.monotonic() + self.config.heartbeat_interval_seconds

            if self._stop_event.is_set():
                break

            now = time.monotonic()
            if now >= next_claim and self.claimed_task is None:
                try:
                    task = client.claim_task(credential)
                    if task is not None:
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
                except (ApiClientError, ManifestError) as exc:
                    LOGGER.warning("Task claim failed: %s", exc)
                next_claim = time.monotonic() + self.config.task_claim_interval_seconds

            wait_until = next_heartbeat
            if self.claimed_task is None:
                wait_until = min(wait_until, next_claim)
            wait_seconds = max(0.0, wait_until - time.monotonic())
            self._stop_event.wait(wait_seconds)

        LOGGER.info("Heartbeat loop stopped")
        return 0
