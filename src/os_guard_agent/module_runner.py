"""Build validated module execution plans without executing modules."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from . import MODULE_VERSION
from .manifest import Manifest, ManifestError, validate_item_support
from .models import Action, CheckResult, OsInfo, ResultStatus, ReviewState, Task


class ModuleExecutionError(RuntimeError):
    """Raised when a trusted local module cannot produce a valid result."""


class ModuleNotFoundError(ModuleExecutionError):
    pass


class ModulePermissionError(ModuleExecutionError):
    pass


class ModuleTimeoutError(ModuleExecutionError):
    pass


class ModuleOutputError(ModuleExecutionError):
    pass


@dataclass(frozen=True)
class PlannedModule:
    item_id: str
    module_path: Path
    action: Action


@dataclass(frozen=True)
class ExecutionPlan:
    job_id: str
    manifest_id: str
    modules: tuple[PlannedModule, ...]


class ModuleRunner:
    """Validates task-to-module mappings; subprocess execution is intentionally absent."""

    def __init__(self, manifest: Manifest, os_info: OsInfo) -> None:
        self.manifest = manifest
        self.os_info = os_info

    def prepare_task(self, task: Task) -> ExecutionPlan:
        if task.manifest_id != self.manifest.manifest_id:
            raise ManifestError("Task manifest_id does not match loaded manifest")
        if task.action is not Action.CHECK:
            raise ManifestError("only CHECK tasks can be prepared in this Agent version")
        if task.scan_scope != "FULL":
            raise ManifestError("only FULL CHECK tasks can be prepared in this Agent version")

        if any(not item.implemented for item in self.manifest.items.values()):
            raise ManifestError("FULL CHECK is unavailable until all 67 modules are implemented")

        modules = tuple(
            self.prepare_item(item_id, task.action)
            for item_id in sorted(self.manifest.items)
        )
        if len(modules) != 67:
            raise ManifestError("FULL CHECK execution plan must contain 67 items")
        return ExecutionPlan(task.job_id, task.manifest_id, modules)

    def prepare_item(self, item_id: str, action: Action) -> PlannedModule:
        item = self.manifest.require_item(item_id)
        validate_item_support(item, self.os_info, action)
        if not item.implemented:
            raise ManifestError(f"module is not implemented: {item_id}")
        return PlannedModule(item.item_id, self.manifest.resolve_module(item), action)

    def execute_check(
        self, planned_module: PlannedModule, timeout_seconds: float = 15.0
    ) -> CheckResult:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")
        if planned_module.action is not Action.CHECK:
            raise ModuleExecutionError("only CHECK module execution is supported")

        item = self.manifest.require_item(planned_module.item_id)
        validate_item_support(item, self.os_info, Action.CHECK)
        if not item.implemented:
            raise ModuleExecutionError("module is not implemented")

        expected_path = self.manifest.resolve_module(item)
        supplied_path = planned_module.module_path.resolve()
        if supplied_path != expected_path:
            raise ModuleExecutionError("planned module path does not match trusted manifest")
        if not expected_path.exists() or not expected_path.is_file():
            raise ModuleNotFoundError("trusted module file is missing")
        if not os.access(expected_path, os.X_OK):
            raise ModulePermissionError("trusted module is not executable")

        environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LC_ALL": "C",
            "OS_GUARD_DISTRO": self.os_info.distro,
            "OS_GUARD_VERSION_ID": self.os_info.version_id,
            "OS_GUARD_MODULE_VERSION": MODULE_VERSION,
        }
        try:
            completed = subprocess.run(
                [str(expected_path)],
                shell=False,
                cwd=expected_path.parent,
                env=environment,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise ModuleTimeoutError("module execution timed out") from None
        except PermissionError:
            raise ModulePermissionError("trusted module execution was denied") from None
        except OSError:
            raise ModuleExecutionError("trusted module could not be executed") from None

        if completed.returncode != 0:
            raise ModuleExecutionError(
                f"module exited with non-zero status {completed.returncode}"
            )
        return self._parse_check_result(completed.stdout, planned_module.item_id)

    def _parse_check_result(self, stdout: str, expected_item_id: str) -> CheckResult:
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            raise ModuleOutputError("module stdout is not a single valid JSON object") from None
        if not isinstance(payload, Mapping):
            raise ModuleOutputError("module stdout JSON must be an object")

        if payload.get("item_id") != expected_item_id:
            raise ModuleOutputError("module result item_id does not match execution plan")
        raw_status = payload.get("status")
        try:
            status = None if raw_status is None else ResultStatus(raw_status)
        except ValueError:
            raise ModuleOutputError("module result status is invalid") from None
        try:
            review_state = ReviewState(payload.get("review_state"))
        except ValueError:
            raise ModuleOutputError("module result review_state is invalid") from None

        current_value = payload.get("current_value")
        evidence = payload.get("evidence")
        error = payload.get("error")
        if not isinstance(current_value, Mapping) or not isinstance(evidence, Mapping):
            raise ModuleOutputError("module result current_value or evidence is invalid")
        if error is not None and not isinstance(error, Mapping):
            raise ModuleOutputError("module result error is invalid")
        if evidence.get("item_id") != expected_item_id:
            raise ModuleOutputError("evidence item_id does not match execution plan")
        if evidence.get("module_version") != MODULE_VERSION:
            raise ModuleOutputError("evidence module_version does not match Agent")
        evidence_os = evidence.get("os")
        if not isinstance(evidence_os, Mapping) or (
            evidence_os.get("distro") != self.os_info.distro
            or evidence_os.get("version_id") != self.os_info.version_id
        ):
            raise ModuleOutputError("evidence OS does not match local detection")

        normalized_evidence = dict(evidence)
        # Kernel identity comes from the Agent's local OS detection rather than
        # module-controlled output, keeping Evidence consistent across modules.
        normalized_evidence["kernel"] = self.os_info.kernel

        return CheckResult(
            item_id=expected_item_id,
            status=status,
            review_state=review_state,
            current_value=dict(current_value),
            evidence=normalized_evidence,
            error=None if error is None else dict(error),
        )
