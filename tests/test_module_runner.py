from __future__ import annotations

import json
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from os_guard_agent.manifest import ManifestError, load_manifest
from os_guard_agent.models import Action, OsInfo, Task, TaskAuthorization
from os_guard_agent.module_runner import ModuleRunner


PROJECT_MANIFEST = Path(__file__).parents[1] / "modules" / "manifest.json"


def os_info() -> OsInfo:
    return OsInfo(
        distro="rocky",
        version="9.4",
        version_id="9.4",
        kernel="test",
        hostname="test",
        architecture="x86_64",
        supported=True,
    )


def task() -> Task:
    future = (
        (datetime.now(timezone.utc) + timedelta(minutes=5))
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )
    return Task(
        schema_version="2.0",
        job_id="job-1",
        scan_run_id="run-1",
        server_id="srv-1",
        agent_id="agt-1",
        action=Action.CHECK,
        scan_scope="FULL",
        attempt_id="attempt-1",
        planned_item_count=67,
        manifest_id="manifest-unix-67-v1",
        criteria_snapshot_id="criteria-1",
        lease_until=future,
        expires_at=future,
        authorization=TaskAuthorization(None, None),
        item_ids=tuple(f"U-{number:02d}" for number in range(1, 68)),
        module_version="unix-2026.1",
    )


class ModuleRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        manifest = load_manifest(PROJECT_MANIFEST, "manifest-unix-67-v1", os_info())
        self.runner = ModuleRunner(manifest, os_info())

    def test_full_check_plan_contains_all_67_modules(self) -> None:
        plan = self.runner.prepare_task(task())
        self.assertEqual(len(plan.modules), 67)
        self.assertEqual(plan.modules[0].item_id, "U-01")
        self.assertEqual(plan.modules[-1].item_id, "U-67")

    def test_partial_plan_runs_only_uncompleted_requested_items(self) -> None:
        partial = replace(
            task(),
            scan_scope="PARTIAL",
            planned_item_count=3,
            item_ids=("U-03", "U-01", "U-02"),
            completed_item_ids=("U-01",),
        )
        plan = self.runner.prepare_task(partial)
        self.assertEqual(
            tuple(module.item_id for module in plan.modules),
            ("U-03", "U-02"),
        )

    def test_safe_password_policy_booleans_remain_boolean_evidence(self) -> None:
        result = self.runner._parse_check_result(
            json.dumps(
                {
                    "item_id": "U-01",
                    "status": "GOOD",
                    "review_state": "NOT_REQUIRED",
                    "current_value": {
                        "password_protected": True,
                        "password_policy_enabled": False,
                    },
                    "evidence": {
                        "item_id": "U-01",
                        "module_version": "unix-2026.1",
                        "os": {"distro": "rocky", "version_id": "9.4"},
                        "password_protected": True,
                    },
                    "error": None,
                }
            ),
            "U-01",
        )
        self.assertIs(result.current_value["password_protected"], True)
        self.assertIs(result.current_value["password_policy_enabled"], False)
        self.assertIs(result.evidence["password_protected"], True)

    def test_u01_is_selected_from_local_manifest(self) -> None:
        planned = self.runner.prepare_item("U-01", Action.CHECK)
        self.assertEqual(planned.item_id, "U-01")
        self.assertEqual(planned.module_path.name, "U-01.sh")

    def test_unregistered_item_is_rejected(self) -> None:
        with self.assertRaisesRegex(ManifestError, "not registered"):
            self.runner.prepare_item("U-68", Action.CHECK)

    def test_disallowed_action_is_rejected(self) -> None:
        with self.assertRaisesRegex(ManifestError, "not allowed"):
            self.runner.prepare_item("U-01", Action.HARDEN)

    def test_all_registered_items_are_implemented(self) -> None:
        self.assertTrue(all(item.implemented for item in self.runner.manifest.items.values()))


if __name__ == "__main__":
    unittest.main()
