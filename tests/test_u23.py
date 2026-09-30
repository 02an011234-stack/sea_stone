from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from os_guard_agent import MODULE_VERSION
from os_guard_agent.manifest import load_manifest
from os_guard_agent.models import Action, OsInfo, ResultStatus, ReviewState
from os_guard_agent.module_runner import ModuleRunner, ModuleTimeoutError


ROOT = Path(__file__).parents[1]
MANIFEST = ROOT / "modules" / "manifest.json"
MODULE = ROOT / "modules" / "unix" / "U-23.sh"


def os_info(distro="rocky", version="9.6"):
    return OsInfo(distro, version, version, "fixture-kernel", "host", "x86_64", True)


def shell_path() -> str | None:
    found = shutil.which("sh")
    if found:
        return found
    for candidate in (Path(r"C:\Program Files\Git\bin\sh.exe"), Path(r"C:\Program Files\Git\usr\bin\sh.exe")):
        if candidate.is_file():
            return str(candidate)
    return None


def payload(distro="rocky", version="9.6"):
    return json.dumps({
        "item_id": "U-23", "status": "GOOD", "review_state": "NOT_REQUIRED",
        "current_value": {
            "scan_scope": "root_filesystem_root_owned_regular_files", "xdev_enabled": True,
            "scan_completed": True, "suid_count": 0, "sgid_count": 0,
            "suid_sgid_count": 0, "sticky_count": 0, "unresolved_count": 0,
            "scan_error_count": 0, "warning_count": 0, "manual_review_required": False,
            "verified_unnecessary_suid_count": 0, "verified_unnecessary_sgid_count": 0,
        },
        "evidence": {
            "item_id": "U-23", "scan_scope": "root_filesystem_root_owned_regular_files",
            "collection_method": "fixture", "xdev_enabled": True, "scan_completed": True,
            "suid_count": 0, "sgid_count": 0, "suid_sgid_count": 0,
            "sticky_count": 0, "unresolved_count": 0, "scan_error_count": 0,
            "warning_count": 0, "manual_review_required": False,
            "verified_unnecessary_suid_count": 0, "verified_unnecessary_sgid_count": 0,
            "reason_code": "KISA_U23_NO_SUID_OR_SGID_FOUND",
            "os": {"distro": distro, "version_id": version}, "kernel": "fixture-kernel",
            "module_version": MODULE_VERSION, "observed_at": "2026-09-29T00:00:00Z",
            "judgment_basis": "fixture",
        }, "error": None,
    })


class U23Tests(unittest.TestCase):
    def runner(self, distro="rocky", version="9.6"):
        detected = os_info(distro, version)
        return ModuleRunner(load_manifest(MANIFEST, "manifest-unix-67-v1", detected), detected)

    def run_real(self, record, *, distro="rocky", version="9.6"):
        executable = shell_path()
        if not executable:
            self.skipTest("POSIX shell is unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fixture = root / "u23-scan.fixture"
            fixture.write_text(record + "\n", encoding="utf-8", newline="\n")
            before = hashlib.sha256(fixture.read_bytes()).hexdigest()
            env = {
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
                "OS_GUARD_DISTRO": distro, "OS_GUARD_VERSION_ID": version,
                "OS_GUARD_MODULE_VERSION": MODULE_VERSION, "OS_GUARD_TEST_ROOT": str(root),
                "OS_GUARD_TEST_SCAN_FILE": str(fixture),
            }
            completed = subprocess.run([executable, str(MODULE)], env=env, capture_output=True, text=True, timeout=5, check=False)
            after = hashlib.sha256(fixture.read_bytes()).hexdigest()
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(before, after)
            return json.loads(completed.stdout), completed.stdout + completed.stderr

    def test_01_manifest_selects_u23(self):
        planned = self.runner().prepare_item("U-23", Action.CHECK)
        self.assertEqual(planned.module_path.name, "U-23.sh")
        self.assertEqual(planned.action, Action.CHECK)

    def test_02_no_suid_or_sgid_is_good(self):
        result, _ = self.run_real("complete|0|0|0|0|0|0|0|0")
        self.assertEqual(result["status"], "GOOD")
        self.assertEqual(result["review_state"], "NOT_REQUIRED")

    def test_03_suid_found_requires_manual_review(self):
        result, _ = self.run_real("complete|2|0|0|0|0|0|0|0")
        self.assertIsNone(result["status"])
        self.assertEqual(result["review_state"], "PENDING")
        self.assertTrue(result["current_value"]["manual_review_required"])

    def test_04_sgid_found_requires_manual_review(self):
        result, _ = self.run_real("complete|0|3|0|0|0|0|0|0")
        self.assertIsNone(result["status"])

    def test_05_suid_and_sgid_found_requires_manual_review(self):
        result, _ = self.run_real("complete|1|1|1|0|0|0|0|0")
        self.assertIsNone(result["status"])
        self.assertEqual(result["current_value"]["suid_sgid_count"], 1)

    def test_06_verified_unnecessary_suid_is_vulnerable(self):
        result, _ = self.run_real("complete|1|0|0|0|1|0|0|0")
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertEqual(result["review_state"], "NOT_REQUIRED")

    def test_07_verified_unnecessary_sgid_is_vulnerable(self):
        result, _ = self.run_real("complete|0|1|0|0|0|1|0|0")
        self.assertEqual(result["status"], "VULNERABLE")

    def test_08_scan_failure_is_uncheckable(self):
        result, _ = self.run_real("scan_error|0|0|0|0|0|0|0|0")
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "FILESYSTEM_SCAN_FAILED")

    def test_09_scan_timeout_is_uncheckable(self):
        result, _ = self.run_real("timeout|0|0|0|0|0|0|0|0")
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "FILESYSTEM_SCAN_TIMEOUT")

    def test_10_result_parse_failure_is_uncheckable(self):
        result, _ = self.run_real("complete|bad|0|0|0|0|0|0|0")
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "SCAN_RESULT_PARSE_FAILED")

    def test_11_nonimpacting_partial_warning_keeps_completed_good_result(self):
        result, _ = self.run_real("partial_warning|0|0|0|0|0|0|0|2")
        self.assertEqual(result["status"], "GOOD")
        self.assertTrue(result["current_value"]["scan_completed"])
        self.assertEqual(result["current_value"]["warning_count"], 2)

    def test_12_unresolved_result_is_uncheckable(self):
        result, _ = self.run_real("complete|0|0|0|0|0|0|1|0")
        self.assertEqual(result["status"], "UNCHECKABLE")

    def test_13_xdev_is_enabled(self):
        result, _ = self.run_real("complete|0|0|0|0|0|0|0|0")
        self.assertTrue(result["current_value"]["xdev_enabled"])
        self.assertIn("-xdev", MODULE.read_text(encoding="utf-8"))

    def test_14_scan_is_limited_to_root_owned_regular_files(self):
        source = MODULE.read_text(encoding="utf-8")
        self.assertIn("-user root -type f", source)
        self.assertIn("find_bin\" / -xdev", source)

    def test_15_sticky_only_is_not_vulnerable(self):
        result, _ = self.run_real("complete|0|0|0|4|0|0|0|0")
        self.assertEqual(result["status"], "GOOD")
        self.assertEqual(result["current_value"]["sticky_count"], 4)

    def test_16_no_os_specific_allowlist(self):
        source = MODULE.read_text(encoding="utf-8")
        for name in ("passwd", "sudo", "mount", "ping", "su"):
            self.assertNotIn(f"/{name}", source)

    def test_17_evidence_has_aggregate_counts(self):
        result, _ = self.run_real("complete|3|4|1|2|0|0|0|0")
        evidence = result["evidence"]
        self.assertEqual(evidence["suid_count"], 3)
        self.assertEqual(evidence["sgid_count"], 4)
        self.assertEqual(evidence["suid_sgid_count"], 1)
        for key in ("scan_scope", "xdev_enabled", "scan_completed", "unresolved_count",
                    "scan_error_count", "manual_review_required", "os", "kernel",
                    "module_version", "observed_at", "reason_code", "judgment_basis"):
            self.assertIn(key, evidence)

    def test_18_paths_and_file_contents_are_not_exposed(self):
        result, output = self.run_real("complete|2|1|0|0|0|0|0|0")
        self.assertIsNone(result["status"])
        self.assertNotIn("/usr/bin/example", output)
        self.assertNotIn("PRIVATE_FILE_CONTENT", output)
        self.assertNotIn("u23-scan.fixture", output)

    def test_19_no_command_injection_input(self):
        source = MODULE.read_text(encoding="utf-8")
        self.assertNotIn("OS_GUARD_COMMAND", source)
        self.assertNotIn("eval ", source)
        self.assertIn('"$find_bin" / -xdev', source)

    def test_20_single_json_stdout_and_read_only(self):
        result, output = self.run_real("complete|0|0|0|0|0|0|0|0")
        self.assertEqual(output.count("\n"), 1)
        self.assertEqual(result["item_id"], "U-23")
        source = MODULE.read_text(encoding="utf-8")
        self.assertNotRegex(source, r"(?m)^\s*(chmod|chown|chgrp|rm|mv|touch|tee|systemctl|service|apt|dnf|yum)\b")
        self.assertNotIn("sed -i", source)

    def test_21_rocky_9_fixture(self): self.assertEqual(self.run_real("complete|0|0|0|0|0|0|0|0", distro="rocky", version="9.6")[0]["status"], "GOOD")
    def test_22_rocky_10_fixture(self): self.assertEqual(self.run_real("complete|1|0|0|0|0|0|0|0", distro="rocky", version="10.0")[0]["review_state"], "PENDING")
    def test_23_ubuntu_22_fixture(self): self.assertEqual(self.run_real("complete|0|1|0|0|0|0|0|0", distro="ubuntu", version="22.04")[0]["review_state"], "PENDING")
    def test_24_ubuntu_24_fixture(self): self.assertEqual(self.run_real("complete|0|0|0|1|0|0|0|0", distro="ubuntu", version="24.04")[0]["status"], "GOOD")

    def test_25_unsupported_os_is_uncheckable(self):
        result, _ = self.run_real("complete|0|0|0|0|0|0|0|0", distro="debian", version="12")
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "UNSUPPORTED_OS_CONFIGURATION")

    def test_26_no_na_status_is_invented(self):
        for record in ("complete|0|0|0|0|0|0|0|0", "complete|1|0|0|0|0|0|0|0", "scan_error|0|0|0|0|0|0|0|0"):
            with self.subTest(record=record):
                self.assertNotEqual(self.run_real(record)[0]["status"], "N/A")

    def test_27_vulnerability_has_priority_over_incomplete_scan(self):
        result, _ = self.run_real("scan_error|1|0|0|0|1|0|0|0")
        self.assertEqual(result["status"], "VULNERABLE")

    def test_28_counts_are_nonnegative_integers(self):
        result, _ = self.run_real("complete|1|2|0|3|0|0|0|0")
        for key in ("suid_count", "sgid_count", "suid_sgid_count", "sticky_count", "unresolved_count", "scan_error_count"):
            self.assertIsInstance(result["current_value"][key], int)
            self.assertGreaterEqual(result["current_value"][key], 0)

    def test_29_runner_contract(self):
        runner = self.runner(); planned = runner.prepare_item("U-23", Action.CHECK)
        completed = subprocess.CompletedProcess([str(MODULE)], 0, payload(), "")
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run", return_value=completed,
        ) as run:
            parsed = runner.execute_check(planned)
        self.assertEqual(parsed.status, ResultStatus.GOOD)
        self.assertEqual(parsed.review_state, ReviewState.NOT_REQUIRED)
        self.assertFalse(run.call_args.kwargs["shell"])

    def test_30_runner_timeout(self):
        runner = self.runner(); planned = runner.prepare_item("U-23", Action.CHECK)
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run", side_effect=subprocess.TimeoutExpired("U-23", 1),
        ):
            with self.assertRaises(ModuleTimeoutError):
                runner.execute_check(planned, timeout_seconds=1)


if __name__ == "__main__":
    unittest.main()
