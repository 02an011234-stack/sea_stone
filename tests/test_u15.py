from __future__ import annotations

import hashlib
import json
import os
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
MODULE = ROOT / "modules" / "unix" / "U-15.sh"


def os_info(distro="rocky", version="9.6"):
    return OsInfo(distro, version, version, "fixture-kernel", "host", "x86_64", True)


def shell_path() -> str | None:
    found = shutil.which("sh")
    if found:
        return found
    for candidate in (
        Path(r"C:\Program Files\Git\bin\sh.exe"),
        Path(r"C:\Program Files\Git\usr\bin\sh.exe"),
    ):
        if candidate.is_file():
            return str(candidate)
    return None


def payload(distro="rocky", version="9.6", status="GOOD", review="NOT_REQUIRED"):
    return json.dumps({
        "item_id": "U-15", "status": status, "review_state": review,
        "current_value": {
            "scan_target": "/", "scan_scope": "root_filesystem_only",
            "scan_attempted": True, "scan_complete": True,
            "orphaned_entry_found": False, "observed_match_count": 0,
            "first_match_type": "none", "find_exit_code": 0,
        },
        "evidence": {
            "item_id": "U-15", "inspection_target": "Root filesystem files and directories",
            "collection_method": "fixture", "assessment_condition": "fixture",
            "scan_success": True,
            "observed_summary": {"orphaned_entry_found": False, "observed_match_count": 0},
            "reason_code": "KISA_U15_NO_ORPHANED_OWNER_OR_GROUP",
            "os": {"distro": distro, "version_id": version},
            "kernel": "fixture-kernel", "module_version": MODULE_VERSION,
            "observed_at": "2026-09-28T00:00:00Z", "decision_reason": "fixture",
        }, "error": None,
    })


class U15Tests(unittest.TestCase):
    def runner(self, distro="rocky", version="9.6"):
        detected = os_info(distro, version)
        return ModuleRunner(load_manifest(MANIFEST, "manifest-unix-67-v1", detected), detected)

    def run_real(self, mode="none", distro="rocky", version="9.6"):
        executable = shell_path()
        if not executable:
            self.skipTest("POSIX shell is unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            fake_find = bin_dir / "find"
            fake_find.write_text(
                """#!/bin/sh
case "${OS_GUARD_TEST_FIND_MODE:-none}" in
  none) exit 0 ;;
  file) printf 'f\\n'; exit 0 ;;
  directory) printf 'd\\n'; exit 0 ;;
  symlink) printf 'l\\n'; exit 0 ;;
  partial_match) printf 'f\\n'; printf 'PRIVATE_SCAN_ERROR\\n' >&2; exit 1 ;;
  error) printf 'PRIVATE_SCAN_ERROR\\n' >&2; exit 1 ;;
  malformed) printf '/private/orphan/path\\n'; exit 0 ;;
  *) exit 65 ;;
esac
""",
                encoding="utf-8",
                newline="\n",
            )
            fake_find.chmod(0o755)
            if os.name == "nt":
                converted = subprocess.run(
                    [executable, "-lc", 'cygpath -u "$1"', "sh", str(bin_dir)],
                    capture_output=True, text=True, timeout=5, check=True,
                ).stdout.strip()
                fixture_path = converted
            else:
                fixture_path = str(bin_dir)
            before = hashlib.sha256(fake_find.read_bytes()).hexdigest()
            env = {
                "PATH": f"{fixture_path}:/usr/sbin:/usr/bin:/sbin:/bin",
                "LC_ALL": "C", "OS_GUARD_DISTRO": distro,
                "OS_GUARD_VERSION_ID": version,
                "OS_GUARD_MODULE_VERSION": MODULE_VERSION,
                "OS_GUARD_TEST_ROOT": str(root),
                "OS_GUARD_TEST_FIND_BIN": str(fake_find),
                "OS_GUARD_TEST_FIND_MODE": mode,
            }
            completed = subprocess.run(
                [executable, str(MODULE)], env=env, capture_output=True, text=True,
                timeout=5, check=False,
            )
            after = hashlib.sha256(fake_find.read_bytes()).hexdigest()
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(before, after)
            return json.loads(completed.stdout), completed.stdout + completed.stderr

    def test_01_manifest_selects_u15(self):
        planned = self.runner().prepare_item("U-15", Action.CHECK)
        self.assertEqual(planned.module_path.name, "U-15.sh")

    def test_02_complete_scan_without_match_is_good(self):
        result, _ = self.run_real("none")
        self.assertEqual(result["status"], "GOOD")
        self.assertEqual(result["review_state"], "NOT_REQUIRED")
        self.assertTrue(result["current_value"]["scan_complete"])

    def test_03_orphaned_file_is_vulnerable(self):
        result, _ = self.run_real("file")
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertEqual(result["current_value"]["first_match_type"], "regular_file")

    def test_04_orphaned_directory_is_vulnerable(self):
        result, _ = self.run_real("directory")
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertEqual(result["current_value"]["first_match_type"], "directory")

    def test_05_orphaned_symlink_is_vulnerable(self):
        result, _ = self.run_real("symlink")
        self.assertEqual(result["status"], "VULNERABLE")

    def test_06_known_match_has_priority_over_incomplete_scan(self):
        result, output = self.run_real("partial_match")
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertFalse(result["current_value"]["scan_complete"])
        self.assertNotIn("PRIVATE_SCAN_ERROR", output)

    def test_07_scan_failure_without_match_is_uncheckable(self):
        result, output = self.run_real("error")
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "FILESYSTEM_SCAN_INCOMPLETE")
        self.assertNotIn("PRIVATE_SCAN_ERROR", output)

    def test_08_malformed_find_output_is_uncheckable_without_path_leak(self):
        result, output = self.run_real("malformed")
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "FIND_OUTPUT_INVALID")
        self.assertNotIn("/private/orphan/path", output)

    def test_09_pending_and_na_are_not_invented(self):
        for mode, expected in (("none", "GOOD"), ("file", "VULNERABLE"), ("error", "UNCHECKABLE")):
            with self.subTest(mode=mode):
                result, _ = self.run_real(mode)
                self.assertEqual(result["status"], expected)
                self.assertNotEqual(result["review_state"], "PENDING")
                self.assertNotEqual(result["status"], "N/A")

    def test_10_evidence_contract_and_summary_only(self):
        result, output = self.run_real("file")
        evidence = result["evidence"]
        self.assertEqual(evidence["item_id"], "U-15")
        self.assertEqual(evidence["os"], {"distro": "rocky", "version_id": "9.6"})
        self.assertIn("kernel", evidence)
        self.assertEqual(evidence["module_version"], MODULE_VERSION)
        self.assertIn("observed_at", evidence)
        self.assertIn("reason_code", evidence)
        self.assertNotIn("path_list", output)
        self.assertNotIn(str(Path.home()), output)

    def test_11_stdout_is_one_json_object(self):
        result, output = self.run_real("none")
        self.assertEqual(output.count("\n"), 1)
        self.assertEqual(result["item_id"], "U-15")

    def test_12_rocky_9_fixture(self):
        result, _ = self.run_real("none", "rocky", "9.6")
        self.assertEqual(result["status"], "GOOD")

    def test_13_rocky_10_fixture(self):
        result, _ = self.run_real("directory", "rocky", "10.0")
        self.assertEqual(result["status"], "VULNERABLE")

    def test_14_ubuntu_22_fixture(self):
        result, _ = self.run_real("file", "ubuntu", "22.04")
        self.assertEqual(result["status"], "VULNERABLE")

    def test_15_ubuntu_24_fixture(self):
        result, _ = self.run_real("none", "ubuntu", "24.04")
        self.assertEqual(result["status"], "GOOD")

    def test_16_unsupported_os_is_uncheckable(self):
        result, _ = self.run_real("none", "debian", "12")
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "UNSUPPORTED_OS_CONFIGURATION")

    def test_17_runner_contract_and_timeout(self):
        runner = self.runner()
        planned = runner.prepare_item("U-15", Action.CHECK)
        completed = subprocess.CompletedProcess([str(MODULE)], 0, payload(), "")
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run", return_value=completed,
        ) as run:
            parsed = runner.execute_check(planned)
        self.assertEqual(parsed.status, ResultStatus.GOOD)
        self.assertEqual(parsed.review_state, ReviewState.NOT_REQUIRED)
        self.assertFalse(run.call_args.kwargs["shell"])
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run",
            side_effect=subprocess.TimeoutExpired("U-15", 1),
        ):
            with self.assertRaises(ModuleTimeoutError):
                runner.execute_check(planned, timeout_seconds=1)

    def test_18_source_is_read_only_and_uses_fixed_find_predicates(self):
        source = MODULE.read_text(encoding="utf-8")
        self.assertIn("-nouser", source)
        self.assertIn("-nogroup", source)
        self.assertIn("-xdev", source)
        self.assertIn("-quit", source)
        self.assertNotRegex(
            source,
            r"(?m)^\s*(chmod|chown|chgrp|rm|mv|touch|systemctl|service|usermod|useradd|userdel|apt|dnf|yum)\b",
        )
        self.assertNotIn("sed -i", source)
        self.assertNotRegex(source, r"(?m)^\s*echo\b.*>>")


if __name__ == "__main__":
    unittest.main()
