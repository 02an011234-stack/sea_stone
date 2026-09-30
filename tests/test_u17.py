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
MODULE = ROOT / "modules" / "unix" / "U-17.sh"


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


def payload(distro="rocky", version="9.6"):
    return json.dumps({
        "item_id": "U-17", "status": "GOOD", "review_state": "NOT_REQUIRED",
        "current_value": {
            "startup_system_type": "systemd", "scan_completed": True,
            "checked_object_count": 1, "regular_file_count": 1,
            "symlink_count": 0, "root_owned_count": 1,
            "non_root_owned_count": 0, "writable_by_non_owner_count": 0,
            "group_write_detected_count": 0, "other_write_detected_count": 0,
            "unresolved_object_count": 0, "vulnerable_object_detected": False,
        },
        "evidence": {
            "item_id": "U-17", "inspection_target": "startup files",
            "collection_method": "fixture", "assessment_condition": "fixture",
            "startup_system_type": "systemd", "scan_completed": True,
            "checked_object_count": 1, "regular_file_count": 1,
            "symlink_count": 0, "root_owned_count": 1,
            "non_root_owned_count": 0, "writable_by_non_owner_count": 0,
            "group_write_detected_count": 0, "other_write_detected_count": 0,
            "unresolved_object_count": 0, "owner_identity_conflict_count": 0,
            "group_write_review_count": 0, "vulnerable_object_detected": False,
            "reason_code": "KISA_U17_ROOT_OWNER_AND_NON_OWNER_WRITE_BLOCKED",
            "os": {"distro": distro, "version_id": version},
            "kernel": "fixture-kernel", "module_version": MODULE_VERSION,
            "observed_at": "2026-09-29T00:00:00Z", "decision_reason": "fixture",
        }, "error": None,
    })


class U17Tests(unittest.TestCase):
    def runner(self, distro="rocky", version="9.6"):
        detected = os_info(distro, version)
        return ModuleRunner(load_manifest(MANIFEST, "manifest-unix-67-v1", detected), detected)

    def run_real(self, records, *, distro="rocky", version="9.6", startup="systemd"):
        executable = shell_path()
        if not executable:
            self.skipTest("POSIX shell is unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "etc").mkdir()
            (root / "etc" / "passwd").write_text(
                "root:x:0:0:root:/root:/bin/bash\n", encoding="utf-8", newline="\n"
            )
            (root / "etc" / "group").write_text(
                "root:x:0:\n", encoding="utf-8", newline="\n"
            )
            scan_file = root / "u17-scan.fixture"
            scan_file.write_text("\n".join(records) + ("\n" if records else ""), encoding="utf-8", newline="\n")
            tracked = (root / "etc" / "passwd", root / "etc" / "group", scan_file)
            before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in tracked}
            env = {
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
                "OS_GUARD_DISTRO": distro, "OS_GUARD_VERSION_ID": version,
                "OS_GUARD_MODULE_VERSION": MODULE_VERSION,
                "OS_GUARD_TEST_ROOT": str(root),
                "OS_GUARD_TEST_SCAN_FILE": str(scan_file),
                "OS_GUARD_TEST_STARTUP_SYSTEM": startup,
            }
            completed = subprocess.run(
                [executable, str(MODULE)], env=env, capture_output=True, text=True,
                timeout=5, check=False,
            )
            after = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in tracked}
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(before, after)
            return json.loads(completed.stdout), completed.stdout + completed.stderr

    def test_01_manifest_selects_u17(self):
        self.assertEqual(self.runner().prepare_item("U-17", Action.CHECK).module_path.name, "U-17.sh")

    def test_02_root_owner_without_non_owner_write_is_good(self):
        result, _ = self.run_real(["regular|0|root|0|root|755|none"])
        self.assertEqual(result["status"], "GOOD")
        self.assertEqual(result["review_state"], "NOT_REQUIRED")

    def test_03_non_root_owner_is_vulnerable(self):
        result, _ = self.run_real(["regular|1000|operator|1000|users|755|none"])
        self.assertEqual(result["status"], "VULNERABLE")

    def test_04_other_write_is_vulnerable(self):
        result, _ = self.run_real(["regular|0|root|0|root|757|none"])
        self.assertEqual(result["status"], "VULNERABLE")

    def test_05_multiple_safe_files_are_good(self):
        result, _ = self.run_real([
            "regular|0|root|0|root|755|none", "regular|0|root|0|root|644|none",
        ])
        self.assertEqual(result["status"], "GOOD")
        self.assertEqual(result["current_value"]["checked_object_count"], 2)

    def test_06_one_non_root_file_makes_the_result_vulnerable(self):
        result, _ = self.run_real([
            "regular|0|root|0|root|755|none", "regular|1001|user|1001|users|755|none",
        ])
        self.assertEqual(result["status"], "VULNERABLE")

    def test_07_one_writable_file_makes_the_result_vulnerable(self):
        result, _ = self.run_real([
            "regular|0|root|0|root|755|none", "regular|0|root|0|root|646|none",
        ])
        self.assertEqual(result["status"], "VULNERABLE")

    def test_08_good_and_vulnerable_mix_preserves_vulnerable(self):
        result, _ = self.run_real([
            "regular|0|root|0|root|644|none", "regular|1002|user|100|users|666|confirmed_non_owner",
        ])
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertTrue(result["current_value"]["vulnerable_object_detected"])

    def test_09_systemd_regular_unit_is_assessed(self):
        result, _ = self.run_real(["regular|0|root|0|root|644|none"], startup="systemd")
        self.assertEqual(result["status"], "GOOD")
        self.assertEqual(result["current_value"]["startup_system_type"], "systemd")

    def test_10_normal_symlink_uses_target_metadata(self):
        result, _ = self.run_real(["symlink|0|root|0|root|644|none"])
        self.assertEqual(result["status"], "GOOD")
        self.assertEqual(result["current_value"]["symlink_count"], 1)
        self.assertEqual(result["current_value"]["regular_file_count"], 1)

    def test_11_broken_symlink_requires_review(self):
        result, _ = self.run_real(["regular|0|root|0|root|644|none", "broken_symlink||||||"])
        self.assertIsNone(result["status"])
        self.assertEqual(result["review_state"], "PENDING")

    def test_12_group_write_with_confirmed_non_owner_is_vulnerable(self):
        result, _ = self.run_real(["regular|0|root|100|operators|775|confirmed_non_owner"])
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertEqual(result["current_value"]["group_write_detected_count"], 1)

    def test_13_root_group_write_without_non_root_member_is_good(self):
        result, _ = self.run_real(["regular|0|root|0|root|775|none"])
        self.assertEqual(result["status"], "GOOD")

    def test_14_unresolved_group_write_requires_review(self):
        result, _ = self.run_real(["regular|0|root|100|operators|775|unknown"])
        self.assertIsNone(result["status"])
        self.assertEqual(result["review_state"], "PENDING")

    def test_15_owner_uid_and_name_conflict_requires_review(self):
        result, _ = self.run_real(["regular|0|administrator|0|root|755|none"])
        self.assertIsNone(result["status"])
        self.assertEqual(result["evidence"]["owner_identity_conflict_count"], 1)

    def test_16_metadata_failure_is_uncheckable(self):
        result, _ = self.run_real(["metadata_error||||||"])
        self.assertEqual(result["status"], "UNCHECKABLE")

    def test_17_partial_scan_failure_does_not_hide_vulnerability(self):
        result, _ = self.run_real(["scan_error||||||", "regular|1000|user|1000|users|755|none"])
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertFalse(result["current_value"]["scan_completed"])

    def test_18_scan_failure_without_vulnerability_is_uncheckable(self):
        result, _ = self.run_real(["regular|0|root|0|root|755|none", "scan_error||||||"])
        self.assertEqual(result["status"], "UNCHECKABLE")

    def test_19_empty_scan_is_uncheckable(self):
        result, _ = self.run_real([])
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "NO_STARTUP_OBJECTS_FOUND")

    def test_20_four_supported_os_fixtures(self):
        fixtures = (("rocky", "9.6"), ("rocky", "10.0"), ("ubuntu", "22.04"), ("ubuntu", "24.04"))
        for distro, version in fixtures:
            with self.subTest(distro=distro, version=version):
                result, _ = self.run_real(["regular|0|root|0|root|755|none"], distro=distro, version=version)
                self.assertEqual(result["status"], "GOOD")
                self.assertEqual(result["evidence"]["os"], {"distro": distro, "version_id": version})

    def test_21_evidence_aggregate_counts_are_exact(self):
        result, _ = self.run_real([
            "regular|0|root|0|root|755|none",
            "symlink|1000|user|100|users|757|confirmed_non_owner",
            "masked_symlink||||||", "broken_symlink||||||",
        ])
        evidence = result["evidence"]
        self.assertEqual(evidence["checked_object_count"], 2)
        self.assertEqual(evidence["regular_file_count"], 2)
        self.assertEqual(evidence["symlink_count"], 3)
        self.assertEqual(evidence["root_owned_count"], 1)
        self.assertEqual(evidence["non_root_owned_count"], 1)
        self.assertEqual(evidence["other_write_detected_count"], 1)
        self.assertEqual(evidence["unresolved_object_count"], 1)

    def test_22_file_contents_and_paths_are_not_exposed(self):
        secret = "PRIVATE_UNIT_COMMAND_OR_TOKEN"
        result, output = self.run_real(["regular|0|root|0|root|755|none"])
        self.assertEqual(result["status"], "GOOD")
        self.assertNotIn(secret, output)
        self.assertNotIn("u17-scan.fixture", output)
        self.assertNotIn(str(Path.home()), output)

    def test_23_single_json_stdout_and_read_only_source(self):
        result, output = self.run_real(["regular|0|root|0|root|755|none"])
        self.assertEqual(output.count("\n"), 1)
        self.assertEqual(result["item_id"], "U-17")
        source = MODULE.read_text(encoding="utf-8")
        self.assertNotRegex(
            source,
            r"(?m)^\s*(chmod|chown|chgrp|rm|mv|touch|systemctl|service|usermod|useradd|userdel|apt|dnf|yum)\b",
        )
        self.assertNotIn("sed -i", source)
        self.assertNotRegex(source, r"(?m)^\s*echo\b.*>>")

    def test_24_unsupported_os_is_uncheckable(self):
        result, _ = self.run_real(["regular|0|root|0|root|755|none"], distro="debian", version="12")
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "UNSUPPORTED_OS_CONFIGURATION")

    def test_25_runner_contract_timeout_and_no_na(self):
        runner = self.runner(); planned = runner.prepare_item("U-17", Action.CHECK)
        completed = subprocess.CompletedProcess([str(MODULE)], 0, payload(), "")
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run", return_value=completed,
        ) as run:
            parsed = runner.execute_check(planned)
        self.assertEqual(parsed.status, ResultStatus.GOOD)
        self.assertEqual(parsed.review_state, ReviewState.NOT_REQUIRED)
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertNotEqual(parsed.status.value, "N/A")
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run",
            side_effect=subprocess.TimeoutExpired("U-17", 1),
        ):
            with self.assertRaises(ModuleTimeoutError):
                runner.execute_check(planned, timeout_seconds=1)


if __name__ == "__main__":
    unittest.main()
