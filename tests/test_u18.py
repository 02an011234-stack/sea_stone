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
MODULE = ROOT / "modules" / "unix" / "U-18.sh"


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
        "item_id": "U-18", "status": "GOOD", "review_state": "NOT_REQUIRED",
        "current_value": {
            "target": "/etc/shadow", "file_exists": True, "file_type": "regular_file",
            "owner_is_root": True, "owner_uid_is_zero": True, "owner_name_state": "root",
            "permission_octal": "400", "permission_within_0400": True,
            "extra_permission_bits_detected": False, "metadata_collection_success": True,
            "manual_review_required": False,
        },
        "evidence": {
            "item_id": "U-18", "target": "/etc/shadow",
            "inspection_target": "/etc/shadow file metadata", "collection_method": "fixture",
            "assessment_condition": "fixture", "file_exists": True,
            "file_type": "regular_file", "owner_is_root": True,
            "owner_uid_is_zero": True, "owner_name_state": "root",
            "permission_octal": "400", "permission_within_0400": True,
            "extra_permission_bits_detected": False, "metadata_collection_success": True,
            "reason_code": "KISA_U18_ROOT_OWNER_AND_PERMISSION_ALLOWED",
            "os": {"distro": distro, "version_id": version},
            "kernel": "fixture-kernel", "module_version": MODULE_VERSION,
            "observed_at": "2026-09-29T00:00:00Z", "decision_reason": "fixture",
        }, "error": None,
    })


class U18Tests(unittest.TestCase):
    def runner(self, distro="rocky", version="9.6"):
        detected = os_info(distro, version)
        return ModuleRunner(load_manifest(MANIFEST, "manifest-unix-67-v1", detected), detected)

    def run_real(
        self, metadata="0|root|400", *, stat_exit=0, distro="rocky", version="9.6",
        file_type="regular", create_target=True,
    ):
        executable = shell_path()
        if not executable:
            self.skipTest("POSIX shell is unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "etc" / "shadow"
            target.parent.mkdir(parents=True)
            secret = "root:$6$PRIVATE_SALT$PRIVATE_HASH:19000:0:99999:7:::\n"
            if create_target:
                if file_type == "directory":
                    target.mkdir()
                else:
                    target.write_text(secret, encoding="utf-8", newline="\n")

            fake_stat = root / "stat-fixture"
            fake_stat.write_text(
                """#!/bin/sh
if [ "${OS_GUARD_TEST_STAT_EXIT:-0}" -ne 0 ]; then
  printf 'PRIVATE_STAT_ERROR\\n' >&2
  exit "${OS_GUARD_TEST_STAT_EXIT}"
fi
printf '%s\\n' "${OS_GUARD_TEST_STAT_OUTPUT}"
""",
                encoding="utf-8", newline="\n",
            )
            fake_stat.chmod(0o755)
            tracked = [fake_stat]
            if target.is_file():
                tracked.append(target)
            before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in tracked}
            env = {
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
                "OS_GUARD_DISTRO": distro, "OS_GUARD_VERSION_ID": version,
                "OS_GUARD_MODULE_VERSION": MODULE_VERSION,
                "OS_GUARD_TEST_ROOT": str(root),
                "OS_GUARD_TEST_STAT_BIN": str(fake_stat),
                "OS_GUARD_TEST_STAT_OUTPUT": metadata,
                "OS_GUARD_TEST_STAT_EXIT": str(stat_exit),
            }
            completed = subprocess.run(
                [executable, str(MODULE)], env=env, capture_output=True, text=True,
                timeout=5, check=False,
            )
            after = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in tracked}
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(before, after)
            return json.loads(completed.stdout), completed.stdout + completed.stderr

    def test_01_manifest_selects_u18(self):
        self.assertEqual(self.runner().prepare_item("U-18", Action.CHECK).module_path.name, "U-18.sh")

    def test_02_root_0400_is_good(self):
        result, _ = self.run_real("0|root|400")
        self.assertEqual(result["status"], "GOOD")
        self.assertTrue(result["current_value"]["permission_within_0400"])

    def test_03_root_0000_is_good(self):
        result, _ = self.run_real("0|root|000")
        self.assertEqual(result["status"], "GOOD")

    def test_04_non_root_owner_is_vulnerable(self):
        result, _ = self.run_real("1000|user|400")
        self.assertEqual(result["status"], "VULNERABLE")

    def assert_permission_vulnerable(self, mode):
        result, _ = self.run_real(f"0|root|{mode}")
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertTrue(result["current_value"]["extra_permission_bits_detected"])

    def test_05_owner_write_0600_is_vulnerable(self):
        self.assert_permission_vulnerable("600")

    def test_06_owner_execute_0500_is_vulnerable(self):
        self.assert_permission_vulnerable("500")

    def test_07_group_read_0440_is_vulnerable(self):
        self.assert_permission_vulnerable("440")

    def test_08_other_read_0404_is_vulnerable(self):
        self.assert_permission_vulnerable("404")

    def test_09_group_write_0420_is_vulnerable(self):
        self.assert_permission_vulnerable("420")

    def test_10_other_write_0402_is_vulnerable(self):
        self.assert_permission_vulnerable("402")

    def test_11_root_0640_is_vulnerable(self):
        self.assert_permission_vulnerable("640")

    def test_12_root_0644_is_vulnerable(self):
        self.assert_permission_vulnerable("644")

    def test_13_root_0777_is_vulnerable(self):
        self.assert_permission_vulnerable("777")

    def test_14_owner_and_permission_both_vulnerable(self):
        result, _ = self.run_real("1000|user|777")
        self.assertEqual(result["status"], "VULNERABLE")

    def test_15_special_permission_bit_is_vulnerable(self):
        self.assert_permission_vulnerable("4400")

    def test_16_missing_shadow_is_uncheckable(self):
        result, _ = self.run_real(create_target=False)
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "SHADOW_FILE_NOT_FOUND")

    def test_17_stat_failure_is_uncheckable_without_stderr_leak(self):
        result, output = self.run_real(stat_exit=1)
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "STAT_COMMAND_FAILED")
        self.assertNotIn("PRIVATE_STAT_ERROR", output)

    def test_18_metadata_parse_failure_is_uncheckable(self):
        for metadata in ("", "root|400", "zero|root|400", "0|root|888"):
            with self.subTest(metadata=metadata):
                result, _ = self.run_real(metadata)
                self.assertEqual(result["status"], "UNCHECKABLE")
                self.assertEqual(result["error"]["code"], "STAT_OUTPUT_INVALID")

    def test_19_uid_name_conflict_is_pending(self):
        for owner_name in ("UNKNOWN", "administrator"):
            with self.subTest(owner_name=owner_name):
                result, _ = self.run_real(f"0|{owner_name}|400")
                self.assertIsNone(result["status"])
                self.assertEqual(result["review_state"], "PENDING")
                self.assertTrue(result["current_value"]["manual_review_required"])

    def test_20_nonstandard_file_type_is_pending(self):
        result, _ = self.run_real("0|root|400", file_type="directory")
        self.assertIsNone(result["status"])
        self.assertEqual(result["review_state"], "PENDING")

    def test_21_rocky_9_fixture(self):
        result, _ = self.run_real("0|root|400", distro="rocky", version="9.6")
        self.assertEqual(result["status"], "GOOD")

    def test_22_rocky_10_fixture(self):
        result, _ = self.run_real("0|root|000", distro="rocky", version="10.0")
        self.assertEqual(result["status"], "GOOD")

    def test_23_ubuntu_22_fixture(self):
        result, _ = self.run_real("0|root|640", distro="ubuntu", version="22.04")
        self.assertEqual(result["status"], "VULNERABLE")

    def test_24_ubuntu_24_fixture(self):
        result, _ = self.run_real("0|root|640", distro="ubuntu", version="24.04")
        self.assertEqual(result["status"], "VULNERABLE")

    def test_25_evidence_is_metadata_only_and_complete(self):
        result, output = self.run_real("0|root|400")
        evidence = result["evidence"]
        self.assertEqual(evidence["item_id"], "U-18")
        self.assertEqual(evidence["target"], "/etc/shadow")
        self.assertTrue(evidence["owner_is_root"])
        self.assertEqual(evidence["permission_octal"], "400")
        self.assertTrue(evidence["permission_within_0400"])
        self.assertEqual(evidence["os"], {"distro": "rocky", "version_id": "9.6"})
        self.assertEqual(evidence["module_version"], MODULE_VERSION)
        self.assertIn("kernel", evidence)
        self.assertIn("observed_at", evidence)
        self.assertIn("reason_code", evidence)
        for secret in ("PRIVATE_SALT", "PRIVATE_HASH", "$6$", "/bin/bash"):
            self.assertNotIn(secret, output)

    def test_26_single_json_stdout_and_check_is_read_only(self):
        result, output = self.run_real("0|root|400")
        self.assertEqual(output.count("\n"), 1)
        self.assertEqual(result["item_id"], "U-18")
        source = MODULE.read_text(encoding="utf-8")
        self.assertNotRegex(
            source,
            r"(?m)^\s*(chmod|chown|chgrp|rm|mv|touch|passwd|usermod|systemctl|service|apt|dnf|yum)\b",
        )
        self.assertNotIn("sed -i", source)
        self.assertNotRegex(source, r"(?m)^\s*echo\b.*>>")

    def test_27_unsupported_os_is_uncheckable(self):
        result, _ = self.run_real("0|root|400", distro="debian", version="12")
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "UNSUPPORTED_OS_CONFIGURATION")

    def test_28_runner_contract_timeout_and_no_na(self):
        runner = self.runner(); planned = runner.prepare_item("U-18", Action.CHECK)
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
            side_effect=subprocess.TimeoutExpired("U-18", 1),
        ):
            with self.assertRaises(ModuleTimeoutError):
                runner.execute_check(planned, timeout_seconds=1)


if __name__ == "__main__":
    unittest.main()
