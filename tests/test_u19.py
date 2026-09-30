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
MODULE = ROOT / "modules" / "unix" / "U-19.sh"


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
        "item_id": "U-19", "status": "GOOD", "review_state": "NOT_REQUIRED",
        "current_value": {
            "target": "/etc/hosts", "file_exists": True, "file_type": "regular_file",
            "owner_is_root": True, "owner_uid_is_zero": True, "owner_name_state": "root",
            "permission_octal": "644", "permission_within_0644": True,
            "extra_permission_bits_detected": False, "metadata_collection_success": True,
            "manual_review_required": False,
        },
        "evidence": {
            "item_id": "U-19", "target": "/etc/hosts", "inspection_target": "/etc/hosts file metadata",
            "collection_method": "fixture", "assessment_condition": "fixture",
            "file_exists": True, "file_type": "regular_file", "metadata_collection_success": True,
            "owner_is_root": True, "owner_uid_is_zero": True, "permission_octal": "644",
            "permission_within_0644": True, "extra_permission_bits_detected": False,
            "reason_code": "KISA_U19_ROOT_OWNER_AND_PERMISSION_ALLOWED",
            "os": {"distro": distro, "version_id": version}, "kernel": "fixture-kernel",
            "module_version": MODULE_VERSION, "observed_at": "2026-09-29T00:00:00Z",
            "judgment_basis": "fixture",
        }, "error": None,
    })


class U19Tests(unittest.TestCase):
    def runner(self, distro="rocky", version="9.6"):
        detected = os_info(distro, version)
        return ModuleRunner(load_manifest(MANIFEST, "manifest-unix-67-v1", detected), detected)

    def run_real(self, metadata="0|root|644", *, stat_exit=0, distro="rocky", version="9.6", file_type="regular", create_target=True):
        executable = shell_path()
        if not executable:
            self.skipTest("POSIX shell is unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "etc" / "hosts"
            target.parent.mkdir(parents=True)
            secret = "192.0.2.10 PRIVATE_HOST_MAPPING\n"
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
""", encoding="utf-8", newline="\n",
            )
            fake_stat.chmod(0o755)
            tracked = [fake_stat]
            if target.is_file():
                tracked.append(target)
            before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in tracked}
            env = {
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
                "OS_GUARD_DISTRO": distro, "OS_GUARD_VERSION_ID": version,
                "OS_GUARD_MODULE_VERSION": MODULE_VERSION, "OS_GUARD_TEST_ROOT": str(root),
                "OS_GUARD_TEST_STAT_BIN": str(fake_stat), "OS_GUARD_TEST_STAT_OUTPUT": metadata,
                "OS_GUARD_TEST_STAT_EXIT": str(stat_exit),
            }
            completed = subprocess.run([executable, str(MODULE)], env=env, capture_output=True, text=True, timeout=5, check=False)
            after = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in tracked}
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(before, after)
            return json.loads(completed.stdout), completed.stdout + completed.stderr

    def test_01_manifest_selects_u19(self):
        self.assertEqual(self.runner().prepare_item("U-19", Action.CHECK).module_path.name, "U-19.sh")

    def assert_good(self, mode):
        result, _ = self.run_real(f"0|root|{mode}")
        self.assertEqual(result["status"], "GOOD")
        self.assertTrue(result["current_value"]["permission_within_0644"])

    def assert_vulnerable(self, mode):
        result, _ = self.run_real(f"0|root|{mode}")
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertTrue(result["current_value"]["extra_permission_bits_detected"])

    def test_02_root_0644_is_good(self): self.assert_good("644")
    def test_03_root_0640_is_good(self): self.assert_good("640")
    def test_04_root_0600_is_good(self): self.assert_good("600")
    def test_05_root_0444_is_good(self): self.assert_good("444")
    def test_06_root_0400_is_good(self): self.assert_good("400")
    def test_07_root_0000_is_good(self): self.assert_good("000")

    def test_08_non_root_owner_is_vulnerable(self):
        result, _ = self.run_real("1000|user|644")
        self.assertEqual(result["status"], "VULNERABLE")

    def test_09_root_0664_is_vulnerable(self): self.assert_vulnerable("664")
    def test_10_root_0646_is_vulnerable(self): self.assert_vulnerable("646")
    def test_11_root_0654_is_vulnerable(self): self.assert_vulnerable("654")
    def test_12_root_0744_is_vulnerable(self): self.assert_vulnerable("744")
    def test_13_root_0755_is_vulnerable(self): self.assert_vulnerable("755")
    def test_14_root_0777_is_vulnerable(self): self.assert_vulnerable("777")

    def test_15_owner_and_permission_are_both_vulnerable(self):
        result, _ = self.run_real("1000|user|777")
        self.assertEqual(result["status"], "VULNERABLE")

    def test_16_special_permission_bit_is_vulnerable(self): self.assert_vulnerable("4644")

    def test_17_missing_hosts_is_uncheckable(self):
        result, _ = self.run_real(create_target=False)
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "HOSTS_FILE_NOT_FOUND")

    def test_18_stat_failure_is_uncheckable_without_stderr_leak(self):
        result, output = self.run_real(stat_exit=1)
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "STAT_COMMAND_FAILED")
        self.assertNotIn("PRIVATE_STAT_ERROR", output)

    def test_19_permission_parse_failure_is_uncheckable(self):
        for metadata in ("", "root|644", "zero|root|644", "0|root|888"):
            with self.subTest(metadata=metadata):
                result, _ = self.run_real(metadata)
                self.assertEqual(result["status"], "UNCHECKABLE")
                self.assertEqual(result["error"]["code"], "STAT_OUTPUT_INVALID")

    def test_20_uid_name_conflict_is_pending(self):
        for owner_name in ("UNKNOWN", "administrator"):
            with self.subTest(owner_name=owner_name):
                result, _ = self.run_real(f"0|{owner_name}|644")
                self.assertIsNone(result["status"])
                self.assertEqual(result["review_state"], "PENDING")

    def test_21_nonstandard_file_type_is_pending(self):
        result, _ = self.run_real("0|root|644", file_type="directory")
        self.assertIsNone(result["status"])
        self.assertEqual(result["review_state"], "PENDING")

    def test_22_rocky_9_fixture(self):
        result, _ = self.run_real("0|root|644", distro="rocky", version="9.6")
        self.assertEqual(result["status"], "GOOD")

    def test_23_rocky_10_fixture(self):
        result, _ = self.run_real("0|root|640", distro="rocky", version="10.0")
        self.assertEqual(result["status"], "GOOD")

    def test_24_ubuntu_22_fixture(self):
        result, _ = self.run_real("0|root|600", distro="ubuntu", version="22.04")
        self.assertEqual(result["status"], "GOOD")

    def test_25_ubuntu_24_fixture(self):
        result, _ = self.run_real("0|root|444", distro="ubuntu", version="24.04")
        self.assertEqual(result["status"], "GOOD")

    def test_26_evidence_is_metadata_only_and_complete(self):
        result, output = self.run_real("0|root|644")
        evidence = result["evidence"]
        self.assertEqual(evidence["item_id"], "U-19")
        self.assertEqual(evidence["target"], "/etc/hosts")
        self.assertTrue(evidence["metadata_collection_success"])
        self.assertTrue(evidence["owner_is_root"])
        self.assertEqual(evidence["permission_octal"], "644")
        self.assertTrue(evidence["permission_within_0644"])
        self.assertEqual(evidence["os"], {"distro": "rocky", "version_id": "9.6"})
        self.assertEqual(evidence["module_version"], MODULE_VERSION)
        self.assertIn("kernel", evidence)
        self.assertIn("observed_at", evidence)
        self.assertIn("reason_code", evidence)
        self.assertIn("judgment_basis", evidence)
        self.assertNotIn("PRIVATE_HOST_MAPPING", output)
        self.assertNotIn("192.0.2.10", output)

    def test_27_single_json_stdout(self):
        result, output = self.run_real("0|root|644")
        self.assertEqual(output.count("\n"), 1)
        self.assertEqual(result["item_id"], "U-19")

    def test_28_check_is_read_only_and_does_not_read_hosts_contents(self):
        source = MODULE.read_text(encoding="utf-8")
        self.assertNotRegex(source, r"(?m)^\s*(chmod|chown|chgrp|rm|mv|touch|tee|systemctl|service|apt|dnf|yum)\b")
        self.assertNotIn("sed -i", source)
        self.assertNotRegex(source, r"(?m)^\s*echo\b.*>")
        self.assertNotRegex(source, r"(?m)^\s*cat\s+.*hosts")

    def test_29_unsupported_os_is_uncheckable(self):
        result, _ = self.run_real("0|root|644", distro="debian", version="12")
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "UNSUPPORTED_OS_CONFIGURATION")

    def test_30_runner_contract_timeout_and_no_na(self):
        runner = self.runner(); planned = runner.prepare_item("U-19", Action.CHECK)
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
            "os_guard_agent.module_runner.subprocess.run", side_effect=subprocess.TimeoutExpired("U-19", 1),
        ):
            with self.assertRaises(ModuleTimeoutError):
                runner.execute_check(planned, timeout_seconds=1)


if __name__ == "__main__":
    unittest.main()
