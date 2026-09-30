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
MODULE = ROOT / "modules" / "unix" / "U-16.sh"


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
        "item_id": "U-16", "status": "GOOD", "review_state": "NOT_REQUIRED",
        "current_value": {
            "target": "/etc/passwd", "file_exists": True, "file_type": "regular_file",
            "owner_is_root": True, "owner_uid_is_zero": True, "owner_name_state": "root",
            "permission_octal": "644", "permission_within_0644": True,
            "extra_permission_bits_detected": False, "metadata_collection_success": True,
            "manual_review_required": False,
        },
        "evidence": {
            "item_id": "U-16", "inspection_target": "/etc/passwd file metadata",
            "collection_method": "fixture", "assessment_condition": "fixture",
            "metadata_collection_success": True,
            "observed_summary": {"file_type": "regular_file"},
            "reason_code": "KISA_U16_ROOT_OWNER_AND_PERMISSION_ALLOWED",
            "os": {"distro": distro, "version_id": version},
            "kernel": "fixture-kernel", "module_version": MODULE_VERSION,
            "observed_at": "2026-09-28T00:00:00Z", "decision_reason": "fixture",
        }, "error": None,
    })


class U16Tests(unittest.TestCase):
    def runner(self, distro="rocky", version="9.6"):
        detected = os_info(distro, version)
        return ModuleRunner(load_manifest(MANIFEST, "manifest-unix-67-v1", detected), detected)

    def run_real(
        self, metadata="0|root|644", *, stat_exit=0, distro="rocky", version="9.6",
        file_type="regular", create_target=True,
    ):
        executable = shell_path()
        if not executable:
            self.skipTest("POSIX shell is unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "etc" / "passwd"
            target.parent.mkdir(parents=True)
            secret = "root:PRIVATE_PASSWORD_FIELD:0:0:root:/root:/bin/bash\n"
            if create_target:
                if file_type == "directory":
                    target.mkdir()
                else:
                    target.write_text(secret, encoding="utf-8")

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

    def test_01_manifest_selects_u16(self):
        self.assertEqual(self.runner().prepare_item("U-16", Action.CHECK).module_path.name, "U-16.sh")

    def test_02_root_0644_is_good(self):
        result, _ = self.run_real("0|root|644")
        self.assertEqual(result["status"], "GOOD")
        self.assertTrue(result["current_value"]["permission_within_0644"])

    def test_03_root_0640_is_good(self):
        result, _ = self.run_real("0|root|640")
        self.assertEqual(result["status"], "GOOD")

    def test_04_root_0600_is_good(self):
        result, _ = self.run_real("0|root|600")
        self.assertEqual(result["status"], "GOOD")

    def test_05_root_0444_is_good(self):
        result, _ = self.run_real("0|root|444")
        self.assertEqual(result["status"], "GOOD")

    def test_06_non_root_owner_is_vulnerable(self):
        result, _ = self.run_real("1000|user|644")
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertFalse(result["current_value"]["owner_uid_is_zero"])

    def test_07_group_write_0664_is_vulnerable(self):
        result, _ = self.run_real("0|root|664")
        self.assertEqual(result["status"], "VULNERABLE")

    def test_08_other_write_0646_is_vulnerable(self):
        result, _ = self.run_real("0|root|646")
        self.assertEqual(result["status"], "VULNERABLE")

    def test_09_execute_bits_0755_are_vulnerable(self):
        result, _ = self.run_real("0|root|755")
        self.assertEqual(result["status"], "VULNERABLE")

    def test_10_0777_is_vulnerable(self):
        result, _ = self.run_real("0|root|777")
        self.assertEqual(result["status"], "VULNERABLE")

    def test_11_owner_and_permission_violation_is_vulnerable(self):
        result, _ = self.run_real("1000|user|777")
        self.assertEqual(result["status"], "VULNERABLE")

    def test_12_missing_passwd_is_uncheckable(self):
        result, _ = self.run_real(create_target=False)
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "PASSWD_FILE_NOT_FOUND")

    def test_13_stat_failure_is_uncheckable_without_stderr_leak(self):
        result, output = self.run_real(stat_exit=1)
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "STAT_COMMAND_FAILED")
        self.assertNotIn("PRIVATE_STAT_ERROR", output)

    def test_14_metadata_parse_failure_is_uncheckable(self):
        for metadata in ("", "root|644", "zero|root|644", "0|root|888"):
            with self.subTest(metadata=metadata):
                result, _ = self.run_real(metadata)
                self.assertEqual(result["status"], "UNCHECKABLE")
                self.assertEqual(result["error"]["code"], "STAT_OUTPUT_INVALID")

    def test_15_nonstandard_file_type_is_pending(self):
        result, _ = self.run_real("0|root|644", file_type="directory")
        self.assertIsNone(result["status"])
        self.assertEqual(result["review_state"], "PENDING")
        self.assertEqual(result["current_value"]["file_type"], "directory")

    def test_16_uid_zero_name_resolution_conflict_is_pending(self):
        for owner_name in ("UNKNOWN", "administrator"):
            with self.subTest(owner_name=owner_name):
                result, _ = self.run_real(f"0|{owner_name}|644")
                self.assertIsNone(result["status"])
                self.assertEqual(result["review_state"], "PENDING")
                self.assertTrue(result["current_value"]["manual_review_required"])

    def test_17_special_permission_bit_is_vulnerable(self):
        result, _ = self.run_real("0|root|4644")
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertTrue(result["current_value"]["extra_permission_bits_detected"])

    def test_18_rocky_9_fixture(self):
        result, _ = self.run_real("0|root|644", distro="rocky", version="9.6")
        self.assertEqual(result["status"], "GOOD")

    def test_19_rocky_10_fixture(self):
        result, _ = self.run_real("0|root|640", distro="rocky", version="10.0")
        self.assertEqual(result["status"], "GOOD")

    def test_20_ubuntu_22_fixture(self):
        result, _ = self.run_real("0|root|600", distro="ubuntu", version="22.04")
        self.assertEqual(result["status"], "GOOD")

    def test_21_ubuntu_24_fixture(self):
        result, _ = self.run_real("0|root|444", distro="ubuntu", version="24.04")
        self.assertEqual(result["status"], "GOOD")

    def test_22_evidence_has_metadata_only_and_no_passwd_contents(self):
        result, output = self.run_real("0|root|644")
        evidence = result["evidence"]
        self.assertEqual(evidence["item_id"], "U-16")
        self.assertEqual(evidence["os"], {"distro": "rocky", "version_id": "9.6"})
        self.assertIn("kernel", evidence)
        self.assertEqual(evidence["module_version"], MODULE_VERSION)
        self.assertIn("observed_at", evidence)
        self.assertIn("reason_code", evidence)
        self.assertNotIn("PRIVATE_PASSWORD_FIELD", output)
        self.assertNotIn("/bin/bash", output)

    def test_23_single_json_stdout_and_read_only_source(self):
        result, output = self.run_real("0|root|644")
        self.assertEqual(output.count("\n"), 1)
        self.assertEqual(result["item_id"], "U-16")
        source = MODULE.read_text(encoding="utf-8")
        self.assertNotRegex(
            source,
            r"(?m)^\s*(chmod|chown|chgrp|rm|mv|touch|systemctl|service|usermod|useradd|userdel|apt|dnf|yum)\b",
        )
        self.assertNotIn("sed -i", source)
        self.assertNotRegex(source, r"(?m)^\s*echo\b.*>>")

    def test_24_runner_contract_timeout_and_no_na(self):
        runner = self.runner(); planned = runner.prepare_item("U-16", Action.CHECK)
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
            side_effect=subprocess.TimeoutExpired("U-16", 1),
        ):
            with self.assertRaises(ModuleTimeoutError):
                runner.execute_check(planned, timeout_seconds=1)


if __name__ == "__main__":
    unittest.main()
