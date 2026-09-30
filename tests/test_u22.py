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
MODULE = ROOT / "modules" / "unix" / "U-22.sh"


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
        "item_id": "U-22", "status": "GOOD", "review_state": "NOT_REQUIRED",
        "current_value": {
            "target": "/etc/services", "file_exists": True, "file_type": "regular",
            "metadata_collection_success": True, "owner_allowed": True,
            "owner_identity_consistent": True, "permission_octal": "644",
            "permission_within_0644": True, "extra_permission_bits_detected": False,
        },
        "evidence": {
            "item_id": "U-22", "target": "/etc/services",
            "collection_method": "fixture metadata", "file_exists": True,
            "file_type": "regular", "metadata_collection_success": True,
            "owner_allowed": True, "owner_identity_consistent": True,
            "permission_octal": "644", "permission_within_0644": True,
            "extra_permission_bits_detected": False,
            "reason_code": "KISA_U22_ALLOWED_OWNER_AND_PERMISSION",
            "os": {"distro": distro, "version_id": version}, "kernel": "fixture-kernel",
            "module_version": MODULE_VERSION, "observed_at": "2026-09-29T00:00:00Z",
            "judgment_basis": "fixture",
        }, "error": None,
    })


class U22Tests(unittest.TestCase):
    def runner(self, distro="rocky", version="9.6"):
        detected = os_info(distro, version)
        return ModuleRunner(load_manifest(MANIFEST, "manifest-unix-67-v1", detected), detected)

    def run_real(self, record, *, distro="rocky", version="9.6"):
        executable = shell_path()
        if not executable:
            self.skipTest("POSIX shell is unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fixture = root / "u22-metadata.fixture"
            fixture.write_text(record + "\n", encoding="utf-8", newline="\n")
            before = hashlib.sha256(fixture.read_bytes()).hexdigest()
            env = {
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
                "OS_GUARD_DISTRO": distro, "OS_GUARD_VERSION_ID": version,
                "OS_GUARD_MODULE_VERSION": MODULE_VERSION, "OS_GUARD_TEST_ROOT": str(root),
                "OS_GUARD_TEST_METADATA_FILE": str(fixture),
            }
            completed = subprocess.run([executable, str(MODULE)], env=env, capture_output=True, text=True, timeout=5, check=False)
            after = hashlib.sha256(fixture.read_bytes()).hexdigest()
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(before, after)
            return json.loads(completed.stdout), completed.stdout + completed.stderr

    def test_01_manifest_selects_u22(self):
        planned = self.runner().prepare_item("U-22", Action.CHECK)
        self.assertEqual(planned.module_path.name, "U-22.sh")
        self.assertEqual(planned.action, Action.CHECK)

    def assert_good(self, owner, uid, mode, identity=""):
        result, _ = self.run_real(f"regular|{uid}|{owner}|{mode}|{identity}")
        self.assertEqual(result["status"], "GOOD")
        self.assertEqual(result["review_state"], "NOT_REQUIRED")

    def assert_bad_mode(self, mode):
        result, _ = self.run_real(f"regular|0|root|{mode}")
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertTrue(result["current_value"]["extra_permission_bits_detected"])

    def test_02_root_0644_good(self): self.assert_good("root", 0, "644")
    def test_03_root_0640_good(self): self.assert_good("root", 0, "640")
    def test_04_root_0600_good(self): self.assert_good("root", 0, "600")
    def test_05_root_0444_good(self): self.assert_good("root", 0, "444")
    def test_06_root_0400_good(self): self.assert_good("root", 0, "400")
    def test_07_root_0000_good(self): self.assert_good("root", 0, "000")
    def test_08_bin_0644_good_with_nss_identity(self): self.assert_good("bin", 1, "644", "verified")
    def test_09_sys_0644_good_with_nss_identity(self): self.assert_good("sys", 3, "644", "verified")

    def test_10_general_owner_vulnerable(self):
        result, _ = self.run_real("regular|1000|user|644")
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertFalse(result["current_value"]["owner_allowed"])

    def test_11_root_0664_vulnerable(self): self.assert_bad_mode("664")
    def test_12_root_0646_vulnerable(self): self.assert_bad_mode("646")
    def test_13_root_0654_vulnerable(self): self.assert_bad_mode("654")
    def test_14_root_0744_vulnerable(self): self.assert_bad_mode("744")
    def test_15_root_0755_vulnerable(self): self.assert_bad_mode("755")
    def test_16_root_0777_vulnerable(self): self.assert_bad_mode("777")
    def test_17_special_permission_bit_vulnerable(self): self.assert_bad_mode("4644")

    def test_18_uid_name_conflict_pending(self):
        result, _ = self.run_real("regular|1|root|644")
        self.assertIsNone(result["status"])
        self.assertEqual(result["review_state"], "PENDING")
        self.assertFalse(result["current_value"]["owner_identity_consistent"])

    def test_19_bin_nss_conflict_pending(self):
        result, _ = self.run_real("regular|1|bin|644|conflict")
        self.assertIsNone(result["status"])

    def test_20_normal_symlink_uses_target_metadata(self):
        result, _ = self.run_real("symlink|0|root|644")
        self.assertEqual(result["status"], "GOOD")
        self.assertEqual(result["current_value"]["file_type"], "symlink")

    def test_21_broken_symlink_pending(self):
        result, _ = self.run_real("broken_symlink||||")
        self.assertIsNone(result["status"])
        self.assertEqual(result["review_state"], "PENDING")

    def test_22_nonstandard_file_type_pending(self):
        result, _ = self.run_real("nonstandard||||")
        self.assertIsNone(result["status"])

    def test_23_missing_services_uncheckable(self):
        result, _ = self.run_real("absent||||")
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertFalse(result["current_value"]["file_exists"])
        self.assertEqual(result["error"]["code"], "TARGET_NOT_FOUND")

    def test_24_stat_failure_uncheckable(self):
        result, _ = self.run_real("stat_error||||")
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "STAT_FAILED")

    def test_25_permission_parse_failure_uncheckable(self):
        result, _ = self.run_real("regular|0|root|888")
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "METADATA_PARSE_FAILED")

    def test_26_evidence_is_complete(self):
        result, _ = self.run_real("regular|0|root|640")
        evidence = result["evidence"]
        for key in ("item_id", "target", "file_exists", "file_type", "metadata_collection_success",
                    "owner_allowed", "owner_identity_consistent", "permission_octal",
                    "permission_within_0644", "extra_permission_bits_detected", "os", "kernel",
                    "module_version", "observed_at", "reason_code", "judgment_basis"):
            self.assertIn(key, evidence)
        self.assertEqual(evidence["permission_octal"], "640")

    def test_27_services_contents_ports_and_names_not_collected(self):
        result, output = self.run_real("regular|0|root|644")
        self.assertEqual(result["status"], "GOOD")
        self.assertNotIn("PRIVATE_SERVICE_ENTRY", output)
        self.assertNotIn("443/tcp", output)
        self.assertNotIn("u22-metadata.fixture", output)
        source = MODULE.read_text(encoding="utf-8")
        self.assertNotIn("cat \"$target\"", source)

    def test_28_rocky_9_fixture(self): self.assertEqual(self.run_real("regular|0|root|644", distro="rocky", version="9.6")[0]["status"], "GOOD")
    def test_29_rocky_10_fixture(self): self.assertEqual(self.run_real("regular|1|bin|640|verified", distro="rocky", version="10.0")[0]["status"], "GOOD")
    def test_30_ubuntu_22_fixture(self): self.assertEqual(self.run_real("regular|3|sys|444|verified", distro="ubuntu", version="22.04")[0]["status"], "GOOD")
    def test_31_ubuntu_24_fixture(self): self.assertEqual(self.run_real("regular|0|root|600", distro="ubuntu", version="24.04")[0]["status"], "GOOD")

    def test_32_single_json_stdout_and_read_only(self):
        result, output = self.run_real("regular|0|root|644")
        self.assertEqual(output.count("\n"), 1)
        self.assertEqual(result["item_id"], "U-22")
        source = MODULE.read_text(encoding="utf-8")
        self.assertNotRegex(source, r"(?m)^\s*(chmod|chown|chgrp|rm|mv|touch|tee|systemctl|service|apt|dnf|yum)\b")
        self.assertNotIn("sed -i", source)
        self.assertNotIn("echo >", source)

    def test_33_unsupported_os_uncheckable(self):
        result, _ = self.run_real("regular|0|root|644", distro="debian", version="12")
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "UNSUPPORTED_OS_CONFIGURATION")

    def test_34_no_na_status_is_invented(self):
        for record in ("regular|0|root|644", "regular|1000|user|644", "absent||||", "nonstandard||||"):
            with self.subTest(record=record):
                self.assertNotEqual(self.run_real(record)[0]["status"], "N/A")

    def test_35_runner_contract(self):
        runner = self.runner(); planned = runner.prepare_item("U-22", Action.CHECK)
        completed = subprocess.CompletedProcess([str(MODULE)], 0, payload(), "")
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run", return_value=completed,
        ) as run:
            parsed = runner.execute_check(planned)
        self.assertEqual(parsed.status, ResultStatus.GOOD)
        self.assertEqual(parsed.review_state, ReviewState.NOT_REQUIRED)
        self.assertFalse(run.call_args.kwargs["shell"])

    def test_36_runner_timeout(self):
        runner = self.runner(); planned = runner.prepare_item("U-22", Action.CHECK)
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run", side_effect=subprocess.TimeoutExpired("U-22", 1),
        ):
            with self.assertRaises(ModuleTimeoutError):
                runner.execute_check(planned, timeout_seconds=1)


if __name__ == "__main__":
    unittest.main()
