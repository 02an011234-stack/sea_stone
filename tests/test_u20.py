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
MODULE = ROOT / "modules" / "unix" / "U-20.sh"


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
        "item_id": "U-20", "status": "GOOD", "review_state": "NOT_REQUIRED",
        "current_value": {
            "detected_service_model": "systemd", "inetd_present": False,
            "xinetd_present": False, "systemd_present": True, "applicable_file_count": 1,
            "checked_file_count": 1, "root_owned_count": 1, "non_root_owned_count": 0,
            "compliant_permission_count": 1, "noncompliant_permission_count": 0,
            "symlink_count": 0, "unresolved_count": 0, "scan_completed": True,
        },
        "evidence": {
            "item_id": "U-20", "inspection_target": "configuration files",
            "collection_method": "fixture", "detected_service_model": "systemd",
            "inetd_present": False, "xinetd_present": False, "systemd_present": True,
            "applicable_file_count": 1, "checked_file_count": 1, "root_owned_count": 1,
            "non_root_owned_count": 0, "compliant_permission_count": 1,
            "noncompliant_permission_count": 0, "symlink_count": 0,
            "unresolved_count": 0, "scan_completed": True,
            "reason_code": "KISA_U20_ROOT_OWNER_AND_PERMISSION_ALLOWED",
            "os": {"distro": distro, "version_id": version}, "kernel": "fixture-kernel",
            "module_version": MODULE_VERSION, "observed_at": "2026-09-29T00:00:00Z",
            "judgment_basis": "fixture",
        }, "error": None,
    })


class U20Tests(unittest.TestCase):
    def runner(self, distro="rocky", version="9.6"):
        detected = os_info(distro, version)
        return ModuleRunner(load_manifest(MANIFEST, "manifest-unix-67-v1", detected), detected)

    def run_real(self, records, *, model="systemd", distro="rocky", version="9.6"):
        executable = shell_path()
        if not executable:
            self.skipTest("POSIX shell is unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            scan_file = root / "u20-scan.fixture"
            scan_file.write_text("\n".join(records) + ("\n" if records else ""), encoding="utf-8", newline="\n")
            before = hashlib.sha256(scan_file.read_bytes()).hexdigest()
            env = {
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
                "OS_GUARD_DISTRO": distro, "OS_GUARD_VERSION_ID": version,
                "OS_GUARD_MODULE_VERSION": MODULE_VERSION, "OS_GUARD_TEST_ROOT": str(root),
                "OS_GUARD_TEST_SCAN_FILE": str(scan_file), "OS_GUARD_TEST_SERVICE_MODEL": model,
            }
            completed = subprocess.run([executable, str(MODULE)], env=env, capture_output=True, text=True, timeout=5, check=False)
            after = hashlib.sha256(scan_file.read_bytes()).hexdigest()
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(before, after)
            return json.loads(completed.stdout), completed.stdout + completed.stderr

    def test_01_manifest_selects_u20(self):
        self.assertEqual(self.runner().prepare_item("U-20", Action.CHECK).module_path.name, "U-20.sh")

    def assert_good(self, mode, model="systemd"):
        result, _ = self.run_real([f"regular|0|root|{mode}"], model=model)
        self.assertEqual(result["status"], "GOOD")

    def assert_vulnerable(self, mode):
        result, _ = self.run_real([f"regular|0|root|{mode}"])
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertEqual(result["current_value"]["noncompliant_permission_count"], 1)

    def test_02_root_0600_is_good(self): self.assert_good("600")
    def test_03_root_0400_is_good(self): self.assert_good("400")
    def test_04_root_0200_is_good(self): self.assert_good("200")
    def test_05_root_0000_is_good(self): self.assert_good("0")

    def test_06_non_root_owner_is_vulnerable(self):
        result, _ = self.run_real(["regular|1000|user|600"])
        self.assertEqual(result["status"], "VULNERABLE")

    def test_07_root_0640_is_vulnerable(self): self.assert_vulnerable("640")
    def test_08_root_0604_is_vulnerable(self): self.assert_vulnerable("604")
    def test_09_root_0620_is_vulnerable(self): self.assert_vulnerable("620")
    def test_10_root_0700_is_vulnerable(self): self.assert_vulnerable("700")
    def test_11_root_0644_is_vulnerable(self): self.assert_vulnerable("644")
    def test_12_root_0777_is_vulnerable(self): self.assert_vulnerable("777")
    def test_13_special_permission_bit_is_vulnerable(self): self.assert_vulnerable("4600")

    def test_14_multiple_safe_files_are_good(self):
        result, _ = self.run_real(["regular|0|root|600", "regular|0|root|400", "regular|0|root|000"])
        self.assertEqual(result["status"], "GOOD")
        self.assertEqual(result["current_value"]["checked_file_count"], 3)

    def test_15_one_non_root_file_makes_result_vulnerable(self):
        result, _ = self.run_real(["regular|0|root|600", "regular|1000|user|600"])
        self.assertEqual(result["status"], "VULNERABLE")

    def test_16_one_bad_permission_makes_result_vulnerable(self):
        result, _ = self.run_real(["regular|0|root|600", "regular|0|root|640"])
        self.assertEqual(result["status"], "VULNERABLE")

    def test_17_inetd_structure(self):
        result, _ = self.run_real(["regular|0|root|600"], model="inetd")
        self.assertEqual(result["status"], "GOOD")
        self.assertTrue(result["current_value"]["inetd_present"])

    def test_18_xinetd_structure(self):
        result, _ = self.run_real(["regular|0|root|600"], model="xinetd")
        self.assertEqual(result["status"], "GOOD")
        self.assertTrue(result["current_value"]["xinetd_present"])

    def test_19_xinetd_d_multiple_files(self):
        result, _ = self.run_real(["regular|0|root|600", "regular|0|root|400"], model="xinetd")
        self.assertEqual(result["status"], "GOOD")
        self.assertEqual(result["current_value"]["applicable_file_count"], 2)

    def test_20_systemd_structure(self):
        result, _ = self.run_real([], model="systemd")
        self.assertEqual(result["status"], "N/A")
        self.assertTrue(result["current_value"]["systemd_present"])

    def test_21_rocky_10_systemd_only_is_not_applicable(self):
        result, _ = self.run_real([], model="systemd", distro="rocky", version="10.2")
        self.assertEqual(result["status"], "N/A")
        self.assertEqual(result["review_state"], "NOT_REQUIRED")
        self.assertEqual(result["evidence"]["reason_code"], "KISA_U20_NOT_APPLICABLE_SYSTEMD_ONLY")
        self.assertFalse(result["current_value"]["inetd_present"])
        self.assertFalse(result["current_value"]["xinetd_present"])

    def test_21b_rocky_10_systemd_only_runtime_discovery(self):
        executable = shell_path()
        if not executable:
            self.skipTest("POSIX shell is unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "usr/lib/systemd/system").mkdir(parents=True)
            env = {
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
                "OS_GUARD_DISTRO": "rocky", "OS_GUARD_VERSION_ID": "10.2",
                "OS_GUARD_MODULE_VERSION": MODULE_VERSION,
                "OS_GUARD_TEST_ROOT": str(root),
            }
            completed = subprocess.run(
                [executable, str(MODULE)], env=env, capture_output=True,
                text=True, timeout=5, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(result["status"], "N/A")
            self.assertEqual(result["current_value"]["detected_service_model"], "systemd")
            self.assertEqual(result["current_value"]["applicable_file_count"], 0)

    def test_22_normal_symlink_uses_target_metadata(self):
        result, _ = self.run_real(["symlink|0|root|600"])
        self.assertEqual(result["status"], "GOOD")
        self.assertEqual(result["current_value"]["symlink_count"], 1)

    def test_23_broken_symlink_is_pending(self):
        result, _ = self.run_real(["regular|0|root|600", "broken_symlink|||"])
        self.assertIsNone(result["status"])
        self.assertEqual(result["review_state"], "PENDING")

    def test_24_uid_name_conflict_is_pending(self):
        result, _ = self.run_real(["regular|0|administrator|600"])
        self.assertIsNone(result["status"])
        self.assertEqual(result["review_state"], "PENDING")

    def test_25_stat_failure_is_uncheckable(self):
        result, _ = self.run_real(["metadata_error|||"])
        self.assertEqual(result["status"], "UNCHECKABLE")

    def test_26_permission_parse_failure_is_uncheckable(self):
        result, _ = self.run_real(["regular|0|root|888"])
        self.assertEqual(result["status"], "UNCHECKABLE")

    def test_27_partial_failure_does_not_hide_vulnerability(self):
        result, _ = self.run_real(["scan_error|||", "regular|1000|user|600"])
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertFalse(result["current_value"]["scan_completed"])

    def test_28_scan_failure_without_vulnerability_is_uncheckable(self):
        result, _ = self.run_real(["regular|0|root|600", "scan_error|||"])
        self.assertEqual(result["status"], "UNCHECKABLE")

    def test_29_empty_scan_is_uncheckable(self):
        result, _ = self.run_real([], model="unknown")
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "NO_APPLICABLE_CONFIGURATION_FOUND")

    def test_30_evidence_aggregate_counts_are_exact(self):
        result, _ = self.run_real(["regular|0|root|600", "symlink|1000|user|640", "broken_symlink|||"])
        evidence = result["evidence"]
        self.assertEqual(evidence["applicable_file_count"], 2)
        self.assertEqual(evidence["checked_file_count"], 2)
        self.assertEqual(evidence["root_owned_count"], 1)
        self.assertEqual(evidence["non_root_owned_count"], 1)
        self.assertEqual(evidence["noncompliant_permission_count"], 1)
        self.assertEqual(evidence["symlink_count"], 2)
        self.assertEqual(evidence["unresolved_count"], 1)

    def test_31_configuration_contents_and_paths_are_not_exposed(self):
        result, output = self.run_real(["regular|0|root|600"])
        self.assertEqual(result["status"], "GOOD")
        self.assertNotIn("PRIVATE_SERVICE_CONFIGURATION", output)
        self.assertNotIn("u20-scan.fixture", output)
        self.assertNotIn(str(Path.home()), output)

    def test_32_rocky_9_fixture(self):
        result, _ = self.run_real(["regular|0|root|600"], distro="rocky", version="9.6")
        self.assertEqual(result["status"], "GOOD")

    def test_33_rocky_10_fixture(self):
        result, _ = self.run_real(["regular|0|root|400"], distro="rocky", version="10.0")
        self.assertEqual(result["status"], "GOOD")

    def test_34_ubuntu_22_fixture(self):
        result, _ = self.run_real(["regular|0|root|200"], distro="ubuntu", version="22.04")
        self.assertEqual(result["status"], "GOOD")

    def test_35_ubuntu_24_fixture(self):
        result, _ = self.run_real(["regular|0|root|000"], distro="ubuntu", version="24.04")
        self.assertEqual(result["status"], "GOOD")

    def test_36_single_json_stdout_and_read_only_bounded_scope(self):
        result, output = self.run_real(["regular|0|root|600"])
        self.assertEqual(output.count("\n"), 1)
        self.assertEqual(result["item_id"], "U-20")
        source = MODULE.read_text(encoding="utf-8")
        self.assertNotRegex(source, r"(?m)^\s*(chmod|chown|chgrp|rm|mv|touch|systemctl|service|apt|dnf|yum)\b")
        self.assertNotIn("sed -i", source)
        self.assertNotIn('"${test_root}/etc/systemd"/*.conf', source)
        self.assertIn('"${test_root}/etc/xinetd.d"', source)

    def test_37_unsupported_os_is_uncheckable(self):
        result, _ = self.run_real(["regular|0|root|600"], distro="debian", version="12")
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "UNSUPPORTED_OS_CONFIGURATION")

    def test_38_runner_contract_timeout(self):
        runner = self.runner(); planned = runner.prepare_item("U-20", Action.CHECK)
        completed = subprocess.CompletedProcess([str(MODULE)], 0, payload(), "")
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run", return_value=completed,
        ) as run:
            parsed = runner.execute_check(planned)
        self.assertEqual(parsed.status, ResultStatus.GOOD)
        self.assertEqual(parsed.review_state, ReviewState.NOT_REQUIRED)
        self.assertFalse(run.call_args.kwargs["shell"])
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run", side_effect=subprocess.TimeoutExpired("U-20", 1),
        ):
            with self.assertRaises(ModuleTimeoutError):
                runner.execute_check(planned, timeout_seconds=1)


if __name__ == "__main__":
    unittest.main()
