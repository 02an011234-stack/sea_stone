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
MODULE = ROOT / "modules" / "unix" / "U-21.sh"


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
        "item_id": "U-21", "status": "GOOD", "review_state": "NOT_REQUIRED",
        "current_value": {
            "detected_logging_model": "rsyslog", "syslog_conf_present": False,
            "rsyslog_conf_present": True, "rsyslog_fragment_dir_present": False,
            "journald_present": False, "applicable_file_count": 1, "checked_file_count": 1,
            "allowed_owner_count": 1, "disallowed_owner_count": 0,
            "compliant_permission_count": 1, "noncompliant_permission_count": 0,
            "symlink_count": 0, "unresolved_count": 0, "scan_completed": True,
        },
        "evidence": {
            "item_id": "U-21", "inspection_target": "logging configuration metadata",
            "collection_method": "fixture", "detected_logging_model": "rsyslog",
            "syslog_conf_present": False, "rsyslog_conf_present": True,
            "rsyslog_fragment_dir_present": False, "journald_present": False,
            "applicable_file_count": 1, "checked_file_count": 1,
            "allowed_owner_count": 1, "disallowed_owner_count": 0,
            "compliant_permission_count": 1, "noncompliant_permission_count": 0,
            "symlink_count": 0, "unresolved_count": 0, "scan_completed": True,
            "reason_code": "KISA_U21_ALLOWED_OWNER_AND_PERMISSION",
            "os": {"distro": distro, "version_id": version}, "kernel": "fixture-kernel",
            "module_version": MODULE_VERSION, "observed_at": "2026-09-29T00:00:00Z",
            "judgment_basis": "fixture",
        }, "error": None,
    })


class U21Tests(unittest.TestCase):
    def runner(self, distro="rocky", version="9.6"):
        detected = os_info(distro, version)
        return ModuleRunner(load_manifest(MANIFEST, "manifest-unix-67-v1", detected), detected)

    def run_real(self, records, *, model="rsyslog", distro="rocky", version="9.6"):
        executable = shell_path()
        if not executable:
            self.skipTest("POSIX shell is unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            scan_file = root / "u21-scan.fixture"
            scan_file.write_text("\n".join(records) + ("\n" if records else ""), encoding="utf-8", newline="\n")
            before = hashlib.sha256(scan_file.read_bytes()).hexdigest()
            env = {
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
                "OS_GUARD_DISTRO": distro, "OS_GUARD_VERSION_ID": version,
                "OS_GUARD_MODULE_VERSION": MODULE_VERSION, "OS_GUARD_TEST_ROOT": str(root),
                "OS_GUARD_TEST_SCAN_FILE": str(scan_file), "OS_GUARD_TEST_LOGGING_MODEL": model,
            }
            completed = subprocess.run([executable, str(MODULE)], env=env, capture_output=True, text=True, timeout=5, check=False)
            after = hashlib.sha256(scan_file.read_bytes()).hexdigest()
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(before, after)
            return json.loads(completed.stdout), completed.stdout + completed.stderr

    def test_01_manifest_selects_u21(self):
        planned = self.runner().prepare_item("U-21", Action.CHECK)
        self.assertEqual(planned.module_path.name, "U-21.sh")
        self.assertEqual(planned.action, Action.CHECK)

    def assert_good(self, owner, uid, mode, identity=""):
        result, _ = self.run_real([f"regular|{uid}|{owner}|{mode}|{identity}"])
        self.assertEqual(result["status"], "GOOD")
        self.assertEqual(result["review_state"], "NOT_REQUIRED")

    def assert_vulnerable_mode(self, mode):
        result, _ = self.run_real([f"regular|0|root|{mode}"])
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertEqual(result["current_value"]["noncompliant_permission_count"], 1)

    def test_02_root_0640_good(self): self.assert_good("root", 0, "640")
    def test_03_root_0600_good(self): self.assert_good("root", 0, "600")
    def test_04_root_0400_good(self): self.assert_good("root", 0, "400")
    def test_05_root_0000_good(self): self.assert_good("root", 0, "000")
    def test_06_bin_0640_good_when_nss_verified(self): self.assert_good("bin", 1, "640", "verified")
    def test_07_sys_0640_good_when_nss_verified(self): self.assert_good("sys", 3, "640", "verified")

    def test_08_general_owner_is_vulnerable(self):
        result, _ = self.run_real(["regular|1000|user|640"])
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertEqual(result["current_value"]["disallowed_owner_count"], 1)

    def test_09_root_0644_vulnerable(self): self.assert_vulnerable_mode("644")
    def test_10_root_0660_vulnerable(self): self.assert_vulnerable_mode("660")
    def test_11_root_0650_vulnerable(self): self.assert_vulnerable_mode("650")
    def test_12_root_0740_vulnerable(self): self.assert_vulnerable_mode("740")
    def test_13_root_0777_vulnerable(self): self.assert_vulnerable_mode("777")
    def test_14_special_permission_bit_vulnerable(self): self.assert_vulnerable_mode("4640")

    def test_15_multiple_compliant_files_good(self):
        result, _ = self.run_real(["regular|0|root|640", "regular|1|bin|600|verified", "regular|3|sys|400|verified"])
        self.assertEqual(result["status"], "GOOD")
        self.assertEqual(result["current_value"]["checked_file_count"], 3)

    def test_16_one_owner_violation_makes_result_vulnerable(self):
        result, _ = self.run_real(["regular|0|root|640", "regular|1000|user|640"])
        self.assertEqual(result["status"], "VULNERABLE")

    def test_17_one_permission_violation_makes_result_vulnerable(self):
        result, _ = self.run_real(["regular|0|root|640", "regular|0|root|644"])
        self.assertEqual(result["status"], "VULNERABLE")

    def test_18_syslog_configuration_model(self):
        result, _ = self.run_real(["regular|0|root|640"], model="syslog")
        self.assertTrue(result["current_value"]["syslog_conf_present"])
        self.assertEqual(result["status"], "GOOD")

    def test_19_rsyslog_configuration_model(self):
        result, _ = self.run_real(["regular|0|root|640"], model="rsyslog")
        self.assertTrue(result["current_value"]["rsyslog_conf_present"])

    def test_20_rsyslog_fragment_structure(self):
        result, _ = self.run_real(["regular|0|root|640", "regular|0|root|600"], model="rsyslog_with_fragments")
        self.assertTrue(result["current_value"]["rsyslog_fragment_dir_present"])
        self.assertEqual(result["status"], "GOOD")

    def test_21_journald_only_is_not_applicable(self):
        result, _ = self.run_real([], model="journald_only")
        self.assertEqual(result["status"], "N/A")
        self.assertEqual(result["evidence"]["reason_code"], "KISA_U21_NOT_APPLICABLE_JOURNALD_ONLY")

    def test_22_absent_unknown_logging_model_is_uncheckable(self):
        result, _ = self.run_real([], model="unknown")
        self.assertEqual(result["status"], "UNCHECKABLE")

    def test_23_normal_symlink_uses_target_metadata(self):
        result, _ = self.run_real(["symlink|0|root|640"])
        self.assertEqual(result["status"], "GOOD")
        self.assertEqual(result["current_value"]["symlink_count"], 1)

    def test_24_broken_symlink_is_pending(self):
        result, _ = self.run_real(["regular|0|root|640", "broken_symlink||||"])
        self.assertIsNone(result["status"])
        self.assertEqual(result["review_state"], "PENDING")

    def test_25_external_symlink_is_pending(self):
        result, _ = self.run_real(["regular|0|root|640", "external_symlink||||"])
        self.assertIsNone(result["status"])

    def test_26_root_uid_name_conflict_is_pending(self):
        result, _ = self.run_real(["regular|1|root|640"])
        self.assertIsNone(result["status"])
        self.assertEqual(result["review_state"], "PENDING")

    def test_27_bin_nss_conflict_is_pending(self):
        result, _ = self.run_real(["regular|1|bin|640|conflict"])
        self.assertIsNone(result["status"])

    def test_28_metadata_failure_is_uncheckable(self):
        result, _ = self.run_real(["metadata_error||||"])
        self.assertEqual(result["status"], "UNCHECKABLE")

    def test_29_permission_parse_failure_is_uncheckable(self):
        result, _ = self.run_real(["regular|0|root|888"])
        self.assertEqual(result["status"], "UNCHECKABLE")

    def test_30_partial_failure_does_not_hide_vulnerability(self):
        result, _ = self.run_real(["scan_error||||", "regular|1000|user|640"])
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertFalse(result["current_value"]["scan_completed"])

    def test_31_partial_failure_without_vulnerability_is_uncheckable(self):
        result, _ = self.run_real(["regular|0|root|640", "scan_error||||"])
        self.assertEqual(result["status"], "UNCHECKABLE")

    def test_32_evidence_aggregate_counts(self):
        result, _ = self.run_real(["regular|0|root|640", "symlink|1|bin|600|verified", "regular|1000|user|644"])
        evidence = result["evidence"]
        self.assertEqual(evidence["applicable_file_count"], 3)
        self.assertEqual(evidence["allowed_owner_count"], 2)
        self.assertEqual(evidence["disallowed_owner_count"], 1)
        self.assertEqual(evidence["compliant_permission_count"], 2)
        self.assertEqual(evidence["noncompliant_permission_count"], 1)

    def test_33_sensitive_contents_and_paths_are_not_exposed(self):
        result, output = self.run_real(["regular|0|root|640"])
        self.assertEqual(result["status"], "GOOD")
        self.assertNotIn("PRIVATE_LOG_CONFIGURATION", output)
        self.assertNotIn("u21-scan.fixture", output)
        self.assertNotIn(str(Path.home()), output)

    def test_34_rocky_9_fixture(self): self.assertEqual(self.run_real(["regular|0|root|640"], distro="rocky", version="9.6")[0]["status"], "GOOD")
    def test_35_rocky_10_fixture(self): self.assertEqual(self.run_real(["regular|1|bin|600|verified"], distro="rocky", version="10.0")[0]["status"], "GOOD")
    def test_36_ubuntu_22_fixture(self): self.assertEqual(self.run_real(["regular|3|sys|400|verified"], distro="ubuntu", version="22.04")[0]["status"], "GOOD")
    def test_37_ubuntu_24_fixture(self): self.assertEqual(self.run_real(["regular|0|root|000"], distro="ubuntu", version="24.04")[0]["status"], "GOOD")

    def test_38_single_json_stdout_and_read_only_scope(self):
        result, output = self.run_real(["regular|0|root|640"])
        self.assertEqual(output.count("\n"), 1)
        self.assertEqual(result["item_id"], "U-21")
        source = MODULE.read_text(encoding="utf-8")
        self.assertNotRegex(source, r"(?m)^\s*(chmod|chown|chgrp|rm|mv|touch|systemctl|service|logger|apt|dnf|yum)\b")
        self.assertNotIn("sed -i", source)

    def test_39_unsupported_os_is_uncheckable(self):
        result, _ = self.run_real(["regular|0|root|640"], distro="debian", version="12")
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "UNSUPPORTED_OS_CONFIGURATION")

    def test_40_runner_contract(self):
        planned = self.runner().prepare_item("U-21", Action.CHECK)
        completed = subprocess.CompletedProcess([str(MODULE)], 0, payload(), "")
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run", return_value=completed,
        ) as run:
            parsed = self.runner().execute_check(planned)
        self.assertEqual(parsed.status, ResultStatus.GOOD)
        self.assertEqual(parsed.review_state, ReviewState.NOT_REQUIRED)
        self.assertFalse(run.call_args.kwargs["shell"])

    def test_41_runner_timeout(self):
        planned = self.runner().prepare_item("U-21", Action.CHECK)
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run", side_effect=subprocess.TimeoutExpired("U-21", 1),
        ):
            with self.assertRaises(ModuleTimeoutError):
                self.runner().execute_check(planned, timeout_seconds=1)


if __name__ == "__main__":
    unittest.main()
