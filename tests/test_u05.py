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
from os_guard_agent.module_runner import ModuleOutputError, ModuleRunner, ModuleTimeoutError


ROOT = Path(__file__).parents[1]
MANIFEST = ROOT / "modules" / "manifest.json"
MODULE = ROOT / "modules" / "unix" / "U-05.sh"


def os_info(distro="rocky", version="9.4"):
    return OsInfo(distro, version, version, "kernel", "host", "x86_64", True)


def payload(
    distro="rocky", version="9.4", *, status="GOOD", review="NOT_REQUIRED",
    valid=20, uid0=1, nonroot0=0, root_entries=1, root_uid=0, malformed=0,
    reason="KISA_U05_ONLY_ROOT_HAS_UID_ZERO", review_reason=None, error=None,
):
    return json.dumps({
        "item_id": "U-05", "status": status, "review_state": review,
        "current_value": {
            "passwd_file_present": True, "passwd_file_readable": True,
            "valid_entry_count": valid, "uid_zero_count": uid0,
            "root_entry_count": root_entries, "root_uid": root_uid,
            "non_root_uid0_count": nonroot0, "non_root_uid0_exists": nonroot0 > 0,
            "malformed_entry_count": malformed,
        },
        "evidence": {
            "item_id": "U-05", "collection_method": "Aggregate local UID metadata",
            "configuration_paths": ["/etc/passwd"], "reason_code": reason,
            "review_reason": review_reason,
            "os": {"distro": distro, "version_id": version},
            "observed_at": "2026-09-22T00:00:00Z", "module_version": MODULE_VERSION,
            "decision_reason": "fixture reason",
        }, "error": error,
    })


class U05Tests(unittest.TestCase):
    def runner(self, distro="rocky", version="9.4"):
        detected = os_info(distro, version)
        return ModuleRunner(load_manifest(MANIFEST, "manifest-unix-67-v1", detected), detected)

    def execute(self, output, distro="rocky", version="9.4"):
        runner = self.runner(distro, version)
        planned = runner.prepare_item("U-05", Action.CHECK)
        completed = subprocess.CompletedProcess([str(MODULE)], 0, output, "")
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run", return_value=completed
        ) as run:
            return runner.execute_check(planned), run

    def run_real(self, passwd_text, distro="rocky", version="9.4"):
        shell = shutil.which("sh")
        if not shell:
            self.skipTest("POSIX shell is unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir); etc = root / "etc"; etc.mkdir()
            passwd_file = etc / "passwd"
            passwd_file.write_text(passwd_text, encoding="utf-8")
            before = hashlib.sha256(passwd_file.read_bytes()).hexdigest()
            env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C",
                "OS_GUARD_DISTRO": distro, "OS_GUARD_VERSION_ID": version,
                "OS_GUARD_MODULE_VERSION": MODULE_VERSION, "OS_GUARD_TEST_ROOT": str(root),
            }
            completed = subprocess.run(
                [shell, str(MODULE)], env=env, capture_output=True, text=True,
                timeout=5, check=False,
            )
            after = hashlib.sha256(passwd_file.read_bytes()).hexdigest()
            self.assertEqual(completed.returncode, 0)
            self.assertEqual(before, after)
            return json.loads(completed.stdout), completed.stdout + completed.stderr

    def test_manifest_root_only_uid_zero_is_good(self):
        self.assertEqual(self.runner().prepare_item("U-05", Action.CHECK).module_path.name, "U-05.sh")
        result, run = self.execute(payload())
        self.assertEqual(result.status, ResultStatus.GOOD)
        self.assertEqual(result.review_state, ReviewState.NOT_REQUIRED)
        self.assertFalse(run.call_args.kwargs["shell"])

    def test_one_non_root_uid_zero_is_vulnerable(self):
        result, _ = self.execute(payload(
            status="VULNERABLE", valid=21, uid0=2, nonroot0=1,
            reason="KISA_U05_NON_ROOT_UID_ZERO_FOUND",
        ))
        self.assertEqual(result.status, ResultStatus.VULNERABLE)
        self.assertTrue(result.current_value["non_root_uid0_exists"])

    def test_multiple_non_root_uid_zero_accounts_are_vulnerable(self):
        result, _ = self.execute(payload(
            status="VULNERABLE", valid=22, uid0=3, nonroot0=2,
            reason="KISA_U05_NON_ROOT_UID_ZERO_FOUND",
        ))
        self.assertEqual(result.status, ResultStatus.VULNERABLE)
        self.assertEqual(result.current_value["non_root_uid0_count"], 2)

    def test_regular_users_do_not_affect_good_result(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\nuser:x:1000:1000::/home/user:/bin/sh\n"
        )
        self.assertEqual(actual["status"], "GOOD")
        self.assertEqual(actual["current_value"]["valid_entry_count"], 2)

    def test_malformed_entry_is_uncheckable(self):
        actual, _ = self.run_real("root:x:0:0:root:/root:/bin/sh\nbroken:x:not-a-uid\n")
        self.assertEqual(actual["status"], "UNCHECKABLE")
        self.assertEqual(actual["error"]["code"], "PASSWD_FILE_PARSE_ERROR")

    def test_passwd_read_failure_is_uncheckable(self):
        result, _ = self.execute(payload(
            status="UNCHECKABLE", reason="KISA_U05_COLLECTION_FAILED",
            error={"code": "PASSWD_FILE_UNREADABLE", "message": "safe"},
        ))
        self.assertEqual(result.status, ResultStatus.UNCHECKABLE)

    def test_empty_passwd_is_uncheckable(self):
        actual, _ = self.run_real("")
        self.assertEqual(actual["status"], "UNCHECKABLE")
        self.assertEqual(actual["current_value"]["valid_entry_count"], 0)

    def test_non_numeric_uid_is_uncheckable(self):
        actual, _ = self.run_real("root:x:zero:0:root:/root:/bin/sh\n")
        self.assertEqual(actual["status"], "UNCHECKABLE")
        self.assertEqual(actual["current_value"]["malformed_entry_count"], 1)

    def test_uid_zero_aggregate_evidence(self):
        result, _ = self.execute(payload(
            status="VULNERABLE", uid0=3, nonroot0=2,
            reason="KISA_U05_NON_ROOT_UID_ZERO_FOUND",
        ))
        self.assertEqual(result.current_value["uid_zero_count"], 3)
        self.assertEqual(result.current_value["root_uid"], 0)
        self.assertEqual(result.evidence["reason_code"], "KISA_U05_NON_ROOT_UID_ZERO_FOUND")

    def test_account_names_passwords_and_hashes_are_not_exposed(self):
        secret_name = "hidden-admin"
        actual, output = self.run_real(
            f"root:x:0:0:root:/root:/bin/sh\n{secret_name}:x:0:0::/:/bin/sh\n"
        )
        self.assertEqual(actual["status"], "VULNERABLE")
        self.assertNotIn(secret_name, output)
        self.assertNotIn("uid_zero_accounts", output)
        source = MODULE.read_text(encoding="utf-8")
        self.assertNotIn("print $1", source)
        self.assertNotIn("print $2", source)

    def test_supported_rocky_versions(self):
        for version in ("9.4", "10"):
            result, _ = self.execute(payload("rocky", version), "rocky", version)
            self.assertEqual(result.status, ResultStatus.GOOD)

    def test_supported_ubuntu_versions(self):
        for version in ("22.04", "24.04"):
            result, _ = self.execute(payload("ubuntu", version), "ubuntu", version)
            self.assertEqual(result.status, ResultStatus.GOOD)

    def test_nonstandard_root_structure_is_pending(self):
        result, _ = self.execute(payload(
            status=None, review="PENDING", uid0=0, root_uid=None,
            root_entries=0, reason="KISA_U05_NONSTANDARD_ROOT_REQUIRES_REVIEW",
            review_reason="ROOT_ACCOUNT_STRUCTURE_NONSTANDARD",
        ))
        self.assertIsNone(result.status)
        self.assertEqual(result.review_state, ReviewState.PENDING)

    def test_check_is_read_only(self):
        source = MODULE.read_text(encoding="utf-8")
        self.assertNotRegex(
            source,
            r"(?m)^\s*(usermod|userdel|passwd|chage|chmod|chown|rm|mv|sudo)\b",
        )
        self.assertNotIn("sed -i", source)

    def test_single_json_contract_invalid_stdout_and_timeout(self):
        actual, _ = self.run_real("root:x:0:0:root:/root:/bin/sh\n")
        self.assertEqual(actual["item_id"], "U-05")
        with self.assertRaises(ModuleOutputError):
            self.execute("debug\n{}")
        runner = self.runner(); planned = runner.prepare_item("U-05", Action.CHECK)
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run",
            side_effect=subprocess.TimeoutExpired("U-05", 1),
        ):
            with self.assertRaises(ModuleTimeoutError):
                runner.execute_check(planned, timeout_seconds=1)


if __name__ == "__main__":
    unittest.main()
