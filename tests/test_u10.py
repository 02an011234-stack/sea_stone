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
MODULE = ROOT / "modules" / "unix" / "U-10.sh"


def os_info(distro="rocky", version="9.4"):
    return OsInfo(distro, version, version, "kernel", "host", "x86_64", True)


def payload(
    distro="rocky", version="9.4", *, status="GOOD", review="NOT_REQUIRED",
    valid=20, unique=20, duplicate_groups=0, duplicate_accounts=0,
    reason="KISA_U10_ALL_UIDS_UNIQUE", error=None,
):
    return json.dumps({
        "item_id": "U-10", "status": status, "review_state": review,
        "current_value": {
            "passwd_file_present": True, "passwd_file_readable": True,
            "valid_entry_count": valid, "unique_uid_count": unique,
            "duplicate_uid_group_count": duplicate_groups,
            "accounts_in_duplicate_uid_groups": duplicate_accounts,
            "duplicate_uid_exists": duplicate_groups > 0,
            "malformed_entry_count": 0,
        },
        "evidence": {
            "item_id": "U-10", "collection_method": "Aggregate integer UID multiplicity",
            "configuration_paths": ["/etc/passwd"], "reason_code": reason,
            "os": {"distro": distro, "version_id": version},
            "observed_at": "2026-09-28T00:00:00Z", "module_version": MODULE_VERSION,
            "decision_reason": "fixture reason",
        }, "error": error,
    })


class U10Tests(unittest.TestCase):
    def runner(self, distro="rocky", version="9.4"):
        detected = os_info(distro, version)
        return ModuleRunner(load_manifest(MANIFEST, "manifest-unix-67-v1", detected), detected)

    def execute(self, output, distro="rocky", version="9.4"):
        runner = self.runner(distro, version); planned = runner.prepare_item("U-10", Action.CHECK)
        completed = subprocess.CompletedProcess([str(MODULE)], 0, output, "")
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run", return_value=completed
        ) as run:
            return runner.execute_check(planned), run

    def run_real(self, passwd, distro="rocky", version="9.4"):
        shell = shutil.which("sh")
        if not shell:
            self.skipTest("POSIX shell is unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir); etc = root / "etc"; etc.mkdir()
            passwd_file = etc / "passwd"; passwd_file.write_text(passwd, encoding="utf-8")
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

    def test_manifest_and_all_unique_uids_are_good(self):
        self.assertEqual(self.runner().prepare_item("U-10", Action.CHECK).module_path.name, "U-10.sh")
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\na:x:1000:1000::/home/a:/bin/sh\n"
        )
        self.assertEqual(actual["status"], "GOOD")
        self.assertFalse(actual["current_value"]["duplicate_uid_exists"])

    def test_two_regular_accounts_same_uid_are_vulnerable(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\na:x:1000:1000::/home/a:/bin/sh\nb:x:1000:1001::/home/b:/bin/sh\n"
        )
        self.assertEqual(actual["status"], "VULNERABLE")
        self.assertEqual(actual["current_value"]["accounts_in_duplicate_uid_groups"], 2)

    def test_three_accounts_same_uid_are_one_duplicate_group(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\na:x:1000:1000::/:/bin/sh\nb:x:1000:1001::/:/bin/sh\nc:x:1000:1002::/:/bin/sh\n"
        )
        self.assertEqual(actual["current_value"]["duplicate_uid_group_count"], 1)
        self.assertEqual(actual["current_value"]["accounts_in_duplicate_uid_groups"], 3)

    def test_two_distinct_duplicate_uid_groups(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\na:x:1000:1::/:/bin/sh\nb:x:1000:2::/:/bin/sh\nc:x:2000:3::/:/bin/sh\nd:x:2000:4::/:/bin/sh\n"
        )
        self.assertEqual(actual["status"], "VULNERABLE")
        self.assertEqual(actual["current_value"]["duplicate_uid_group_count"], 2)
        self.assertEqual(actual["current_value"]["accounts_in_duplicate_uid_groups"], 4)

    def test_uid_zero_duplicate_is_vulnerable(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\nadmin:x:0:1000::/home/admin:/bin/sh\n"
        )
        self.assertEqual(actual["status"], "VULNERABLE")

    def test_system_accounts_are_not_excluded(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\ndaemon:x:2:2::/:/usr/sbin/nologin\nsvc:x:2:3::/:/usr/sbin/nologin\n"
        )
        self.assertEqual(actual["status"], "VULNERABLE")

    def test_non_login_accounts_are_not_excluded(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\na:x:50:50::/:/bin/false\nb:x:50:51::/:/sbin/nologin\n"
        )
        self.assertEqual(actual["status"], "VULNERABLE")

    def test_locked_accounts_are_not_excluded(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\na:!:60:60::/:/bin/false\nb:*:60:61::/:/bin/false\n"
        )
        self.assertEqual(actual["status"], "VULNERABLE")

    def test_uid_below_uid_min_is_not_excluded(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\na:x:99:99::/:/bin/false\nb:x:099:100::/:/bin/false\n"
        )
        self.assertEqual(actual["status"], "VULNERABLE")
        self.assertEqual(actual["current_value"]["duplicate_uid_group_count"], 1)

    def test_passwd_read_failure_is_uncheckable(self):
        result, _ = self.execute(payload(
            status="UNCHECKABLE", reason="KISA_U10_COLLECTION_FAILED",
            error={"code": "PASSWD_FILE_UNREADABLE", "message": "safe"},
        ))
        self.assertEqual(result.status, ResultStatus.UNCHECKABLE)

    def test_malformed_passwd_is_uncheckable(self):
        actual, _ = self.run_real("root:x:0:0:root:/root\n")
        self.assertEqual(actual["status"], "UNCHECKABLE")

    def test_non_numeric_uid_is_uncheckable(self):
        actual, _ = self.run_real("root:x:not-a-uid:0:root:/root:/bin/sh\n")
        self.assertEqual(actual["status"], "UNCHECKABLE")
        self.assertEqual(actual["error"]["code"], "PASSWD_FILE_PARSE_ERROR")

    def test_empty_passwd_is_uncheckable(self):
        actual, _ = self.run_real("")
        self.assertEqual(actual["status"], "UNCHECKABLE")
        self.assertEqual(actual["current_value"]["valid_entry_count"], 0)

    def test_rocky_fixtures(self):
        for version in ("9.4", "10"):
            result, _ = self.execute(payload("rocky", version), "rocky", version)
            self.assertEqual(result.status, ResultStatus.GOOD)

    def test_ubuntu_fixtures(self):
        for version in ("22.04", "24.04"):
            result, _ = self.execute(payload("ubuntu", version), "ubuntu", version)
            self.assertEqual(result.status, ResultStatus.GOOD)

    def test_duplicate_aggregate_values_are_exact(self):
        result, _ = self.execute(payload(
            status="VULNERABLE", valid=8, unique=5, duplicate_groups=2,
            duplicate_accounts=5, reason="KISA_U10_DUPLICATE_UID_FOUND",
        ))
        self.assertEqual(result.current_value["duplicate_uid_group_count"], 2)
        self.assertEqual(result.current_value["accounts_in_duplicate_uid_groups"], 5)
        self.assertTrue(result.current_value["duplicate_uid_exists"])

    def test_account_names_uid_values_and_password_fields_are_not_exposed(self):
        secret_name = "private-user"; secret_password = "$6$salt$hash"
        actual, output = self.run_real(
            f"root:x:0:0:root:/root:/bin/sh\n{secret_name}:{secret_password}:1000:1000::/:/bin/sh\nother:x:1000:1001::/:/bin/sh\n"
        )
        self.assertEqual(actual["status"], "VULNERABLE")
        self.assertNotIn(secret_name, output)
        self.assertNotIn(secret_password, output)
        self.assertNotIn('"uid_values"', output)

    def test_check_is_read_only(self):
        source = MODULE.read_text(encoding="utf-8")
        self.assertNotRegex(
            source,
            r"(?m)^\s*(usermod|useradd|userdel|passwd|chown|chmod|rm|mv)\b",
        )
        self.assertNotIn("sed -i", source)

    def test_single_json_invalid_stdout_and_timeout(self):
        actual, _ = self.run_real("root:x:0:0:root:/root:/bin/sh\n")
        self.assertEqual(actual["item_id"], "U-10")
        with self.assertRaises(ModuleOutputError):
            self.execute("debug\n{}")
        runner = self.runner(); planned = runner.prepare_item("U-10", Action.CHECK)
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run",
            side_effect=subprocess.TimeoutExpired("U-10", 1),
        ):
            with self.assertRaises(ModuleTimeoutError):
                runner.execute_check(planned, timeout_seconds=1)


if __name__ == "__main__":
    unittest.main()
