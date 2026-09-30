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
MODULE = ROOT / "modules" / "unix" / "U-08.sh"


def os_info(distro="rocky", version="9.4"):
    return OsInfo(distro, version, version, "kernel", "host", "x86_64", True)


def payload(
    distro="rocky", version="9.4", *, status=None, review="PENDING",
    members=2, primary=1, explicit=1, overlap=0, nonroot=1, external=0,
    name_is_root=True, manual=True,
    reason="KISA_U08_ADMIN_ACCOUNT_NECESSITY_REQUIRES_REVIEW", error=None,
):
    return json.dumps({
        "item_id": "U-08", "status": status, "review_state": review,
        "current_value": {
            "passwd_file_present": True, "passwd_file_readable": True,
            "group_file_present": True, "group_file_readable": True,
            "administrator_group_confirmed": True, "administrator_group_gid": 0,
            "administrator_group_name_is_root": name_is_root,
            "administrator_group_member_count": members,
            "primary_gid_member_count": primary, "explicit_group_member_count": explicit,
            "duplicate_member_reference_count": overlap, "root_account_included": True,
            "non_root_administrator_count": nonroot,
            "external_or_unknown_member_count": external,
            "manual_review_target_count": nonroot, "manual_review_required": manual,
            "valid_passwd_entry_count": 20, "valid_group_entry_count": 20,
            "malformed_passwd_entry_count": 0, "malformed_group_entry_count": 0,
        },
        "evidence": {
            "item_id": "U-08", "collection_method": "Aggregate root-group membership",
            "configuration_paths": ["/etc/passwd", "/etc/group"],
            "kisa_basis_type": "ROOT_GROUP_MINIMUM_MEMBERSHIP_REVIEW",
            "reason_code": reason,
            "os": {"distro": distro, "version_id": version},
            "observed_at": "2026-09-22T00:00:00Z", "module_version": MODULE_VERSION,
            "decision_reason": "fixture reason",
        }, "error": error,
    })


class U08Tests(unittest.TestCase):
    def runner(self, distro="rocky", version="9.4"):
        detected = os_info(distro, version)
        return ModuleRunner(load_manifest(MANIFEST, "manifest-unix-67-v1", detected), detected)

    def execute(self, output, distro="rocky", version="9.4"):
        runner = self.runner(distro, version); planned = runner.prepare_item("U-08", Action.CHECK)
        completed = subprocess.CompletedProcess([str(MODULE)], 0, output, "")
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run", return_value=completed
        ) as run:
            return runner.execute_check(planned), run

    def run_real(self, passwd, group, distro="rocky", version="9.4"):
        shell = shutil.which("sh")
        if not shell:
            self.skipTest("POSIX shell is unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir); etc = root / "etc"; etc.mkdir()
            files = {etc / "passwd": passwd, etc / "group": group}
            for path, content in files.items():
                path.write_text(content, encoding="utf-8")
            before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
            env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C",
                "OS_GUARD_DISTRO": distro, "OS_GUARD_VERSION_ID": version,
                "OS_GUARD_MODULE_VERSION": MODULE_VERSION, "OS_GUARD_TEST_ROOT": str(root),
            }
            completed = subprocess.run(
                [shell, str(MODULE)], env=env, capture_output=True, text=True,
                timeout=5, check=False,
            )
            after = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
            self.assertEqual(completed.returncode, 0)
            self.assertEqual(before, after)
            return json.loads(completed.stdout), completed.stdout + completed.stderr

    def test_manifest_and_root_only_admin_group_are_good(self):
        self.assertEqual(self.runner().prepare_item("U-08", Action.CHECK).module_path.name, "U-08.sh")
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\nuser:x:1000:1000::/home/user:/bin/sh\n",
            "root:x:0:\nusers:x:1000:user\n",
        )
        self.assertEqual(actual["status"], "GOOD")
        self.assertEqual(actual["current_value"]["administrator_group_member_count"], 1)

    def test_non_root_admin_member_is_pending(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000::/home/admin:/bin/sh\n",
            "root:x:0:admin\nusers:x:1000:admin\n",
        )
        self.assertIsNone(actual["status"])
        self.assertEqual(actual["review_state"], "PENDING")

    def test_explicit_group_member_is_counted(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000::/home/admin:/bin/sh\n",
            "root:x:0:admin\nusers:x:1000:admin\n",
        )
        self.assertEqual(actual["current_value"]["explicit_group_member_count"], 1)
        self.assertEqual(actual["current_value"]["non_root_administrator_count"], 1)

    def test_primary_gid_member_is_counted(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:0::/home/admin:/bin/sh\n",
            "root:x:0:\n",
        )
        self.assertEqual(actual["current_value"]["primary_gid_member_count"], 2)
        self.assertEqual(actual["current_value"]["non_root_administrator_count"], 1)

    def test_primary_and_explicit_duplicate_is_deduplicated(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:0::/home/admin:/bin/sh\n",
            "root:x:0:admin,admin\n",
        )
        self.assertEqual(actual["current_value"]["administrator_group_member_count"], 2)
        self.assertEqual(actual["current_value"]["duplicate_member_reference_count"], 1)

    def test_member_count_does_not_create_automatic_vulnerability(self):
        result, _ = self.execute(payload(members=5, explicit=4, nonroot=4))
        self.assertIsNone(result.status)
        self.assertEqual(result.review_state, ReviewState.PENDING)

    def test_normal_group_members_are_not_admin_members(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\nuser:x:1000:1000::/home/user:/bin/sh\n",
            "root:x:0:\nusers:x:1000:user\n",
        )
        self.assertEqual(actual["current_value"]["non_root_administrator_count"], 0)
        self.assertEqual(actual["status"], "GOOD")

    def test_external_or_unknown_explicit_member_is_pending(self):
        actual, output = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\n",
            "root:x:0:external-admin\n",
        )
        self.assertEqual(actual["current_value"]["external_or_unknown_member_count"], 1)
        self.assertEqual(actual["review_state"], "PENDING")
        self.assertNotIn("external-admin", output)

    def test_nonstandard_gid_zero_group_name_is_pending(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\n",
            "administrators:x:0:\n",
        )
        self.assertTrue(actual["current_value"]["administrator_group_confirmed"])
        self.assertFalse(actual["current_value"]["administrator_group_name_is_root"])
        self.assertEqual(actual["review_state"], "PENDING")

    def test_group_and_passwd_read_failures_are_uncheckable(self):
        for code in ("GROUP_FILE_UNREADABLE", "PASSWD_FILE_UNREADABLE"):
            with self.subTest(code=code):
                result, _ = self.execute(payload(
                    status="UNCHECKABLE", review="NOT_REQUIRED", manual=False,
                    reason="KISA_U08_COLLECTION_FAILED",
                    error={"code": code, "message": "safe"},
                ))
                self.assertEqual(result.status, ResultStatus.UNCHECKABLE)

    def test_malformed_group_is_uncheckable(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\n", "root:x:not-a-gid:\n"
        )
        self.assertEqual(actual["status"], "UNCHECKABLE")
        self.assertEqual(actual["error"]["code"], "ACCOUNT_GROUP_PARSE_ERROR")

    def test_malformed_passwd_is_uncheckable(self):
        actual, _ = self.run_real("root:x:zero:0:root:/root:/bin/sh\n", "root:x:0:\n")
        self.assertEqual(actual["status"], "UNCHECKABLE")

    def test_rocky_and_ubuntu_supported_contract(self):
        for distro, version in (("rocky", "9.4"), ("rocky", "10"), ("ubuntu", "22.04"), ("ubuntu", "24.04")):
            with self.subTest(distro=distro, version=version):
                result, _ = self.execute(payload(distro, version), distro, version)
                self.assertEqual(result.review_state, ReviewState.PENDING)

    def test_evidence_contains_reproducible_aggregate_counts(self):
        result, _ = self.execute(payload(members=4, primary=2, explicit=3, overlap=1, nonroot=3))
        self.assertEqual(result.current_value["administrator_group_member_count"], 4)
        self.assertEqual(result.current_value["duplicate_member_reference_count"], 1)
        self.assertEqual(result.evidence["reason_code"], "KISA_U08_ADMIN_ACCOUNT_NECESSITY_REQUIRES_REVIEW")

    def test_account_names_are_not_exposed(self):
        secret = "private-admin"
        actual, output = self.run_real(
            f"root:x:0:0:root:/root:/bin/sh\n{secret}:x:1000:0::/home/x:/bin/sh\n",
            f"root:x:0:{secret}\n",
        )
        self.assertEqual(actual["review_state"], "PENDING")
        self.assertNotIn(secret, output)

    def test_check_is_read_only(self):
        source = MODULE.read_text(encoding="utf-8")
        self.assertNotRegex(
            source,
            r"(?m)^\s*(usermod|groupmod|gpasswd|userdel|groupdel|passwd|chmod|chown|rm|mv)\b",
        )
        self.assertNotIn("sed -i", source)

    def test_single_json_invalid_stdout_and_timeout(self):
        actual, _ = self.run_real("root:x:0:0:root:/root:/bin/sh\n", "root:x:0:\n")
        self.assertEqual(actual["item_id"], "U-08")
        with self.assertRaises(ModuleOutputError):
            self.execute("debug\n{}")
        runner = self.runner(); planned = runner.prepare_item("U-08", Action.CHECK)
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run",
            side_effect=subprocess.TimeoutExpired("U-08", 1),
        ):
            with self.assertRaises(ModuleTimeoutError):
                runner.execute_check(planned, timeout_seconds=1)


if __name__ == "__main__":
    unittest.main()
