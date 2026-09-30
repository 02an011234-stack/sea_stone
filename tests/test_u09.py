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
MODULE = ROOT / "modules" / "unix" / "U-09.sh"


def os_info(distro="rocky", version="9.4"):
    return OsInfo(distro, version, version, "kernel", "host", "x86_64", True)


def payload(
    distro="rocky", version="9.4", *, status="GOOD", review="NOT_REQUIRED",
    primary=2, groups=2, linked=2, unlinked=0, missing_primary=0,
    duplicates=0, unknown_members=0, nss_state="local_files_only", external=False,
    reason="KISA_U09_ALL_GROUP_GIDS_CONNECTED", review_reason=None, error=None,
):
    return json.dumps({
        "item_id": "U-09", "status": status, "review_state": review,
        "current_value": {
            "passwd_file_present": True, "passwd_file_readable": True,
            "group_file_present": True, "group_file_readable": True,
            "valid_passwd_entry_count": 2, "valid_group_entry_count": groups,
            "unique_primary_gid_count": primary, "unique_group_gid_count": groups,
            "linked_group_gid_count": linked, "unlinked_group_gid_count": unlinked,
            "problem_gid_count": unlinked,
            "missing_primary_group_gid_count": missing_primary,
            "duplicate_group_gid_count": duplicates,
            "unknown_explicit_member_reference_count": unknown_members,
            "malformed_passwd_entry_count": 0, "malformed_group_entry_count": 0,
            "nss_configuration_state": nss_state,
            "external_identity_sources_present": external,
        },
        "evidence": {
            "item_id": "U-09", "collection_method": "Aggregate GID relationship",
            "configuration_paths": ["/etc/passwd", "/etc/group", "/etc/nsswitch.conf"],
            "reason_code": reason, "review_reason": review_reason,
            "os": {"distro": distro, "version_id": version},
            "observed_at": "2026-09-28T00:00:00Z", "module_version": MODULE_VERSION,
            "decision_reason": "fixture reason",
        }, "error": error,
    })


class U09Tests(unittest.TestCase):
    def runner(self, distro="rocky", version="9.4"):
        detected = os_info(distro, version)
        return ModuleRunner(load_manifest(MANIFEST, "manifest-unix-67-v1", detected), detected)

    def execute(self, output, distro="rocky", version="9.4"):
        runner = self.runner(distro, version); planned = runner.prepare_item("U-09", Action.CHECK)
        completed = subprocess.CompletedProcess([str(MODULE)], 0, output, "")
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run", return_value=completed
        ) as run:
            return runner.execute_check(planned), run

    def run_real(self, passwd, group, nsswitch="passwd: files\ngroup: files\n", distro="rocky", version="9.4"):
        shell = shutil.which("sh")
        if not shell:
            self.skipTest("POSIX shell is unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir); etc = root / "etc"; etc.mkdir()
            files = {etc / "passwd": passwd, etc / "group": group}
            if nsswitch is not None:
                files[etc / "nsswitch.conf"] = nsswitch
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

    def test_manifest_and_normal_relationship_are_good(self):
        self.assertEqual(self.runner().prepare_item("U-09", Action.CHECK).module_path.name, "U-09.sh")
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\nuser:x:1000:1000::/home/user:/bin/sh\n",
            "root:x:0:\nusers:x:1000:\n",
        )
        self.assertEqual(actual["status"], "GOOD")
        self.assertEqual(actual["current_value"]["linked_group_gid_count"], 2)

    def test_group_gid_without_account_is_vulnerable(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\n", "root:x:0:\norphan:x:2000:\n"
        )
        self.assertEqual(actual["status"], "VULNERABLE")
        self.assertEqual(actual["current_value"]["problem_gid_count"], 1)

    def test_multiple_normal_gids_are_good(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\na:x:1000:1000::/:/bin/sh\nb:x:1001:1001::/:/bin/sh\n",
            "root:x:0:\na:x:1000:\nb:x:1001:\n",
        )
        self.assertEqual(actual["status"], "GOOD")
        self.assertEqual(actual["current_value"]["unique_group_gid_count"], 3)

    def test_multiple_problem_gids_are_vulnerable(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\n",
            "root:x:0:\norphan1:x:2000:\norphan2:x:2001:\n",
        )
        self.assertEqual(actual["status"], "VULNERABLE")
        self.assertEqual(actual["current_value"]["unlinked_group_gid_count"], 2)

    def test_missing_primary_group_is_separate_and_pending(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\nuser:x:1000:7777::/:/bin/sh\n",
            "root:x:0:\n",
        )
        self.assertIsNone(actual["status"])
        self.assertEqual(actual["current_value"]["missing_primary_group_gid_count"], 1)
        self.assertEqual(actual["evidence"]["review_reason"], "PRIMARY_GID_NOT_DEFINED_IN_LOCAL_GROUP")

    def test_valid_explicit_member_connects_group_without_primary_gid(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\nuser:x:1000:1000::/:/bin/sh\n",
            "root:x:0:\nusers:x:1000:\nproject:x:2000:user\n",
        )
        self.assertEqual(actual["status"], "GOOD")
        self.assertEqual(actual["current_value"]["linked_group_gid_count"], 3)

    def test_duplicate_group_gid_is_deduplicated(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\n",
            "root:x:0:\nroot-alias:x:0:\n",
        )
        self.assertEqual(actual["status"], "GOOD")
        self.assertEqual(actual["current_value"]["unique_group_gid_count"], 1)
        self.assertEqual(actual["current_value"]["duplicate_group_gid_count"], 1)

    def test_unknown_explicit_member_does_not_create_connection(self):
        actual, output = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\n",
            "root:x:0:\nproject:x:2000:ghost-user\n",
        )
        self.assertEqual(actual["status"], "VULNERABLE")
        self.assertEqual(actual["current_value"]["unknown_explicit_member_reference_count"], 1)
        self.assertNotIn("ghost-user", output)

    def test_malformed_passwd_is_uncheckable(self):
        actual, _ = self.run_real("root:x:no:0:root:/root:/bin/sh\n", "root:x:0:\n")
        self.assertEqual(actual["status"], "UNCHECKABLE")

    def test_malformed_group_is_uncheckable(self):
        actual, _ = self.run_real("root:x:0:0:root:/root:/bin/sh\n", "root:x:no:\n")
        self.assertEqual(actual["status"], "UNCHECKABLE")

    def test_passwd_and_group_read_failures_are_uncheckable(self):
        for code in ("PASSWD_FILE_UNREADABLE", "GROUP_FILE_UNREADABLE"):
            with self.subTest(code=code):
                result, _ = self.execute(payload(
                    status="UNCHECKABLE", review="NOT_REQUIRED",
                    reason="KISA_U09_COLLECTION_FAILED",
                    error={"code": code, "message": "safe"},
                ))
                self.assertEqual(result.status, ResultStatus.UNCHECKABLE)

    def test_external_nss_is_pending(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\n",
            "root:x:0:\norphan:x:2000:\n",
            "passwd: files sss\ngroup: files sss\n",
        )
        self.assertIsNone(actual["status"])
        self.assertTrue(actual["current_value"]["external_identity_sources_present"])
        self.assertEqual(actual["evidence"]["review_reason"], "EXTERNAL_OR_UNKNOWN_NSS_REQUIRES_REVIEW")

    def test_missing_nss_configuration_is_pending(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\n", "root:x:0:\n", nsswitch=None
        )
        self.assertEqual(actual["review_state"], "PENDING")
        self.assertEqual(actual["current_value"]["nss_configuration_state"], "not_found")

    def test_rocky_and_ubuntu_supported_contract(self):
        for distro, version in (("rocky", "9.4"), ("rocky", "10"), ("ubuntu", "22.04"), ("ubuntu", "24.04")):
            with self.subTest(distro=distro, version=version):
                result, _ = self.execute(payload(distro, version), distro, version)
                self.assertEqual(result.status, ResultStatus.GOOD)

    def test_evidence_aggregate_counts_are_reproducible(self):
        result, _ = self.execute(payload(groups=5, linked=3, unlinked=2, duplicates=1))
        self.assertEqual(result.current_value["unique_group_gid_count"], 5)
        self.assertEqual(result.current_value["problem_gid_count"], 2)
        self.assertEqual(result.evidence["reason_code"], "KISA_U09_ALL_GROUP_GIDS_CONNECTED")

    def test_account_group_and_gid_lists_are_not_exposed(self):
        secret = "private-group"
        actual, output = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\n",
            f"root:x:0:\n{secret}:x:2222:\n",
        )
        self.assertEqual(actual["status"], "VULNERABLE")
        self.assertNotIn(secret, output)
        self.assertNotIn('"gid_values"', output)

    def test_check_is_read_only(self):
        source = MODULE.read_text(encoding="utf-8")
        self.assertNotRegex(
            source,
            r"(?m)^\s*(groupdel|groupadd|groupmod|usermod|userdel|gpasswd|rm|mv|systemctl|service)\b",
        )
        self.assertNotIn("sed -i", source)

    def test_single_json_invalid_stdout_and_timeout(self):
        actual, _ = self.run_real("root:x:0:0:root:/root:/bin/sh\n", "root:x:0:\n")
        self.assertEqual(actual["item_id"], "U-09")
        with self.assertRaises(ModuleOutputError):
            self.execute("debug\n{}")
        runner = self.runner(); planned = runner.prepare_item("U-09", Action.CHECK)
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run",
            side_effect=subprocess.TimeoutExpired("U-09", 1),
        ):
            with self.assertRaises(ModuleTimeoutError):
                runner.execute_check(planned, timeout_seconds=1)


if __name__ == "__main__":
    unittest.main()
