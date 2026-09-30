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
MODULE = ROOT / "modules" / "unix" / "U-07.sh"


def os_info(distro="rocky", version="9.4"):
    return OsInfo(distro, version, version, "kernel", "host", "x86_64", True)


def payload(
    distro="rocky", version="9.4", *, status=None, review="PENDING",
    valid=20, root_count=1, nonroot=19, system=15, regular=5,
    nonlogin=14, login_candidates=6, locked=14, unlocked=5,
    manual_targets=19, manual_required=True,
    reason="KISA_U07_ACCOUNT_NECESSITY_REQUIRES_REVIEW", error=None,
):
    return json.dumps({
        "item_id": "U-07", "status": status, "review_state": review,
        "current_value": {
            "passwd_file_present": True, "passwd_file_readable": True,
            "valid_account_count": valid, "root_account_count": root_count,
            "non_root_account_count": nonroot, "uid_min": 1000,
            "system_account_count": system, "regular_account_count": regular,
            "non_login_shell_count": nonlogin,
            "login_shell_candidate_count": login_candidates,
            "shadow_collection_state": "collected", "locked_account_count": locked,
            "unlocked_account_count": unlocked, "missing_shadow_account_count": 0,
            "malformed_entry_count": 0, "automatic_judgment_target_count": 0,
            "manual_review_target_count": manual_targets,
            "manual_review_required": manual_required,
        },
        "evidence": {
            "item_id": "U-07", "collection_method": "Aggregate account metadata",
            "configuration_paths": ["/etc/passwd", "/etc/login.defs", "/etc/shadow"],
            "kisa_basis_type": "ACCOUNT_NECESSITY_REVIEW", "reason_code": reason,
            "os": {"distro": distro, "version_id": version},
            "observed_at": "2026-09-22T00:00:00Z", "module_version": MODULE_VERSION,
            "decision_reason": "fixture reason",
        }, "error": error,
    })


class U07Tests(unittest.TestCase):
    def runner(self, distro="rocky", version="9.4"):
        detected = os_info(distro, version)
        return ModuleRunner(load_manifest(MANIFEST, "manifest-unix-67-v1", detected), detected)

    def execute(self, output, distro="rocky", version="9.4"):
        runner = self.runner(distro, version); planned = runner.prepare_item("U-07", Action.CHECK)
        completed = subprocess.CompletedProcess([str(MODULE)], 0, output, "")
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run", return_value=completed
        ) as run:
            return runner.execute_check(planned), run

    def run_real(self, passwd, shadow="", login_defs="UID_MIN 1000\n", distro="rocky", version="9.4"):
        shell = shutil.which("sh")
        if not shell:
            self.skipTest("POSIX shell is unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir); etc = root / "etc"; etc.mkdir()
            files = {etc / "passwd": passwd, etc / "login.defs": login_defs}
            if shadow is not None:
                files[etc / "shadow"] = shadow
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

    def test_manifest_and_root_only_are_good(self):
        self.assertEqual(self.runner().prepare_item("U-07", Action.CHECK).module_path.name, "U-07.sh")
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\n", "root:!:1:0:99999:7:::\n"
        )
        self.assertEqual(actual["status"], "GOOD")
        self.assertEqual(actual["review_state"], "NOT_REQUIRED")

    def test_kisa_example_account_name_is_not_automatic_vulnerability(self):
        actual, output = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\nlp:x:4:7:lp:/var/spool/lpd:/usr/sbin/nologin\n",
            "root:!:1:0:99999:7:::\nlp:*:1:0:99999:7:::\n",
        )
        self.assertIsNone(actual["status"])
        self.assertEqual(actual["review_state"], "PENDING")
        self.assertNotIn('"lp"', output)

    def test_normal_system_account_is_not_vulnerable_by_presence(self):
        result, _ = self.execute(payload(system=17, regular=3))
        self.assertIsNone(result.status)
        self.assertEqual(result.review_state, ReviewState.PENDING)

    def test_service_account_requires_review(self):
        result, _ = self.execute(payload(manual_targets=4, nonroot=4))
        self.assertTrue(result.current_value["manual_review_required"])
        self.assertEqual(result.current_value["manual_review_target_count"], 4)

    def test_custom_user_name_does_not_create_denylist_finding(self):
        secret = "custom-operator"
        actual, output = self.run_real(
            f"root:x:0:0:root:/root:/bin/sh\n{secret}:x:1001:1001::/home/x:/bin/sh\n",
            f"root:!:1:0:99999:7:::\n{secret}:!:1:0:99999:7:::\n",
        )
        self.assertIsNone(actual["status"])
        self.assertNotIn(secret, output)

    def test_locked_system_account_is_aggregated_but_pending(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\ndaemon:x:2:2::/:/usr/sbin/nologin\n",
            "root:!:1:0:99999:7:::\ndaemon:*:1:0:99999:7:::\n",
        )
        self.assertIsNone(actual["status"])
        self.assertEqual(actual["current_value"]["locked_account_count"], 1)

    def test_non_login_shell_is_aggregated_without_good_or_vulnerable_guess(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\nsvc:x:20:20::/:/bin/false\n",
            "root:!:1:0:99999:7:::\nsvc:*:1:0:99999:7:::\n",
        )
        self.assertEqual(actual["current_value"]["non_login_shell_count"], 1)
        self.assertEqual(actual["review_state"], "PENDING")

    def test_missing_shadow_remains_reviewable_without_false_vulnerability(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\nsvc:x:20:20::/:/bin/false\n",
            shadow=None,
        )
        self.assertEqual(actual["current_value"]["shadow_collection_state"], "not_present")
        self.assertEqual(actual["review_state"], "PENDING")

    def test_missing_uid_policy_keeps_classification_unknown(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/sh\nuser:x:1000:1000::/home/user:/bin/sh\n",
            "root:!:1:0:99999:7:::\nuser:!:1:0:99999:7:::\n",
            login_defs="",
        )
        self.assertIsNone(actual["current_value"]["system_account_count"])
        self.assertIsNone(actual["current_value"]["regular_account_count"])
        self.assertEqual(actual["review_state"], "PENDING")

    def test_operational_purpose_review_has_reason_code(self):
        result, _ = self.execute(payload())
        self.assertEqual(result.evidence["reason_code"], "KISA_U07_ACCOUNT_NECESSITY_REQUIRES_REVIEW")
        self.assertTrue(result.current_value["manual_review_required"])

    def test_passwd_read_failure_is_uncheckable(self):
        result, _ = self.execute(payload(
            status="UNCHECKABLE", review="NOT_REQUIRED", reason="KISA_U07_COLLECTION_FAILED",
            error={"code": "PASSWD_FILE_UNREADABLE", "message": "safe"},
        ))
        self.assertEqual(result.status, ResultStatus.UNCHECKABLE)

    def test_malformed_passwd_is_uncheckable(self):
        actual, _ = self.run_real("root:x:not-a-uid:0:root:/root:/bin/sh\n")
        self.assertEqual(actual["status"], "UNCHECKABLE")
        self.assertEqual(actual["error"]["code"], "PASSWD_FILE_PARSE_ERROR")

    def test_rocky_and_ubuntu_supported_contract(self):
        for distro, version in (("rocky", "9.4"), ("rocky", "10"), ("ubuntu", "22.04"), ("ubuntu", "24.04")):
            with self.subTest(distro=distro, version=version):
                result, _ = self.execute(payload(distro, version), distro, version)
                self.assertEqual(result.review_state, ReviewState.PENDING)

    def test_evidence_aggregates_system_regular_and_account_state(self):
        result, _ = self.execute(payload(system=12, regular=8, locked=10, unlocked=9))
        self.assertEqual(result.current_value["system_account_count"], 12)
        self.assertEqual(result.current_value["regular_account_count"], 8)
        self.assertEqual(result.current_value["locked_account_count"], 10)
        self.assertEqual(result.evidence["kisa_basis_type"], "ACCOUNT_NECESSITY_REVIEW")

    def test_account_identifiers_and_shadow_values_are_not_exposed(self):
        secret_name = "private-service"; secret_hash = "$6$salt$hash"
        actual, output = self.run_real(
            f"root:x:0:0:root:/root:/bin/sh\n{secret_name}:x:50:50::/:/bin/false\n",
            f"root:!:1:0:99999:7:::\n{secret_name}:{secret_hash}:1:0:99999:7:::\n",
        )
        self.assertIsNone(actual["status"])
        self.assertNotIn(secret_name, output)
        self.assertNotIn(secret_hash, output)

    def test_check_is_read_only(self):
        source = MODULE.read_text(encoding="utf-8")
        self.assertNotRegex(
            source,
            r"(?m)^\s*(userdel|usermod|passwd|chage|rm|mv|service|systemctl|apt|dnf|yum)\b",
        )
        self.assertNotIn("sed -i", source)

    def test_single_json_invalid_stdout_and_timeout(self):
        actual, _ = self.run_real("root:x:0:0:root:/root:/bin/sh\n")
        self.assertEqual(actual["item_id"], "U-07")
        with self.assertRaises(ModuleOutputError):
            self.execute("debug\n{}")
        runner = self.runner(); planned = runner.prepare_item("U-07", Action.CHECK)
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run",
            side_effect=subprocess.TimeoutExpired("U-07", 1),
        ):
            with self.assertRaises(ModuleTimeoutError):
                runner.execute_check(planned, timeout_seconds=1)


if __name__ == "__main__":
    unittest.main()
