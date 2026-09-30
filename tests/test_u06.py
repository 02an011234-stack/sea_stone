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
MODULE = ROOT / "modules" / "unix" / "U-06.sh"


def os_info(distro="rocky", version="9.4"):
    return OsInfo(distro, version, version, "kernel", "host", "x86_64", True)


def payload(
    distro="rocky", version="9.4", *, status="GOOD", review="NOT_REQUIRED",
    method="pam_wheel_required", policy=True, pam_active=True, valid_pam=1,
    nonstandard_pam=0, complex_pam=False, group_exists=True, members=1,
    su_mode="4755", root_only=False, reason="KISA_U06_SU_RESTRICTED_TO_GROUP",
    review_reason=None, error=None,
):
    return json.dumps({
        "item_id": "U-06", "status": status, "review_state": review,
        "current_value": {
            "su_present": True, "su_metadata_collected": True, "su_mode": su_mode,
            "pam_file_present": True, "pam_file_readable": True,
            "pam_wheel_active": pam_active, "pam_wheel_valid_count": valid_pam,
            "pam_wheel_nonstandard_count": nonstandard_pam, "pam_complex": complex_pam,
            "restriction_method": method, "restriction_group_exists": group_exists,
            "restriction_group_member_count": members, "su_group_matches_policy": False,
            "policy_active": policy, "root_only_system": root_only,
            "valid_account_count": 20, "malformed_passwd_entry_count": 0,
        },
        "evidence": {
            "item_id": "U-06", "collection_method": "Read-only su policy inspection",
            "configuration_paths": ["/usr/bin/su", "/etc/pam.d/su", "/etc/group", "/etc/passwd"],
            "reason_code": reason, "review_reason": review_reason,
            "os": {"distro": distro, "version_id": version},
            "observed_at": "2026-09-22T00:00:00Z", "module_version": MODULE_VERSION,
            "decision_reason": "fixture reason",
        }, "error": error,
    })


class U06Tests(unittest.TestCase):
    def runner(self, distro="rocky", version="9.4"):
        detected = os_info(distro, version)
        return ModuleRunner(load_manifest(MANIFEST, "manifest-unix-67-v1", detected), detected)

    def execute(self, output, distro="rocky", version="9.4"):
        runner = self.runner(distro, version); planned = runner.prepare_item("U-06", Action.CHECK)
        completed = subprocess.CompletedProcess([str(MODULE)], 0, output, "")
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run", return_value=completed
        ) as run:
            return runner.execute_check(planned), run

    def run_real(self, *, pam, group="wheel:x:10:alice\n", passwd=None, distro="rocky", version="9.4"):
        shell = shutil.which("sh")
        if not shell:
            self.skipTest("POSIX shell is unavailable")
        if passwd is None:
            passwd = "root:x:0:0:root:/root:/bin/sh\nalice:x:1000:10::/home/alice:/bin/sh\n"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir); (root / "etc/pam.d").mkdir(parents=True); (root / "usr/bin").mkdir(parents=True)
            files = {
                root / "etc/passwd": passwd,
                root / "etc/group": group,
                root / "etc/pam.d/su": pam,
                root / "usr/bin/su": "fixture executable\n",
            }
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

    def test_manifest_and_complete_pam_policy_are_good(self):
        planned = self.runner().prepare_item("U-06", Action.CHECK)
        self.assertEqual(planned.module_path.name, "U-06.sh")
        result, run = self.execute(payload())
        self.assertEqual(result.status, ResultStatus.GOOD)
        self.assertEqual(result.review_state, ReviewState.NOT_REQUIRED)
        self.assertFalse(run.call_args.kwargs["shell"])

    def test_no_su_restriction_is_vulnerable(self):
        actual, _ = self.run_real(pam="auth sufficient pam_rootok.so\n")
        self.assertEqual(actual["status"], "VULNERABLE")
        self.assertFalse(actual["current_value"]["policy_active"])

    def test_inactive_commented_pam_wheel_is_not_active(self):
        actual, _ = self.run_real(pam="# auth required pam_wheel.so use_uid\nauth sufficient pam_rootok.so\n")
        self.assertEqual(actual["status"], "VULNERABLE")
        self.assertFalse(actual["current_value"]["pam_wheel_active"])

    def test_valid_pam_wheel_use_uid_is_good(self):
        actual, _ = self.run_real(pam="auth required pam_wheel.so use_uid\n")
        self.assertEqual(actual["status"], "GOOD")
        self.assertEqual(actual["current_value"]["restriction_method"], "pam_wheel_required")

    def test_valid_pam_group_argument_is_good(self):
        actual, _ = self.run_real(
            pam="auth required /usr/lib64/security/pam_wheel.so group=suadmins\n",
            group="suadmins:x:20:alice\n",
        )
        self.assertEqual(actual["status"], "GOOD")
        self.assertTrue(actual["current_value"]["restriction_group_exists"])

    def test_required_group_absence_is_vulnerable(self):
        actual, _ = self.run_real(
            pam="auth required pam_wheel.so use_uid\n", group="users:x:100:alice\n"
        )
        self.assertEqual(actual["status"], "VULNERABLE")

    def test_non_required_pam_policy_is_pending(self):
        actual, _ = self.run_real(pam="auth sufficient pam_wheel.so use_uid\n")
        self.assertIsNone(actual["status"])
        self.assertEqual(actual["review_state"], "PENDING")
        self.assertTrue(actual["current_value"]["pam_wheel_active"])
        self.assertEqual(actual["evidence"]["review_reason"], "NONSTANDARD_OR_COMPLEX_PAM_POLICY")

    def test_multiline_or_conflicting_pam_is_pending(self):
        result, _ = self.execute(payload(
            status=None, review="PENDING", policy=False, valid_pam=2,
            nonstandard_pam=1, complex_pam=True, method="none",
            reason="KISA_U06_REVIEW_REQUIRED",
            review_reason="NONSTANDARD_OR_COMPLEX_PAM_POLICY",
        ))
        self.assertEqual(result.review_state, ReviewState.PENDING)

    def test_non_pam_mode_4750_group_restriction_is_good(self):
        result, _ = self.execute(payload(
            method="su_file_group_mode_4750", pam_active=False, valid_pam=0,
            su_mode="4750", reason="KISA_U06_SU_RESTRICTED_TO_GROUP",
        ))
        self.assertEqual(result.status, ResultStatus.GOOD)

    def test_root_only_exception_is_good(self):
        result, _ = self.execute(payload(
            method="root_only_exception", root_only=True, pam_active=False,
            valid_pam=0, reason="KISA_U06_ROOT_ONLY_EXCEPTION",
        ))
        self.assertEqual(result.status, ResultStatus.GOOD)

    def test_required_configuration_failure_is_uncheckable(self):
        result, _ = self.execute(payload(
            status="UNCHECKABLE", policy=False, reason="KISA_U06_COLLECTION_FAILED",
            error={"code": "PAM_CONFIGURATION_UNREADABLE", "message": "safe"},
        ))
        self.assertEqual(result.status, ResultStatus.UNCHECKABLE)

    def test_rocky_and_ubuntu_supported_contract(self):
        for distro, version in (("rocky", "9.4"), ("rocky", "10"), ("ubuntu", "22.04"), ("ubuntu", "24.04")):
            with self.subTest(distro=distro, version=version):
                result, _ = self.execute(payload(distro, version), distro, version)
                self.assertEqual(result.status, ResultStatus.GOOD)

    def test_evidence_has_policy_reason_and_aggregate_member_count(self):
        result, _ = self.execute(payload(members=3))
        self.assertEqual(result.current_value["restriction_group_member_count"], 3)
        self.assertEqual(result.evidence["reason_code"], "KISA_U06_SU_RESTRICTED_TO_GROUP")
        self.assertIn("/etc/pam.d/su", result.evidence["configuration_paths"])

    def test_account_and_group_members_are_not_exposed(self):
        secret = "private-operator"
        actual, output = self.run_real(
            pam="auth required pam_wheel.so use_uid\n",
            group=f"wheel:x:10:{secret}\n",
            passwd=f"root:x:0:0:root:/root:/bin/sh\n{secret}:x:1000:10::/home/x:/bin/sh\n",
        )
        self.assertEqual(actual["status"], "GOOD")
        self.assertNotIn(secret, output)

    def test_check_is_read_only_and_never_invokes_su(self):
        source = MODULE.read_text(encoding="utf-8")
        self.assertNotRegex(
            source,
            r"(?m)^\s*(su|usermod|groupmod|gpasswd|chmod|chown|useradd|userdel|rm|mv|sudo)\b",
        )
        self.assertNotIn("sed -i", source)

    def test_single_json_invalid_stdout_and_timeout(self):
        actual, _ = self.run_real(pam="auth required pam_wheel.so use_uid\n")
        self.assertEqual(actual["item_id"], "U-06")
        with self.assertRaises(ModuleOutputError):
            self.execute("debug\n{}")
        runner = self.runner(); planned = runner.prepare_item("U-06", Action.CHECK)
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run",
            side_effect=subprocess.TimeoutExpired("U-06", 1),
        ):
            with self.assertRaises(ModuleTimeoutError):
                runner.execute_check(planned, timeout_seconds=1)


if __name__ == "__main__":
    unittest.main()
