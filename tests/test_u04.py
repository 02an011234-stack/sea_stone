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
MODULE = ROOT / "modules" / "unix" / "U-04.sh"


def os_info(distro="rocky", version="9.4"):
    return OsInfo(distro, version, version, "kernel", "host", "x86_64", True)


def payload(
    distro="rocky", version="9.4", *, status="GOOD", review="NOT_REQUIRED",
    refs=18, empty=0, locked=2, direct=0, unknown=0, shadow_present=True,
    shadow_readable=True, shadow_valid=True, missing=0,
    reason="KISA_U04_SHADOW_PASSWORDS_CONFIRMED", review_reason=None, error=None,
):
    return json.dumps({
        "item_id": "U-04", "status": status, "review_state": review,
        "current_value": {
            "passwd_file_present": True, "passwd_file_readable": True,
            "shadow_file_present": shadow_present, "shadow_file_readable": shadow_readable,
            "shadow_structure_valid": shadow_valid,
            "passwd_entry_count": refs + empty + locked + direct + unknown,
            "shadow_entry_count": refs, "shadow_reference_count": refs,
            "empty_field_count": empty, "locked_field_count": locked,
            "direct_encrypted_candidate_count": direct, "unknown_field_count": unknown,
            "malformed_passwd_entry_count": 0, "malformed_shadow_entry_count": 0,
            "missing_shadow_entry_count": missing,
        },
        "evidence": {
            "item_id": "U-04", "collection_method": "Aggregate metadata only",
            "configuration_paths": ["/etc/passwd", "/etc/shadow"],
            "reason_code": reason, "review_reason": review_reason,
            "os": {"distro": distro, "version_id": version},
            "observed_at": "2026-09-22T00:00:00Z", "module_version": MODULE_VERSION,
            "decision_reason": "fixture reason",
        }, "error": error,
    })


class U04Tests(unittest.TestCase):
    def runner(self, distro="rocky", version="9.4"):
        detected = os_info(distro, version)
        return ModuleRunner(load_manifest(MANIFEST, "manifest-unix-67-v1", detected), detected)

    def execute(self, output, distro="rocky", version="9.4"):
        runner = self.runner(distro, version)
        planned = runner.prepare_item("U-04", Action.CHECK)
        completed = subprocess.CompletedProcess([str(MODULE)], 0, output, "")
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run", return_value=completed
        ) as run:
            return runner.execute_check(planned), run

    def test_manifest_and_normal_shadow_are_good(self):
        planned = self.runner().prepare_item("U-04", Action.CHECK)
        self.assertEqual(planned.module_path.name, "U-04.sh")
        result, run = self.execute(payload())
        self.assertEqual(result.status, ResultStatus.GOOD)
        self.assertEqual(result.review_state, ReviewState.NOT_REQUIRED)
        self.assertFalse(run.call_args.kwargs["shell"])

    def test_x_reference_and_shadow_structure_are_good(self):
        result, _ = self.execute(payload(refs=20, locked=0))
        self.assertEqual(result.status, ResultStatus.GOOD)
        self.assertTrue(result.current_value["shadow_structure_valid"])

    def test_clear_unprotected_empty_field_is_vulnerable(self):
        result, _ = self.execute(payload(
            status="VULNERABLE", refs=19, empty=1, locked=0,
            reason="KISA_U04_UNPROTECTED_PASSWORD_FIELD",
        ))
        self.assertEqual(result.status, ResultStatus.VULNERABLE)

    def test_empty_and_locked_fields_are_distinct(self):
        result, _ = self.execute(payload(
            status="VULNERABLE", refs=1, empty=1, locked=3,
            reason="KISA_U04_UNPROTECTED_PASSWORD_FIELD",
        ))
        self.assertEqual(result.current_value["empty_field_count"], 1)
        self.assertEqual(result.current_value["locked_field_count"], 3)

    def test_locked_accounts_do_not_override_valid_shadow_good(self):
        result, _ = self.execute(payload(refs=5, locked=15))
        self.assertEqual(result.status, ResultStatus.GOOD)

    def test_mixed_shadow_and_clear_unprotected_is_vulnerable(self):
        result, _ = self.execute(payload(
            status="VULNERABLE", refs=18, empty=1, locked=1,
            reason="KISA_U04_UNPROTECTED_PASSWORD_FIELD",
        ))
        self.assertEqual(result.status, ResultStatus.VULNERABLE)

    def test_shadow_absence_with_references_is_pending(self):
        result, _ = self.execute(payload(
            status=None, review="PENDING", shadow_present=False, shadow_readable=False,
            shadow_valid=False, reason="KISA_U04_REVIEW_REQUIRED",
            review_reason="SHADOW_REFERENCE_WITHOUT_SHADOW_FILE",
        ))
        self.assertIsNone(result.status)
        self.assertEqual(result.review_state, ReviewState.PENDING)

    def test_unreadable_required_shadow_is_uncheckable(self):
        result, _ = self.execute(payload(
            status="UNCHECKABLE", shadow_readable=False, shadow_valid=False,
            reason="KISA_U04_COLLECTION_FAILED",
            error={"code": "SHADOW_FILE_UNREADABLE", "message": "safe"},
        ))
        self.assertEqual(result.status, ResultStatus.UNCHECKABLE)

    def test_direct_encrypted_candidate_is_pending(self):
        result, _ = self.execute(payload(
            status=None, review="PENDING", refs=0, locked=0, direct=1,
            reason="KISA_U04_REVIEW_REQUIRED",
            review_reason="DIRECT_ENCRYPTED_CANDIDATE_REQUIRES_REVIEW",
        ))
        self.assertEqual(result.review_state, ReviewState.PENDING)

    def test_nonstandard_value_is_pending(self):
        result, _ = self.execute(payload(
            status=None, review="PENDING", refs=0, locked=0, unknown=1,
            reason="KISA_U04_REVIEW_REQUIRED",
            review_reason="NONSTANDARD_PASSWORD_FIELD_REQUIRES_REVIEW",
        ))
        self.assertEqual(result.review_state, ReviewState.PENDING)

    def test_incomplete_shadow_mapping_is_pending(self):
        result, _ = self.execute(payload(
            status=None, review="PENDING", missing=1, reason="KISA_U04_REVIEW_REQUIRED",
            review_reason="SHADOW_REFERENCE_MAPPING_INCOMPLETE",
        ))
        self.assertEqual(result.review_state, ReviewState.PENDING)

    def test_passwd_read_and_parse_failures_are_uncheckable(self):
        for code in ("PASSWD_FILE_UNREADABLE", "PASSWD_FILE_PARSE_ERROR"):
            with self.subTest(code=code):
                result, _ = self.execute(payload(
                    status="UNCHECKABLE", reason="KISA_U04_COLLECTION_FAILED",
                    error={"code": code, "message": "safe"},
                ))
                self.assertEqual(result.status, ResultStatus.UNCHECKABLE)

    def test_evidence_has_counts_and_no_secret_or_account_name(self):
        secret = "$6$private-salt$private-hash"
        result, _ = self.execute(payload(refs=7, locked=4))
        serialized = json.dumps({"current": result.current_value, "evidence": result.evidence})
        self.assertNotIn(secret, serialized)
        self.assertNotIn("account_name", serialized)
        self.assertEqual(result.current_value["shadow_reference_count"], 7)
        self.assertIn("reason_code", result.evidence)

    def test_rocky_and_ubuntu_use_common_linux_paths(self):
        for distro, version in (("rocky", "10"), ("ubuntu", "22.04"), ("ubuntu", "24.04")):
            with self.subTest(distro=distro, version=version):
                result, _ = self.execute(payload(distro, version), distro, version)
                self.assertEqual(result.status, ResultStatus.GOOD)
                self.assertEqual(result.evidence["configuration_paths"], ["/etc/passwd", "/etc/shadow"])

    def test_invalid_json_and_timeout_are_rejected(self):
        with self.assertRaises(ModuleOutputError):
            self.execute("debug\n{}")
        runner = self.runner()
        planned = runner.prepare_item("U-04", Action.CHECK)
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run",
            side_effect=subprocess.TimeoutExpired("U-04", 1),
        ):
            with self.assertRaises(ModuleTimeoutError):
                runner.execute_check(planned, timeout_seconds=1)

    def test_source_is_read_only_and_avoids_secret_outputs(self):
        source = MODULE.read_text(encoding="utf-8")
        self.assertNotRegex(
            source,
            r"(?m)^\s*(pwconv|pwunconv|usermod|chage|passwd|systemctl|service|chmod|chown|rm|mv)\b",
        )
        self.assertNotIn("sed -i", source)
        self.assertNotIn("password_hash", source)
        self.assertNotIn("account_names", source)

    @unittest.skipUnless(shutil.which("sh"), "POSIX shell is unavailable")
    def test_real_module_does_not_modify_fixture_or_leak_hash(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir); etc = root / "etc"; etc.mkdir()
            passwd = etc / "passwd"; shadow = etc / "shadow"
            passwd.write_text(
                "root:x:0:0:root:/root:/bin/sh\nlocked:!:1:1::/:/bin/false\n",
                encoding="utf-8",
            )
            secret = "$6$private-salt$private-hash"
            shadow.write_text(f"root:{secret}:1:0:99999:7:::\n", encoding="utf-8")
            before = hashlib.sha256(passwd.read_bytes() + shadow.read_bytes()).hexdigest()
            env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C",
                "OS_GUARD_DISTRO": "rocky", "OS_GUARD_VERSION_ID": "9.4",
                "OS_GUARD_MODULE_VERSION": MODULE_VERSION, "OS_GUARD_TEST_ROOT": str(root),
            }
            completed = subprocess.run(
                [shutil.which("sh"), str(MODULE)], env=env, capture_output=True,
                text=True, timeout=5, check=False,
            )
            self.assertEqual(completed.returncode, 0)
            self.assertEqual(json.loads(completed.stdout)["status"], "GOOD")
            self.assertNotIn(secret, completed.stdout + completed.stderr)
            after = hashlib.sha256(passwd.read_bytes() + shadow.read_bytes()).hexdigest()
            self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
