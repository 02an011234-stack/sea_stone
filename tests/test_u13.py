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
from os_guard_agent.models import Action, OsInfo, ResultStatus
from os_guard_agent.module_runner import ModuleOutputError, ModuleRunner, ModuleTimeoutError


ROOT = Path(__file__).parents[1]
MANIFEST = ROOT / "modules" / "manifest.json"
MODULE = ROOT / "modules" / "unix" / "U-13.sh"


def os_info(distro="rocky", version="9.6"):
    return OsInfo(distro, version, version, "fixture-kernel", "host", "x86_64", True)


def shell_path() -> str | None:
    found = shutil.which("sh")
    if found:
        return found
    for candidate in (
        Path(r"C:\Program Files\Git\bin\sh.exe"),
        Path(r"C:\Program Files\Git\usr\bin\sh.exe"),
    ):
        if candidate.is_file():
            return str(candidate)
    return None


def payload(
    distro="rocky", version="9.6", *, status="GOOD", review="NOT_REQUIRED",
    safe=1, weak=0, unknown=0, locked=1, method="SHA512",
    pam_state="SAFE", conflict=False, current="SAFE", future="SAFE",
    manual=False, reason="KISA_U13_SHA2_OR_STRONGER_CONFIRMED", error=None,
):
    return json.dumps({
        "item_id": "U-13", "status": status, "review_state": review,
        "current_value": {
            "checked_account_count": safe + weak + unknown,
            "safe_hash_count": safe, "weak_hash_count": weak,
            "unknown_hash_count": unknown, "locked_or_no_password_count": locked,
            "effective_encrypt_method": method, "login_encrypt_method": "SHA512",
            "login_method_count": 1, "pam_policy_state": pam_state,
            "pam_unix_record_count": 2 if distro == "rocky" else 1,
            "pam_complex": False,
            "authselect_state": "fixture_not_queried" if distro == "rocky" else "not_applicable",
            "policy_conflict_detected": conflict, "current_hash_state": current,
            "future_password_policy_state": future,
            "manual_review_required": manual,
        },
        "evidence": {
            "item_id": "U-13", "collection_method": "Aggregate algorithm fixture",
            "configuration_paths": ["/etc/passwd", "/etc/shadow", "/etc/login.defs"],
            "reason_code": reason,
            "os": {"distro": distro, "version_id": version},
            "kernel": "fixture-kernel", "observed_at": "2026-09-28T00:00:00Z",
            "module_version": MODULE_VERSION, "decision_reason": "fixture decision",
        }, "error": error,
    })


class U13Tests(unittest.TestCase):
    def runner(self, distro="rocky", version="9.6"):
        detected = os_info(distro, version)
        return ModuleRunner(load_manifest(MANIFEST, "manifest-unix-67-v1", detected), detected)

    def execute(self, output, distro="rocky", version="9.6"):
        runner = self.runner(distro, version)
        planned = runner.prepare_item("U-13", Action.CHECK)
        completed = subprocess.CompletedProcess([str(MODULE)], 0, output, "")
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run", return_value=completed
        ) as run:
            return runner.execute_check(planned), run

    def run_real(
        self, *, shadow="$6$salt$sha512", login_defs="ENCRYPT_METHOD SHA512\n",
        pam="password required pam_unix.so sha512 shadow use_authtok\n",
        distro="rocky", version="9.6", passwd_field="x", malformed_shadow=False,
    ):
        shell = shell_path()
        if not shell:
            self.skipTest("POSIX shell is unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            files = {
                "etc/passwd": f"root:x:0:0:root:/root:/bin/bash\nuser:{passwd_field}:1000:1000::/home/user:/bin/bash\n",
                "etc/shadow": "root:!:1:0:99999:7:::\n" + (
                    "user:broken\n" if malformed_shadow else f"user:{shadow}:1:0:99999:7:::\n"
                ),
                "etc/login.defs": login_defs,
            }
            if distro == "rocky":
                files["etc/pam.d/system-auth"] = pam
                files["etc/pam.d/password-auth"] = pam
            else:
                files["etc/pam.d/common-password"] = pam
            hashes = {}
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
                hashes[path] = hashlib.sha256(path.read_bytes()).hexdigest()
            env = {
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
                "OS_GUARD_DISTRO": distro, "OS_GUARD_VERSION_ID": version,
                "OS_GUARD_MODULE_VERSION": MODULE_VERSION,
                "OS_GUARD_TEST_ROOT": str(root),
            }
            completed = subprocess.run(
                [shell, str(MODULE)], env=env, capture_output=True, text=True,
                timeout=5, check=False,
            )
            after = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in hashes}
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(hashes, after)
            return json.loads(completed.stdout), completed.stdout + completed.stderr

    def test_manifest_and_sha512_hash_with_safe_policy_is_good(self):
        self.assertEqual(self.runner().prepare_item("U-13", Action.CHECK).module_path.name, "U-13.sh")
        result, _ = self.run_real()
        self.assertEqual(result["status"], "GOOD")
        self.assertEqual(result["current_value"]["safe_hash_count"], 1)

    def test_sha256_hash_with_safe_policy_is_good(self):
        result, _ = self.run_real(
            shadow="$5$salt$sha256", login_defs="ENCRYPT_METHOD SHA256\n",
            pam="password required pam_unix.so sha256 shadow\n",
        )
        self.assertEqual(result["status"], "GOOD")

    def test_md5_hash_is_vulnerable(self):
        result, _ = self.run_real(shadow="$1$salt$md5")
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertEqual(result["current_value"]["weak_hash_count"], 1)

    def test_weak_hash_overrides_safe_login_defs(self):
        result, _ = self.run_real(shadow="$2b$cost$blowfish", login_defs="ENCRYPT_METHOD SHA512\n")
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertEqual(result["current_value"]["current_hash_state"], "WEAK")

    def test_safe_hash_with_weak_future_policy_is_vulnerable(self):
        result, _ = self.run_real(
            login_defs="ENCRYPT_METHOD MD5\n",
            pam="password required pam_unix.so shadow use_authtok\n",
        )
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertEqual(result["current_value"]["future_password_policy_state"], "WEAK")

    def test_locked_and_no_password_markers_are_not_hashes(self):
        for marker in ("!", "!!", "*", ""):
            with self.subTest(marker=marker):
                result, output = self.run_real(shadow=marker)
                self.assertEqual(result["status"], "GOOD")
                self.assertEqual(result["current_value"]["checked_account_count"], 0)
                self.assertEqual(result["current_value"]["locked_or_no_password_count"], 2)
                self.assertNotIn('"weak_hash_count":1', output)

    def test_unknown_hash_prefix_is_pending(self):
        result, _ = self.run_real(shadow="$y$j9T$opaque")
        self.assertIsNone(result["status"])
        self.assertEqual(result["review_state"], "PENDING")
        self.assertEqual(result["current_value"]["unknown_hash_count"], 1)

    def test_commented_login_defs_uses_documented_pam_unix_default(self):
        result, _ = self.run_real(
            login_defs="# ENCRYPT_METHOD MD5\n",
            pam="password required pam_unix.so shadow use_authtok\n",
        )
        self.assertEqual(result["status"], "GOOD")
        self.assertEqual(result["current_value"]["effective_encrypt_method"], "SHA512_DEFAULT")

    def test_duplicate_login_defs_uses_final_value(self):
        result, _ = self.run_real(
            login_defs="ENCRYPT_METHOD MD5\nENCRYPT_METHOD SHA512\n",
            pam="password required pam_unix.so shadow\n",
        )
        self.assertEqual(result["status"], "GOOD")
        self.assertTrue(result["current_value"]["policy_conflict_detected"])
        self.assertEqual(result["current_value"]["login_encrypt_method"], "SHA512")

    def test_explicit_pam_option_overrides_login_defs_and_records_conflict(self):
        result, _ = self.run_real(
            login_defs="ENCRYPT_METHOD MD5\n",
            pam="password required pam_unix.so sha512 shadow\n",
        )
        self.assertEqual(result["status"], "GOOD")
        self.assertTrue(result["current_value"]["policy_conflict_detected"])
        self.assertEqual(result["current_value"]["effective_encrypt_method"], "SHA512")

    def test_weak_pam_option_overrides_safe_login_defs(self):
        result, _ = self.run_real(pam="password required pam_unix.so md5 shadow\n")
        self.assertEqual(result["status"], "VULNERABLE")

    def test_complex_or_nonstandard_pam_is_pending(self):
        fixtures = (
            "password include custom-password\n",
            "password required pam_custom_hash.so\n",
            "password required pam_unix.so yescrypt shadow\n",
        )
        for pam in fixtures:
            with self.subTest(pam=pam):
                result, _ = self.run_real(pam=pam)
                self.assertIsNone(result["status"])
                self.assertEqual(result["review_state"], "PENDING")

    def test_shadow_collection_failure_is_uncheckable(self):
        result, _ = self.execute(payload(
            status="UNCHECKABLE", safe=0, current="UNKNOWN", future="UNKNOWN",
            reason="KISA_U13_COLLECTION_FAILED",
            error={"code": "ACCOUNT_DATABASE_UNREADABLE", "message": "safe"},
        ))
        self.assertEqual(result.status, ResultStatus.UNCHECKABLE)

    def test_shadow_structure_error_is_uncheckable(self):
        result, _ = self.run_real(malformed_shadow=True)
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "ACCOUNT_DATABASE_PARSE_ERROR")

    def test_four_supported_os_have_distinct_policy_fixtures(self):
        fixtures = (
            ("rocky", "9.6", "$6$s$r9", "ENCRYPT_METHOD SHA512\n", "password required pam_unix.so sha512 shadow\n", "GOOD"),
            ("rocky", "10.0", "$5$s$r10", "ENCRYPT_METHOD SHA256\n", "password required pam_unix.so shadow\n", "GOOD"),
            ("ubuntu", "22.04", "$6$s$u22", "ENCRYPT_METHOD SHA512\n", "password [success=1 default=ignore] pam_unix.so sha512 obscure\n", "GOOD"),
            ("ubuntu", "24.04", "$y$j9T$u24", "ENCRYPT_METHOD YESCRYPT\n", "password [success=1 default=ignore] pam_unix.so yescrypt obscure\n", None),
        )
        for distro, version, shadow, login_defs, pam, expected in fixtures:
            with self.subTest(distro=distro, version=version):
                result, _ = self.run_real(
                    distro=distro, version=version, shadow=shadow,
                    login_defs=login_defs, pam=pam,
                )
                self.assertEqual(result["status"], expected)
                self.assertEqual(result["evidence"]["os"], {"distro": distro, "version_id": version})

    def test_evidence_never_contains_hash_salt_account_mapping_or_token(self):
        secret_hash = "$6$PRIVATE_SALT$PRIVATE_HASH"
        secret_token = "credential-token-secret"
        result, output = self.run_real(
            shadow=secret_hash,
            login_defs=f"# {secret_token}\nENCRYPT_METHOD SHA512\n",
        )
        self.assertEqual(result["status"], "GOOD")
        for secret in (secret_hash, "PRIVATE_SALT", "PRIVATE_HASH", secret_token, "user:$6$"):
            self.assertNotIn(secret, output)
        self.assertNotIn("account_hashes", output)
        self.assertIn("kernel", result["evidence"])

    def test_single_json_runner_contract_and_timeout(self):
        result, run = self.execute(payload())
        self.assertEqual(result.status, ResultStatus.GOOD)
        self.assertFalse(run.call_args.kwargs["shell"])
        with self.assertRaises(ModuleOutputError):
            self.execute("debug\n{}")
        runner = self.runner(); planned = runner.prepare_item("U-13", Action.CHECK)
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run",
            side_effect=subprocess.TimeoutExpired("U-13", 1),
        ):
            with self.assertRaises(ModuleTimeoutError):
                runner.execute_check(planned, timeout_seconds=1)

    def test_check_is_read_only(self):
        source = MODULE.read_text(encoding="utf-8")
        self.assertNotRegex(
            source,
            r"(?m)^\s*(passwd|chpasswd|usermod|authselect\s+(select|enable-feature)|chmod|chown|rm|mv|touch)\b",
        )
        self.assertNotIn("sed -i", source)
        self.assertNotRegex(source, r"(?m)^\s*echo\b.*>>")


if __name__ == "__main__":
    unittest.main()
