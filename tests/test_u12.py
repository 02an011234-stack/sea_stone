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
MODULE = ROOT / "modules" / "unix" / "U-12.sh"


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
    distro="rocky",
    version="9.6",
    *,
    status="GOOD",
    review="NOT_REQUIRED",
    configured=True,
    seconds=600,
    source="/etc/profile",
    export_state="exported",
    assignments=1,
    duplicates=0,
    conflict=False,
    dynamic=False,
    checked=1,
    manual=False,
    reason="KISA_U12_TIMEOUT_WITHIN_LIMIT",
    error=None,
):
    return json.dumps(
        {
            "item_id": "U-12",
            "status": status,
            "review_state": review,
            "current_value": {
                "timeout_configured": configured,
                "effective_timeout_seconds": seconds,
                "timeout_source": source,
                "export_state": export_state,
                "assignment_count": assignments,
                "duplicate_setting_count": duplicates,
                "conflict_detected": conflict,
                "dynamic_setting_detected": dynamic,
                "checked_config_count": checked,
                "manual_review_required": manual,
            },
            "evidence": {
                "item_id": "U-12",
                "collection_method": "Static read-only global profile evaluation",
                "configuration_paths": ["/etc/profile"],
                "reason_code": reason,
                "os": {"distro": distro, "version_id": version},
                "kernel": "fixture-kernel",
                "observed_at": "2026-09-28T00:00:00Z",
                "module_version": MODULE_VERSION,
                "decision_reason": "fixture decision",
            },
            "error": error,
        }
    )


class U12Tests(unittest.TestCase):
    def runner(self, distro="rocky", version="9.6"):
        detected = os_info(distro, version)
        return ModuleRunner(load_manifest(MANIFEST, "manifest-unix-67-v1", detected), detected)

    def execute(self, output, distro="rocky", version="9.6"):
        runner = self.runner(distro, version)
        planned = runner.prepare_item("U-12", Action.CHECK)
        completed = subprocess.CompletedProcess([str(MODULE)], 0, output, "")
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run", return_value=completed
        ) as run:
            return runner.execute_check(planned), run

    def run_real(self, files, distro="rocky", version="9.6"):
        shell = shell_path()
        if not shell:
            self.skipTest("POSIX shell is unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            paths = {}
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
                paths[path] = hashlib.sha256(path.read_bytes()).hexdigest()
            env = {
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LC_ALL": "C",
                "OS_GUARD_DISTRO": distro,
                "OS_GUARD_VERSION_ID": version,
                "OS_GUARD_MODULE_VERSION": MODULE_VERSION,
                "OS_GUARD_TEST_ROOT": str(root),
            }
            completed = subprocess.run(
                [shell, str(MODULE)], env=env, capture_output=True, text=True,
                timeout=5, check=False,
            )
            after = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(paths, after)
            return json.loads(completed.stdout), completed.stdout + completed.stderr

    def assert_real_status(self, profile, expected, **kwargs):
        result, _output = self.run_real({"etc/profile": profile}, **kwargs)
        self.assertEqual(result["status"], expected)
        return result

    def test_manifest_and_tmout_600_export_is_good(self):
        self.assertEqual(self.runner().prepare_item("U-12", Action.CHECK).module_path.name, "U-12.sh")
        result = self.assert_real_status("TMOUT=600\nexport TMOUT\n", "GOOD")
        self.assertEqual(result["current_value"]["effective_timeout_seconds"], 600)
        self.assertEqual(result["current_value"]["export_state"], "exported")

    def test_tmout_300_export_is_good(self):
        self.assert_real_status("export TMOUT=300\n", "GOOD")

    def test_tmout_one_is_good_without_guessing_a_higher_minimum(self):
        result = self.assert_real_status("TMOUT=1\n", "GOOD")
        self.assertEqual(result["current_value"]["export_state"], "not_exported")

    def test_tmout_601_and_900_are_vulnerable(self):
        for seconds in (601, 900):
            with self.subTest(seconds=seconds):
                self.assert_real_status(f"TMOUT={seconds}\nexport TMOUT\n", "VULNERABLE")

    def test_missing_and_commented_tmout_are_vulnerable(self):
        for profile in ("PATH=/usr/bin\n", "# TMOUT=600\n# export TMOUT\n"):
            with self.subTest(profile=profile):
                result = self.assert_real_status(profile, "VULNERABLE")
                self.assertFalse(result["current_value"]["timeout_configured"])

    def test_zero_is_disabled_and_vulnerable(self):
        result = self.assert_real_status("TMOUT=0\nexport TMOUT\n", "VULNERABLE")
        self.assertFalse(result["current_value"]["timeout_configured"])

    def test_nonnumeric_tmout_is_pending(self):
        result = self.assert_real_status("TMOUT=$SESSION_LIMIT\nexport TMOUT\n", None)
        self.assertEqual(result["review_state"], "PENDING")
        self.assertTrue(result["current_value"]["dynamic_setting_detected"])
        self.assertTrue(result["current_value"]["manual_review_required"])

    def test_duplicate_final_600_is_good(self):
        result = self.assert_real_status("TMOUT=300\nTMOUT=600\nexport TMOUT\n", "GOOD")
        self.assertEqual(result["current_value"]["effective_timeout_seconds"], 600)
        self.assertEqual(result["current_value"]["duplicate_setting_count"], 1)
        self.assertTrue(result["current_value"]["conflict_detected"])

    def test_duplicate_final_900_is_vulnerable(self):
        result = self.assert_real_status("TMOUT=300\nTMOUT=900\nexport TMOUT\n", "VULNERABLE")
        self.assertEqual(result["current_value"]["effective_timeout_seconds"], 900)

    def test_dynamic_or_conditional_final_setting_is_pending(self):
        fixtures = (
            "TMOUT=300\nTMOUT=$SESSION_LIMIT\n",
            "if [ -n \"$SSH_TTY\" ]; then\nTMOUT=300\nfi\n",
            "TMOUT=300\n. /etc/custom-session-policy\n",
        )
        for profile in fixtures:
            with self.subTest(profile=profile):
                self.assert_real_status(profile, None)

    def test_later_literal_can_resolve_an_earlier_dynamic_value(self):
        result = self.assert_real_status("TMOUT=$SESSION_LIMIT\nTMOUT=600\nexport TMOUT\n", "GOOD")
        self.assertFalse(result["current_value"]["dynamic_setting_detected"])

    def test_csh_autologout_ten_minutes_is_good(self):
        result, _ = self.run_real({"etc/profile": "PATH=/usr/bin\n", "etc/csh.cshrc": "set autologout=10\n"})
        self.assertEqual(result["status"], "GOOD")
        self.assertEqual(result["current_value"]["effective_timeout_seconds"], 600)
        self.assertEqual(result["current_value"]["export_state"], "not_applicable")

    def test_csh_autologout_over_ten_minutes_is_vulnerable(self):
        result, _ = self.run_real({"etc/profile": "PATH=/usr/bin\n", "etc/csh.login": "set autologout=11\n"})
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertEqual(result["current_value"]["effective_timeout_seconds"], 660)

    def test_missing_required_profile_is_uncheckable(self):
        result, _ = self.run_real({"etc/profile.d/10-path.sh": "PATH=/usr/bin\n"})
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "PROFILE_FILE_NOT_FOUND")

    def test_four_supported_os_use_distinct_representative_fixtures(self):
        fixtures = (
            ("rocky", "9.6", {"etc/profile": "TMOUT=600\nexport TMOUT\n"}, "/etc/profile"),
            ("rocky", "10.0", {"etc/profile": "for i in /etc/profile.d/*.sh; do . $i; done\n", "etc/profile.d/90-tmout.sh": "export TMOUT=300\n"}, "/etc/profile.d/90-tmout.sh"),
            ("ubuntu", "22.04", {"etc/profile": ". /etc/bash.bashrc\nexport TMOUT=600\n"}, "/etc/profile"),
            ("ubuntu", "24.04", {"etc/profile": "for i in /etc/profile.d/*.sh; do . $i; done\n", "etc/profile.d/99-session-timeout.sh": "TMOUT=300\nexport TMOUT\n"}, "/etc/profile.d/99-session-timeout.sh"),
        )
        for distro, version, files, source in fixtures:
            with self.subTest(distro=distro, version=version):
                result, _ = self.run_real(files, distro, version)
                self.assertEqual(result["status"], "GOOD")
                self.assertEqual(result["evidence"]["os"], {"distro": distro, "version_id": version})
                self.assertEqual(result["current_value"]["timeout_source"], source)

    def test_unreferenced_profile_fragment_is_not_treated_as_effective(self):
        result, _ = self.run_real({
            "etc/profile": "PATH=/usr/bin\n",
            "etc/profile.d/99-session-timeout.sh": "TMOUT=300\nexport TMOUT\n",
        })
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertEqual(result["current_value"]["checked_config_count"], 1)

    def test_evidence_is_complete_without_configuration_contents(self):
        secret = "PRIVATE_PROFILE_VALUE"
        result, output = self.run_real({"etc/profile": f"SECRET={secret}\nTMOUT=600\nexport TMOUT\n"})
        self.assertEqual(result["evidence"]["item_id"], "U-12")
        self.assertIn("kernel", result["evidence"])
        self.assertIn("observed_at", result["evidence"])
        self.assertEqual(result["evidence"]["module_version"], MODULE_VERSION)
        self.assertNotIn(secret, output)
        self.assertNotIn("profile_contents", output)

    def test_runner_contract_single_json_and_timeout(self):
        result, run = self.execute(payload())
        self.assertEqual(result.status, ResultStatus.GOOD)
        self.assertFalse(run.call_args.kwargs["shell"])
        with self.assertRaises(ModuleOutputError):
            self.execute("debug\n{}")
        runner = self.runner(); planned = runner.prepare_item("U-12", Action.CHECK)
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run",
            side_effect=subprocess.TimeoutExpired("U-12", 1),
        ):
            with self.assertRaises(ModuleTimeoutError):
                runner.execute_check(planned, timeout_seconds=1)

    def test_collection_failure_contract_is_uncheckable(self):
        result, _ = self.execute(payload(
            status="UNCHECKABLE", configured=False, seconds=None, source=None,
            reason="KISA_U12_COLLECTION_FAILED",
            error={"code": "PROFILE_FILE_UNREADABLE", "message": "safe"},
        ))
        self.assertEqual(result.status, ResultStatus.UNCHECKABLE)

    def test_check_source_is_read_only(self):
        source = MODULE.read_text(encoding="utf-8")
        self.assertNotRegex(
            source,
            r"(?m)^\s*(chmod|chown|rm|mv|touch|systemctl|service|usermod|useradd|userdel)\b",
        )
        self.assertNotIn("sed -i", source)
        self.assertNotRegex(source, r"(?m)^\s*echo\b.*>>")


if __name__ == "__main__":
    unittest.main()
