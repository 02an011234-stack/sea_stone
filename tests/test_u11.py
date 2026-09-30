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
MODULE = ROOT / "modules" / "unix" / "U-11.sh"
TARGETS = ("daemon", "bin", "sys", "adm", "listen", "nobody", "nobody4", "noaccess", "diag", "operator", "games", "gopher")


def os_info(distro="rocky", version="9.4"):
    return OsInfo(distro, version, version, "kernel", "host", "x86_64", True)


def target_lines(shells: str | list[str]) -> str:
    selected = [shells] * len(TARGETS) if isinstance(shells, str) else shells
    return "".join(
        f"{name}:x:{100 + index}:{100 + index}::/:{selected[index]}\n"
        for index, name in enumerate(TARGETS)
    )


def payload(
    distro="rocky", version="9.4", *, status="GOOD", review="NOT_REQUIRED",
    valid=20, existing=12, compliant=12, violating=0,
    reason="KISA_U11_TARGET_SHELLS_RESTRICTED", error=None,
):
    return json.dumps({
        "item_id": "U-11", "status": status, "review_state": review,
        "current_value": {
            "passwd_file_present": True, "passwd_file_readable": True,
            "valid_entry_count": valid, "target_account_definition_count": 12,
            "existing_target_count": existing, "compliant_shell_count": compliant,
            "violating_target_count": violating, "missing_target_count": 12 - existing,
            "nonstandard_shell_count": violating, "malformed_entry_count": 0,
        },
        "evidence": {
            "item_id": "U-11", "collection_method": "Aggregate KISA target shell states",
            "configuration_paths": ["/etc/passwd"], "reason_code": reason,
            "os": {"distro": distro, "version_id": version},
            "observed_at": "2026-09-28T00:00:00Z", "module_version": MODULE_VERSION,
            "decision_reason": "fixture reason",
        }, "error": error,
    })


class U11Tests(unittest.TestCase):
    def runner(self, distro="rocky", version="9.4"):
        detected = os_info(distro, version)
        return ModuleRunner(load_manifest(MANIFEST, "manifest-unix-67-v1", detected), detected)

    def execute(self, output, distro="rocky", version="9.4"):
        runner = self.runner(distro, version); planned = runner.prepare_item("U-11", Action.CHECK)
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

    def test_manifest_and_all_false_are_good(self):
        self.assertEqual(self.runner().prepare_item("U-11", Action.CHECK).module_path.name, "U-11.sh")
        actual, _ = self.run_real("root:x:0:0:root:/root:/bin/bash\n" + target_lines("/bin/false"))
        self.assertEqual(actual["status"], "GOOD")
        self.assertEqual(actual["current_value"]["compliant_shell_count"], 12)

    def test_all_sbin_nologin_are_good(self):
        actual, _ = self.run_real("root:x:0:0:root:/root:/bin/bash\n" + target_lines("/sbin/nologin"))
        self.assertEqual(actual["status"], "GOOD")

    def test_false_and_nologin_mix_is_good(self):
        shells = ["/bin/false" if index % 2 else "/sbin/nologin" for index in range(12)]
        actual, _ = self.run_real("root:x:0:0:root:/root:/bin/bash\n" + target_lines(shells))
        self.assertEqual(actual["status"], "GOOD")

    def test_daemon_bash_is_vulnerable(self):
        actual, _ = self.run_real("root:x:0:0:root:/root:/bin/bash\ndaemon:x:2:2::/:/bin/bash\n")
        self.assertEqual(actual["status"], "VULNERABLE")
        self.assertEqual(actual["current_value"]["violating_target_count"], 1)

    def test_target_bin_sh_is_vulnerable(self):
        actual, _ = self.run_real("root:x:0:0:root:/root:/bin/bash\ngames:x:12:12::/:/bin/sh\n")
        self.assertEqual(actual["status"], "VULNERABLE")

    def test_multiple_violations_are_vulnerable(self):
        actual, _ = self.run_real(
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:2:2::/:/bin/bash\ngames:x:12:12::/:/bin/sh\n"
        )
        self.assertEqual(actual["current_value"]["violating_target_count"], 2)

    def test_missing_target_accounts_are_not_violations(self):
        actual, _ = self.run_real("root:x:0:0:root:/root:/bin/bash\ndaemon:x:2:2::/:/bin/false\n")
        self.assertEqual(actual["status"], "GOOD")
        self.assertEqual(actual["current_value"]["missing_target_count"], 11)

    def test_general_user_bash_is_not_u11_violation(self):
        actual, _ = self.run_real("root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash\n")
        self.assertEqual(actual["status"], "GOOD")
        self.assertEqual(actual["current_value"]["existing_target_count"], 0)

    def test_root_bash_is_not_u11_violation(self):
        actual, _ = self.run_real("root:x:0:0:root:/root:/bin/bash\n")
        self.assertEqual(actual["status"], "GOOD")

    def test_usr_sbin_nologin_is_not_exact_kisa_shell(self):
        actual, _ = self.run_real("root:x:0:0:root:/root:/bin/bash\ndaemon:x:2:2::/:/usr/sbin/nologin\n")
        self.assertEqual(actual["status"], "VULNERABLE")

    def test_malformed_passwd_is_uncheckable(self):
        actual, _ = self.run_real("root:x:0:0:root:/root\n")
        self.assertEqual(actual["status"], "UNCHECKABLE")

    def test_passwd_read_failure_is_uncheckable(self):
        result, _ = self.execute(payload(
            status="UNCHECKABLE", reason="KISA_U11_COLLECTION_FAILED",
            error={"code": "PASSWD_FILE_UNREADABLE", "message": "safe"},
        ))
        self.assertEqual(result.status, ResultStatus.UNCHECKABLE)

    def test_empty_passwd_is_uncheckable(self):
        actual, _ = self.run_real("")
        self.assertEqual(actual["status"], "UNCHECKABLE")

    def test_rocky_fixtures(self):
        for version in ("9.4", "10"):
            result, _ = self.execute(payload("rocky", version), "rocky", version)
            self.assertEqual(result.status, ResultStatus.GOOD)

    def test_ubuntu_fixtures(self):
        for version in ("22.04", "24.04"):
            result, _ = self.execute(payload("ubuntu", version), "ubuntu", version)
            self.assertEqual(result.status, ResultStatus.GOOD)

    def test_evidence_aggregate_counts_are_exact(self):
        result, _ = self.execute(payload(
            status="VULNERABLE", existing=8, compliant=6, violating=2,
            reason="KISA_U11_LOGIN_SHELL_ASSIGNED",
        ))
        self.assertEqual(result.current_value["target_account_definition_count"], 12)
        self.assertEqual(result.current_value["missing_target_count"], 4)
        self.assertEqual(result.current_value["nonstandard_shell_count"], 2)

    def test_account_names_and_password_fields_are_not_exposed(self):
        secret_user = "private-user"; secret_password = "$6$salt$hash"
        actual, output = self.run_real(
            f"root:x:0:0:root:/root:/bin/bash\n{secret_user}:{secret_password}:1000:1000::/home/x:/bin/bash\ndaemon:x:2:2::/:/bin/false\n"
        )
        self.assertEqual(actual["status"], "GOOD")
        self.assertNotIn(secret_user, output)
        self.assertNotIn(secret_password, output)
        self.assertNotIn('"account_names"', output)

    def test_check_is_read_only(self):
        source = MODULE.read_text(encoding="utf-8")
        self.assertNotRegex(
            source,
            r"(?m)^\s*(usermod|chsh|useradd|userdel|passwd|rm|mv|chmod|chown)\b",
        )
        self.assertNotIn("sed -i", source)

    def test_single_json_invalid_stdout_and_timeout(self):
        actual, _ = self.run_real("root:x:0:0:root:/root:/bin/bash\n")
        self.assertEqual(actual["item_id"], "U-11")
        with self.assertRaises(ModuleOutputError):
            self.execute("debug\n{}")
        runner = self.runner(); planned = runner.prepare_item("U-11", Action.CHECK)
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run",
            side_effect=subprocess.TimeoutExpired("U-11", 1),
        ):
            with self.assertRaises(ModuleTimeoutError):
                runner.execute_check(planned, timeout_seconds=1)


if __name__ == "__main__":
    unittest.main()
