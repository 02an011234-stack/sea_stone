from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from os_guard_agent import MODULE_VERSION
from os_guard_agent.manifest import load_manifest
from os_guard_agent.models import Action, OsInfo, ResultStatus, ReviewState
from os_guard_agent.module_runner import ModuleRunner, ModuleTimeoutError


ROOT = Path(__file__).parents[1]
MANIFEST = ROOT / "modules" / "manifest.json"
MODULE = ROOT / "modules" / "unix" / "U-14.sh"


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


class U14Tests(unittest.TestCase):
    def runner(self, distro="rocky", version="9.6"):
        detected = os_info(distro, version)
        return ModuleRunner(load_manifest(MANIFEST, "manifest-unix-67-v1", detected), detected)

    def run_real(
        self,
        profile="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nexport PATH\n",
        *,
        distro="rocky",
        version="9.6",
        home="/root",
        shell="/bin/bash",
        root_files=None,
        include_profile=True,
        passwd="default",
    ):
        executable = shell_path()
        if not executable:
            self.skipTest("POSIX shell is unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            if passwd == "default":
                passwd = f"root:x:0:0:root:{home}:{shell}\nuser:x:1000:1000::/home/user:/bin/bash\n"
            files = {"etc/passwd": passwd}
            if include_profile:
                files["etc/profile"] = profile
            files.update(root_files or {})
            before = {}
            for relative, content in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
                before[path] = hashlib.sha256(path.read_bytes()).hexdigest()
            env = {
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LC_ALL": "C",
                "OS_GUARD_DISTRO": distro,
                "OS_GUARD_VERSION_ID": version,
                "OS_GUARD_MODULE_VERSION": MODULE_VERSION,
                "OS_GUARD_TEST_ROOT": str(root),
            }
            completed = subprocess.run(
                [executable, str(MODULE)], env=env, capture_output=True, text=True,
                timeout=5, check=False,
            )
            after = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in before}
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(before, after)
            return json.loads(completed.stdout), completed.stdout + completed.stderr

    def test_01_manifest_selects_u14(self):
        planned = self.runner().prepare_item("U-14", Action.CHECK)
        self.assertEqual(planned.module_path.name, "U-14.sh")

    def test_02_path_without_current_directory_is_good(self):
        result, _ = self.run_real()
        self.assertEqual(result["status"], "GOOD")
        self.assertEqual(result["review_state"], "NOT_REQUIRED")

    def test_03_leading_dot_is_vulnerable(self):
        result, _ = self.run_real("PATH=.:/usr/bin:/bin\n")
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertEqual(result["current_value"]["current_directory_position"], "leading")

    def test_04_middle_dot_is_vulnerable(self):
        result, _ = self.run_real("PATH=/usr/bin:.:/bin\n")
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertEqual(result["current_value"]["current_directory_position"], "middle")

    def test_05_trailing_dot_is_good(self):
        result, _ = self.run_real("PATH=/usr/bin:/bin:.\n")
        self.assertEqual(result["status"], "GOOD")
        self.assertEqual(result["current_value"]["current_directory_position"], "trailing")

    def test_06_commented_dot_is_ignored(self):
        result, _ = self.run_real("# PATH=.:/usr/bin\nPATH=/usr/bin:/bin\n")
        self.assertEqual(result["status"], "GOOD")
        self.assertFalse(result["current_value"]["current_directory_component_found"])

    def test_07_duplicate_assignment_final_good(self):
        result, _ = self.run_real("PATH=.:/usr/bin\nPATH=/usr/bin:/bin\n")
        self.assertEqual(result["status"], "GOOD")
        self.assertTrue(result["current_value"]["conflict_detected"])

    def test_08_duplicate_assignment_final_vulnerable(self):
        result, _ = self.run_real("PATH=/usr/bin:/bin\nPATH=/usr/bin:.:/bin\n")
        self.assertEqual(result["status"], "VULNERABLE")

    def test_09_export_path_assignment_is_supported(self):
        result, _ = self.run_real("export PATH=/usr/bin:/bin\n")
        self.assertEqual(result["status"], "GOOD")

    def test_10_existing_path_reassignment_is_resolved(self):
        result, output = self.run_real("PATH=/usr/bin:/bin\nPATH=\"$PATH:/custom/bin\"\n")
        self.assertEqual(result["status"], "GOOD")
        self.assertNotIn("/usr/bin:/bin:/custom/bin", output)

    def test_11_dynamic_path_is_pending(self):
        fixtures = (
            'PATH="$(custom-path):/usr/bin"\n',
            'if [ -n "$SSH_TTY" ]; then PATH=.:/usr/bin; fi\n',
        )
        for profile in fixtures:
            with self.subTest(profile=profile):
                result, _ = self.run_real(profile)
                self.assertIsNone(result["status"])
                self.assertEqual(result["review_state"], "PENDING")
                self.assertTrue(result["current_value"]["dynamic_path_detected"])

    def test_12_complex_source_is_pending(self):
        result, _ = self.run_real("PATH=/usr/bin:/bin\n. /etc/custom-root-path\n")
        self.assertIsNone(result["status"])
        self.assertEqual(result["review_state"], "PENDING")

    def test_13_nonstandard_root_home_is_pending(self):
        result, _ = self.run_real(home="/admin")
        self.assertIsNone(result["status"])
        self.assertEqual(result["review_state"], "PENDING")
        self.assertEqual(result["current_value"]["root_home_source"], "/etc/passwd")

    def test_14_root_entry_missing_or_malformed_is_uncheckable(self):
        fixtures = ("user:x:1000:1000::/home/user:/bin/bash\n", "root:x:0\n")
        for passwd in fixtures:
            with self.subTest(passwd=passwd):
                result, _ = self.run_real(passwd=passwd)
                self.assertEqual(result["status"], "UNCHECKABLE")

    def test_15_required_profile_unavailable_is_uncheckable(self):
        result, _ = self.run_real(include_profile=False)
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "PROFILE_FILE_NOT_FOUND")

    def test_16_leading_empty_component_is_vulnerable(self):
        result, _ = self.run_real("PATH=:/usr/bin:/bin\n")
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertTrue(result["current_value"]["empty_component_found"])

    def test_17_middle_empty_component_is_vulnerable(self):
        result, _ = self.run_real("PATH=/usr/bin::/bin\n")
        self.assertEqual(result["status"], "VULNERABLE")

    def test_18_trailing_empty_component_is_good(self):
        result, _ = self.run_real("PATH=/usr/bin:/bin:\n")
        self.assertEqual(result["status"], "GOOD")
        self.assertEqual(result["current_value"]["current_directory_position"], "trailing")

    def test_19_rocky_9_fixture(self):
        result, _ = self.run_real(distro="rocky", version="9.6")
        self.assertEqual(result["status"], "GOOD")

    def test_20_rocky_10_profile_d_fixture(self):
        included, _ = self.run_real(
            "for i in /etc/profile.d/*.sh; do . $i; done\n",
            distro="rocky", version="10.0",
            root_files={"etc/profile.d/90-root-path.sh": "PATH=/usr/sbin:/usr/bin:/sbin:/bin\n"},
        )
        self.assertEqual(included["status"], "GOOD", included)
        result, _ = self.run_real(
            "for i in /etc/profile.d/*.sh; do . $i; done\nPATH=/usr/sbin:/usr/bin:/sbin:/bin\n",
            distro="rocky", version="10.0",
            root_files={"etc/profile.d/90-root-path.sh": "PATH=.:/usr/bin\n"},
        )
        self.assertIsNone(result["status"])
        self.assertEqual(result["review_state"], "PENDING")
        self.assertEqual(result["current_value"]["checked_config_count"], 2)

    def test_21_ubuntu_22_root_profile_fixture(self):
        result, _ = self.run_real(
            "PATH=/usr/bin:/bin\n", distro="ubuntu", version="22.04",
            root_files={"root/.profile": "PATH=\"$PATH:/usr/local/bin\"\n"},
        )
        self.assertEqual(result["status"], "GOOD")
        self.assertEqual(result["current_value"]["checked_config_count"], 2)

    def test_22_ubuntu_24_bashrc_fixture(self):
        included, _ = self.run_real(
            "PATH=/usr/bin:/bin\n", distro="ubuntu", version="24.04",
            root_files={
                "root/.bash_profile": ". $HOME/.bashrc\n",
                "root/.bashrc": "PATH=\"$PATH:/usr/local/sbin\"\n",
            },
        )
        self.assertEqual(included["status"], "GOOD")
        result, _ = self.run_real(
            "PATH=/usr/bin:/bin\n", distro="ubuntu", version="24.04",
            root_files={
                "root/.bash_profile": ". $HOME/.bashrc\nPATH=/usr/bin:/usr/local/sbin\n",
                "root/.bashrc": "PATH=.:/usr/bin\n",
            },
        )
        self.assertIsNone(result["status"])
        self.assertEqual(result["review_state"], "PENDING")
        self.assertEqual(result["current_value"]["checked_config_count"], 3)

    def test_23_evidence_contract_and_no_profile_contents(self):
        secret = "PRIVATE_PROFILE_MARKER"
        result, output = self.run_real(f"SECRET={secret}\nPATH=/usr/bin:/bin\n")
        evidence = result["evidence"]
        self.assertEqual(evidence["item_id"], "U-14")
        self.assertEqual(evidence["os"], {"distro": "rocky", "version_id": "9.6"})
        self.assertIn("kernel", evidence)
        self.assertEqual(evidence["module_version"], MODULE_VERSION)
        self.assertIn("observed_at", evidence)
        self.assertIn("reason_code", evidence)
        self.assertNotIn(secret, output)

    def test_24_stdout_is_one_json_object(self):
        result, output = self.run_real()
        self.assertEqual(output.count("\n"), 1)
        self.assertEqual(result["item_id"], "U-14")

    def test_25_runner_contract_and_timeout(self):
        runner = self.runner()
        planned = runner.prepare_item("U-14", Action.CHECK)
        completed = subprocess.CompletedProcess(
            [str(MODULE)], 0,
            json.dumps({
                "item_id": "U-14", "status": "GOOD", "review_state": "NOT_REQUIRED",
                "current_value": {},
                "evidence": {
                    "item_id": "U-14", "os": {"distro": "rocky", "version_id": "9.6"},
                    "module_version": MODULE_VERSION, "observed_at": "2026-09-28T00:00:00Z",
                    "reason_code": "KISA_U14_CURRENT_DIRECTORY_ABSENT_OR_LAST",
                }, "error": None,
            }), "",
        )
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run", return_value=completed,
        ) as run:
            parsed = runner.execute_check(planned)
        self.assertEqual(parsed.status, ResultStatus.GOOD)
        self.assertEqual(parsed.review_state, ReviewState.NOT_REQUIRED)
        self.assertFalse(run.call_args.kwargs["shell"])
        with patch("os_guard_agent.module_runner.os.access", return_value=True), patch(
            "os_guard_agent.module_runner.subprocess.run",
            side_effect=subprocess.TimeoutExpired("U-14", 1),
        ):
            with self.assertRaises(ModuleTimeoutError):
                runner.execute_check(planned, timeout_seconds=1)

    def test_26_unsupported_os_and_source_are_safe(self):
        result, _ = self.run_real(distro="debian", version="12")
        self.assertEqual(result["status"], "UNCHECKABLE")
        source = MODULE.read_text(encoding="utf-8")
        self.assertNotRegex(
            source,
            r"(?m)^\s*(chmod|chown|rm|mv|touch|systemctl|service|usermod|useradd|userdel)\b",
        )
        self.assertNotIn("sed -i", source)
        self.assertNotRegex(source, r"(?m)^\s*echo\b.*>>")


if __name__ == "__main__":
    unittest.main()
