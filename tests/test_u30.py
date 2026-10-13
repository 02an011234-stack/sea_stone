from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from os_guard_agent import MODULE_VERSION
from os_guard_agent.manifest import load_manifest
from os_guard_agent.models import Action, OsInfo
from os_guard_agent.module_runner import ModuleRunner


ROOT = Path(__file__).parents[1]
MODULE = ROOT / "modules" / "unix" / "U-30.sh"
MANIFEST = ROOT / "modules" / "manifest.json"


def shell_executable() -> str | None:
    discovered = shutil.which("sh")
    git_bash = Path(r"C:\Program Files\Git\bin\sh.exe")
    if discovered:
        return discovered
    if git_bash.is_file():
        return str(git_bash)
    return None


def os_info(distro: str = "rocky", version: str = "9.6") -> OsInfo:
    return OsInfo(
        distro,
        version,
        version,
        "fixture-kernel",
        "host",
        "x86_64",
        True,
    )


class U30Tests(unittest.TestCase):
    def run_fixture_case(
        self,
        row: str,
        distro: str = "rocky",
        version: str = "9.6",
    ) -> dict:
        shell = shell_executable()
        if not shell:
            self.skipTest("POSIX shell is unavailable")

        with tempfile.TemporaryDirectory(dir=ROOT) as temp_directory:
            fixture_path = Path(temp_directory) / "umask-result"
            fixture_path.write_text(row + "\n", encoding="utf-8", newline="\n")
            environment = self.environment(temp_directory, distro, version)
            environment["OS_GUARD_TEST_UMASK_FILE"] = str(fixture_path)
            return self.run_module(shell, environment)

    def run_runtime_case(
        self,
        source_content: str,
        distro: str = "rocky",
        version: str = "9.6",
    ) -> dict:
        shell = shell_executable()
        if not shell:
            self.skipTest("POSIX shell is unavailable")

        with tempfile.TemporaryDirectory(dir=ROOT) as temp_directory:
            profile_path = Path(temp_directory) / "etc" / "profile"
            profile_path.parent.mkdir(parents=True)
            profile_path.write_text(source_content, encoding="utf-8", newline="\n")
            environment = self.environment(temp_directory, distro, version)
            return self.run_module(shell, environment)

    @staticmethod
    def environment(
        test_root: str,
        distro: str,
        version: str,
    ) -> dict[str, str]:
        return {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LC_ALL": "C",
            "OS_GUARD_DISTRO": distro,
            "OS_GUARD_VERSION_ID": version,
            "OS_GUARD_MODULE_VERSION": MODULE_VERSION,
            "OS_GUARD_TEST_ROOT": str(Path(test_root).resolve()),
        }

    def run_module(self, shell: str, environment: dict[str, str]) -> dict:
        completed = subprocess.run(
            [shell, str(MODULE)],
            env=environment,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.count("\n"), 1)
        return json.loads(completed.stdout)

    def test_manifest_selects_u30(self):
        current_os = os_info()
        runner = ModuleRunner(
            load_manifest(MANIFEST, "manifest-unix-67-v1", current_os),
            current_os,
        )
        plan = runner.prepare_item("U-30", Action.CHECK)
        self.assertEqual(plan.module_path.name, "U-30.sh")

    def test_fixture_022_is_good(self):
        result = self.run_fixture_case("complete|2|1|1|0|0|022")
        self.assertEqual(result["status"], "GOOD")

    def test_fixture_027_is_good(self):
        result = self.run_fixture_case("complete|2|1|1|0|0|027")
        self.assertEqual(result["status"], "GOOD")

    def test_fixture_077_is_good(self):
        result = self.run_fixture_case("complete|2|1|1|0|0|077")
        self.assertEqual(result["status"], "GOOD")

    def test_fixture_002_is_vulnerable(self):
        result = self.run_fixture_case("complete|1|1|0|1|0|002")
        self.assertEqual(result["status"], "VULNERABLE")

    def test_missing_setting_is_vulnerable(self):
        result = self.run_fixture_case("complete|1|0|0|0|0|")
        self.assertEqual(result["status"], "VULNERABLE")

    def test_ambiguous_setting_is_pending(self):
        result = self.run_fixture_case("complete|3|2|1|1|1|022")
        self.assertIsNone(result["status"])
        self.assertEqual(result["review_state"], "PENDING")

    def test_read_error_is_uncheckable(self):
        result = self.run_fixture_case("read_error|1|0|0|0|0|")
        self.assertEqual(result["status"], "UNCHECKABLE")

    def test_four_supported_operating_systems(self):
        supported_systems = (
            ("rocky", "9.6"),
            ("rocky", "10.0"),
            ("ubuntu", "22.04"),
            ("ubuntu", "24.04"),
        )
        for distro, version in supported_systems:
            with self.subTest(distro=distro, version=version):
                result = self.run_fixture_case(
                    "complete|2|1|1|0|0|022",
                    distro,
                    version,
                )
                self.assertEqual(result["status"], "GOOD")

    def test_runtime_octal_values_and_boundary(self):
        expectations = {
            "0022": "GOOD",
            "022": "GOOD",
            "027": "GOOD",
            "077": "GOOD",
            "0002": "VULNERABLE",
        }
        for mask, expected_status in expectations.items():
            with self.subTest(mask=mask):
                result = self.run_runtime_case(f"umask {mask}\n")
                self.assertEqual(result["status"], expected_status)
                self.assertEqual(result["current_value"]["effective_mask"], mask)

    def test_runtime_good_reason_and_contract(self):
        result = self.run_runtime_case("umask 0022\n")
        self.assertEqual(result["status"], "GOOD")
        self.assertEqual(result["review_state"], "NOT_REQUIRED")
        self.assertEqual(
            result["evidence"]["reason_code"],
            "KISA_U30_MASK_COMPLIANT",
        )
        self.assertIsNone(result["error"])

    def test_runtime_vulnerable_reason_and_contract(self):
        result = self.run_runtime_case("umask 0002\n")
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertEqual(result["review_state"], "NOT_REQUIRED")
        self.assertEqual(
            result["evidence"]["reason_code"],
            "KISA_U30_MASK_BELOW_REQUIREMENT",
        )

    def test_invalid_runtime_value_is_pending_not_good(self):
        result = self.run_runtime_case("umask 09\n")
        self.assertIsNone(result["status"])
        self.assertEqual(result["review_state"], "PENDING")
        self.assertEqual(
            result["evidence"]["reason_code"],
            "KISA_U30_EFFECTIVE_VALUE_AMBIGUOUS",
        )

    def test_sources_and_read_only_operations(self):
        source = MODULE.read_text(encoding="utf-8")
        for required_source in (
            "/etc/profile",
            "/etc/login.defs",
            "/etc/profile.d",
            ".bashrc",
        ):
            self.assertIn(required_source, source)
        self.assertIn("required_mask_decimal=$((0022))", source)
        self.assertNotRegex(
            source,
            r"(?m)^\s*(chmod|chown|rm|mv|touch|tee|usermod|systemctl)\b",
        )


if __name__ == "__main__":
    unittest.main()
