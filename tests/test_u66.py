from __future__ import annotations

import json
import os
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
MODULE = ROOT / "modules" / "unix" / "U-66.sh"
MANIFEST = ROOT / "modules" / "manifest.json"


def shell_path() -> str | None:
    found = shutil.which("sh")
    if found:
        return found
    candidate = Path(r"C:\Program Files\Git\bin\sh.exe")
    return str(candidate) if candidate.is_file() else None


def os_info(distro="rocky", version="9.6"):
    return OsInfo(distro, version, version, "fixture", "host", "x86_64", True)


class U66Tests(unittest.TestCase):
    def case(self, row, distro="rocky", version="9.6"):
        executable = shell_path()
        if not executable:
            self.skipTest("POSIX shell is unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = Path(temp_dir) / "u66.fixture"
            fixture.write_text(row + "\n", encoding="utf-8", newline="\n")
            env = {
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
                "OS_GUARD_DISTRO": distro, "OS_GUARD_VERSION_ID": version,
                "OS_GUARD_MODULE_VERSION": MODULE_VERSION,
                "OS_GUARD_TEST_ROOT": temp_dir,
                "OS_GUARD_TEST_U66_FILE": str(fixture),
            }
            completed = subprocess.run(
                [executable, str(MODULE)], env=env, capture_output=True,
                text=True, timeout=5, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            return json.loads(completed.stdout), completed.stdout

    def runtime_case(
        self, *, distro="rocky", version="10.2", journald_active=True,
        analyzer_output=None, analyzer_exit=0, files=None, log_output=True,
    ):
        executable = shell_path()
        if not executable:
            self.skipTest("POSIX shell is unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            systemctl = bin_dir / "systemctl"
            systemctl.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = is-active ] && [ \"$2\" = systemd-journald.service ]; then\n"
                "  [ \"${OS_GUARD_JOURNALD_ACTIVE:-0}\" = 1 ] && printf 'active\\n' || printf 'inactive\\n'\n"
                "else printf 'inactive\\n'; fi\n",
                encoding="utf-8", newline="\n",
            )
            systemctl.chmod(0o755)

            env = os.environ.copy()
            env.update({
                "PATH": f"{bin_dir.as_posix()}:/usr/bin:/bin", "LC_ALL": "C",
                "OS_GUARD_DISTRO": distro, "OS_GUARD_VERSION_ID": version,
                "OS_GUARD_MODULE_VERSION": MODULE_VERSION,
                "OS_GUARD_TEST_ROOT": root.as_posix(),
                "OS_GUARD_JOURNALD_ACTIVE": "1" if journald_active else "0",
            })

            args_file = root / "systemd-analyze.args"
            if analyzer_output is not None:
                analyzer = bin_dir / "systemd-analyze"
                analyzer.write_text(
                    "#!/bin/sh\n"
                    "printf '%s\\n' \"$*\" > \"$OS_GUARD_ANALYZE_ARGS\"\n"
                    "printf '%s\\n' \"$OS_GUARD_ANALYZE_OUTPUT\"\n"
                    "exit \"$OS_GUARD_ANALYZE_EXIT\"\n",
                    encoding="utf-8", newline="\n",
                )
                analyzer.chmod(0o755)
                env.update({
                    "OS_GUARD_TEST_SYSTEMD_ANALYZE_BIN": analyzer.as_posix(),
                    "OS_GUARD_ANALYZE_OUTPUT": analyzer_output,
                    "OS_GUARD_ANALYZE_EXIT": str(analyzer_exit),
                    "OS_GUARD_ANALYZE_ARGS": args_file.as_posix(),
                })

            for relative_path, content in (files or {}).items():
                path = root / relative_path
                if content is None:
                    path.mkdir(parents=True)
                else:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(content, encoding="utf-8", newline="\n")

            log_dir = root / "var" / "log"
            log_dir.mkdir(parents=True, exist_ok=True)
            if log_output:
                (log_dir / "messages").write_text("PRIVATE_LOG_CONTENT\n", encoding="utf-8")

            completed = subprocess.run(
                [executable, str(MODULE)], env=env, capture_output=True,
                text=True, timeout=5, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            return json.loads(completed.stdout), completed.stdout + completed.stderr, (
                args_file.read_text(encoding="utf-8").strip() if args_file.exists() else None
            )

    def test_manifest(self):
        detected = os_info()
        runner = ModuleRunner(load_manifest(MANIFEST, "manifest-unix-67-v1", detected), detected)
        self.assertEqual(runner.prepare_item("U-66", Action.CHECK).module_path.name, "U-66.sh")

    def test_inactive(self):
        self.assertEqual(self.case("complete|0|0|0|0|0|none")[0]["status"], "VULNERABLE")

    def test_rsyslog_policy_verified(self):
        self.assertEqual(self.case("complete|1|1|1|5|0|rsyslog")[0]["status"], "GOOD")

    def test_journald_policy_verified(self):
        self.assertEqual(self.case("complete|1|1|1|1|0|journald")[0]["status"], "GOOD")

    def test_output_absent(self):
        self.assertEqual(self.case("complete|1|0|1|4|0|rsyslog")[0]["status"], "VULNERABLE")

    def test_rules_absent(self):
        self.assertEqual(self.case("complete|1|1|0|0|0|rsyslog")[0]["status"], "VULNERABLE")

    def test_policy_unknown(self):
        self.assertIsNone(self.case("complete|1|1|0|4|0|rsyslog")[0]["status"])

    def test_complex_remote(self):
        self.assertIsNone(self.case("complete|1|1|1|4|1|mixed")[0]["status"])

    def test_error(self):
        self.assertEqual(self.case("error|0|0|0|0|0|none")[0]["status"], "UNCHECKABLE")

    def test_four_os_and_no_log_content(self):
        for distro, version, backend in (
            ("rocky", "9.6", "rsyslog"), ("rocky", "10.2", "rsyslog"),
            ("ubuntu", "22.04", "journald"), ("ubuntu", "24.04", "journald"),
        ):
            with self.subTest(distro=distro, version=version):
                self.assertEqual(
                    self.case(f"complete|1|1|1|2|0|{backend}", distro, version)[0]["status"],
                    "GOOD",
                )
        _, output = self.case("complete|1|1|1|2|0|rsyslog")
        self.assertNotIn("authentication failure", output)

    def test_local_etc_journald_conf(self):
        result, output, _ = self.runtime_case(files={"etc/systemd/journald.conf": "[Journal]\nStorage=auto\n"})
        self.assertIsNone(result["status"])
        self.assertEqual(result["review_state"], "PENDING")
        self.assertNotIn("PRIVATE_LOG_CONTENT", output)

    def test_rocky_vendor_only_without_etc_override(self):
        result, _, _ = self.runtime_case(files={"usr/lib/systemd/journald.conf": "[Journal]\n#Storage=auto\n"})
        self.assertIsNone(result["status"])
        self.assertIsNone(result["error"])
        self.assertEqual(result["current_value"]["required_rules_present_count"], 1)

    def test_drop_in_without_analyzer_is_reviewable(self):
        result, _, _ = self.runtime_case(files={
            "usr/lib/systemd/journald.conf": "[Journal]\n#Storage=auto\n",
            "etc/systemd/journald.conf.d/10-local.conf": "[Journal]\nStorage=persistent\n",
        })
        self.assertIsNone(result["status"])
        self.assertGreater(result["current_value"]["complex_config_count"], 0)

    def test_analyzer_applies_vendor_and_local_precedence(self):
        merged = (
            "# /usr/lib/systemd/journald.conf\n[Journal]\nStorage=none\n"
            "# /etc/systemd/journald.conf.d/10-local.conf\n[Journal]\nStorage=persistent\n"
        )
        result, _, args = self.runtime_case(analyzer_output=merged)
        self.assertIsNone(result["status"])
        self.assertEqual(result["current_value"]["required_rules_present_count"], 1)
        self.assertEqual(result["current_value"]["complex_config_count"], 0)
        self.assertEqual(args, "cat-config systemd/journald.conf")

    def test_analyzer_last_override_can_disable_storage(self):
        merged = (
            "# /usr/lib/systemd/journald.conf\n[Journal]\nStorage=persistent\n"
            "# /etc/systemd/journald.conf.d/10-local.conf\n[Journal]\nStorage=none\n"
        )
        result, _, _ = self.runtime_case(analyzer_output=merged)
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertEqual(result["evidence"]["reason_code"], "KISA_U66_REQUIRED_RULES_ABSENT")

    def test_analyzer_unavailable_uses_vendor_fallback(self):
        result, _, args = self.runtime_case(files={"usr/lib/systemd/journald.conf": "[Journal]\nStorage=auto\n"})
        self.assertIsNone(result["status"])
        self.assertIsNone(args)

    def test_journald_inactive(self):
        result, _, _ = self.runtime_case(journald_active=False)
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertEqual(result["evidence"]["reason_code"], "KISA_U66_LOGGING_INACTIVE")

    def test_storage_none_is_vulnerable(self):
        result, _, _ = self.runtime_case(analyzer_output="# /usr/lib/systemd/journald.conf\n[Journal]\nStorage=none\n")
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertEqual(result["evidence"]["reason_code"], "KISA_U66_REQUIRED_RULES_ABSENT")

    def test_collection_failure_is_uncheckable(self):
        result, _, _ = self.runtime_case(files={"etc/systemd/journald.conf": None})
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "JOURNALD_CONFIG_UNREADABLE")

    def test_malformed_configuration_is_uncheckable(self):
        result, _, _ = self.runtime_case(analyzer_output="not-a-journald-configuration")
        self.assertEqual(result["status"], "UNCHECKABLE")
        self.assertEqual(result["error"]["code"], "JOURNALD_CONFIG_INVALID")

    def test_compiled_defaults_are_not_collection_failure(self):
        result, _, _ = self.runtime_case()
        self.assertIsNone(result["status"])
        self.assertEqual(result["review_state"], "PENDING")
        self.assertIsNone(result["error"])

    def test_runtime_log_output_absent(self):
        result, _, _ = self.runtime_case(
            files={"usr/lib/systemd/journald.conf": "[Journal]\nStorage=auto\n"},
            log_output=False,
        )
        self.assertEqual(result["status"], "VULNERABLE")
        self.assertEqual(result["evidence"]["reason_code"], "KISA_U66_LOG_OUTPUT_ABSENT")

    def test_read_only_and_fixed_analyzer_command(self):
        source = MODULE.read_text(encoding="utf-8")
        self.assertIn("cat-config systemd/journald.conf", source)
        self.assertNotRegex(source, r"(?m)^\s*(rm|mv|touch|chmod|chown|systemctl restart|systemctl reload|apt|dnf|yum)\b")
        self.assertNotIn("sed -i", source)


if __name__ == "__main__":
    unittest.main()
