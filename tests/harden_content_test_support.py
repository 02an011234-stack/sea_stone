from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from os_guard_agent import MODULE_VERSION


ROOT = Path(__file__).parents[1]


def shell_path() -> str | None:
    discovered = shutil.which("sh")
    if discovered:
        return discovered
    candidate = Path(r"C:\Program Files\Git\bin\sh.exe")
    return str(candidate) if candidate.is_file() else None


class ContentHardenTestBase(unittest.TestCase):
    __test__ = False
    item_id = ""
    target_path = "/etc/profile"
    vulnerable_content = ""
    good_content = ""
    expected_fragment = ""
    sensitive_marker = "UNRELATED_CONFIGURATION_MUST_REMAIN"

    def setUp(self):
        self.shell = shell_path()
        if not self.shell:
            self.skipTest("POSIX shell is unavailable")
        self.module = ROOT / "modules" / "unix" / "harden" / f"{self.item_id}.sh"

    @staticmethod
    def _posix(path: Path) -> str:
        value = path.as_posix()
        if os.name == "nt" and len(value) > 2 and value[1] == ":":
            return f"/{value[0].lower()}{value[2:]}"
        return value

    def _write_command(self, path: Path, content: str):
        path.write_text(content, encoding="utf-8", newline="\n")
        path.chmod(0o755)

    def create_fixture(self, temp_dir: str, *, good=False, content=None):
        root = Path(temp_dir)
        (root / "etc").mkdir(parents=True)
        (root / "root").mkdir(parents=True)
        (root / "etc/passwd").write_text(
            "root:x:0:0:root:/root:/bin/bash\n",
            encoding="utf-8",
            newline="\n",
        )
        target = root / self.target_path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        selected = content if content is not None else (self.good_content if good else self.vulnerable_content)
        target.write_text(
            selected + self.sensitive_marker + "\n",
            encoding="utf-8",
            newline="\n",
        )
        metadata = root / "metadata.state"
        metadata.write_text(
            "100|200|0|0|644|300|400|system_u:object_r:etc_t:s0\n",
            encoding="utf-8",
            newline="\n",
        )
        command_dir = root / "bin"
        command_dir.mkdir()

        fake_stat = command_dir / "stat"
        self._write_command(
            fake_stat,
            r'''#!/bin/sh
[ "${OS_GUARD_TEST_STAT_FAILURE:-false}" = true ] && exit 1
IFS='|' read -r device inode uid gid mode mtime ctime context < "$OS_GUARD_TEST_METADATA_STATE"
case "$2" in
    '%d|%i|%u|%g|%a|%Y|%Z') printf '%s|%s|%s|%s|%s|%s|%s\n' "$device" "$inode" "$uid" "$gid" "$mode" "$mtime" "$ctime" ;;
    '%C')
        [ "${OS_GUARD_TEST_SELINUX_CONTEXT_FAILURE:-false}" != true ] || exit 1
        printf '%s\n' "$context"
        ;;
    '%u|%g|%a') printf '%s|%s|%s\n' "$uid" "$gid" "$mode" ;;
    *) exit 2 ;;
esac
''',
        )
        fake_chmod = command_dir / "chmod"
        self._write_command(fake_chmod, "#!/bin/sh\nexit 0\n")
        fake_chown = command_dir / "chown"
        self._write_command(fake_chown, "#!/bin/sh\nexit 0\n")
        fake_cp = command_dir / "cp"
        self._write_command(
            fake_cp,
            r'''#!/bin/sh
eval "destination=\${$#}"
source=''
for argument in "$@"; do
    case "$argument" in
        -*) ;;
        *)
            if [ -z "$source" ]; then source=$argument; fi
            ;;
    esac
done
exec /usr/bin/cp "$source" "$destination"
''',
        )

        return {
            "root": root,
            "target": target,
            "metadata": metadata,
            "bin": command_dir,
            "stat": fake_stat,
            "chmod": fake_chmod,
            "chown": fake_chown,
            "cp": fake_cp,
        }

    def environment(self, fixture, *, distro="rocky", version="9.6", extra=None):
        command_path = self._posix(fixture["bin"])
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{command_path}:/usr/sbin:/usr/bin:/sbin:/bin",
                "LC_ALL": "C",
                "OS_GUARD_DISTRO": distro,
                "OS_GUARD_VERSION_ID": version,
                "OS_GUARD_MODULE_VERSION": MODULE_VERSION,
                "OS_GUARD_TEST_ROOT": fixture["root"].as_posix(),
                "OS_GUARD_TEST_STAT_BIN": fixture["stat"].as_posix(),
                "OS_GUARD_TEST_CHMOD_BIN": fixture["chmod"].as_posix(),
                "OS_GUARD_TEST_CHOWN_BIN": fixture["chown"].as_posix(),
                "OS_GUARD_TEST_METADATA_STATE": fixture["metadata"].as_posix(),
                "OS_GUARD_TEST_DISABLE_ACL_BACKUP": "true",
                "OS_GUARD_TEST_BACKUP_ROOT": (
                    fixture["root"].resolve().relative_to(ROOT.resolve()) / "backups"
                ).as_posix(),
            }
        )
        if extra:
            environment.update(extra)
        return environment

    def run_action(self, action, environment):
        completed = subprocess.run(
            [self.shell, str(self.module), action],
            env=environment,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.count("\n"), 1, completed.stdout)
        return json.loads(completed.stdout), completed.stdout + completed.stderr

    def execute(self, fixture, *, extra=None):
        environment = self.environment(fixture)
        preview, _ = self.run_action("PREVIEW", environment)
        execute_environment = environment.copy()
        execute_environment.update(
            {
                "OS_GUARD_HARDEN_APPROVED": "true",
                "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"],
            }
        )
        if extra:
            execute_environment.update(extra)
        result, output = self.run_action("EXECUTE", execute_environment)
        return preview, result, output

    def temporary_directory(self):
        return tempfile.TemporaryDirectory(dir=ROOT)

    def test_01_good_no_change(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, good=True)
            before = fixture["target"].read_bytes()
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["outcome"], "NO_CHANGE")
            self.assertEqual(fixture["target"].read_bytes(), before)

    def test_02_vulnerable_minimal_change(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            preview, result, _ = self.execute(fixture)
            self.assertEqual(preview["outcome"], "PLANNED")
            self.assertEqual(result["outcome"], "SUCCESS")
            content = fixture["target"].read_text(encoding="utf-8")
            self.assertIn(self.expected_fragment, content)
            self.assertIn(self.sensitive_marker, content)

    def test_03_preview_read_only(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            before = fixture["target"].read_bytes()
            self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(fixture["target"].read_bytes(), before)
            self.assertFalse((fixture["root"] / "backups").exists())

    def test_04_approval_required(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            environment = self.environment(fixture)
            preview, _ = self.run_action("PREVIEW", environment)
            environment["OS_GUARD_HARDEN_EXPECTED_STATE"] = preview["preview"]["state_fingerprint"]
            result, _ = self.run_action("EXECUTE", environment)
            self.assertEqual(result["error"]["code"], "APPROVAL_REQUIRED")

    def test_05_wrong_fingerprint(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            environment = self.environment(
                fixture,
                extra={"OS_GUARD_HARDEN_APPROVED": "true", "OS_GUARD_HARDEN_EXPECTED_STATE": "wrong"},
            )
            result, _ = self.run_action("EXECUTE", environment)
            self.assertEqual(result["error"]["code"], "STATE_DRIFT")

    def test_06_state_drift(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            environment = self.environment(fixture)
            preview, _ = self.run_action("PREVIEW", environment)
            fixture["target"].write_text(
                fixture["target"].read_text(encoding="utf-8") + "# drift\n",
                encoding="utf-8",
                newline="\n",
            )
            environment.update({"OS_GUARD_HARDEN_APPROVED": "true", "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"]})
            result, _ = self.run_action("EXECUTE", environment)
            self.assertEqual(result["error"]["code"], "STATE_DRIFT")

    def test_07_symlink_rejected(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            extra = {"OS_GUARD_TEST_FORCE_SYMLINK_PATH": self.target_path}
            result, _ = self.run_action("PREVIEW", self.environment(fixture, extra=extra))
            self.assertEqual(result["error"]["code"], "SYMLINK_TARGET_REJECTED")

    def test_08_backup_failure(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            before = fixture["target"].read_bytes()
            _, result, _ = self.execute(fixture, extra={"OS_GUARD_TEST_FAIL_STEP": "backup"})
            self.assertEqual(result["error"]["code"], "BACKUP_FAILED")
            self.assertEqual(fixture["target"].read_bytes(), before)

    def test_09_apply_failure_rolls_back(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            before = fixture["target"].read_bytes()
            _, result, _ = self.execute(fixture, extra={"OS_GUARD_TEST_FAIL_STEP": "apply"})
            self.assertTrue(result["execution"]["rollback_attempted"])
            self.assertTrue(result["execution"]["rollback_success"])
            self.assertEqual(fixture["target"].read_bytes(), before)

    def test_10_validation_failure_rolls_back(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            before = fixture["target"].read_bytes()
            _, result, _ = self.execute(fixture, extra={"OS_GUARD_TEST_FORCE_VALIDATION_FAILURE": "true"})
            self.assertEqual(result["error"]["code"], "VALIDATION_FAILED")
            self.assertTrue(result["execution"]["rollback_success"])
            self.assertEqual(fixture["target"].read_bytes(), before)

    def test_11_initial_check_failure(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, _ = self.run_action("PREVIEW", self.environment(fixture, extra={"OS_GUARD_TEST_CHECK_FAILURE": "true"}))
            self.assertEqual(result["error"]["code"], "CHECK_EXECUTION_FAILED")

    def test_12_post_check_failure_rolls_back(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            before = fixture["target"].read_bytes()
            _, result, _ = self.execute(fixture, extra={"OS_GUARD_TEST_FORCE_RECHECK_FAILURE": "true"})
            self.assertEqual(result["error"]["code"], "RECHECK_FAILED")
            self.assertTrue(result["execution"]["rollback_success"])
            self.assertEqual(fixture["target"].read_bytes(), before)

    def test_13_rollback_failure(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            _, result, _ = self.execute(
                fixture,
                extra={"OS_GUARD_TEST_FORCE_VALIDATION_FAILURE": "true", "OS_GUARD_TEST_FAIL_STEP": "rollback"},
            )
            self.assertTrue(result["execution"]["rollback_attempted"])
            self.assertFalse(result["execution"]["rollback_success"])

    def test_14_idempotent(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            _, result, _ = self.execute(fixture)
            self.assertEqual(result["outcome"], "SUCCESS")
            before = fixture["target"].read_bytes()
            second, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(second["outcome"], "NO_CHANGE")
            self.assertEqual(fixture["target"].read_bytes(), before)

    def test_15_unrelated_content_preserved(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            self.execute(fixture)
            self.assertIn(self.sensitive_marker, fixture["target"].read_text(encoding="utf-8"))

    def test_16_rocky_9(self):
        self.assert_supported("rocky", "9.6")

    def test_17_rocky_10(self):
        self.assert_supported("rocky", "10.1")

    def test_18_ubuntu_22(self):
        self.assert_supported("ubuntu", "22.04")

    def test_19_ubuntu_24(self):
        self.assert_supported("ubuntu", "24.04")

    def assert_supported(self, distro, version):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, _ = self.run_action("PREVIEW", self.environment(fixture, distro=distro, version=version))
            self.assertEqual(result["outcome"], "PLANNED")
