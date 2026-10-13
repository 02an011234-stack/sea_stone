from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from os_guard_agent import MODULE_VERSION


ROOT = Path(__file__).parents[1]
HARDEN_MODULE = ROOT / "modules" / "unix" / "harden" / "U-19.sh"


def shell_path() -> str | None:
    found = shutil.which("sh")
    if found:
        return found
    candidate = Path(r"C:\Program Files\Git\bin\sh.exe")
    return str(candidate) if candidate.is_file() else None


class U19HardenTests(unittest.TestCase):
    def setUp(self):
        self.executable = shell_path()
        if not self.executable:
            self.skipTest("POSIX shell is unavailable")

    def create_fixture(
        self, temp_dir: str, *, uid="0", owner="root", gid="0", mode="644",
        create_target=True, symlink=False,
    ):
        root = Path(temp_dir)
        target = root / "etc" / "hosts"
        target.parent.mkdir(parents=True)
        content = "192.0.2.25 PRIVATE_HOST_MAPPING\n"

        if create_target:
            if symlink:
                target.write_text(content, encoding="utf-8", newline="\n")
            else:
                target.write_text(content, encoding="utf-8", newline="\n")

        state_file = root / "metadata.state"
        state_file.write_text(
            f"{uid}|{owner}|{gid}|{mode}|100|200|300|400|?\n",
            encoding="utf-8", newline="\n",
        )

        bin_dir = root / "bin"
        bin_dir.mkdir()

        fake_stat = bin_dir / "stat"
        fake_stat.write_text(
            """#!/bin/sh
if [ "${OS_GUARD_TEST_STAT_FAILURE:-false}" = true ]; then
    exit 1
fi
IFS='|' read -r uid owner gid mode device inode mtime ctime context < "$OS_GUARD_TEST_STATE_FILE"
case "$2" in
    '%u|%U|%a')
        printf '%s|%s|%s\n' "$uid" "$owner" "$mode"
        ;;
    '%d|%i|%u|%U|%g|%a|%Y|%Z|%C')
        printf '%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$device" "$inode" "$uid" "$owner" "$gid" "$mode" "$mtime" "$ctime" "$context"
        ;;
    '%d|%i')
        printf '%s|%s\n' "$device" "$inode"
        ;;
    *)
        exit 2
        ;;
esac
""",
            encoding="utf-8", newline="\n",
        )

        fake_chmod = bin_dir / "chmod"
        fake_chmod.write_text(
            """#!/bin/sh
new_mode=$1
IFS='|' read -r uid owner gid mode device inode mtime ctime context < "$OS_GUARD_TEST_STATE_FILE"
printf '%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$uid" "$owner" "$gid" "$new_mode" "$device" "$inode" "$mtime" "$ctime" "$context" > "$OS_GUARD_TEST_STATE_FILE.tmp"
mv -- "$OS_GUARD_TEST_STATE_FILE.tmp" "$OS_GUARD_TEST_STATE_FILE"
""",
            encoding="utf-8", newline="\n",
        )

        fake_chown = bin_dir / "chown"
        fake_chown.write_text(
            """#!/bin/sh
identity=$1
new_uid=${identity%%:*}
if [ "$identity" = "$new_uid" ]; then
    new_gid=''
else
    new_gid=${identity#*:}
fi
IFS='|' read -r uid owner gid mode device inode mtime ctime context < "$OS_GUARD_TEST_STATE_FILE"
if [ -n "$new_gid" ]; then
    gid=$new_gid
fi
uid=$new_uid
if [ "$uid" = 0 ]; then
    owner=root
else
    owner=user
fi
printf '%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$uid" "$owner" "$gid" "$mode" "$device" "$inode" "$mtime" "$ctime" "$context" > "$OS_GUARD_TEST_STATE_FILE.tmp"
mv -- "$OS_GUARD_TEST_STATE_FILE.tmp" "$OS_GUARD_TEST_STATE_FILE"
""",
            encoding="utf-8", newline="\n",
        )

        for command in (fake_stat, fake_chmod, fake_chown):
            command.chmod(0o755)

        return root, target, state_file, fake_stat, fake_chmod, fake_chown

    def environment(
        self, root, state_file, fake_stat, fake_chmod, fake_chown,
        *, distro="rocky", version="9.6", extra=None,
    ):
        env = os.environ.copy()
        backup_root = root.as_posix()
        if os.name == "nt" and len(backup_root) > 2 and backup_root[1] == ":":
            backup_root = f"/{backup_root[0].lower()}{backup_root[2:]}"

        env.update({
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LC_ALL": "C",
            "OS_GUARD_DISTRO": distro,
            "OS_GUARD_VERSION_ID": version,
            "OS_GUARD_MODULE_VERSION": MODULE_VERSION,
            "OS_GUARD_TEST_ROOT": root.as_posix(),
            "OS_GUARD_TEST_STATE_FILE": state_file.as_posix(),
            "OS_GUARD_TEST_STAT_BIN": fake_stat.as_posix(),
            "OS_GUARD_TEST_CHMOD_BIN": fake_chmod.as_posix(),
            "OS_GUARD_TEST_CHOWN_BIN": fake_chown.as_posix(),
            "OS_GUARD_TEST_BACKUP_ROOT": backup_root,
            "OS_GUARD_TEST_DISABLE_ACL_BACKUP": "true",
        })
        if extra:
            env.update(extra)
        return env

    def run_action(self, action, env):
        completed = subprocess.run(
            [self.executable, str(HARDEN_MODULE), action],
            env=env,
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.count("\n"), 1)
        return json.loads(completed.stdout), completed.stdout + completed.stderr

    def preview_and_execute(self, env):
        preview, _ = self.run_action("PREVIEW", env)
        execute_env = env.copy()
        execute_env.update({
            "OS_GUARD_HARDEN_APPROVED": "true",
            "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"],
        })
        executed, output = self.run_action("EXECUTE", execute_env)
        return preview, executed, output

    @staticmethod
    def read_state(state_file):
        fields = state_file.read_text(encoding="utf-8").strip().split("|")
        return {"uid": fields[0], "owner": fields[1], "gid": fields[2], "mode": fields[3]}

    def test_01_root_0644_requires_no_change(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            fixture = self.create_fixture(temp_dir, mode="644")
            env = self.environment(fixture[0], fixture[2], *fixture[3:])
            result, _ = self.run_action("PREVIEW", env)
            self.assertEqual(result["outcome"], "NO_CHANGE")
            self.assertFalse(result["preview"]["backup_required"])

    def test_02_root_0600_is_not_widened(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            fixture = self.create_fixture(temp_dir, mode="600")
            env = self.environment(fixture[0], fixture[2], *fixture[3:])
            result, _ = self.run_action("PREVIEW", env)
            self.assertEqual(result["outcome"], "NO_CHANGE")
            self.assertEqual(result["preview"]["expected_permission"], "600")

    def test_03_excess_permission_changes_permission_only(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            fixture = self.create_fixture(temp_dir, mode="666")
            env = self.environment(fixture[0], fixture[2], *fixture[3:])
            preview, executed, _ = self.preview_and_execute(env)
            self.assertFalse(preview["preview"]["owner_change_required"])
            self.assertTrue(preview["preview"]["permission_change_required"])
            self.assertEqual(preview["preview"]["expected_permission"], "644")
            self.assertEqual(executed["outcome"], "SUCCESS")
            self.assertEqual(self.read_state(fixture[2])["mode"], "644")

    def test_04_non_root_owner_changes_owner_only(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            fixture = self.create_fixture(temp_dir, uid="1000", owner="user", gid="1000", mode="640")
            env = self.environment(fixture[0], fixture[2], *fixture[3:])
            preview, executed, _ = self.preview_and_execute(env)
            self.assertTrue(preview["preview"]["owner_change_required"])
            self.assertFalse(preview["preview"]["permission_change_required"])
            self.assertEqual(executed["outcome"], "SUCCESS")
            state = self.read_state(fixture[2])
            self.assertEqual(state["uid"], "0")
            self.assertEqual(state["gid"], "1000")
            self.assertEqual(state["mode"], "640")

    def test_05_owner_and_permission_are_both_changed(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            fixture = self.create_fixture(temp_dir, uid="1000", owner="user", gid="1000", mode="777")
            env = self.environment(fixture[0], fixture[2], *fixture[3:])
            preview, executed, _ = self.preview_and_execute(env)
            self.assertTrue(preview["preview"]["owner_change_required"])
            self.assertTrue(preview["preview"]["permission_change_required"])
            self.assertEqual(executed["outcome"], "SUCCESS")
            self.assertEqual(self.read_state(fixture[2])["mode"], "644")

    def test_06_missing_target_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            fixture = self.create_fixture(temp_dir, create_target=False)
            env = self.environment(fixture[0], fixture[2], *fixture[3:])
            result, _ = self.run_action("PREVIEW", env)
            self.assertEqual(result["error"]["code"], "TARGET_NOT_FOUND")

    def test_07_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            fixture = self.create_fixture(temp_dir, symlink=True)
            env = self.environment(fixture[0], fixture[2], *fixture[3:])
            env["OS_GUARD_TEST_FORCE_SYMLINK"] = "true"
            result, _ = self.run_action("PREVIEW", env)
            self.assertEqual(result["error"]["code"], "SYMLINK_TARGET_REJECTED")

    def test_08_stat_failure_is_uncheckable_for_hardening(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            fixture = self.create_fixture(temp_dir)
            env = self.environment(
                fixture[0], fixture[2], *fixture[3:],
                extra={"OS_GUARD_TEST_STAT_FAILURE": "true"},
            )
            result, _ = self.run_action("PREVIEW", env)
            self.assertEqual(result["error"]["code"], "STAT_COMMAND_FAILED")

    def test_09_backup_failure_stops_before_change(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            fixture = self.create_fixture(temp_dir, mode="666")
            env = self.environment(fixture[0], fixture[2], *fixture[3:])
            preview, _ = self.run_action("PREVIEW", env)
            env.update({
                "OS_GUARD_HARDEN_APPROVED": "true",
                "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"],
                "OS_GUARD_TEST_FAIL_STEP": "backup",
            })
            result, _ = self.run_action("EXECUTE", env)
            self.assertEqual(result["error"]["code"], "BACKUP_FAILED")
            self.assertFalse(result["execution"]["changes_applied"])
            self.assertEqual(self.read_state(fixture[2])["mode"], "666")

    def test_10_chmod_failure_rolls_back(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            fixture = self.create_fixture(temp_dir, mode="666")
            env = self.environment(fixture[0], fixture[2], *fixture[3:])
            preview, _ = self.run_action("PREVIEW", env)
            env.update({
                "OS_GUARD_HARDEN_APPROVED": "true",
                "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"],
                "OS_GUARD_TEST_FAIL_STEP": "chmod",
            })
            result, _ = self.run_action("EXECUTE", env)
            self.assertEqual(result["error"]["code"], "CHMOD_FAILED")
            self.assertTrue(result["execution"]["rollback_attempted"])
            self.assertTrue(result["execution"]["rollback_success"])

    def test_11_chown_failure_rolls_back(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            fixture = self.create_fixture(temp_dir, uid="1000", owner="user", gid="1000")
            env = self.environment(fixture[0], fixture[2], *fixture[3:])
            preview, _ = self.run_action("PREVIEW", env)
            env.update({
                "OS_GUARD_HARDEN_APPROVED": "true",
                "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"],
                "OS_GUARD_TEST_FAIL_STEP": "chown",
            })
            result, _ = self.run_action("EXECUTE", env)
            self.assertEqual(result["error"]["code"], "CHOWN_FAILED")
            self.assertTrue(result["execution"]["rollback_success"])
            self.assertEqual(self.read_state(fixture[2])["uid"], "1000")

    def test_12_failed_recheck_causes_rollback(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            fixture = self.create_fixture(temp_dir, uid="1000", owner="user", gid="1000", mode="666")
            env = self.environment(fixture[0], fixture[2], *fixture[3:])
            preview, _ = self.run_action("PREVIEW", env)
            env.update({
                "OS_GUARD_HARDEN_APPROVED": "true",
                "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"],
                "OS_GUARD_TEST_FORCE_RECHECK_FAILURE": "true",
            })
            result, _ = self.run_action("EXECUTE", env)
            self.assertEqual(result["error"]["code"], "RECHECK_FAILED")
            self.assertTrue(result["execution"]["rollback_success"])
            self.assertEqual(self.read_state(fixture[2])["uid"], "1000")
            self.assertEqual(self.read_state(fixture[2])["mode"], "666")

    def test_13_rollback_success_is_reported(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            fixture = self.create_fixture(temp_dir, mode="666")
            env = self.environment(fixture[0], fixture[2], *fixture[3:])
            preview, _ = self.run_action("PREVIEW", env)
            env.update({
                "OS_GUARD_HARDEN_APPROVED": "true",
                "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"],
                "OS_GUARD_TEST_FORCE_RECHECK_FAILURE": "true",
            })
            result, _ = self.run_action("EXECUTE", env)
            self.assertTrue(result["execution"]["rollback_attempted"])
            self.assertTrue(result["execution"]["rollback_success"])

    def test_14_rollback_failure_is_reported(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            fixture = self.create_fixture(temp_dir, mode="666")
            env = self.environment(fixture[0], fixture[2], *fixture[3:])
            preview, _ = self.run_action("PREVIEW", env)
            env.update({
                "OS_GUARD_HARDEN_APPROVED": "true",
                "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"],
                "OS_GUARD_TEST_FORCE_RECHECK_FAILURE": "true",
                "OS_GUARD_TEST_FAIL_STEP": "rollback",
            })
            result, _ = self.run_action("EXECUTE", env)
            self.assertTrue(result["execution"]["rollback_attempted"])
            self.assertFalse(result["execution"]["rollback_success"])

    def test_15_preview_does_not_change_state_or_create_backup(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            fixture = self.create_fixture(temp_dir, uid="1000", owner="user", mode="666")
            before_state = fixture[2].read_bytes()
            before_content = hashlib.sha256(fixture[1].read_bytes()).hexdigest()
            env = self.environment(fixture[0], fixture[2], *fixture[3:])
            result, _ = self.run_action("PREVIEW", env)
            backup_root = fixture[0] / "var/lib/os-guard-agent/backups/U-19"
            self.assertEqual(result["outcome"], "PLANNED")
            self.assertEqual(fixture[2].read_bytes(), before_state)
            self.assertEqual(hashlib.sha256(fixture[1].read_bytes()).hexdigest(), before_content)
            self.assertFalse(backup_root.exists())

    def test_16_second_execution_is_idempotent(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            fixture = self.create_fixture(temp_dir, mode="666")
            env = self.environment(fixture[0], fixture[2], *fixture[3:])
            self.preview_and_execute(env)
            state_after_first = fixture[2].read_bytes()
            second_preview, _ = self.run_action("PREVIEW", env)
            self.assertEqual(second_preview["outcome"], "NO_CHANGE")
            self.assertEqual(fixture[2].read_bytes(), state_after_first)

    def test_17_to_20_supported_os_preview(self):
        fixtures = (
            ("ubuntu", "22.04"),
            ("ubuntu", "24.04"),
            ("rocky", "9.6"),
            ("rocky", "10.2"),
        )
        for distro, version in fixtures:
            with self.subTest(distro=distro, version=version):
                with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
                    fixture = self.create_fixture(temp_dir, mode="666")
                    env = self.environment(
                        fixture[0], fixture[2], *fixture[3:],
                        distro=distro, version=version,
                    )
                    result, _ = self.run_action("PREVIEW", env)
                    self.assertEqual(result["outcome"], "PLANNED")

    def test_21_execute_requires_approval(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            fixture = self.create_fixture(temp_dir, mode="666")
            env = self.environment(fixture[0], fixture[2], *fixture[3:])
            result, _ = self.run_action("EXECUTE", env)
            self.assertEqual(result["error"]["code"], "APPROVAL_REQUIRED")

    def test_22_changed_state_after_preview_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            fixture = self.create_fixture(temp_dir, mode="666")
            env = self.environment(fixture[0], fixture[2], *fixture[3:])
            preview, _ = self.run_action("PREVIEW", env)
            fields = fixture[2].read_text(encoding="utf-8").strip().split("|")
            fields[3] = "664"
            fixture[2].write_text("|".join(fields) + "\n", encoding="utf-8", newline="\n")
            env.update({
                "OS_GUARD_HARDEN_APPROVED": "true",
                "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"],
            })
            result, _ = self.run_action("EXECUTE", env)
            self.assertEqual(result["error"]["code"], "TARGET_STATE_CHANGED")

    def test_23_backup_and_result_do_not_expose_hosts_content(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temp_dir:
            fixture = self.create_fixture(temp_dir, mode="666")
            env = self.environment(fixture[0], fixture[2], *fixture[3:])
            _, executed, output = self.preview_and_execute(env)
            self.assertTrue(executed["execution"]["backup_created"])
            self.assertIsNotNone(executed["execution"]["backup_id"])
            self.assertNotIn("PRIVATE_HOST_MAPPING", output)
            self.assertNotIn("192.0.2.25", output)

    def test_24_source_is_readable_and_does_not_modify_file_contents(self):
        source = HARDEN_MODULE.read_text(encoding="utf-8")
        self.assertNotIn("eval ", source)
        self.assertNotIn("sed -i", source)
        self.assertNotRegex(source, r"(?m)^\s*(cat|tee)\s+.*hosts")
        self.assertIn("run_u19_check", source)
        self.assertIn("rollback_changes", source)


if __name__ == "__main__":
    unittest.main()
