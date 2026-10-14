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


def shell_path() -> str | None:
    discovered = shutil.which("sh")
    if discovered:
        return discovered
    candidate = Path(r"C:\Program Files\Git\bin\sh.exe")
    return str(candidate) if candidate.is_file() else None


class MetadataHardenTestBase(unittest.TestCase):
    __test__ = False
    item_id = ""
    target_path = ""
    good_mode = ""
    vulnerable_mode = ""
    missing_is_no_change = False
    sensitive_marker = "PRIVATE_METADATA_CONTENT"

    def setUp(self):
        self.executable = shell_path()
        if not self.executable:
            self.skipTest("POSIX shell is unavailable")
        self.module = ROOT / "modules" / "unix" / "harden" / f"{self.item_id}.sh"

    def create_fixture(
        self,
        temp_dir: str,
        *,
        uid: str = "0",
        owner: str = "root",
        gid: str = "0",
        mode: str | None = None,
        create_target: bool = True,
    ):
        fixture_root = Path(temp_dir)
        target = fixture_root / self.target_path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        if create_target:
            target.write_text(self.sensitive_marker + "\n", encoding="utf-8", newline="\n")

        state_file = fixture_root / "metadata.state"
        state_file.write_text(
            f"{uid}|{owner}|{gid}|{mode or self.good_mode}|100|200|300|400|system_u:object_r:etc_t:s0\n",
            encoding="utf-8",
            newline="\n",
        )
        check_fixture = fixture_root / "check.fixture"
        if self.item_id == "U-22":
            check_fixture.write_text(
                f"regular|{uid}|{owner}|{mode or self.good_mode}|{owner}\n",
                encoding="utf-8",
                newline="\n",
            )
        elif self.item_id == "U-29":
            numeric_mode = int(mode or self.good_mode, 8)
            owner_ok = uid == "0" and owner == "root"
            permission_ok = numeric_mode & ~0o600 == 0
            check_fixture.write_text(
                f"complete|true|true|{str(owner_ok).lower()}|{str(permission_ok).lower()}|false\n",
                encoding="utf-8",
                newline="\n",
            )

        command_directory = fixture_root / "bin"
        command_directory.mkdir()
        fake_stat = command_directory / "stat"
        fake_chmod = command_directory / "chmod"
        fake_chown = command_directory / "chown"
        fake_getent = command_directory / "getent"

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
    '%d|%i|%u|%U|%g|%a|%Y|%Z')
        printf '%s|%s|%s|%s|%s|%s|%s|%s\n' "$device" "$inode" "$uid" "$owner" "$gid" "$mode" "$mtime" "$ctime"
        ;;
    '%C')
        if [ "${OS_GUARD_TEST_SELINUX_CONTEXT_FAILURE:-false}" = true ]; then
            exit 1
        fi
        printf '%s\n' "$context"
        ;;
    '%d|%i')
        printf '%s|%s\n' "$device" "$inode"
        ;;
    *)
        exit 2
        ;;
esac
""",
            encoding="utf-8",
            newline="\n",
        )
        fake_chmod.write_text(
            """#!/bin/sh
new_mode=$1
IFS='|' read -r uid owner gid mode device inode mtime ctime context < "$OS_GUARD_TEST_STATE_FILE"
printf '%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$uid" "$owner" "$gid" "$new_mode" "$device" "$inode" "$mtime" "$ctime" "$context" > "$OS_GUARD_TEST_STATE_FILE"
if [ "${OS_GUARD_TEST_ITEM_ID:-}" = U-22 ]; then
    printf 'regular|%s|%s|%s|%s\n' "$uid" "$owner" "$new_mode" "$owner" > "$OS_GUARD_TEST_CHECK_FIXTURE"
elif [ "${OS_GUARD_TEST_ITEM_ID:-}" = U-29 ]; then
    owner_ok=false
    permission_ok=false
    if [ "$uid" = 0 ] && [ "$owner" = root ]; then
        owner_ok=true
    fi
    permission_value=$((0$new_mode))
    if [ $((permission_value & ~0600)) -eq 0 ]; then
        permission_ok=true
    fi
    printf 'complete|true|true|%s|%s|false\n' "$owner_ok" "$permission_ok" > "$OS_GUARD_TEST_CHECK_FIXTURE"
fi
""",
            encoding="utf-8",
            newline="\n",
        )
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
uid=$new_uid
if [ -n "$new_gid" ]; then
    gid=$new_gid
fi
if [ "$uid" = 0 ]; then
    owner=root
else
    owner=user
fi
printf '%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$uid" "$owner" "$gid" "$mode" "$device" "$inode" "$mtime" "$ctime" "$context" > "$OS_GUARD_TEST_STATE_FILE"
if [ "${OS_GUARD_TEST_ITEM_ID:-}" = U-22 ]; then
    printf 'regular|%s|%s|%s|%s\n' "$uid" "$owner" "$mode" "$owner" > "$OS_GUARD_TEST_CHECK_FIXTURE"
elif [ "${OS_GUARD_TEST_ITEM_ID:-}" = U-29 ]; then
    owner_ok=false
    permission_ok=false
    if [ "$uid" = 0 ] && [ "$owner" = root ]; then
        owner_ok=true
    fi
    permission_value=$((0$mode))
    if [ $((permission_value & ~0600)) -eq 0 ]; then
        permission_ok=true
    fi
    printf 'complete|true|true|%s|%s|false\n' "$owner_ok" "$permission_ok" > "$OS_GUARD_TEST_CHECK_FIXTURE"
fi
""",
            encoding="utf-8",
            newline="\n",
        )
        fake_getent.write_text(
            """#!/bin/sh
case "${2:-}" in
    root) printf 'root:x:0:0:root:/root:/bin/sh\n' ;;
    bin) printf 'bin:x:1:1:bin:/bin:/sbin/nologin\n' ;;
    sys) printf 'sys:x:3:3:sys:/dev:/sbin/nologin\n' ;;
    *) exit 2 ;;
esac
""",
            encoding="utf-8",
            newline="\n",
        )

        for command in (fake_stat, fake_chmod, fake_chown, fake_getent):
            command.chmod(0o755)

        return fixture_root, target, state_file, command_directory, fake_stat, fake_chmod, fake_chown

    def environment(self, fixture, *, distro="rocky", version="9.6", extra=None):
        fixture_root, _, state_file, command_directory, fake_stat, fake_chmod, fake_chown = fixture
        backup_root = fixture_root.as_posix()
        command_path = command_directory.as_posix()
        if os.name == "nt" and len(backup_root) > 2 and backup_root[1] == ":":
            backup_root = f"/{backup_root[0].lower()}{backup_root[2:]}"
        if os.name == "nt" and len(command_path) > 2 and command_path[1] == ":":
            command_path = f"/{command_path[0].lower()}{command_path[2:]}"

        environment = os.environ.copy()
        environment.update({
            "PATH": f"{command_path}:/usr/sbin:/usr/bin:/sbin:/bin",
            "LC_ALL": "C",
            "OS_GUARD_DISTRO": distro,
            "OS_GUARD_VERSION_ID": version,
            "OS_GUARD_MODULE_VERSION": MODULE_VERSION,
            "OS_GUARD_TEST_ROOT": fixture_root.as_posix(),
            "OS_GUARD_TEST_STATE_FILE": state_file.as_posix(),
            "OS_GUARD_TEST_STAT_BIN": fake_stat.as_posix(),
            "OS_GUARD_TEST_CHMOD_BIN": fake_chmod.as_posix(),
            "OS_GUARD_TEST_CHOWN_BIN": fake_chown.as_posix(),
            "OS_GUARD_TEST_BACKUP_ROOT": backup_root,
            "OS_GUARD_TEST_DISABLE_ACL_BACKUP": "true",
            "OS_GUARD_TEST_ITEM_ID": self.item_id,
            "OS_GUARD_TEST_CHECK_FIXTURE": (fixture_root / "check.fixture").as_posix(),
        })
        if self.item_id == "U-22":
            environment["OS_GUARD_TEST_METADATA_FILE"] = (fixture_root / "check.fixture").as_posix()
        if self.item_id == "U-29" and (fixture_root / self.target_path.lstrip("/")).exists():
            environment["OS_GUARD_TEST_U29_FILE"] = (fixture_root / "check.fixture").as_posix()
        if extra:
            environment.update(extra)
        return environment

    def run_action(self, action, environment):
        completed = subprocess.run(
            [self.executable, str(self.module), action],
            env=environment,
            capture_output=True,
            text=True,
            timeout=12,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.count("\n"), 1)
        return json.loads(completed.stdout), completed.stdout + completed.stderr

    def preview_and_execute(self, environment):
        preview, _ = self.run_action("PREVIEW", environment)
        execute_environment = environment.copy()
        execute_environment.update({
            "OS_GUARD_HARDEN_APPROVED": "true",
            "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"],
        })
        executed, output = self.run_action("EXECUTE", execute_environment)
        return preview, executed, output

    @staticmethod
    def read_state(state_file):
        fields = state_file.read_text(encoding="utf-8").strip().split("|")
        return {"uid": fields[0], "owner": fields[1], "gid": fields[2], "mode": fields[3]}

    def temporary_directory(self):
        return tempfile.TemporaryDirectory(dir=ROOT)

    def test_01_good_state_is_not_changed(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            before = fixture[2].read_bytes()
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["outcome"], "NO_CHANGE")
            self.assertEqual(fixture[2].read_bytes(), before)

    def test_02_owner_only_is_hardened(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, uid="1000", owner="user")
            preview, result, _ = self.preview_and_execute(self.environment(fixture))
            self.assertTrue(preview["preview"]["owner_change_required"])
            self.assertFalse(preview["preview"]["permission_change_required"])
            self.assertEqual(result["outcome"], "SUCCESS")

    def test_03_permission_only_is_hardened(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, mode=self.vulnerable_mode)
            preview, result, _ = self.preview_and_execute(self.environment(fixture))
            self.assertFalse(preview["preview"]["owner_change_required"])
            self.assertTrue(preview["preview"]["permission_change_required"])
            self.assertEqual(result["outcome"], "SUCCESS")

    def test_04_owner_and_permission_are_hardened(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, uid="1000", owner="user", mode=self.vulnerable_mode)
            preview, result, _ = self.preview_and_execute(self.environment(fixture))
            self.assertTrue(preview["preview"]["owner_change_required"])
            self.assertTrue(preview["preview"]["permission_change_required"])
            self.assertEqual(result["outcome"], "SUCCESS")

    def test_05_missing_target_policy(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, create_target=False)
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            expected = "NO_CHANGE" if self.missing_is_no_change else "FAILED"
            self.assertEqual(result["outcome"], expected)
            self.assertFalse(fixture[1].exists())

    def test_06_symlink_is_rejected(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, mode=self.vulnerable_mode)
            environment = self.environment(fixture, extra={"OS_GUARD_TEST_FORCE_SYMLINK": "true"})
            result, _ = self.run_action("PREVIEW", environment)
            self.assertEqual(result["error"]["code"], "SYMLINK_TARGET_REJECTED")

    def test_07_nonregular_target_is_rejected(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, mode=self.vulnerable_mode)
            environment = self.environment(fixture, extra={"OS_GUARD_TEST_FORCE_NONREGULAR": "true"})
            result, _ = self.run_action("PREVIEW", environment)
            self.assertEqual(result["error"]["code"], "TARGET_NOT_REGULAR_FILE")

    def test_08_stat_failure_is_reported(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, mode=self.vulnerable_mode)
            environment = self.environment(fixture, extra={"OS_GUARD_TEST_STAT_FAILURE": "true"})
            result, _ = self.run_action("PREVIEW", environment)
            self.assertEqual(result["error"]["code"], "STAT_COMMAND_FAILED")

    def execute_with_failure(self, failure_step, *, uid="0", owner="root", mode=None, extra=None):
        temporary = self.temporary_directory()
        temp_dir = temporary.__enter__()
        fixture = self.create_fixture(temp_dir, uid=uid, owner=owner, mode=mode or self.vulnerable_mode)
        environment = self.environment(fixture)
        preview, _ = self.run_action("PREVIEW", environment)
        execution_extra = {
            "OS_GUARD_HARDEN_APPROVED": "true",
            "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"],
            "OS_GUARD_TEST_FAIL_STEP": failure_step,
        }
        if extra:
            execution_extra.update(extra)
        environment.update(execution_extra)
        result, output = self.run_action("EXECUTE", environment)
        return temporary, fixture, result, output

    def test_09_backup_failure_stops_changes(self):
        temporary, fixture, result, _ = self.execute_with_failure("backup")
        try:
            self.assertEqual(result["error"]["code"], "BACKUP_FAILED")
            self.assertFalse(result["execution"]["changes_applied"])
        finally:
            temporary.__exit__(None, None, None)

    def test_10_chmod_failure_attempts_rollback(self):
        temporary, fixture, result, _ = self.execute_with_failure("chmod")
        try:
            self.assertEqual(result["error"]["code"], "CHMOD_FAILED")
            self.assertTrue(result["execution"]["rollback_attempted"])
        finally:
            temporary.__exit__(None, None, None)

    def test_11_chown_failure_attempts_rollback(self):
        temporary, fixture, result, _ = self.execute_with_failure(
            "chown", uid="1000", owner="user", mode=self.good_mode,
        )
        try:
            self.assertEqual(result["error"]["code"], "CHOWN_FAILED")
            self.assertTrue(result["execution"]["rollback_attempted"])
        finally:
            temporary.__exit__(None, None, None)

    def test_12_validation_failure_rolls_back(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, mode=self.vulnerable_mode)
            environment = self.environment(fixture)
            preview, _ = self.run_action("PREVIEW", environment)
            environment.update({
                "OS_GUARD_HARDEN_APPROVED": "true",
                "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"],
                "OS_GUARD_TEST_FORCE_VALIDATION_FAILURE": "true",
            })
            result, _ = self.run_action("EXECUTE", environment)
            self.assertEqual(result["error"]["code"], "VALIDATION_FAILED")
            self.assertTrue(result["execution"]["rollback_attempted"])

    def test_13_existing_check_execution_failure(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, mode=self.vulnerable_mode)
            environment = self.environment(fixture, extra={"OS_GUARD_TEST_CHECK_FAILURE": "true"})
            result, _ = self.run_action("PREVIEW", environment)
            self.assertEqual(result["error"]["code"], "CHECK_EXECUTION_FAILED")

    def test_14_post_check_not_good_rolls_back(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, mode=self.vulnerable_mode)
            environment = self.environment(fixture)
            preview, _ = self.run_action("PREVIEW", environment)
            environment.update({
                "OS_GUARD_HARDEN_APPROVED": "true",
                "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"],
                "OS_GUARD_TEST_FORCE_RECHECK_FAILURE": "true",
            })
            result, _ = self.run_action("EXECUTE", environment)
            self.assertEqual(result["error"]["code"], "RECHECK_FAILED")
            self.assertTrue(result["execution"]["rollback_attempted"])

    def test_15_rollback_success_is_reported(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, mode=self.vulnerable_mode)
            original = self.read_state(fixture[2])
            environment = self.environment(fixture)
            preview, _ = self.run_action("PREVIEW", environment)
            environment.update({
                "OS_GUARD_HARDEN_APPROVED": "true",
                "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"],
                "OS_GUARD_TEST_FORCE_RECHECK_FAILURE": "true",
            })
            result, _ = self.run_action("EXECUTE", environment)
            self.assertTrue(result["execution"]["rollback_success"])
            self.assertEqual(self.read_state(fixture[2]), original)

    def test_16_rollback_failure_is_reported(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, mode=self.vulnerable_mode)
            environment = self.environment(fixture)
            preview, _ = self.run_action("PREVIEW", environment)
            environment.update({
                "OS_GUARD_HARDEN_APPROVED": "true",
                "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"],
                "OS_GUARD_TEST_FORCE_RECHECK_FAILURE": "true",
                "OS_GUARD_TEST_FAIL_STEP": "rollback",
            })
            result, _ = self.run_action("EXECUTE", environment)
            self.assertTrue(result["execution"]["rollback_attempted"])
            self.assertFalse(result["execution"]["rollback_success"])

    def test_17_preview_is_read_only(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, mode=self.vulnerable_mode)
            content_before = hashlib.sha256(fixture[1].read_bytes()).hexdigest()
            state_before = fixture[2].read_bytes()
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["outcome"], "PLANNED")
            self.assertEqual(hashlib.sha256(fixture[1].read_bytes()).hexdigest(), content_before)
            self.assertEqual(fixture[2].read_bytes(), state_before)

    def test_18_state_drift_is_rejected(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, mode=self.vulnerable_mode)
            environment = self.environment(fixture)
            preview, _ = self.run_action("PREVIEW", environment)
            fields = fixture[2].read_text(encoding="utf-8").strip().split("|")
            fields[7] = "401"
            fixture[2].write_text("|".join(fields) + "\n", encoding="utf-8", newline="\n")
            environment.update({
                "OS_GUARD_HARDEN_APPROVED": "true",
                "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"],
            })
            result, _ = self.run_action("EXECUTE", environment)
            self.assertEqual(result["error"]["code"], "STATE_DRIFT")

    def test_19_repeated_hardening_is_idempotent(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, mode=self.vulnerable_mode)
            environment = self.environment(fixture)
            _, first_result, _ = self.preview_and_execute(environment)
            second_result, _ = self.run_action("PREVIEW", environment)
            self.assertEqual(first_result["outcome"], "SUCCESS")
            self.assertEqual(second_result["outcome"], "NO_CHANGE")

    def test_20_sensitive_content_is_not_exposed_or_changed(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, mode=self.vulnerable_mode)
            content_before = fixture[1].read_bytes()
            _, result, output = self.preview_and_execute(self.environment(fixture))
            self.assertEqual(result["outcome"], "SUCCESS")
            self.assertNotIn(self.sensitive_marker, output)
            self.assertEqual(fixture[1].read_bytes(), content_before)

    def test_21_to_24_supported_operating_systems(self):
        operating_systems = (
            ("rocky", "9.6"),
            ("rocky", "10.2"),
            ("ubuntu", "22.04"),
            ("ubuntu", "24.04"),
        )
        for distro, version in operating_systems:
            with self.subTest(distro=distro, version=version):
                with self.temporary_directory() as temp_dir:
                    fixture = self.create_fixture(temp_dir, mode=self.vulnerable_mode)
                    environment = self.environment(fixture, distro=distro, version=version)
                    result, _ = self.run_action("PREVIEW", environment)
                    self.assertEqual(result["outcome"], "PLANNED")
