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
MODULE = ROOT / "modules" / "unix" / "harden" / "U-20.sh"


def shell_path() -> str | None:
    discovered = shutil.which("sh")
    if discovered:
        return discovered
    candidate = Path(r"C:\Program Files\Git\bin\sh.exe")
    return str(candidate) if candidate.is_file() else None


class TestU20Harden(unittest.TestCase):
    def setUp(self):
        self.executable = shell_path()
        if not self.executable:
            self.skipTest("POSIX shell is unavailable")

    def create_fixture(self, temp_dir, records, *, systemd=False):
        root = Path(temp_dir)
        state_file = root / "metadata.state"
        state_lines = []
        target_files = []
        for index, (display_path, uid, owner, gid, mode) in enumerate(records, start=1):
            target = root / display_path.lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"PRIVATE_U20_CONTENT_{index}\n", encoding="utf-8", newline="\n")
            state_lines.append(
                f"{target.as_posix()}|{uid}|{owner}|{gid}|{mode}|100|{200 + index}|300|400|?"
            )
            target_files.append(target)
        state_file.write_text("\n".join(state_lines) + ("\n" if state_lines else ""), encoding="utf-8", newline="\n")
        scan_file = root / "u20-scan.fixture"
        scan_file.write_text(
            "\n".join(f"regular|{uid}|{owner}|{mode}" for _, uid, owner, _, mode in records)
            + ("\n" if records else ""),
            encoding="utf-8",
            newline="\n",
        )

        if systemd:
            (root / "run/systemd/system").mkdir(parents=True, exist_ok=True)

        command_directory = root / "bin"
        command_directory.mkdir()
        fake_stat = command_directory / "stat"
        fake_chmod = command_directory / "chmod"
        fake_chown = command_directory / "chown"

        fake_stat.write_text(
            """#!/bin/sh
if [ "${OS_GUARD_TEST_STAT_FAILURE:-false}" = true ]; then
    exit 1
fi
format=$2
target=$4
record=$(awk -F'|' -v target="$target" '$1 == target { print; exit }' "$OS_GUARD_TEST_STATE_FILE")
if [ -z "$record" ]; then
    exit 2
fi
IFS='|' read -r path uid owner gid mode device inode mtime ctime context <<EOF
$record
EOF
case "$format" in
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
        exit 3
        ;;
esac
""",
            encoding="utf-8",
            newline="\n",
        )
        fake_chmod.write_text(
            """#!/bin/sh
new_mode=$1
target=$3
awk -F'|' -v OFS='|' -v target="$target" -v new_mode="$new_mode" '
    $1 == target { $5 = new_mode }
    { print }
' "$OS_GUARD_TEST_STATE_FILE" > "$OS_GUARD_TEST_STATE_FILE.tmp"
mv -- "$OS_GUARD_TEST_STATE_FILE.tmp" "$OS_GUARD_TEST_STATE_FILE"
awk -F'|' '{ print "regular|" $2 "|" $3 "|" $5 }' "$OS_GUARD_TEST_STATE_FILE" > "$OS_GUARD_TEST_SCAN_FILE"
""",
            encoding="utf-8",
            newline="\n",
        )
        fake_chown.write_text(
            """#!/bin/sh
identity=$1
target=$3
new_uid=${identity%%:*}
if [ "$identity" = "$new_uid" ]; then
    new_gid=''
else
    new_gid=${identity#*:}
fi
awk -F'|' -v OFS='|' -v target="$target" -v new_uid="$new_uid" -v new_gid="$new_gid" '
    $1 == target {
        $2 = new_uid
        if (new_uid == 0) {
            $3 = "root"
        } else {
            $3 = "user"
        }
        if (new_gid != "") {
            $4 = new_gid
        }
    }
    { print }
' "$OS_GUARD_TEST_STATE_FILE" > "$OS_GUARD_TEST_STATE_FILE.tmp"
mv -- "$OS_GUARD_TEST_STATE_FILE.tmp" "$OS_GUARD_TEST_STATE_FILE"
awk -F'|' '{ print "regular|" $2 "|" $3 "|" $5 }' "$OS_GUARD_TEST_STATE_FILE" > "$OS_GUARD_TEST_SCAN_FILE"
""",
            encoding="utf-8",
            newline="\n",
        )
        for command in (fake_stat, fake_chmod, fake_chown):
            command.chmod(0o755)

        return root, state_file, target_files, command_directory, fake_stat, fake_chmod, fake_chown

    def environment(self, fixture, *, distro="rocky", version="9.6", extra=None):
        root, state_file, _, command_directory, fake_stat, fake_chmod, fake_chown = fixture
        backup_root = root.as_posix()
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
            "OS_GUARD_TEST_ROOT": root.as_posix(),
            "OS_GUARD_TEST_STATE_FILE": state_file.as_posix(),
            "OS_GUARD_TEST_STAT_BIN": fake_stat.as_posix(),
            "OS_GUARD_TEST_CHMOD_BIN": fake_chmod.as_posix(),
            "OS_GUARD_TEST_CHOWN_BIN": fake_chown.as_posix(),
            "OS_GUARD_TEST_BACKUP_ROOT": backup_root,
            "OS_GUARD_TEST_DISABLE_ACL_BACKUP": "true",
            "OS_GUARD_TEST_SCAN_FILE": (root / "u20-scan.fixture").as_posix(),
        })
        has_inetd = (root / "etc/inetd.conf").exists()
        has_xinetd = (root / "etc/xinetd.conf").exists() or (root / "etc/xinetd.d").exists()
        has_systemd = (root / "run/systemd/system").exists()
        if has_systemd and (has_inetd or has_xinetd):
            environment["OS_GUARD_TEST_SERVICE_MODEL"] = "systemd_with_legacy"
        elif has_systemd:
            environment["OS_GUARD_TEST_SERVICE_MODEL"] = "systemd"
        elif has_inetd and has_xinetd:
            environment["OS_GUARD_TEST_SERVICE_MODEL"] = "inetd_and_xinetd"
        elif has_xinetd:
            environment["OS_GUARD_TEST_SERVICE_MODEL"] = "xinetd"
        elif has_inetd:
            environment["OS_GUARD_TEST_SERVICE_MODEL"] = "inetd"
        else:
            environment["OS_GUARD_TEST_SERVICE_MODEL"] = "unknown"
        if extra:
            environment.update(extra)
        return environment

    def run_action(self, action, environment):
        completed = subprocess.run(
            [self.executable, str(MODULE), action],
            env=environment,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.count("\n"), 1)
        return json.loads(completed.stdout), completed.stdout + completed.stderr

    def preview_and_execute(self, environment):
        preview, _ = self.run_action("PREVIEW", environment)
        execution_environment = environment.copy()
        execution_environment.update({
            "OS_GUARD_HARDEN_APPROVED": "true",
            "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"],
        })
        result, output = self.run_action("EXECUTE", execution_environment)
        return preview, result, output

    def temporary_directory(self):
        return tempfile.TemporaryDirectory(dir=ROOT)

    def test_01_systemd_only_is_no_change(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, [], systemd=True)
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["outcome"], "NO_CHANGE")
            self.assertEqual(result["execution"]["recheck_status"], "N/A")

    def test_02_inetd_good_is_no_change(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, [("/etc/inetd.conf", "0", "root", "0", "600")])
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["outcome"], "NO_CHANGE")
            self.assertEqual(result["preview"]["targets"][0]["target"], "/etc/inetd.conf")

    def test_03_xinetd_permission_is_hardened(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, [("/etc/xinetd.conf", "0", "root", "0", "644")])
            preview, result, _ = self.preview_and_execute(self.environment(fixture))
            self.assertTrue(preview["preview"]["targets"][0]["permission_change_required"])
            self.assertEqual(result["outcome"], "SUCCESS")

    def test_04_owner_only_is_hardened(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, [("/etc/inetd.conf", "1000", "user", "1000", "600")])
            preview, result, _ = self.preview_and_execute(self.environment(fixture))
            self.assertTrue(preview["preview"]["targets"][0]["owner_change_required"])
            self.assertEqual(result["outcome"], "SUCCESS")

    def test_05_multiple_targets_are_hardened(self):
        with self.temporary_directory() as temp_dir:
            records = [
                ("/etc/inetd.conf", "1000", "user", "1000", "644"),
                ("/etc/xinetd.conf", "0", "root", "0", "666"),
                ("/etc/xinetd.d/telnet", "0", "root", "0", "640"),
            ]
            fixture = self.create_fixture(temp_dir, records)
            preview, result, _ = self.preview_and_execute(self.environment(fixture))
            self.assertEqual(len(preview["preview"]["targets"]), 3)
            self.assertEqual(result["outcome"], "SUCCESS")

    def test_06_no_target_without_systemd_is_not_actionable(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, [])
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["outcome"], "FAILED")
            self.assertEqual(result["execution"]["recheck_status"], "UNCHECKABLE")

    def test_07_systemd_configuration_is_not_selected(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, [], systemd=True)
            systemd_file = fixture[0] / "etc/systemd/system/example.service"
            systemd_file.parent.mkdir(parents=True, exist_ok=True)
            systemd_file.write_text("PRIVATE_SYSTEMD_CONFIGURATION\n", encoding="utf-8")
            before = systemd_file.read_bytes()
            result, output = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["outcome"], "NO_CHANGE")
            self.assertNotIn("example.service", output)
            self.assertEqual(systemd_file.read_bytes(), before)

    def test_08_symlink_target_is_rejected(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, [("/etc/inetd.conf", "0", "root", "0", "644")])
            environment = self.environment(fixture, extra={"OS_GUARD_TEST_FORCE_SYMLINK_PATH": "/etc/inetd.conf"})
            result, _ = self.run_action("PREVIEW", environment)
            self.assertEqual(result["outcome"], "FAILED")

    def test_09_nonregular_target_is_rejected(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, [("/etc/inetd.conf", "0", "root", "0", "644")])
            environment = self.environment(fixture, extra={"OS_GUARD_TEST_FORCE_NONREGULAR_PATH": "/etc/inetd.conf"})
            result, _ = self.run_action("PREVIEW", environment)
            self.assertEqual(result["outcome"], "FAILED")

    def test_10_stat_failure_is_reported(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, [("/etc/inetd.conf", "0", "root", "0", "644")])
            environment = self.environment(fixture, extra={"OS_GUARD_TEST_STAT_FAILURE": "true"})
            result, _ = self.run_action("PREVIEW", environment)
            self.assertEqual(result["outcome"], "FAILED")

    def execute_failure(self, step=None, extra=None):
        temporary = self.temporary_directory()
        temp_dir = temporary.__enter__()
        fixture = self.create_fixture(temp_dir, [("/etc/inetd.conf", "1000", "user", "1000", "644")])
        environment = self.environment(fixture)
        preview, _ = self.run_action("PREVIEW", environment)
        environment.update({
            "OS_GUARD_HARDEN_APPROVED": "true",
            "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"],
        })
        if step:
            environment["OS_GUARD_TEST_FAIL_STEP"] = step
        if extra:
            environment.update(extra)
        result, output = self.run_action("EXECUTE", environment)
        return temporary, fixture, result, output

    def test_11_to_13_backup_chmod_chown_failures(self):
        for step, expected_code in (("backup", "BACKUP_FAILED"), ("chmod", "CHMOD_FAILED"), ("chown", "CHOWN_FAILED")):
            with self.subTest(step=step):
                temporary, fixture, result, _ = self.execute_failure(step)
                try:
                    self.assertEqual(result["error"]["code"], expected_code)
                finally:
                    temporary.__exit__(None, None, None)

    def test_14_validation_failure_rolls_back(self):
        temporary, fixture, result, _ = self.execute_failure(
            extra={"OS_GUARD_TEST_FORCE_VALIDATION_FAILURE": "true"}
        )
        try:
            self.assertEqual(result["error"]["code"], "VALIDATION_FAILED")
            self.assertTrue(result["execution"]["rollback_attempted"])
        finally:
            temporary.__exit__(None, None, None)

    def test_15_existing_check_failure_stops_preview(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, [("/etc/inetd.conf", "0", "root", "0", "644")])
            environment = self.environment(fixture, extra={"OS_GUARD_TEST_CHECK_FAILURE": "true"})
            result, _ = self.run_action("PREVIEW", environment)
            self.assertEqual(result["error"]["code"], "CHECK_EXECUTION_FAILED")

    def test_16_post_check_failure_rolls_back(self):
        temporary, fixture, result, _ = self.execute_failure(
            extra={"OS_GUARD_TEST_FORCE_RECHECK_FAILURE": "true"}
        )
        try:
            self.assertEqual(result["error"]["code"], "RECHECK_FAILED")
            self.assertTrue(result["execution"]["rollback_attempted"])
            self.assertTrue(result["execution"]["rollback_success"])
        finally:
            temporary.__exit__(None, None, None)

    def test_17_rollback_failure_is_reported(self):
        temporary, fixture, result, _ = self.execute_failure(
            "rollback", {"OS_GUARD_TEST_FORCE_RECHECK_FAILURE": "true"}
        )
        try:
            self.assertTrue(result["execution"]["rollback_attempted"])
            self.assertFalse(result["execution"]["rollback_success"])
        finally:
            temporary.__exit__(None, None, None)

    def test_18_preview_is_read_only(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, [("/etc/inetd.conf", "0", "root", "0", "644")])
            state_before = fixture[1].read_bytes()
            content_before = hashlib.sha256(fixture[2][0].read_bytes()).hexdigest()
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["outcome"], "PLANNED")
            self.assertEqual(fixture[1].read_bytes(), state_before)
            self.assertEqual(hashlib.sha256(fixture[2][0].read_bytes()).hexdigest(), content_before)

    def test_19_state_drift_is_rejected(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, [("/etc/inetd.conf", "0", "root", "0", "644")])
            environment = self.environment(fixture)
            preview, _ = self.run_action("PREVIEW", environment)
            changed = fixture[1].read_text(encoding="utf-8").replace("|400|?", "|401|?")
            fixture[1].write_text(changed, encoding="utf-8", newline="\n")
            environment.update({
                "OS_GUARD_HARDEN_APPROVED": "true",
                "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"],
            })
            result, _ = self.run_action("EXECUTE", environment)
            self.assertEqual(result["error"]["code"], "STATE_DRIFT")

    def test_20_repeated_hardening_is_idempotent(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, [("/etc/inetd.conf", "0", "root", "0", "644")])
            environment = self.environment(fixture)
            _, result, _ = self.preview_and_execute(environment)
            second, _ = self.run_action("PREVIEW", environment)
            self.assertEqual(result["outcome"], "SUCCESS")
            self.assertEqual(second["outcome"], "NO_CHANGE")

    def test_21_sensitive_content_is_not_exposed(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, [("/etc/inetd.conf", "0", "root", "0", "644")])
            before = fixture[2][0].read_bytes()
            _, result, output = self.preview_and_execute(self.environment(fixture))
            self.assertEqual(result["outcome"], "SUCCESS")
            self.assertNotIn("PRIVATE_U20_CONTENT", output)
            self.assertEqual(fixture[2][0].read_bytes(), before)

    def test_22_to_25_supported_operating_systems(self):
        operating_systems = (
            ("rocky", "9.6"),
            ("rocky", "10.2"),
            ("ubuntu", "22.04"),
            ("ubuntu", "24.04"),
        )
        for distro, version in operating_systems:
            with self.subTest(distro=distro, version=version):
                with self.temporary_directory() as temp_dir:
                    fixture = self.create_fixture(temp_dir, [("/etc/inetd.conf", "0", "root", "0", "644")])
                    environment = self.environment(fixture, distro=distro, version=version)
                    result, _ = self.run_action("PREVIEW", environment)
                    self.assertEqual(result["outcome"], "PLANNED")
