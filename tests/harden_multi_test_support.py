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


class MultiTargetHardenTestBase(unittest.TestCase):
    __test__ = False
    item_id = ""
    targets: tuple[tuple[str, str, str, str], ...] = ()
    acl_policy = False
    sensitive_marker = "PRIVATE_CONFIGURATION_CONTENT"

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

    def _write_command(self, path: Path, body: str):
        path.write_text(body, encoding="utf-8", newline="\n")
        path.chmod(0o755)

    def create_fixture(self, temp_dir: str, *, vulnerability: str = "permission"):
        root = Path(temp_dir)
        (root / "etc").mkdir(parents=True, exist_ok=True)
        (root / "etc/passwd").write_text(
            "root:x:0:0:root:/root:/bin/sh\nuser:x:1000:1000:user:/home/user:/bin/sh\n"
            "user2:x:1001:1001:user2:/home/user2:/bin/sh\n",
            encoding="utf-8",
            newline="\n",
        )
        (root / "etc/group").write_text(
            "root:x:0:\nuser:x:1000:\nuser2:x:1001:\n",
            encoding="utf-8",
            newline="\n",
        )

        records = []
        contents = {}
        for index, (display, kind, good_mode, target_class) in enumerate(self.targets, start=1):
            actual = root / display.lstrip("/")
            actual.parent.mkdir(parents=True, exist_ok=True)
            if kind == "directory":
                actual.mkdir(exist_ok=True)
                child = actual / "preserved.txt"
                child.write_text(self.sensitive_marker, encoding="utf-8")
                contents[child] = child.read_bytes()
            else:
                actual.write_text(self.sensitive_marker, encoding="utf-8", newline="\n")
                contents[actual] = actual.read_bytes()

            expected_uid, expected_name = self.expected_owner(display)
            uid, owner = expected_uid, expected_name
            mode = good_mode
            acl = "safe"
            if vulnerability in {"owner", "both"}:
                uid, owner = "2000", "intruder"
            if vulnerability in {"permission", "both"}:
                mode = self.vulnerable_mode(display, good_mode, target_class)
            if vulnerability == "acl":
                acl = "unsafe"
            records.append(
                "|".join(
                    (
                        display,
                        kind,
                        uid,
                        owner,
                        "0",
                        "root",
                        mode,
                        "100",
                        str(1000 + index),
                        "200",
                        "300",
                        "system_u:object_r:etc_t:s0",
                        acl,
                        expected_uid,
                        expected_name,
                        target_class,
                    )
                )
            )

        state = root / "metadata.state"
        state.write_text("\n".join(records) + "\n", encoding="utf-8", newline="\n")
        initial_state = root / "metadata.initial"
        shutil.copyfile(state, initial_state)
        check_fixture = root / "check.fixture"
        operation_log = root / "operations.log"
        command_dir = root / "bin"
        command_dir.mkdir()

        refresh = command_dir / "refresh"
        self._write_command(
            refresh,
            r'''#!/bin/sh
state=$OS_GUARD_TEST_STATE_FILE
fixture=$OS_GUARD_TEST_CHECK_FIXTURE
case "$OS_GUARD_TEST_ITEM_ID" in
    U-17)
        awk -F'|' '{ access=(and(strtonum("0" $7), 0020) ? "unrelated" : "safe"); print "regular|" $3 "|" $4 "|" $5 "|" $6 "|" $7 "|" access }' "$state" > "$fixture"
        ;;
    U-21)
        awk -F'|' '{ print "regular|" $3 "|" $4 "|" $7 "|" $4 }' "$state" > "$fixture"
        ;;
    U-24)
        awk -F'|' '
            function octal(v, i,n,d) { n=0; for(i=1;i<=length(v);i++){d=substr(v,i,1);n=n*8+d} return n }
            { files++; checked++; if ($3==0 && $4=="root") root_owned++; else if ($3==$14 && $4==$15) account_owned++; else owner_bad++; if (and(octal($7), 18)) mode_bad++; if ($13=="unsafe") acl_bad++ }
            END { print "complete|2|" files+0 "|" checked+0 "|" root_owned+0 "|" account_owned+0 "|" owner_bad+0 "|" mode_bad+0 "|" acl_bad+0 "|0|0" }
        ' "$state" > "$fixture"
        ;;
    U-31)
        awk -F'|' '
            function octal(v, i,n,d) { n=0; for(i=1;i<=length(v);i++){d=substr(v,i,1);n=n*8+d} return n }
            { checked++; if ($3!=$14 || $4!=$15) owner_bad++; if (and(octal($7), 2)) write_bad++; if ($13=="unsafe") acl_bad++ }
            END { print "complete|2|" checked+0 "|" owner_bad+0 "|" write_bad+0 "|" acl_bad+0 "|0" }
        ' "$state" > "$fixture"
        ;;
    U-37)
        awk -F'|' '
            function octal(v, i,n,d) { n=0; for(i=1;i<=length(v);i++){d=substr(v,i,1);n=n*8+d} return n }
            { checked++; if ($3!=0 || $4!="root") owner_bad++; m=octal($7); if (($16=="executable" && and(m, compl(488))) || ($16=="configuration" && and(m, compl(416))) || ($16=="directory" && and(m, 2))) mode_bad++ }
            END { print "complete|" checked+0 "|" owner_bad+0 "|" mode_bad+0 "|0|0" }
        ' "$state" > "$fixture"
        ;;
    U-63)
        awk -F'|' '
            function octal(v, i,n,d) { n=0; for(i=1;i<=length(v);i++){d=substr(v,i,1);n=n*8+d} return n }
            NR==1 { owner_ok=($3==0 && $4=="root"); mode=$7; numeric=octal(mode); extra=(and(numeric,compl(416)) ? 1 : 0); restrictive=(extra==0 && mode!="640" ? 1 : 0); print "complete|1|" owner_ok "|" mode "|" extra "|" restrictive }
        ' "$state" > "$fixture"
        ;;
    U-67)
        awk -F'|' '
            function octal(v, i,n,d) { n=0; for(i=1;i<=length(v);i++){d=substr(v,i,1);n=n*8+d} return n }
            { scanned++; owner_ok=($3==0 && $4=="root"); mode_ok=(and(octal($7),compl(420))==0); if(owner_ok) root_owned++; if(mode_ok) safe++; if(!owner_ok || !mode_ok) violations++ }
            END { print "complete|" scanned+0 "|" root_owned+0 "|" safe+0 "|" violations+0 "|0|0" }
        ' "$state" > "$fixture"
        ;;
esac
''',
        )

        fake_stat = command_dir / "stat"
        self._write_command(
            fake_stat,
            r'''#!/bin/sh
[ "${OS_GUARD_TEST_STAT_FAILURE:-false}" = true ] && exit 1
format=$2
eval "path=\${$#}"
display=${path#"$OS_GUARD_TEST_ROOT"}
record=$(awk -F'|' -v p="$display" '$1==p { print; exit }' "$OS_GUARD_TEST_STATE_FILE")
[ -n "$record" ] || exit 1
old_ifs=$IFS; IFS='|'; set -- $record; IFS=$old_ifs
kind=$2; uid=$3; owner=$4; gid=$5; group=$6; mode=$7; device=$8; inode=$9
shift 9; mtime=$1; ctime=$2; context=$3
case "$format" in
    '%u|%U') printf '%s|%s\n' "$uid" "$owner" ;;
    '%g|%G|%a') printf '%s|%s|%s\n' "$gid" "$group" "$mode" ;;
    '%d|%i') printf '%s|%s\n' "$device" "$inode" ;;
    '%d|%i|%u|%g|%a') printf '%s|%s|%s|%s|%s\n' "$device" "$inode" "$uid" "$gid" "$mode" ;;
    '%d|%i|%u|%U|%g|%G|%a|%Y|%Z') printf '%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$device" "$inode" "$uid" "$owner" "$gid" "$group" "$mode" "$mtime" "$ctime" ;;
    '%C')
        [ "${OS_GUARD_TEST_SELINUX_CONTEXT_FAILURE:-false}" != true ] || exit 1
        printf '%s\n' "$context"
        ;;
    *) exit 2 ;;
esac
''',
        )

        fake_chmod = command_dir / "chmod"
        self._write_command(
            fake_chmod,
            r'''#!/bin/sh
mode=$1; eval "path=\${$#}"; display=${path#"$OS_GUARD_TEST_ROOT"}
if ! awk -F'|' -v p="$display" '$1==p {found=1} END {exit found ? 0 : 1}' "$OS_GUARD_TEST_STATE_FILE"; then
    exec /usr/bin/chmod "$@"
fi
printf 'chmod|%s|%s|%s\n' "${OS_GUARD_HARDEN_ROLLBACK:-false}" "$display" "$mode" >> "$OS_GUARD_TEST_OPERATION_LOG"
awk -F'|' -v OFS='|' -v p="$display" -v value="$mode" '$1==p {$7=value} {print}' "$OS_GUARD_TEST_STATE_FILE" > "$OS_GUARD_TEST_STATE_FILE.tmp" || exit 1
mv "$OS_GUARD_TEST_STATE_FILE.tmp" "$OS_GUARD_TEST_STATE_FILE" || exit 1
"$OS_GUARD_TEST_REFRESH_BIN"
''',
        )

        fake_chown = command_dir / "chown"
        self._write_command(
            fake_chown,
            r'''#!/bin/sh
identity=$1; eval "path=\${$#}"; display=${path#"$OS_GUARD_TEST_ROOT"}; uid=${identity%%:*}
if [ "$identity" = "$uid" ]; then gid=''; else gid=${identity#*:}; fi
printf 'chown|%s|%s|%s\n' "${OS_GUARD_HARDEN_ROLLBACK:-false}" "$display" "$identity" >> "$OS_GUARD_TEST_OPERATION_LOG"
awk -F'|' -v OFS='|' -v p="$display" -v uid="$uid" -v gid="$gid" '
    $1==p { $3=uid; $4=(uid==0 ? "root" : $15); if(gid!="") $5=gid } {print}
' "$OS_GUARD_TEST_STATE_FILE" > "$OS_GUARD_TEST_STATE_FILE.tmp" || exit 1
mv "$OS_GUARD_TEST_STATE_FILE.tmp" "$OS_GUARD_TEST_STATE_FILE" || exit 1
"$OS_GUARD_TEST_REFRESH_BIN"
''',
        )

        fake_getfacl = command_dir / "getfacl"
        self._write_command(
            fake_getfacl,
            r'''#!/bin/sh
eval "path=\${$#}"; display=${path#"$OS_GUARD_TEST_ROOT"}
acl=$(awk -F'|' -v p="$display" '$1==p {print $13; exit}' "$OS_GUARD_TEST_STATE_FILE")
[ -n "$acl" ] || exit 1
printf '# file: %s\nuser::rw-\n' "$display"
[ "$acl" = unsafe ] && printf 'user:intruder:rw-\n'
printf 'group::r--\nother::---\n'
''',
        )

        fake_setfacl = command_dir / "setfacl"
        self._write_command(
            fake_setfacl,
            r'''#!/bin/sh
case "$1" in
    --restore=*)
        cp "$OS_GUARD_TEST_INITIAL_STATE_FILE" "$OS_GUARD_TEST_STATE_FILE" || exit 1
        printf 'setfacl-restore|true|all\n' >> "$OS_GUARD_TEST_OPERATION_LOG"
        ;;
    -m)
        eval "path=\${$#}"; display=${path#"$OS_GUARD_TEST_ROOT"}
        printf 'setfacl|false|%s\n' "$display" >> "$OS_GUARD_TEST_OPERATION_LOG"
        awk -F'|' -v OFS='|' -v p="$display" '$1==p {$13="safe"} {print}' "$OS_GUARD_TEST_STATE_FILE" > "$OS_GUARD_TEST_STATE_FILE.tmp" || exit 1
        mv "$OS_GUARD_TEST_STATE_FILE.tmp" "$OS_GUARD_TEST_STATE_FILE" || exit 1
        ;;
    *) exit 2 ;;
esac
"$OS_GUARD_TEST_REFRESH_BIN"
''',
        )

        fake_visudo = command_dir / "visudo"
        self._write_command(
            fake_visudo,
            r'''#!/bin/sh
[ "${OS_GUARD_TEST_VISUDO_FAILURE:-false}" = true ] && exit 1
exit 0
''',
        )

        fixture = {
            "root": root,
            "state": state,
            "initial": initial_state,
            "check": check_fixture,
            "log": operation_log,
            "bin": command_dir,
            "stat": fake_stat,
            "chmod": fake_chmod,
            "chown": fake_chown,
            "getfacl": fake_getfacl,
            "setfacl": fake_setfacl,
            "refresh": refresh,
            "visudo": fake_visudo,
            "contents": contents,
        }
        environment = self.environment(fixture)
        subprocess.run([self.shell, str(refresh)], env=environment, check=True, timeout=5)
        return fixture

    def expected_owner(self, display: str) -> tuple[str, str]:
        if self.item_id in {"U-24", "U-31"}:
            return ("1001", "user2") if "user2" in display else ("1000", "user")
        return "0", "root"

    @staticmethod
    def vulnerable_mode(display: str, good_mode: str, target_class: str) -> str:
        value = int(good_mode, 8) | 0o002
        return format(value, "o")

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
                "OS_GUARD_TEST_ROOT": self._posix(fixture["root"]),
                "OS_GUARD_TEST_STATE_FILE": self._posix(fixture["state"]),
                "OS_GUARD_TEST_INITIAL_STATE_FILE": self._posix(fixture["initial"]),
                "OS_GUARD_TEST_CHECK_FIXTURE": self._posix(fixture["check"]),
                "OS_GUARD_TEST_OPERATION_LOG": self._posix(fixture["log"]),
                "OS_GUARD_TEST_REFRESH_BIN": self._posix(fixture["refresh"]),
                "OS_GUARD_TEST_STAT_BIN": self._posix(fixture["stat"]),
                "OS_GUARD_TEST_CHMOD_BIN": self._posix(fixture["chmod"]),
                "OS_GUARD_TEST_CHOWN_BIN": self._posix(fixture["chown"]),
                "OS_GUARD_TEST_GETFACL_BIN": self._posix(fixture["getfacl"]),
                "OS_GUARD_TEST_SETFACL_BIN": self._posix(fixture["setfacl"]),
                "OS_GUARD_TEST_BACKUP_ROOT": (
                    fixture["root"].resolve().relative_to(ROOT.resolve()) / "backups"
                ).as_posix(),
                "OS_GUARD_TEST_ITEM_ID": self.item_id,
            }
        )
        if self.item_id in {"U-17", "U-21", "U-24"}:
            environment["OS_GUARD_TEST_SCAN_FILE"] = self._posix(fixture["check"])
        elif self.item_id == "U-31":
            environment["OS_GUARD_TEST_HOME_SCAN_FILE"] = self._posix(fixture["check"])
        elif self.item_id == "U-37":
            environment["OS_GUARD_TEST_CRON_FILE"] = self._posix(fixture["check"])
        elif self.item_id == "U-63":
            environment["OS_GUARD_TEST_U63_FILE"] = self._posix(fixture["check"])
            environment["OS_GUARD_TEST_VISUDO_BIN"] = self._posix(fixture["visudo"])
        elif self.item_id == "U-67":
            environment["OS_GUARD_TEST_U67_FILE"] = self._posix(fixture["check"])
        if self.item_id == "U-21":
            environment["OS_GUARD_TEST_LOGGING_MODEL"] = "rsyslog_with_fragments"
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
        execution_environment = environment.copy()
        execution_environment.update(
            {
                "OS_GUARD_HARDEN_APPROVED": "true",
                "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"],
            }
        )
        if extra:
            execution_environment.update(extra)
        result, output = self.run_action("EXECUTE", execution_environment)
        return preview, result, output

    def temporary_directory(self):
        return tempfile.TemporaryDirectory(dir=ROOT)

    def assert_contents_unchanged(self, fixture):
        for path, content in fixture["contents"].items():
            self.assertEqual(path.read_bytes(), content)

    def test_01_good_state_no_change(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, vulnerability="good")
            before = fixture["state"].read_bytes()
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["outcome"], "NO_CHANGE")
            self.assertEqual(fixture["state"].read_bytes(), before)

    def test_02_owner_only(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, vulnerability="owner")
            preview, result, _ = self.execute(fixture)
            self.assertTrue(any(target["owner_change_required"] for target in preview["preview"]["targets"]))
            self.assertEqual(result["outcome"], "SUCCESS")

    def test_03_permission_only(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            preview, result, _ = self.execute(fixture)
            self.assertTrue(any(target["permission_change_required"] for target in preview["preview"]["targets"]))
            self.assertEqual(result["outcome"], "SUCCESS")

    def test_04_owner_and_permission(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, vulnerability="both")
            _, result, _ = self.execute(fixture)
            self.assertEqual(result["outcome"], "SUCCESS")

    def test_05_acl_policy(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, vulnerability="acl")
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            acl_changes = [target["acl_change_required"] for target in result["preview"]["targets"]]
            self.assertEqual(any(acl_changes), self.acl_policy)

    def test_06_symlink_rejected(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            extra = {"OS_GUARD_TEST_FORCE_SYMLINK_PATH": self.targets[0][0]}
            result, _ = self.run_action("PREVIEW", self.environment(fixture, extra=extra))
            self.assertEqual(result["error"]["code"], "SYMLINK_TARGET_REJECTED")

    def test_07_wrong_type_rejected(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            extra = {"OS_GUARD_TEST_FORCE_NONREGULAR_PATH": self.targets[0][0]}
            result, _ = self.run_action("PREVIEW", self.environment(fixture, extra=extra))
            self.assertEqual(result["error"]["code"], "TARGET_TYPE_INVALID")

    def test_08_stat_failure(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, _ = self.run_action("PREVIEW", self.environment(fixture, extra={"OS_GUARD_TEST_STAT_FAILURE": "true"}))
            self.assertEqual(result["error"]["code"], "STAT_COMMAND_FAILED")

    def test_09_backup_failure_prevents_change(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            before = fixture["state"].read_bytes()
            _, result, _ = self.execute(fixture, extra={"OS_GUARD_TEST_FAIL_STEP": "backup"})
            self.assertEqual(result["error"]["code"], "BACKUP_FAILED")
            self.assertEqual(fixture["state"].read_bytes(), before)

    def test_10_chown_failure_rolls_back(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, vulnerability="owner")
            _, result, _ = self.execute(fixture, extra={"OS_GUARD_TEST_FAIL_STEP": "chown"})
            self.assertTrue(result["execution"]["rollback_attempted"])
            self.assertTrue(result["execution"]["rollback_success"])

    def test_11_chmod_failure_rolls_back(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            _, result, _ = self.execute(fixture, extra={"OS_GUARD_TEST_FAIL_STEP": "chmod"})
            self.assertTrue(result["execution"]["rollback_attempted"])
            self.assertTrue(result["execution"]["rollback_success"])

    def test_12_acl_failure_policy(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir, vulnerability="acl")
            _, result, _ = self.execute(fixture, extra={"OS_GUARD_TEST_FAIL_STEP": "acl"})
            if self.acl_policy:
                self.assertEqual(result["error"]["code"], "ACL_CHANGE_FAILED")
                self.assertTrue(result["execution"]["rollback_success"])
            else:
                self.assertEqual(result["outcome"], "NO_CHANGE")

    def test_13_validation_failure_rolls_back(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            _, result, _ = self.execute(fixture, extra={"OS_GUARD_TEST_FORCE_VALIDATION_FAILURE": "true"})
            self.assertEqual(result["error"]["code"], "VALIDATION_FAILED")
            self.assertTrue(result["execution"]["rollback_success"])

    def test_14_initial_check_failure(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, _ = self.run_action("PREVIEW", self.environment(fixture, extra={"OS_GUARD_TEST_CHECK_FAILURE": "true"}))
            self.assertEqual(result["error"]["code"], "CHECK_EXECUTION_FAILED")

    def test_15_post_check_not_good_rolls_back(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            _, result, _ = self.execute(fixture, extra={"OS_GUARD_TEST_FORCE_RECHECK_FAILURE": "true"})
            self.assertEqual(result["error"]["code"], "RECHECK_FAILED")
            self.assertTrue(result["execution"]["rollback_success"])

    def test_16_rollback_failure_reported(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            _, result, _ = self.execute(
                fixture,
                extra={"OS_GUARD_TEST_FORCE_VALIDATION_FAILURE": "true", "OS_GUARD_TEST_FAIL_STEP": "rollback"},
            )
            self.assertTrue(result["execution"]["rollback_attempted"])
            self.assertFalse(result["execution"]["rollback_success"])

    def test_17_partial_failure_is_atomic(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            before = fixture["state"].read_bytes()
            _, result, _ = self.execute(
                fixture,
                extra={"OS_GUARD_TEST_FAIL_STEP": "chmod", "OS_GUARD_TEST_FAIL_TARGET": self.targets[1][0]},
            )
            self.assertTrue(result["execution"]["rollback_success"])
            self.assertEqual(fixture["state"].read_bytes(), before)

    def test_18_rollback_runs_in_reverse_order(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            self.execute(fixture, extra={"OS_GUARD_TEST_FORCE_VALIDATION_FAILURE": "true"})
            rollback_paths = [
                line.split("|")[2]
                for line in fixture["log"].read_text(encoding="utf-8").splitlines()
                if "|true|" in line and not line.startswith("setfacl")
            ]
            self.assertGreaterEqual(len(rollback_paths), 2)
            self.assertEqual(rollback_paths[0], self.targets[-1][0])

    def test_19_preview_is_read_only(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            before = fixture["state"].read_bytes()
            self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(fixture["state"].read_bytes(), before)
            self.assertFalse((fixture["root"] / "backups").exists())
            self.assert_contents_unchanged(fixture)

    def test_20_state_drift(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            environment = self.environment(fixture)
            preview, _ = self.run_action("PREVIEW", environment)
            data = fixture["state"].read_text(encoding="utf-8").replace("|100|1001|", "|101|1001|", 1)
            fixture["state"].write_text(data, encoding="utf-8", newline="\n")
            environment.update({"OS_GUARD_HARDEN_APPROVED": "true", "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"]})
            result, _ = self.run_action("EXECUTE", environment)
            self.assertEqual(result["error"]["code"], "STATE_DRIFT")

    def test_21_target_list_drift(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            environment = self.environment(fixture)
            preview, _ = self.run_action("PREVIEW", environment)
            self.add_drift_target(fixture)
            subprocess.run([self.shell, str(fixture["refresh"])], env=environment, check=True, timeout=5)
            environment.update({"OS_GUARD_HARDEN_APPROVED": "true", "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"]})
            result, _ = self.run_action("EXECUTE", environment)
            self.assertEqual(result["error"]["code"], "STATE_DRIFT")

    def add_drift_target(self, fixture):
        display, kind, mode, target_class = self.targets[0]
        new_display = display + ".new" if kind == "file" else display + "-new"
        actual = fixture["root"] / new_display.lstrip("/")
        if kind == "directory":
            actual.mkdir(parents=True)
        else:
            actual.write_text(self.sensitive_marker, encoding="utf-8")
        uid, name = self.expected_owner(display)
        with fixture["state"].open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(
                f"{new_display}|{kind}|{uid}|{name}|0|root|{mode}|100|9999|200|300|"
                f"system_u:object_r:etc_t:s0|safe|{uid}|{name}|{target_class}\n"
            )

    def test_22_idempotent_second_preview(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            _, result, _ = self.execute(fixture)
            self.assertEqual(result["outcome"], "SUCCESS")
            second, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(second["outcome"], "NO_CHANGE")

    def test_23_backup_permissions_declared(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            _, result, _ = self.execute(fixture)
            backup = fixture["root"] / "backups" / result["execution"]["backup_id"]
            self.assertTrue((backup / "metadata").is_file())

    def test_24_content_preserved(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            self.execute(fixture)
            self.assert_contents_unchanged(fixture)

    def test_25_rocky_9(self):
        self.assert_supported("rocky", "9.6")

    def test_26_rocky_10(self):
        self.assert_supported("rocky", "10.1")

    def test_27_ubuntu_22(self):
        self.assert_supported("ubuntu", "22.04")

    def test_28_ubuntu_24(self):
        self.assert_supported("ubuntu", "24.04")

    def test_29_missing_targets_follow_check_policy(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            for display, kind, _, _ in reversed(self.targets):
                target = fixture["root"] / display.lstrip("/")
                if kind == "directory":
                    shutil.rmtree(target)
                else:
                    target.unlink()
            fixture["state"].write_text("", encoding="utf-8")
            environment = self.environment(fixture)
            subprocess.run(
                [self.shell, str(fixture["refresh"])],
                env=environment,
                check=True,
                timeout=5,
            )
            result, _ = self.run_action("PREVIEW", environment)
            if self.item_id in {"U-17", "U-21", "U-63", "U-67"}:
                self.assertEqual(result["error"]["code"], "CHECK_STATE_NOT_ACTIONABLE")
            else:
                self.assertEqual(result["outcome"], "NO_CHANGE")

    def assert_supported(self, distro, version):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, _ = self.run_action("PREVIEW", self.environment(fixture, distro=distro, version=version))
            self.assertEqual(result["outcome"], "PLANNED")
