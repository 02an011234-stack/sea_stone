from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from os_guard_agent import MODULE_VERSION


ROOT = Path(__file__).parents[1]
HARDEN_MODULE = ROOT / "modules" / "unix" / "harden" / "U-34.sh"


def shell_path() -> str | None:
    discovered = shutil.which("sh")
    if discovered:
        return discovered
    candidate = Path(r"C:\Program Files\Git\bin\sh.exe")
    return str(candidate) if candidate.is_file() else None


def posix_path(path: Path) -> str:
    value = path.resolve().as_posix()
    if os.name == "nt" and len(value) > 2 and value[1] == ":":
        return f"/{value[0].lower()}{value[2:]}"
    return value


class U34HardenHarness:
    def __init__(self):
        self.shell = shell_path()
        if not self.shell:
            pytest.skip("POSIX shell is unavailable")

    @staticmethod
    def write_executable(path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8", newline="\n")
        path.chmod(0o755)

    def create_fixture(
        self,
        directory: str,
        *,
        active: bool = True,
        enabled_state: str | None = None,
    ):
        root = Path(directory)
        (root / "etc" / "xinetd.d").mkdir(parents=True)
        command_directory = root / "bin"
        command_directory.mkdir()
        state_file = root / "systemd.state"
        active_state = "active" if active else "inactive"
        if enabled_state is None:
            enabled_state = "enabled" if active else "disabled"
        state_file.write_text(
            f"finger.service|{active_state}|{enabled_state}\n",
            encoding="utf-8",
            newline="\n",
        )
        operation_log = root / "operations.log"
        operation_log.write_text("", encoding="utf-8")

        systemctl = command_directory / "systemctl"
        self.write_executable(
            systemctl,
            r'''#!/bin/sh
set -u

action=${1:-}
unit_name=${2:-}
runtime_option=false
if [ "$unit_name" = '--runtime' ]; then
    runtime_option=true
    unit_name=${3:-}
fi
state_file=$OS_GUARD_TEST_SYSTEMD_STATE
operation_log=$OS_GUARD_TEST_OPERATION_LOG

read_field() {
    wanted_unit=$1
    field_number=$2
    awk -F'|' -v wanted="$wanted_unit" -v field="$field_number" '
        $1 == wanted { print $field; found=1 }
        END { exit found ? 0 : 1 }
    ' "$state_file"
}

update_field() {
    wanted_unit=$1
    field_number=$2
    new_value=$3
    temporary_file="${state_file}.tmp"
    awk -F'|' -v OFS='|' -v wanted="$wanted_unit" \
        -v field="$field_number" -v value="$new_value" '
        $1 == wanted { $field=value }
        { print }
    ' "$state_file" > "$temporary_file"
    mv "$temporary_file" "$state_file"
}

case "$action" in
    is-active)
        value=$(read_field "$unit_name" 2) || exit 4
        printf '%s\n' "$value"
        [ "$value" = 'active' ]
        ;;
    is-enabled)
        value=$(read_field "$unit_name" 3) || exit 4
        printf '%s\n' "$value"
        [ "$value" = 'enabled' ] || [ "$value" = 'enabled-runtime' ]
        ;;
    list-unit-files)
        value=$(read_field "$unit_name" 3) || exit 0
        printf '%s %s\n' "$unit_name" "$value"
        ;;
    disable|stop|enable|start)
        printf '%s|%s\n' "$action" "$unit_name" >> "$operation_log"
        if [ "${OS_GUARD_TEST_SYSTEMCTL_FAIL:-}" = "$action" ]; then
            exit 1
        fi
        case "$action" in
            disable)
                update_field "$unit_name" 3 disabled
                ;;
            stop)
                update_field "$unit_name" 2 inactive
                ;;
            enable)
                if [ "$runtime_option" = true ]; then
                    update_field "$unit_name" 3 enabled-runtime
                else
                    update_field "$unit_name" 3 enabled
                fi
                ;;
            start)
                update_field "$unit_name" 2 active
                ;;
        esac
        ;;
    *)
        exit 2
        ;;
esac
''',
        )

        return {
            "root": root,
            "state": state_file,
            "log": operation_log,
            "bin": command_directory,
            "systemctl": systemctl,
        }

    def environment(
        self,
        fixture,
        *,
        distro: str = "rocky",
        version: str = "9.6",
        extra: dict[str, str] | None = None,
    ) -> dict[str, str]:
        backup_root = (
            fixture["root"].resolve().relative_to(ROOT.resolve()) / "backups"
        ).as_posix()
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{posix_path(fixture['bin'])}:/usr/sbin:/usr/bin:/sbin:/bin",
                "LC_ALL": "C",
                "OS_GUARD_DISTRO": distro,
                "OS_GUARD_VERSION_ID": version,
                "OS_GUARD_MODULE_VERSION": MODULE_VERSION,
                "OS_GUARD_TEST_ROOT": posix_path(fixture["root"]),
                "OS_GUARD_TEST_SYSTEMCTL_BIN": posix_path(fixture["systemctl"]),
                "OS_GUARD_TEST_SYSTEMD_STATE": posix_path(fixture["state"]),
                "OS_GUARD_TEST_OPERATION_LOG": posix_path(fixture["log"]),
                "OS_GUARD_TEST_BACKUP_ROOT": backup_root,
            }
        )
        if extra:
            environment.update(extra)
        return environment

    def run_action(self, action: str, environment: dict[str, str]):
        completed = subprocess.run(
            [self.shell, str(HARDEN_MODULE), action],
            env=environment,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        assert completed.stdout.count("\n") == 1, completed.stdout
        return json.loads(completed.stdout)

    def execute(self, fixture, *, extra: dict[str, str] | None = None):
        environment = self.environment(fixture)
        preview = self.run_action("PREVIEW", environment)
        execute_environment = environment.copy()
        execute_environment.update(
            {
                "OS_GUARD_HARDEN_APPROVED": "true",
                "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"],
            }
        )
        if extra:
            execute_environment.update(extra)
        result = self.run_action("EXECUTE", execute_environment)
        return preview, result


@pytest.fixture
def harness():
    return U34HardenHarness()


def test_good_service_state_is_not_changed(harness):
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        fixture = harness.create_fixture(directory, active=False)
        before = fixture["state"].read_bytes()
        result = harness.run_action("PREVIEW", harness.environment(fixture))
        assert result["outcome"] == "NO_CHANGE"
        assert fixture["state"].read_bytes() == before
        assert fixture["log"].read_text(encoding="utf-8") == ""


def test_preview_is_read_only_and_reports_stop(harness):
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        fixture = harness.create_fixture(directory)
        before = fixture["state"].read_bytes()
        result = harness.run_action("PREVIEW", harness.environment(fixture))
        assert result["outcome"] == "PLANNED"
        assert result["preview"]["service_stop_required"] is True
        assert result["preview"]["risk"] == "HIGH"
        assert result["preview"]["active_units"] == ["finger.service"]
        assert result["preview"]["expected_state"] == (
            "inactive; enabled units become disabled"
        )
        assert fixture["state"].read_bytes() == before
        assert not (fixture["root"] / "backups").exists()


def test_execute_requires_approval(harness):
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        fixture = harness.create_fixture(directory)
        environment = harness.environment(fixture)
        preview = harness.run_action("PREVIEW", environment)
        environment["OS_GUARD_HARDEN_EXPECTED_STATE"] = preview["preview"]["state_fingerprint"]
        result = harness.run_action("EXECUTE", environment)
        assert result["error"]["code"] == "APPROVAL_REQUIRED"
        assert fixture["log"].read_text(encoding="utf-8") == ""


def test_wrong_fingerprint_is_rejected(harness):
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        fixture = harness.create_fixture(directory)
        environment = harness.environment(
            fixture,
            extra={
                "OS_GUARD_HARDEN_APPROVED": "true",
                "OS_GUARD_HARDEN_EXPECTED_STATE": "wrong",
            },
        )
        result = harness.run_action("EXECUTE", environment)
        assert result["error"]["code"] == "STATE_DRIFT"
        assert fixture["log"].read_text(encoding="utf-8") == ""


def test_state_drift_is_rejected(harness):
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        fixture = harness.create_fixture(directory)
        environment = harness.environment(fixture)
        preview = harness.run_action("PREVIEW", environment)
        fixture["state"].write_text(
            "finger.service|active|disabled\n",
            encoding="utf-8",
            newline="\n",
        )
        environment.update(
            {
                "OS_GUARD_HARDEN_APPROVED": "true",
                "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"],
            }
        )
        result = harness.run_action("EXECUTE", environment)
        assert result["error"]["code"] == "STATE_DRIFT"
        assert fixture["log"].read_text(encoding="utf-8") == ""


def test_backup_failure_prevents_service_change(harness):
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        fixture = harness.create_fixture(directory)
        _, result = harness.execute(
            fixture,
            extra={"OS_GUARD_TEST_FAIL_STEP": "backup"},
        )
        assert result["error"]["code"] == "BACKUP_FAILED"
        assert fixture["state"].read_text(encoding="utf-8") == "finger.service|active|enabled\n"


def test_execute_disables_stops_and_rechecks_good(harness):
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        fixture = harness.create_fixture(directory)
        preview, result = harness.execute(fixture)
        assert preview["outcome"] == "PLANNED"
        assert result["outcome"] == "SUCCESS", result
        assert result["execution"]["backup_created"] is True
        assert result["execution"]["validation_success"] is True
        assert result["execution"]["recheck_status"] == "GOOD"
        assert fixture["state"].read_text(encoding="utf-8") == "finger.service|inactive|disabled\n"
        operations = fixture["log"].read_text(encoding="utf-8")
        assert "disable|finger.service" in operations
        assert "stop|finger.service" in operations


@pytest.mark.parametrize("failed_action", ["disable", "stop"])
def test_apply_failure_restores_original_service_state(harness, failed_action):
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        fixture = harness.create_fixture(directory)
        _, result = harness.execute(
            fixture,
            extra={"OS_GUARD_TEST_SYSTEMCTL_FAIL": failed_action},
        )
        assert result["execution"]["rollback_attempted"] is True
        assert result["execution"]["rollback_success"] is True
        assert fixture["state"].read_text(encoding="utf-8") == "finger.service|active|enabled\n"


def test_recheck_failure_rolls_back(harness):
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        fixture = harness.create_fixture(directory)
        _, result = harness.execute(
            fixture,
            extra={"OS_GUARD_TEST_FORCE_RECHECK_FAILURE": "true"},
        )
        assert result["error"]["code"] == "RECHECK_FAILED"
        assert result["execution"]["rollback_success"] is True
        assert fixture["state"].read_text(encoding="utf-8") == "finger.service|active|enabled\n"


def test_runtime_enabled_state_is_restored_exactly(harness):
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        fixture = harness.create_fixture(directory, enabled_state="enabled-runtime")
        _, result = harness.execute(
            fixture,
            extra={"OS_GUARD_TEST_FORCE_RECHECK_FAILURE": "true"},
        )
        assert result["error"]["code"] == "RECHECK_FAILED"
        assert result["execution"]["rollback_success"] is True
        assert fixture["state"].read_text(encoding="utf-8") == (
            "finger.service|active|enabled-runtime\n"
        )


def test_active_masked_unit_is_rejected_without_changes(harness):
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        fixture = harness.create_fixture(directory, enabled_state="masked")
        result = harness.run_action("PREVIEW", harness.environment(fixture))
        assert result["error"]["code"] == "MASKED_ACTIVE_UNIT_UNSAFE"
        assert fixture["log"].read_text(encoding="utf-8") == ""


def test_rollback_failure_is_not_reported_as_success(harness):
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        fixture = harness.create_fixture(directory)
        _, result = harness.execute(
            fixture,
            extra={
                "OS_GUARD_TEST_FORCE_RECHECK_FAILURE": "true",
                "OS_GUARD_TEST_FAIL_STEP": "rollback",
            },
        )
        assert result["execution"]["rollback_attempted"] is True
        assert result["execution"]["rollback_success"] is False


def test_second_preview_is_idempotent(harness):
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        fixture = harness.create_fixture(directory)
        _, result = harness.execute(fixture)
        second = harness.run_action("PREVIEW", harness.environment(fixture))
        assert result["outcome"] == "SUCCESS"
        assert second["outcome"] == "NO_CHANGE"


def test_legacy_activation_is_manual_and_unchanged(harness):
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        fixture = harness.create_fixture(directory, active=False)
        inetd = fixture["root"] / "etc" / "inetd.conf"
        inetd.write_text("finger stream tcp nowait nobody /usr/sbin/in.fingerd in.fingerd\n", encoding="utf-8")
        before = inetd.read_bytes()
        result = harness.run_action("PREVIEW", harness.environment(fixture))
        assert result["error"]["code"] == "LEGACY_ACTIVATION_REQUIRES_MANUAL_REMEDIATION"
        assert inetd.read_bytes() == before
        assert fixture["log"].read_text(encoding="utf-8") == ""


def test_check_failure_blocks_preview(harness):
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        fixture = harness.create_fixture(directory)
        result = harness.run_action(
            "PREVIEW",
            harness.environment(
                fixture,
                extra={"OS_GUARD_TEST_CHECK_FAILURE": "true"},
            ),
        )
        assert result["error"]["code"] == "CHECK_EXECUTION_FAILED"


@pytest.mark.parametrize(
    ("distro", "version"),
    (
        ("rocky", "9.6"),
        ("rocky", "10.1"),
        ("ubuntu", "22.04"),
        ("ubuntu", "24.04"),
    ),
)
def test_supported_os_preview(harness, distro, version):
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        fixture = harness.create_fixture(directory)
        result = harness.run_action(
            "PREVIEW",
            harness.environment(fixture, distro=distro, version=version),
        )
        assert result["outcome"] == "PLANNED"


def test_source_uses_only_fixed_units_and_no_shell_eval():
    source = HARDEN_MODULE.read_text(encoding="utf-8")
    assert "eval " not in source
    assert "finger.service" in source
    assert "fingerd.socket" in source
    assert "OS_GUARD_TEST_SYSTEMCTL_BIN" in source
