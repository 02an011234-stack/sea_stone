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


class ServiceHardenHarness:
    def __init__(self, module: Path, primary_unit: str, secondary_unit: str):
        self.module = module
        self.primary_unit = primary_unit
        self.secondary_unit = secondary_unit
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
        second_active: bool = False,
    ):
        root = Path(directory)
        (root / "etc" / "xinetd.d").mkdir(parents=True)
        command_directory = root / "bin"
        command_directory.mkdir()
        active_state = "active" if active else "inactive"
        if enabled_state is None:
            enabled_state = "enabled" if active else "disabled"
        state_file = root / "systemd.state"
        rows = [f"{self.primary_unit}|{active_state}|{enabled_state}"]
        if second_active:
            rows.append(f"{self.secondary_unit}|active|enabled")
        state_file.write_text("\n".join(rows) + "\n", encoding="utf-8", newline="\n")
        dependency_file = root / "dependencies"
        dependency_file.write_text("", encoding="utf-8")
        operation_log = root / "operations.log"
        operation_log.write_text("", encoding="utf-8")

        systemctl = command_directory / "systemctl"
        self.write_executable(
            systemctl,
            r'''#!/bin/sh
set -u

action=${1:-}
state_file=$OS_GUARD_TEST_SYSTEMD_STATE
dependency_file=$OS_GUARD_TEST_DEPENDENCY_FILE
operation_log=$OS_GUARD_TEST_OPERATION_LOG
runtime_option=false

case "$action" in
    list-dependencies)
        unit_name=${5:-}
        awk -F'|' -v wanted="$unit_name" '$1 == wanted { print $2 }' "$dependency_file"
        exit 0
        ;;
esac

unit_name=${2:-}
if [ "$unit_name" = '--runtime' ]; then
    runtime_option=true
    unit_name=${3:-}
fi

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
        value=$(read_field "$unit_name" 2) || {
            printf 'unknown\n'
            exit 4
        }
        printf '%s\n' "$value"
        [ "$value" = 'active' ]
        ;;
    is-enabled)
        value=$(read_field "$unit_name" 3) || exit 4
        printf '%s\n' "$value"
        [ "$value" = 'enabled' ] || [ "$value" = 'enabled-runtime' ]
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
            "dependencies": dependency_file,
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
                "OS_GUARD_TEST_DEPENDENCY_FILE": posix_path(fixture["dependencies"]),
                "OS_GUARD_TEST_OPERATION_LOG": posix_path(fixture["log"]),
                "OS_GUARD_TEST_BACKUP_ROOT": backup_root,
            }
        )
        if extra:
            environment.update(extra)
        return environment

    def run_action(self, action: str, environment: dict[str, str]):
        completed = subprocess.run(
            [self.shell, str(self.module), action],
            env=environment,
            capture_output=True,
            text=True,
            timeout=20,
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
        return preview, self.run_action("EXECUTE", execute_environment)


class ServiceHardenContractMixin:
    harden_module: Path
    primary_unit: str
    secondary_unit: str
    legacy_relative_path: str
    legacy_content: str

    def harness(self) -> ServiceHardenHarness:
        return ServiceHardenHarness(
            self.harden_module, self.primary_unit, self.secondary_unit
        )

    def test_good_state_is_no_change(self):
        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory, active=False)
            before = fixture["state"].read_bytes()
            result = harness.run_action("PREVIEW", harness.environment(fixture))
            assert result["outcome"] == "NO_CHANGE"
            assert fixture["state"].read_bytes() == before

    def test_preview_is_read_only(self):
        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            before = fixture["state"].read_bytes()
            result = harness.run_action("PREVIEW", harness.environment(fixture))
            assert result["outcome"] == "PLANNED"
            assert result["preview"]["service_stop_required"] is True
            assert result["preview"]["active_units"] == [self.primary_unit]
            assert fixture["state"].read_bytes() == before
            assert fixture["log"].read_text(encoding="utf-8") == ""

    def test_execute_requires_approval(self):
        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            environment = harness.environment(fixture)
            preview = harness.run_action("PREVIEW", environment)
            environment["OS_GUARD_HARDEN_EXPECTED_STATE"] = preview["preview"]["state_fingerprint"]
            result = harness.run_action("EXECUTE", environment)
            assert result["error"]["code"] == "APPROVAL_REQUIRED"

    def test_wrong_fingerprint_is_rejected(self):
        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            result = harness.run_action(
                "EXECUTE",
                harness.environment(
                    fixture,
                    extra={
                        "OS_GUARD_HARDEN_APPROVED": "true",
                        "OS_GUARD_HARDEN_EXPECTED_STATE": "wrong",
                    },
                ),
            )
            assert result["error"]["code"] == "STATE_DRIFT"

    def test_state_drift_is_rejected(self):
        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            environment = harness.environment(fixture)
            preview = harness.run_action("PREVIEW", environment)
            fixture["state"].write_text(
                f"{self.primary_unit}|active|disabled\n", encoding="utf-8"
            )
            environment.update(
                {
                    "OS_GUARD_HARDEN_APPROVED": "true",
                    "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"],
                }
            )
            result = harness.run_action("EXECUTE", environment)
            assert result["error"]["code"] == "STATE_DRIFT"

    def test_backup_failure_blocks_change(self):
        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            _, result = harness.execute(
                fixture, extra={"OS_GUARD_TEST_FAIL_STEP": "backup"}
            )
            assert result["error"]["code"] == "BACKUP_FAILED"
            assert "|active|enabled" in fixture["state"].read_text(encoding="utf-8")

    def test_execute_disables_stops_and_rechecks(self):
        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            _, result = harness.execute(fixture)
            assert result["outcome"] == "SUCCESS", result
            assert result["execution"]["backup_created"] is True
            assert result["execution"]["recheck_status"] == "GOOD"
            assert f"{self.primary_unit}|inactive|disabled" in fixture["state"].read_text(encoding="utf-8")

    @pytest.mark.parametrize("failed_action", ["disable", "stop"])
    def test_apply_failure_rolls_back(self, failed_action):
        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            _, result = harness.execute(
                fixture, extra={"OS_GUARD_TEST_SYSTEMCTL_FAIL": failed_action}
            )
            assert result["execution"]["rollback_attempted"] is True
            assert result["execution"]["rollback_success"] is True
            assert f"{self.primary_unit}|active|enabled" in fixture["state"].read_text(encoding="utf-8")

    def test_recheck_failure_rolls_back(self):
        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            _, result = harness.execute(
                fixture, extra={"OS_GUARD_TEST_FORCE_RECHECK_FAILURE": "true"}
            )
            assert result["error"]["code"] == "RECHECK_FAILED"
            assert result["execution"]["rollback_success"] is True

    def test_multiple_units_roll_back_in_reverse_order(self):
        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory, second_active=True)
            preview, result = harness.execute(
                fixture, extra={"OS_GUARD_TEST_FORCE_RECHECK_FAILURE": "true"}
            )
            start_order = [
                line.split("|", 1)[1]
                for line in fixture["log"].read_text(encoding="utf-8").splitlines()
                if line.startswith("start|")
            ]
            assert result["execution"]["rollback_success"] is True
            assert start_order == list(reversed(preview["preview"]["active_units"]))

    @pytest.mark.parametrize("enabled_state", ["enabled-runtime", "disabled", "static", "indirect"])
    def test_supported_enablement_states(self, enabled_state):
        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory, enabled_state=enabled_state)
            result = harness.run_action("PREVIEW", harness.environment(fixture))
            assert result["outcome"] == "PLANNED"

    def test_masked_active_unit_is_rejected(self):
        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory, enabled_state="masked")
            result = harness.run_action("PREVIEW", harness.environment(fixture))
            assert result["error"]["code"] == "MASKED_ACTIVE_UNIT_UNSAFE"

    def test_rollback_failure_is_reported(self):
        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            _, result = harness.execute(
                fixture,
                extra={
                    "OS_GUARD_TEST_FORCE_RECHECK_FAILURE": "true",
                    "OS_GUARD_TEST_FAIL_STEP": "rollback",
                },
            )
            assert result["execution"]["rollback_success"] is False

    def test_second_preview_is_idempotent(self):
        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            _, first = harness.execute(fixture)
            second = harness.run_action("PREVIEW", harness.environment(fixture))
            assert first["outcome"] == "SUCCESS"
            assert second["outcome"] == "NO_CHANGE"

    def test_legacy_activation_is_manual(self):
        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory, active=False)
            legacy = fixture["root"] / self.legacy_relative_path
            legacy.parent.mkdir(parents=True, exist_ok=True)
            legacy.write_text(self.legacy_content, encoding="utf-8")
            before = legacy.read_bytes()
            result = harness.run_action("PREVIEW", harness.environment(fixture))
            assert result["error"]["code"] == "LEGACY_ACTIVATION_REQUIRES_MANUAL_REMEDIATION"
            assert legacy.read_bytes() == before

    def test_reverse_dependency_is_manual(self):
        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            fixture["dependencies"].write_text(
                f"{self.primary_unit}|dependent.service\n", encoding="utf-8"
            )
            result = harness.run_action("PREVIEW", harness.environment(fixture))
            assert result["error"]["code"] == "ACTIVE_DEPENDENCY_REQUIRES_MANUAL_REMEDIATION"

    def test_check_failure_blocks_preview(self):
        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            result = harness.run_action(
                "PREVIEW",
                harness.environment(
                    fixture, extra={"OS_GUARD_TEST_CHECK_FAILURE": "true"}
                ),
            )
            assert result["error"]["code"] == "CHECK_EXECUTION_FAILED"

    @pytest.mark.parametrize(
        ("distro", "version"),
        (("rocky", "9.6"), ("rocky", "10.1"), ("ubuntu", "22.04"), ("ubuntu", "24.04")),
    )
    def test_supported_os_preview(self, distro, version):
        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            result = harness.run_action(
                "PREVIEW", harness.environment(fixture, distro=distro, version=version)
            )
            assert result["outcome"] == "PLANNED"

    def test_service_and_socket_can_be_planned_together(self):
        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory, second_active=True)
            result = harness.run_action("PREVIEW", harness.environment(fixture))
            assert result["preview"]["active_unit_count"] == 2
            assert set(result["preview"]["active_units"]) == {
                self.primary_unit,
                self.secondary_unit,
            }

    def test_json_contract_and_fixed_command_surface(self):
        source = self.harden_module.read_text(encoding="utf-8")
        common = (ROOT / "modules" / "lib" / "harden_service.sh").read_text(encoding="utf-8")
        assert "eval " not in source
        assert "eval " not in common
        assert self.primary_unit in source
        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            result = harness.run_action("PREVIEW", harness.environment(fixture))
            assert set(result) == {"item_id", "action", "outcome", "preview", "execution", "error"}
