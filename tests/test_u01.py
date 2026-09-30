from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from os_guard_agent import MODULE_VERSION
from os_guard_agent.manifest import load_manifest
from os_guard_agent.models import Action, OsInfo, ResultStatus, ReviewState
from os_guard_agent.module_runner import (
    ModuleExecutionError,
    ModuleNotFoundError,
    ModuleOutputError,
    ModulePermissionError,
    ModuleRunner,
    ModuleTimeoutError,
    PlannedModule,
)


PROJECT_ROOT = Path(__file__).parents[1]
PROJECT_MANIFEST = PROJECT_ROOT / "modules" / "manifest.json"
U01_MODULE = PROJECT_ROOT / "modules" / "unix" / "U-01.sh"


def os_info(distro: str = "rocky", version_id: str = "9.4") -> OsInfo:
    return OsInfo(
        distro=distro,
        version=version_id,
        version_id=version_id,
        kernel="test-kernel",
        hostname="test-host",
        architecture="x86_64",
        supported=True,
    )


def result_json(
    *,
    status: str | None,
    review_state: str = "NOT_REQUIRED",
    ssh_in_use: bool | None = False,
    ssh_state: str = "inactive",
    permit_root_login: str | None = None,
    ssh_restriction: str = "not_applicable",
    telnet_in_use: bool | None = False,
    telnet_state: str = "inactive",
    pam_securetty: bool | None = None,
    securetty_exists: bool = False,
    pts_allowed: bool | None = None,
    telnet_restriction: str = "not_applicable",
    includes: list[str] | None = None,
    match_present: bool | None = False,
    reason: str = "All detected remote terminal services are unused or block direct root login",
    error: dict[str, str] | None = None,
    distro: str = "rocky",
    version_id: str = "9.4",
) -> str:
    include_directives = includes or []
    return json.dumps(
        {
            "item_id": "U-01",
            "status": status,
            "review_state": review_state,
            "current_value": {
                "ssh": {
                    "service_in_use": ssh_in_use,
                    "service_state": ssh_state,
                    "permit_root_login": permit_root_login,
                    "value_source": "sshd_effective_config" if permit_root_login else "not_checked",
                    "root_login_restriction": ssh_restriction,
                },
                "telnet": {
                    "service_in_use": telnet_in_use,
                    "service_state": telnet_state,
                    "activation_source": "dedicated_service",
                    "pam_securetty_applied": pam_securetty,
                    "securetty_exists": securetty_exists,
                    "securetty_readable": securetty_exists,
                    "pts_entries_allowed": pts_allowed,
                    "root_login_restriction": telnet_restriction,
                },
            },
            "evidence": {
                "item_id": "U-01",
                "collection_method": (
                    "Service state inspection, OpenSSH effective configuration query, "
                    "and KISA Telnet PAM/securetty inspection"
                ),
                "configuration_paths": [
                    "/etc/ssh/sshd_config",
                    "/etc/pam.d/login",
                    "/etc/securetty",
                    "/etc/inetd.conf",
                    "/etc/xinetd.d/telnet",
                ],
                "include_directives": include_directives,
                "include_present": bool(include_directives),
                "match_condition_present": match_present,
                "ssh_service_units": ["sshd.service", "sshd.socket"],
                "telnet_service_units": ["telnet.socket", "telnet.service"],
                "sshd_executable": "/usr/sbin/sshd" if ssh_in_use else None,
                "os": {"distro": distro, "version_id": version_id},
                "observed_at": "2026-09-22T00:00:00Z",
                "module_version": MODULE_VERSION,
                "decision_reason": reason,
            },
            "error": error,
        }
    )


class U01ExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        detected_os = os_info()
        manifest = load_manifest(PROJECT_MANIFEST, "manifest-unix-67-v1", detected_os)
        self.runner = ModuleRunner(manifest, detected_os)
        self.planned = self.runner.prepare_item("U-01", Action.CHECK)

    def run_with(self, stdout: str, *, returncode: int = 0, stderr: str = ""):
        completed = subprocess.CompletedProcess(
            args=[str(U01_MODULE)], returncode=returncode, stdout=stdout, stderr=stderr
        )
        with (
            patch("os_guard_agent.module_runner.os.access", return_value=True),
            patch("os_guard_agent.module_runner.subprocess.run", return_value=completed) as run,
        ):
            result = self.runner.execute_check(self.planned, timeout_seconds=3)
        return result, run

    def assert_status(self, stdout: str, expected: ResultStatus) -> None:
        result, _run = self.run_with(stdout)
        self.assertEqual(result.status, expected)
        self.assertEqual(result.review_state, ReviewState.NOT_REQUIRED)

    def test_ssh_and_telnet_unused_is_good(self) -> None:
        self.assert_status(result_json(status="GOOD"), ResultStatus.GOOD)

    def test_active_ssh_with_permit_root_login_no_is_good(self) -> None:
        self.assert_status(
            result_json(status="GOOD", ssh_in_use=True, ssh_state="active",
                        permit_root_login="no", ssh_restriction="blocked"),
            ResultStatus.GOOD,
        )

    def test_active_ssh_with_root_login_allowed_is_vulnerable(self) -> None:
        for value in ("yes", "prohibit-password", "forced-commands-only"):
            with self.subTest(value=value):
                self.assert_status(
                    result_json(status="VULNERABLE", ssh_in_use=True, ssh_state="active",
                                permit_root_login=value, ssh_restriction="allowed"),
                    ResultStatus.VULNERABLE,
                )

    def test_ssh_include_effective_value_is_used(self) -> None:
        result, _run = self.run_with(
            result_json(status="GOOD", ssh_in_use=True, ssh_state="active",
                        permit_root_login="no", ssh_restriction="blocked",
                        includes=["/etc/ssh/sshd_config.d/*.conf"])
        )
        self.assertEqual(result.status, ResultStatus.GOOD)
        self.assertTrue(result.evidence["include_present"])
        self.assertEqual(result.current_value["ssh"]["value_source"], "sshd_effective_config")

    def test_ssh_match_condition_requires_review(self) -> None:
        result, _run = self.run_with(
            result_json(status=None, review_state="PENDING", ssh_in_use=True,
                        ssh_state="active", permit_root_login="no",
                        ssh_restriction="review_required", match_present=True,
                        reason="OpenSSH Match conditions require contextual review")
        )
        self.assertIsNone(result.status)
        self.assertEqual(result.review_state, ReviewState.PENDING)
        self.assertTrue(result.evidence["match_condition_present"])

    def test_telnet_unused_does_not_make_safe_ssh_vulnerable(self) -> None:
        self.assert_status(
            result_json(status="GOOD", ssh_in_use=True, ssh_state="active",
                        permit_root_login="no", ssh_restriction="blocked"),
            ResultStatus.GOOD,
        )

    def test_active_telnet_with_root_restricted_is_good(self) -> None:
        self.assert_status(
            result_json(status="GOOD", telnet_in_use=True, telnet_state="active",
                        pam_securetty=True, securetty_exists=True, pts_allowed=False,
                        telnet_restriction="blocked"),
            ResultStatus.GOOD,
        )

    def test_active_telnet_with_required_pam_and_no_securetty_is_good(self) -> None:
        self.assert_status(
            result_json(status="GOOD", telnet_in_use=True, telnet_state="active",
                        pam_securetty=True, securetty_exists=False, pts_allowed=None,
                        telnet_restriction="blocked"),
            ResultStatus.GOOD,
        )

    def test_active_telnet_with_root_allowed_is_vulnerable(self) -> None:
        for pam_applied, pts_allowed in ((False, False), (True, True)):
            with self.subTest(pam_applied=pam_applied, pts_allowed=pts_allowed):
                self.assert_status(
                    result_json(status="VULNERABLE", telnet_in_use=True,
                                telnet_state="active", pam_securetty=pam_applied,
                                securetty_exists=True, pts_allowed=pts_allowed,
                                telnet_restriction="allowed"),
                    ResultStatus.VULNERABLE,
                )

    def test_telnet_vulnerability_overrides_safe_ssh(self) -> None:
        self.assert_status(
            result_json(status="VULNERABLE", ssh_in_use=True, ssh_state="active",
                        permit_root_login="no", ssh_restriction="blocked",
                        telnet_in_use=True, telnet_state="active", pam_securetty=True,
                        securetty_exists=True, pts_allowed=True,
                        telnet_restriction="allowed"),
            ResultStatus.VULNERABLE,
        )

    def test_configuration_failure_is_uncheckable(self) -> None:
        result, _run = self.run_with(
            result_json(status="UNCHECKABLE", ssh_in_use=True, ssh_state="active",
                        ssh_restriction="unknown",
                        error={"code": "REMOTE_ACCESS_CHECK_UNAVAILABLE",
                               "message": "Remote access state could not be verified"})
        )
        self.assertEqual(result.status, ResultStatus.UNCHECKABLE)
        self.assertEqual(result.review_state, ReviewState.NOT_REQUIRED)
        self.assertEqual(result.error["code"], "REMOTE_ACCESS_CHECK_UNAVAILABLE")

    def test_evidence_contains_decision_inputs_and_reason(self) -> None:
        result, _run = self.run_with(
            result_json(status="GOOD", ssh_in_use=True, ssh_state="active",
                        permit_root_login="no", ssh_restriction="blocked",
                        includes=["/etc/ssh/sshd_config.d/*.conf"])
        )
        self.assertEqual(result.evidence["module_version"], MODULE_VERSION)
        self.assertEqual(result.evidence["os"], {"distro": "rocky", "version_id": "9.4"})
        self.assertIn("decision_reason", result.evidence)
        self.assertIn("/etc/ssh/sshd_config", result.evidence["configuration_paths"])
        self.assertIn("ssh", result.current_value)
        self.assertIn("telnet", result.current_value)

    def test_ubuntu_result_uses_the_same_contract(self) -> None:
        detected_os = os_info("ubuntu", "24.04")
        manifest = load_manifest(PROJECT_MANIFEST, "manifest-unix-67-v1", detected_os)
        runner = ModuleRunner(manifest, detected_os)
        planned = runner.prepare_item("U-01", Action.CHECK)
        completed = subprocess.CompletedProcess(
            args=[str(U01_MODULE)],
            returncode=0,
            stdout=result_json(status="GOOD", distro="ubuntu", version_id="24.04"),
            stderr="",
        )
        with (
            patch("os_guard_agent.module_runner.os.access", return_value=True),
            patch("os_guard_agent.module_runner.subprocess.run", return_value=completed),
        ):
            result = runner.execute_check(planned)
        self.assertEqual(result.status, ResultStatus.GOOD)
        self.assertEqual(result.evidence["os"], {"distro": "ubuntu", "version_id": "24.04"})

    def test_supported_os_telnet_activation_sources_are_read_only(self) -> None:
        source = U01_MODULE.read_text(encoding="utf-8")
        self.assertIn("inetutils-inetd.service", source)
        self.assertIn("/etc/inetd.conf", source)
        self.assertIn("xinetd.service", source)
        self.assertIn("/etc/xinetd.d/telnet", source)

    def test_sensitive_values_are_not_exposed(self) -> None:
        secret = "enrollment-token-secret"
        self.assertNotIn(secret, result_json(status="GOOD"))
        completed = subprocess.CompletedProcess(
            args=[str(U01_MODULE)], returncode=2, stdout="", stderr=f"token={secret}"
        )
        with (
            patch("os_guard_agent.module_runner.os.access", return_value=True),
            patch("os_guard_agent.module_runner.subprocess.run", return_value=completed),
        ):
            with self.assertRaises(ModuleExecutionError) as caught:
                self.runner.execute_check(self.planned)
        self.assertNotIn(secret, str(caught.exception))

    def test_runner_uses_fixed_argv_without_shell(self) -> None:
        _result, run = self.run_with(result_json(status="GOOD"))
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertEqual(run.call_args.args[0], [str(self.planned.module_path)])
        self.assertEqual(run.call_args.kwargs["timeout"], 3)

    def test_missing_module(self) -> None:
        with patch("os_guard_agent.module_runner.Path.exists", return_value=False):
            with self.assertRaises(ModuleNotFoundError):
                self.runner.execute_check(self.planned)

    def test_execution_permission_error(self) -> None:
        with patch("os_guard_agent.module_runner.os.access", return_value=False):
            with self.assertRaises(ModulePermissionError):
                self.runner.execute_check(self.planned)

    def test_timeout(self) -> None:
        with (
            patch("os_guard_agent.module_runner.os.access", return_value=True),
            patch("os_guard_agent.module_runner.subprocess.run",
                  side_effect=subprocess.TimeoutExpired("U-01", 1)),
        ):
            with self.assertRaises(ModuleTimeoutError):
                self.runner.execute_check(self.planned, timeout_seconds=1)

    def test_invalid_or_unexpected_stdout(self) -> None:
        valid = result_json(status="GOOD")
        for stdout in ("not-json", "debug output\n" + valid, valid + valid):
            with self.subTest(stdout=stdout[:20]):
                with self.assertRaises(ModuleOutputError):
                    self.run_with(stdout)

    def test_path_traversal_and_external_path_are_rejected(self) -> None:
        for unsafe_path in (self.planned.module_path.parent / ".." / "outside.sh",
                            Path("/tmp/outside.sh")):
            with self.subTest(path=unsafe_path):
                malicious_plan = PlannedModule("U-01", unsafe_path, Action.CHECK)
                with self.assertRaisesRegex(ModuleExecutionError, "trusted manifest"):
                    self.runner.execute_check(malicious_plan)

    def test_check_source_has_no_system_mutation(self) -> None:
        source = U01_MODULE.read_text(encoding="utf-8")
        for operation in ("sed -i", "systemctl start", "systemctl stop",
                          "systemctl restart", "service ssh", "service telnet",
                          "chmod ", "chown ", "useradd ", "passwd ", "apt ", "dnf "):
            self.assertNotIn(operation, source)
        self.assertIn('systemctl is-active "$unit_name"', source)
        self.assertIn('"$sshd_bin" -T -C', source)
        self.assertIn("pam_securetty", source)
        self.assertIn("securetty", source)


if __name__ == "__main__":
    unittest.main()
