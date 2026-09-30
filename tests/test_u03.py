from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from os_guard_agent import MODULE_VERSION
from os_guard_agent.manifest import load_manifest
from os_guard_agent.models import Action, OsInfo, ResultStatus, ReviewState
from os_guard_agent.module_runner import ModuleOutputError, ModuleRunner, ModuleTimeoutError


PROJECT_ROOT = Path(__file__).parents[1]
PROJECT_MANIFEST = PROJECT_ROOT / "modules" / "manifest.json"
U03_MODULE = PROJECT_ROOT / "modules" / "unix" / "U-03.sh"


def os_info(distro: str, version_id: str) -> OsInfo:
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
    distro: str,
    version_id: str,
    *,
    status: str | None = "GOOD",
    review_state: str = "NOT_REQUIRED",
    module: str | None = "pam_faillock",
    active: bool | None = True,
    deny: int | None = 5,
    deny_sources: list[str] | None = None,
    faillock_count: int = 4,
    tally_count: int = 0,
    complex_structure: bool = False,
    authselect_state: str = "configured",
    with_faillock: bool | None = True,
    failures: list[str] | None = None,
    review_reasons: list[str] | None = None,
    reason_code: str = "KISA_U03_COMPLIANT",
    error: dict[str, str] | None = None,
) -> str:
    pam_paths = (
        ["/etc/pam.d/system-auth", "/etc/pam.d/password-auth"]
        if distro == "rocky"
        else ["/etc/pam.d/common-auth", "/etc/pam.d/common-account"]
    )
    return json.dumps(
        {
            "item_id": "U-03",
            "status": status,
            "review_state": review_state,
            "current_value": {
                "lockout_module": module,
                "policy_active": active,
                "effective_deny": deny,
                "unlock_time": 120,
                "pam": {
                    "configuration_paths": ["/etc/security/faillock.conf", *pam_paths],
                    "faillock_record_count": faillock_count,
                    "tally_record_count": tally_count,
                    "complex_structure": complex_structure,
                },
                "authselect": {
                    "state": authselect_state if distro == "rocky" else "not_applicable",
                    "profile_id": "sssd" if distro == "rocky" else None,
                    "with_faillock": with_faillock if distro == "rocky" else None,
                },
            },
            "evidence": {
                "item_id": "U-03",
                "collection_method": (
                    "Read faillock configuration, inspect PAM auth/account stacks, "
                    "and query Rocky authselect state without changing counters"
                ),
                "configuration_paths": ["/etc/security/faillock.conf", *pam_paths],
                "deny_sources": deny_sources or ["/etc/security/faillock.conf"],
                "criteria_failures": failures or [],
                "review_reasons": review_reasons or [],
                "reason_code": reason_code,
                "unlock_time_used_for_judgment": False,
                "os": {"distro": distro, "version_id": version_id},
                "observed_at": "2026-09-22T00:00:00Z",
                "module_version": MODULE_VERSION,
                "decision_reason": "fixture decision reason",
            },
            "error": error,
        }
    )


class U03Tests(unittest.TestCase):
    def make_runner(self, distro: str = "rocky", version_id: str = "9.4") -> ModuleRunner:
        detected_os = os_info(distro, version_id)
        manifest = load_manifest(PROJECT_MANIFEST, "manifest-unix-67-v1", detected_os)
        return ModuleRunner(manifest, detected_os)

    def execute_fixture(self, distro: str, version_id: str, stdout: str):
        runner = self.make_runner(distro, version_id)
        planned = runner.prepare_item("U-03", Action.CHECK)
        completed = subprocess.CompletedProcess(
            args=[str(U03_MODULE)], returncode=0, stdout=stdout, stderr=""
        )
        with (
            patch("os_guard_agent.module_runner.os.access", return_value=True),
            patch("os_guard_agent.module_runner.subprocess.run", return_value=completed) as run,
        ):
            result = runner.execute_check(planned)
        return result, run

    def assert_vulnerable(self, failure: str, **values) -> None:
        result, _run = self.execute_fixture(
            "rocky",
            "9.4",
            result_json(
                "rocky",
                "9.4",
                status="VULNERABLE",
                failures=[failure],
                reason_code="KISA_U03_POLICY_INSUFFICIENT",
                **values,
            ),
        )
        self.assertEqual(result.status, ResultStatus.VULNERABLE)
        self.assertEqual(result.review_state, ReviewState.NOT_REQUIRED)
        self.assertIn(failure, result.evidence["criteria_failures"])

    def test_manifest_lookup_and_deny_one_is_good(self) -> None:
        runner = self.make_runner()
        planned = runner.prepare_item("U-03", Action.CHECK)
        self.assertEqual(planned.module_path.name, "U-03.sh")
        result, run = self.execute_fixture(
            "rocky", "9.4", result_json("rocky", "9.4", deny=1)
        )
        self.assertEqual(result.status, ResultStatus.GOOD)
        self.assertEqual(result.review_state, ReviewState.NOT_REQUIRED)
        self.assertFalse(run.call_args.kwargs["shell"])

    def test_deny_ten_is_good_boundary(self) -> None:
        result, _run = self.execute_fixture(
            "ubuntu", "24.04", result_json("ubuntu", "24.04", deny=10)
        )
        self.assertEqual(result.status, ResultStatus.GOOD)

    def test_unset_deny_is_vulnerable(self) -> None:
        self.assert_vulnerable("DENY_NOT_CONFIGURED", deny=None, deny_sources=[])

    def test_deny_zero_is_vulnerable(self) -> None:
        self.assert_vulnerable("DENY_NOT_POSITIVE", deny=0)

    def test_deny_eleven_is_vulnerable_boundary(self) -> None:
        self.assert_vulnerable("DENY_EXCEEDS_10", deny=11)

    def test_missing_or_inactive_lockout_module_is_vulnerable(self) -> None:
        self.assert_vulnerable(
            "LOCKOUT_MODULE_NOT_APPLIED",
            module=None,
            active=False,
            deny=None,
            faillock_count=0,
            with_faillock=False,
        )
        self.assert_vulnerable("LOCKOUT_POLICY_NOT_ACTIVE", active=False)

    def test_rocky_authselect_with_faillock_is_recorded(self) -> None:
        result, _run = self.execute_fixture(
            "rocky",
            "10",
            result_json("rocky", "10", authselect_state="configured", with_faillock=True),
        )
        self.assertEqual(result.status, ResultStatus.GOOD)
        self.assertTrue(result.current_value["authselect"]["with_faillock"])
        self.assertEqual(result.current_value["authselect"]["profile_id"], "sssd")

    def test_rocky_inactive_policy_is_vulnerable(self) -> None:
        self.assert_vulnerable(
            "LOCKOUT_MODULE_NOT_APPLIED",
            module=None,
            active=False,
            deny=None,
            faillock_count=0,
            authselect_state="configured",
            with_faillock=False,
        )

    def test_ubuntu_faillock_auth_and_account_stack_is_good(self) -> None:
        result, _run = self.execute_fixture(
            "ubuntu", "22.04", result_json("ubuntu", "22.04", deny=5)
        )
        self.assertEqual(result.status, ResultStatus.GOOD)
        self.assertEqual(result.current_value["authselect"]["state"], "not_applicable")
        self.assertIn("/etc/pam.d/common-auth", result.evidence["configuration_paths"])
        self.assertIn("/etc/pam.d/common-account", result.evidence["configuration_paths"])

    def test_pam_argument_overrides_configuration_file(self) -> None:
        result, _run = self.execute_fixture(
            "rocky",
            "9.4",
            result_json(
                "rocky",
                "9.4",
                deny=7,
                deny_sources=["/etc/pam.d/system-auth:5", "/etc/pam.d/password-auth:5"],
            ),
        )
        self.assertEqual(result.current_value["effective_deny"], 7)
        self.assertTrue(all(source.startswith("/etc/pam.d/") for source in result.evidence["deny_sources"]))

    def test_conflicting_deny_values_are_pending(self) -> None:
        result, _run = self.execute_fixture(
            "rocky",
            "9.4",
            result_json(
                "rocky",
                "9.4",
                status=None,
                review_state="PENDING",
                deny=None,
                review_reasons=["CONFLICTING_EFFECTIVE_DENY_VALUES"],
                reason_code="KISA_U03_EFFECTIVE_POLICY_REVIEW_REQUIRED",
            ),
        )
        self.assertIsNone(result.status)
        self.assertEqual(result.review_state, ReviewState.PENDING)

    def test_duplicate_lockout_module_types_are_pending(self) -> None:
        result, _run = self.execute_fixture(
            "ubuntu",
            "24.04",
            result_json(
                "ubuntu",
                "24.04",
                status=None,
                review_state="PENDING",
                module="multiple",
                active=None,
                deny=None,
                faillock_count=2,
                tally_count=2,
                review_reasons=["MULTIPLE_LOCKOUT_MODULE_TYPES_REQUIRE_REVIEW"],
                reason_code="KISA_U03_EFFECTIVE_POLICY_REVIEW_REQUIRED",
            ),
        )
        self.assertIsNone(result.status)
        self.assertEqual(result.review_state, ReviewState.PENDING)

    def test_complex_pam_include_is_pending(self) -> None:
        result, _run = self.execute_fixture(
            "ubuntu",
            "24.04",
            result_json(
                "ubuntu",
                "24.04",
                status=None,
                review_state="PENDING",
                active=None,
                deny=None,
                complex_structure=True,
                review_reasons=["PAM_INCLUDE_OR_MULTILINE_REQUIRES_REVIEW"],
                reason_code="KISA_U03_EFFECTIVE_POLICY_REVIEW_REQUIRED",
            ),
        )
        self.assertIsNone(result.status)
        self.assertEqual(result.review_state, ReviewState.PENDING)

    def test_read_or_parse_failure_is_uncheckable(self) -> None:
        error = {
            "code": "PAM_CONFIGURATION_UNREADABLE",
            "message": "Account lockout policy collection or parsing failed",
        }
        result, _run = self.execute_fixture(
            "ubuntu",
            "22.04",
            result_json(
                "ubuntu",
                "22.04",
                status="UNCHECKABLE",
                reason_code="KISA_U03_COLLECTION_FAILED",
                error=error,
            ),
        )
        self.assertEqual(result.status, ResultStatus.UNCHECKABLE)
        self.assertEqual(result.review_state, ReviewState.NOT_REQUIRED)
        self.assertEqual(result.error["code"], "PAM_CONFIGURATION_UNREADABLE")

    def test_evidence_contains_effective_deny_source_and_reason(self) -> None:
        result, _run = self.execute_fixture(
            "rocky", "9.4", result_json("rocky", "9.4", deny=5)
        )
        self.assertEqual(result.evidence["module_version"], MODULE_VERSION)
        self.assertEqual(result.evidence["reason_code"], "KISA_U03_COMPLIANT")
        self.assertIn("/etc/security/faillock.conf", result.evidence["deny_sources"])
        self.assertFalse(result.evidence["unlock_time_used_for_judgment"])
        self.assertIn("decision_reason", result.evidence)

    def test_sensitive_authentication_data_is_not_collected(self) -> None:
        payload = result_json("rocky", "9.4")
        for sensitive in ("cleartext-password", "password_hash", "failed_password", "secret-value"):
            self.assertNotIn(sensitive, payload)

    def test_invalid_json_contract(self) -> None:
        with self.assertRaises(ModuleOutputError):
            self.execute_fixture("rocky", "9.4", "diagnostic\n{}")

    def test_timeout(self) -> None:
        runner = self.make_runner()
        planned = runner.prepare_item("U-03", Action.CHECK)
        with (
            patch("os_guard_agent.module_runner.os.access", return_value=True),
            patch(
                "os_guard_agent.module_runner.subprocess.run",
                side_effect=subprocess.TimeoutExpired("U-03", 1),
            ),
        ):
            with self.assertRaises(ModuleTimeoutError):
                runner.execute_check(planned, timeout_seconds=1)

    def test_check_is_read_only_and_preserves_runner_security(self) -> None:
        source = U03_MODULE.read_text(encoding="utf-8")
        for forbidden in (
            "--reset",
            "pam_tally2 --reset",
            "sed -i",
            "authselect enable-feature",
            "authselect select",
            "systemctl ",
            "service ",
            "chmod ",
            "chown ",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn('../lib/common.sh', source)
        self.assertIn('"$authselect_bin" current', source)
        self.assertIn("/etc/security/faillock.conf", source)
        self.assertIn("pam_faillock", source)
        self.assertIn("pam_tally2", source)


if __name__ == "__main__":
    unittest.main()
