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
U02_MODULE = PROJECT_ROOT / "modules" / "unix" / "U-02.sh"


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
    minlen: int | None = 8,
    dcredit: int | None = -1,
    ucredit: int | None = -1,
    lcredit: int | None = -1,
    ocredit: int | None = -1,
    pass_min_days: int | None = 1,
    pass_max_days: int | None = 90,
    remember: int | None = 4,
    pwquality_root: bool = True,
    pwhistory_root: bool = True,
    pwquality_present: bool = True,
    pwhistory_present: bool = True,
    pam_unix_present: bool = True,
    pwquality_before_unix: bool | None = True,
    pwhistory_before_unix: bool | None = True,
    complex_structure: bool = False,
    failures: list[str] | None = None,
    review_reasons: list[str] | None = None,
    reason_code: str = "KISA_U02_COMPLIANT",
    error: dict[str, str] | None = None,
) -> str:
    pam_path = "/etc/pam.d/system-auth" if distro == "rocky" else "/etc/pam.d/common-password"
    return json.dumps(
        {
            "item_id": "U-02",
            "status": status,
            "review_state": review_state,
            "current_value": {
                "min_length": {"value": minlen, "source": "/etc/security/pwquality.conf"},
                "character_requirements": {
                    "dcredit": dcredit,
                    "ucredit": ucredit,
                    "lcredit": lcredit,
                    "ocredit": ocredit,
                },
                "pass_min_days": pass_min_days,
                "pass_max_days": pass_max_days,
                "password_history": {
                    "remember": remember,
                    "source": "/etc/security/pwhistory.conf",
                },
                "root_enforcement": {
                    "pwquality": pwquality_root,
                    "pwhistory": pwhistory_root,
                },
                "pam": {
                    "configuration_path": pam_path,
                    "pam_pwquality_present": pwquality_present,
                    "pam_pwhistory_present": pwhistory_present,
                    "pam_unix_present": pam_unix_present,
                    "pwquality_before_unix": pwquality_before_unix,
                    "pwhistory_before_unix": pwhistory_before_unix,
                    "complex_structure": complex_structure,
                },
            },
            "evidence": {
                "item_id": "U-02",
                "collection_method": (
                    "Read login.defs, resolve libpwquality and pwhistory configuration "
                    "precedence, and inspect the active PAM password stack"
                ),
                "configuration_paths": [
                    "/etc/login.defs",
                    "/etc/security/pwquality.conf",
                    "/etc/security/pwquality.conf.d/*.conf",
                    "/etc/security/pwhistory.conf",
                    pam_path,
                ],
                "effective_value_sources": {
                    "minlen": "/etc/security/pwquality.conf",
                    "dcredit": "/etc/security/pwquality.conf",
                    "ucredit": "/etc/security/pwquality.conf",
                    "lcredit": "/etc/security/pwquality.conf",
                    "ocredit": "/etc/security/pwquality.conf",
                    "remember": "/etc/security/pwhistory.conf",
                    "pwquality_root": "/etc/security/pwquality.conf",
                    "pwhistory_root": "/etc/security/pwhistory.conf",
                },
                "criteria_failures": failures or [],
                "review_reasons": review_reasons or [],
                "reason_code": reason_code,
                "pass_min_days_criterion": {
                    "value": 1,
                    "basis": "KISA final recommendations",
                },
                "os": {"distro": distro, "version_id": version_id},
                "observed_at": "2026-09-22T00:00:00Z",
                "module_version": MODULE_VERSION,
                "decision_reason": "fixture decision reason",
            },
            "error": error,
        }
    )


class U02Tests(unittest.TestCase):
    def make_runner(self, distro: str = "rocky", version_id: str = "9.4") -> ModuleRunner:
        detected_os = os_info(distro, version_id)
        manifest = load_manifest(PROJECT_MANIFEST, "manifest-unix-67-v1", detected_os)
        return ModuleRunner(manifest, detected_os)

    def execute_fixture(self, distro: str, version_id: str, stdout: str):
        runner = self.make_runner(distro, version_id)
        planned = runner.prepare_item("U-02", Action.CHECK)
        completed = subprocess.CompletedProcess(
            args=[str(U02_MODULE)], returncode=0, stdout=stdout, stderr=""
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
                reason_code="KISA_U02_POLICY_INSUFFICIENT",
                **values,
            ),
        )
        self.assertEqual(result.status, ResultStatus.VULNERABLE)
        self.assertEqual(result.review_state, ReviewState.NOT_REQUIRED)
        self.assertIn(failure, result.evidence["criteria_failures"])

    def test_manifest_lookup_and_all_criteria_satisfied_is_good(self) -> None:
        runner = self.make_runner()
        planned = runner.prepare_item("U-02", Action.CHECK)
        self.assertEqual(planned.module_path.name, "U-02.sh")
        result, run = self.execute_fixture("rocky", "9.4", result_json("rocky", "9.4"))
        self.assertEqual(result.status, ResultStatus.GOOD)
        self.assertEqual(result.review_state, ReviewState.NOT_REQUIRED)
        self.assertFalse(run.call_args.kwargs["shell"])

    def test_minimum_length_below_eight_is_vulnerable(self) -> None:
        self.assert_vulnerable("MIN_LENGTH_BELOW_8", minlen=7)

    def test_missing_character_requirement_is_vulnerable(self) -> None:
        for field, failure in (
            ("dcredit", "DIGIT_REQUIREMENT_NOT_MINUS_1"),
            ("ucredit", "UPPERCASE_REQUIREMENT_NOT_MINUS_1"),
            ("lcredit", "LOWERCASE_REQUIREMENT_NOT_MINUS_1"),
            ("ocredit", "SPECIAL_CHARACTER_REQUIREMENT_NOT_MINUS_1"),
        ):
            with self.subTest(field=field):
                self.assert_vulnerable(failure, **{field: 0})

    def test_pass_min_days_below_one_is_vulnerable(self) -> None:
        self.assert_vulnerable("PASS_MIN_DAYS_BELOW_1", pass_min_days=0)

    def test_pass_max_days_above_ninety_is_vulnerable(self) -> None:
        self.assert_vulnerable("PASS_MAX_DAYS_OUTSIDE_1_TO_90", pass_max_days=91)

    def test_password_history_below_four_is_vulnerable(self) -> None:
        self.assert_vulnerable("PASSWORD_HISTORY_BELOW_4", remember=3)

    def test_root_policy_not_enforced_is_vulnerable(self) -> None:
        self.assert_vulnerable("PWQUALITY_NOT_ENFORCED_FOR_ROOT", pwquality_root=False)
        self.assert_vulnerable("PWHISTORY_NOT_ENFORCED_FOR_ROOT", pwhistory_root=False)

    def test_pam_module_order_is_enforced(self) -> None:
        self.assert_vulnerable(
            "PAM_PWQUALITY_NOT_BEFORE_PAM_UNIX", pwquality_before_unix=False
        )
        self.assert_vulnerable(
            "PAM_PWHISTORY_NOT_BEFORE_PAM_UNIX", pwhistory_before_unix=False
        )

    def test_missing_required_policy_is_vulnerable(self) -> None:
        self.assert_vulnerable("PAM_PWQUALITY_NOT_APPLIED", pwquality_present=False)
        self.assert_vulnerable("PAM_PWHISTORY_NOT_APPLIED", pwhistory_present=False)

    def test_complex_pam_structure_is_pending(self) -> None:
        result, _run = self.execute_fixture(
            "rocky",
            "10",
            result_json(
                "rocky",
                "10",
                status=None,
                review_state="PENDING",
                complex_structure=True,
                review_reasons=["PAM_INCLUDE_OR_MULTILINE_REQUIRES_REVIEW"],
                reason_code="KISA_U02_EFFECTIVE_POLICY_REVIEW_REQUIRED",
            ),
        )
        self.assertIsNone(result.status)
        self.assertEqual(result.review_state, ReviewState.PENDING)

    def test_collection_or_parse_failure_is_uncheckable(self) -> None:
        error = {
            "code": "POLICY_FILE_UNREADABLE",
            "message": "Password policy collection or parsing failed",
        }
        result, _run = self.execute_fixture(
            "ubuntu",
            "22.04",
            result_json(
                "ubuntu",
                "22.04",
                status="UNCHECKABLE",
                reason_code="KISA_U02_COLLECTION_FAILED",
                error=error,
            ),
        )
        self.assertEqual(result.status, ResultStatus.UNCHECKABLE)
        self.assertEqual(result.review_state, ReviewState.NOT_REQUIRED)
        self.assertEqual(result.error["code"], "POLICY_FILE_UNREADABLE")

    def test_rocky_uses_system_auth(self) -> None:
        result, _run = self.execute_fixture("rocky", "10", result_json("rocky", "10"))
        self.assertEqual(result.current_value["pam"]["configuration_path"], "/etc/pam.d/system-auth")

    def test_ubuntu_uses_common_password(self) -> None:
        result, _run = self.execute_fixture(
            "ubuntu", "24.04", result_json("ubuntu", "24.04")
        )
        self.assertEqual(result.status, ResultStatus.GOOD)
        self.assertEqual(
            result.current_value["pam"]["configuration_path"], "/etc/pam.d/common-password"
        )

    def test_evidence_has_effective_values_sources_and_reason(self) -> None:
        result, _run = self.execute_fixture("rocky", "9.4", result_json("rocky", "9.4"))
        self.assertEqual(result.evidence["module_version"], MODULE_VERSION)
        self.assertIn("effective_value_sources", result.evidence)
        self.assertEqual(result.evidence["pass_min_days_criterion"]["value"], 1)
        self.assertEqual(result.evidence["reason_code"], "KISA_U02_COMPLIANT")
        self.assertIn("decision_reason", result.evidence)

    def test_passwords_and_hashes_are_not_collected(self) -> None:
        payload = result_json("rocky", "9.4")
        for sensitive in ("password_hash", "shadow_hash", "operating_token", "secret-value"):
            self.assertNotIn(sensitive, payload)
        source = U02_MODULE.read_text(encoding="utf-8")
        self.assertNotIn("/etc/shadow", source)

    def test_timeout(self) -> None:
        runner = self.make_runner()
        planned = runner.prepare_item("U-02", Action.CHECK)
        with (
            patch("os_guard_agent.module_runner.os.access", return_value=True),
            patch(
                "os_guard_agent.module_runner.subprocess.run",
                side_effect=subprocess.TimeoutExpired("U-02", 1),
            ),
        ):
            with self.assertRaises(ModuleTimeoutError):
                runner.execute_check(planned, timeout_seconds=1)

    def test_invalid_stdout_is_rejected(self) -> None:
        with self.assertRaises(ModuleOutputError):
            self.execute_fixture("rocky", "9.4", "debug output\n{}")

    def test_check_is_read_only_and_preserves_runner_security(self) -> None:
        source = U02_MODULE.read_text(encoding="utf-8")
        for forbidden in (
            "sed -i",
            "passwd ",
            "chage ",
            "systemctl ",
            "service ",
            "chmod ",
            "chown ",
            "apt ",
            "dnf ",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn('../lib/common.sh', source)
        self.assertIn("/etc/login.defs", source)
        self.assertIn("/etc/security/pwhistory.conf", source)
        self.assertIn("pam_pwquality", source)
        self.assertIn("pam_pwhistory", source)


if __name__ == "__main__":
    unittest.main()
