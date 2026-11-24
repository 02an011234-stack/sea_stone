from pathlib import Path

from harden_policy_content_test_support import PolicyContentHardenTestBase


class TestU62Harden(PolicyContentHardenTestBase):
    __test__ = True
    item_id = "U-62"
    target_path = "/etc/issue.net"
    active_unit = "no-supported-service.service"
    fixture_result_variable = "OS_GUARD_TEST_U62_FILE"
    vulnerable_content = "Ubuntu 24.04 LTS\n"
    good_content = "Authorized access only. Unauthorized use is prohibited.\n"
    expected_fragment = "Authorized access only. Unauthorized use is prohibited."
    fixture_policy = {
        "OS_GUARD_TEST_POLICY_FIXTURE": "true",
        "OS_GUARD_TEST_LOGIN_WARNING_TARGET": "/etc/issue.net",
        "OS_GUARD_TEST_LOGIN_WARNING_SCOPE": "system-only",
        "OS_GUARD_TEST_APPROVED_BANNER_TEXT": (
            "Authorized access only. Unauthorized use is prohibited."
        ),
        "OS_GUARD_TEST_BANNER_APPROVAL_VERIFIED": "true",
    }

    def pending_fixture_row(self):
        return "complete|1|0|0|0|0|0|0|0|0|1\n"

    def test_02_vulnerable_minimal_change(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            preview, result, _ = self.execute(fixture)
            self.assertEqual(preview["outcome"], "PLANNED")
            self.assertEqual(result["outcome"], "SUCCESS")
            self.assertEqual(
                fixture["target"].read_text(encoding="utf-8"),
                self.fixture_policy["OS_GUARD_TEST_APPROVED_BANNER_TEXT"] + "\n",
            )

    def test_21_reload_approval_is_required_for_execute(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_BANNER_APPROVAL_VERIFIED": "false"},
                ),
            )
            self.assertEqual(result["error"]["code"], "BANNER_APPROVAL_EVIDENCE_REQUIRED")

    def test_25_missing_policy_text_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_APPROVED_BANNER_TEXT": ""},
                ),
            )
            self.assertEqual(result["error"]["code"], "APPROVED_BANNER_INVALID")

    def test_26_non_warning_text_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_APPROVED_BANNER_TEXT": "Welcome to this server"},
                ),
            )
            self.assertEqual(result["error"]["code"], "APPROVED_BANNER_INVALID")

    def test_27_active_service_specific_banner_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            self._write_command(
                fixture["systemctl"],
                '''#!/bin/sh
if [ "${1:-}" = "is-active" ] && [ "${2:-}" = "telnet.socket" ]; then
    printf 'active\n'
    exit 0
fi
printf 'inactive\n'
exit 3
''',
            )
            result, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(result["error"]["code"], "ACTIVE_SERVICE_BANNER_UNSUPPORTED")

    def test_28_banner_text_is_not_returned_in_json(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            _, output = self.run_action("PREVIEW", self.environment(fixture))
            self.assertNotIn(self.fixture_policy["OS_GUARD_TEST_APPROVED_BANNER_TEXT"], output)

    def test_15_unrelated_content_preserved(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            before = fixture["target"].read_bytes()
            preview, _ = self.run_action("PREVIEW", self.environment(fixture))
            self.assertEqual(preview["outcome"], "PLANNED")
            self.assertEqual(fixture["target"].read_bytes(), before)

    def test_23_uncheckable_check_is_not_actionable(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            state_file = Path(temp_dir) / "check.state"
            state_file.write_text(
                "collection_failed|0|0|0|0|0|0|0|0|0|0\n",
                encoding="utf-8",
            )
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={self.fixture_result_variable: state_file.as_posix()},
                ),
            )
            self.assertEqual(result["error"]["code"], "CHECK_STATE_NOT_ACTIONABLE")
