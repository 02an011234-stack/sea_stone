from __future__ import annotations

from pathlib import Path

from harden_content_test_support import ContentHardenTestBase


class PolicyContentHardenTestBase(ContentHardenTestBase):
    __test__ = False
    active_unit = ""
    fixture_result_variable = ""
    fixture_policy: dict[str, str] = {}

    def create_fixture(self, temp_dir: str, *, good=False, content=None):
        fixture = super().create_fixture(temp_dir, good=good, content=content)
        systemctl = fixture["bin"] / "systemctl"
        self._write_command(
            systemctl,
            f'''#!/bin/sh
if [ "${{1:-}}" != "is-active" ]; then
    exit 2
fi
if [ "${{2:-}}" = "{self.active_unit}" ]; then
    printf 'active\\n'
    exit 0
fi
printf 'inactive\\n'
exit 3
''',
        )
        fixture["systemctl"] = systemctl
        return fixture

    def environment(self, fixture, *, distro="rocky", version="9.6", extra=None):
        merged = dict(self.fixture_policy)
        if extra:
            merged.update(extra)
        return super().environment(
            fixture,
            distro=distro,
            version=version,
            extra=merged,
        )

    def test_20_policy_fixture_is_required(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, output = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_POLICY_FIXTURE": "false"},
                ),
            )
            self.assertEqual(result["error"]["code"], "POLICY_INTEGRATION_REQUIRED")
            self.assertNotIn("token", output.lower())
            self.assertNotIn("password", output.lower())

    def test_21_reload_approval_is_required_for_execute(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            environment = self.environment(fixture)
            preview, _ = self.run_action("PREVIEW", environment)
            environment.update(
                {
                    "OS_GUARD_HARDEN_APPROVED": "true",
                    "OS_GUARD_HARDEN_EXPECTED_STATE": preview["preview"]["state_fingerprint"],
                    "OS_GUARD_TEST_RELOAD_APPROVED": "false",
                }
            )
            before = fixture["target"].read_bytes()
            result, _ = self.run_action("EXECUTE", environment)
            self.assertEqual(result["error"]["code"], "SERVICE_RELOAD_APPROVAL_REQUIRED")
            self.assertEqual(fixture["target"].read_bytes(), before)

    def test_22_pending_check_is_not_actionable(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            state_file = Path(temp_dir) / "check.state"
            state_file.write_text(self.pending_fixture_row(), encoding="utf-8")
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={self.fixture_result_variable: state_file.as_posix()},
                ),
            )
            self.assertEqual(result["error"]["code"], "CHECK_STATE_NOT_ACTIONABLE")

    def test_23_uncheckable_check_is_not_actionable(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            state_file = Path(temp_dir) / "check.state"
            state_file.write_text("collection_failed|x\n", encoding="utf-8")
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(
                    fixture,
                    extra={self.fixture_result_variable: state_file.as_posix()},
                ),
            )
            self.assertEqual(result["error"]["code"], "CHECK_STATE_NOT_ACTIONABLE")

    def test_24_item_syntax_failure_rolls_back(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            before = fixture["target"].read_bytes()
            _, result, _ = self.execute(
                fixture,
                extra={"OS_GUARD_TEST_FORCE_ITEM_SYNTAX_FAILURE": "true"},
            )
            self.assertTrue(result["execution"]["rollback_attempted"])
            self.assertTrue(result["execution"]["rollback_success"])
            self.assertEqual(fixture["target"].read_bytes(), before)

    def test_90_unsupported_os_is_blocked(self):
        with self.temporary_directory() as temp_dir:
            fixture = self.create_fixture(temp_dir)
            result, _ = self.run_action(
                "PREVIEW",
                self.environment(fixture, distro="debian", version="13"),
            )
            self.assertEqual(result["error"]["code"], "UNSUPPORTED_OS_CONFIGURATION")

    def pending_fixture_row(self) -> str:
        raise NotImplementedError
