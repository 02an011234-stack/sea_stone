from pathlib import Path

from harden_policy_service_test_support import PolicyServiceHardenHarness
from harden_service_test_support import ROOT, ServiceHardenContractMixin


class TestU52Harden(ServiceHardenContractMixin):
    harden_module = ROOT / "modules" / "unix" / "harden" / "U-52.sh"
    primary_unit = "telnet.socket"
    secondary_unit = "telnet.service"
    legacy_relative_path = Path("etc/xinetd.d/telnet")
    legacy_content = "service telnet\n{\n disable = no\n}\n"
    fixture_policy = {
        "OS_GUARD_TEST_POLICY_FIXTURE": "true",
        "OS_GUARD_TEST_APPROVED_SERVICE_UNITS": "telnet.socket\ntelnet.service",
        "OS_GUARD_TEST_TELNET_DISABLE_APPROVED": "true",
        "OS_GUARD_TEST_SERVICE_STOP_APPROVED": "true",
        "OS_GUARD_TEST_ALTERNATIVE_MANAGEMENT_METHOD": "ssh-verified",
        "OS_GUARD_TEST_ACTIVE_TELNET_SESSIONS_CLEARED": "true",
    }

    def harness(self):
        return PolicyServiceHardenHarness(
            self.harden_module,
            self.primary_unit,
            self.secondary_unit,
            self.fixture_policy,
        )

    def test_policy_fixture_is_required(self):
        harness = self.harness()
        import tempfile

        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            result = harness.run_action(
                "PREVIEW",
                harness.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_POLICY_FIXTURE": "false"},
                ),
            )
            assert result["error"]["code"] == "POLICY_INTEGRATION_REQUIRED"

    def test_unverified_alternative_access_is_blocked(self):
        harness = self.harness()
        import tempfile

        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            result = harness.run_action(
                "PREVIEW",
                harness.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_ALTERNATIVE_MANAGEMENT_METHOD": "ssh-running-only"},
                ),
            )
            assert result["error"]["code"] == "ALTERNATIVE_MANAGEMENT_EVIDENCE_REQUIRED"

    def test_unreviewed_active_sessions_are_blocked(self):
        harness = self.harness()
        import tempfile

        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            result = harness.run_action(
                "PREVIEW",
                harness.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_ACTIVE_TELNET_SESSIONS_CLEARED": "false"},
                ),
            )
            assert result["error"]["code"] == "ACTIVE_SESSION_EVIDENCE_REQUIRED"

    def test_unapproved_active_unit_is_blocked(self):
        harness = self.harness()
        import tempfile

        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            result = harness.run_action(
                "PREVIEW",
                harness.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_APPROVED_SERVICE_UNITS": "telnet.service"},
                ),
            )
            assert result["error"]["code"] == "SERVICE_SCOPE_NOT_APPROVED"

    def test_pending_check_is_blocked(self):
        harness = self.harness()
        import tempfile

        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            state_file = Path(directory) / "check.state"
            state_file.write_text("complete|2|0|1|1\n", encoding="utf-8")
            result = harness.run_action(
                "PREVIEW",
                harness.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_U52_FILE": state_file.as_posix()},
                ),
            )
            assert result["error"]["code"] == "CHECK_STATE_NOT_ACTIONABLE"

    def test_uncheckable_check_is_blocked(self):
        harness = self.harness()
        import tempfile

        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            state_file = Path(directory) / "check.state"
            state_file.write_text("collection_failed|0|0|0|0\n", encoding="utf-8")
            result = harness.run_action(
                "PREVIEW",
                harness.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_U52_FILE": state_file.as_posix()},
                ),
            )
            assert result["error"]["code"] == "CHECK_STATE_NOT_ACTIONABLE"

    def test_unsupported_os_is_blocked(self):
        harness = self.harness()
        import tempfile

        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            result = harness.run_action(
                "PREVIEW",
                harness.environment(fixture, distro="debian", version="13"),
            )
            assert result["error"]["code"] == "UNSUPPORTED_OS_CONFIGURATION"

    def test_sensitive_fixture_values_are_not_reported(self):
        harness = self.harness()
        import tempfile

        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            result = harness.run_action(
                "PREVIEW",
                harness.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_SECRET": "TOPSECRET"},
                ),
            )
            assert "TOPSECRET" not in str(result)
