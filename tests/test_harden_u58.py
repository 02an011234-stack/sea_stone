from pathlib import Path

from harden_policy_service_test_support import PolicyServiceHardenHarness
from harden_service_test_support import ROOT, ServiceHardenContractMixin


class TestU58Harden(ServiceHardenContractMixin):
    harden_module = ROOT / "modules" / "unix" / "harden" / "U-58.sh"
    primary_unit = "snmpd.service"
    secondary_unit = "snmptrapd.service"
    legacy_relative_path = Path("etc/xinetd.d/snmpd")
    legacy_content = "service snmpd\n{\n disable = no\n}\n"
    fixture_policy = {
        "OS_GUARD_TEST_POLICY_FIXTURE": "true",
        "OS_GUARD_TEST_APPROVED_SERVICE_UNITS": (
            "snmpd.service\nsnmpd.socket\nsnmptrapd.service\nsnmptrapd.socket"
        ),
        "OS_GUARD_TEST_SNMP_RETIREMENT_APPROVED": "true",
        "OS_GUARD_TEST_SERVICE_STOP_APPROVED": "true",
        "OS_GUARD_TEST_MONITORING_IMPACT_VERIFIED": "true",
        "OS_GUARD_TEST_ALTERNATIVE_MONITORING_VERIFIED": "true",
    }

    def _prepare_harness(self, harness, fixture):
        pgrep = fixture["bin"] / "pgrep"
        harness.write_executable(pgrep, "#!/bin/sh\nexit 1\n")
        return fixture

    def harness(self):
        base = PolicyServiceHardenHarness(
            self.harden_module,
            self.primary_unit,
            self.secondary_unit,
            self.fixture_policy,
        )
        original_create_fixture = base.create_fixture

        def create_fixture(directory, **kwargs):
            fixture = original_create_fixture(directory, **kwargs)
            return self._prepare_harness(base, fixture)

        base.create_fixture = create_fixture
        return base

    def test_policy_fixture_is_required(self):
        import tempfile

        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            result = harness.run_action(
                "PREVIEW",
                harness.environment(
                    fixture, extra={"OS_GUARD_TEST_POLICY_FIXTURE": "false"}
                ),
            )
            assert result["error"]["code"] == "POLICY_INTEGRATION_REQUIRED"

    def test_monitoring_impact_evidence_is_required(self):
        import tempfile

        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            result = harness.run_action(
                "PREVIEW",
                harness.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_MONITORING_IMPACT_VERIFIED": "false"},
                ),
            )
            assert result["error"]["code"] == "SNMP_OPERATING_EVIDENCE_REQUIRED"

    def test_unapproved_snmp_unit_is_blocked(self):
        import tempfile

        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            result = harness.run_action(
                "PREVIEW",
                harness.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_APPROVED_SERVICE_UNITS": "snmptrapd.service"},
                ),
            )
            assert result["error"]["code"] == "SERVICE_SCOPE_NOT_APPROVED"


def test_u58_does_not_expose_or_edit_snmp_credentials():
    source = (ROOT / "modules" / "unix" / "harden" / "U-58.sh").read_text(
        encoding="utf-8"
    )
    for forbidden in ("community", "authpass", "privpass", "snmpd.conf"):
        assert forbidden not in source.lower()
