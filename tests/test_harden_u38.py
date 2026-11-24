from pathlib import Path

from harden_service_test_support import ROOT, ServiceHardenContractMixin
from harden_synced_policy_service_test_support import (
    SyncedPolicyServiceHardenHarness,
)


class TestU38Harden(ServiceHardenContractMixin):
    harden_module = ROOT / "modules" / "unix" / "harden" / "U-38.sh"
    primary_unit = "echo.socket"
    secondary_unit = "chargen.socket"
    legacy_relative_path = Path("etc/xinetd.d/echo")
    legacy_content = "service echo\n{\n disable = no\n}\n"
    fixture_policy = {
        "OS_GUARD_TEST_POLICY_FIXTURE": "true",
        "OS_GUARD_TEST_APPROVED_SERVICE_UNITS": (
            "echo.service\necho.socket\ndiscard.service\ndiscard.socket\n"
            "daytime.service\ndaytime.socket\nchargen.service\nchargen.socket"
        ),
        "OS_GUARD_TEST_LEGACY_DOS_SERVICE_RETIREMENT_APPROVED": "true",
        "OS_GUARD_TEST_SERVICE_STOP_APPROVED": "true",
        "OS_GUARD_TEST_DEPENDENCY_EVIDENCE_VERIFIED": "true",
    }

    def harness(self):
        return SyncedPolicyServiceHardenHarness(
            self.harden_module,
            self.primary_unit,
            self.secondary_unit,
            self.fixture_policy,
            "OS_GUARD_TEST_DOS_SERVICE_FILE",
            "complete|10|1|9|0|1|1\n",
            "complete|10|0|10|0|0|0\n",
        )

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

    def test_legacy_activation_is_manual(self):
        import tempfile

        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            legacy = fixture["root"] / self.legacy_relative_path
            legacy.write_text(self.legacy_content, encoding="utf-8", newline="\n")
            before = legacy.read_bytes()
            result = harness.run_action("PREVIEW", harness.environment(fixture))
            assert result["error"]["code"] == (
                "LEGACY_ACTIVATION_REQUIRES_MANUAL_REMEDIATION"
            )
            assert legacy.read_bytes() == before

    def test_infrastructure_service_guard_blocks_preview(self):
        import tempfile

        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            with fixture["state"].open("a", encoding="utf-8", newline="\n") as state:
                state.write("chronyd.service|active|enabled\n")
            result = harness.run_action("PREVIEW", harness.environment(fixture))
            assert result["error"]["code"] == (
                "OPERATIONAL_DEPENDENCY_REQUIRES_MANUAL_REMEDIATION"
            )


def test_u38_scope_excludes_dns_ntp_and_snmp_from_change_targets():
    source = (ROOT / "modules" / "unix" / "harden" / "U-38.sh").read_text(
        encoding="utf-8"
    )
    targets = source.split("HARDEN_SYSTEMD_UNITS=", 1)[1].split(
        "HARDEN_LEGACY_FILES=", 1
    )[0]
    for protected in ("named", "bind9", "ntpd", "chronyd", "snmpd"):
        assert protected not in targets
