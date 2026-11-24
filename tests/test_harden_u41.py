from pathlib import Path

from harden_policy_service_test_support import PolicyServiceHardenHarness
from harden_service_test_support import ROOT, ServiceHardenContractMixin


class TestU41Harden(ServiceHardenContractMixin):
    harden_module = ROOT / "modules" / "unix" / "harden" / "U-41.sh"
    primary_unit = "autofs.service"
    secondary_unit = "automount.service"
    legacy_relative_path = Path("etc/xinetd.d/autofs")
    legacy_content = "# no legacy activation\n"
    fixture_policy = {
        "OS_GUARD_TEST_POLICY_FIXTURE": "true",
        "OS_GUARD_TEST_APPROVED_SERVICE_UNITS": "autofs.service\nautomount.service",
        "OS_GUARD_TEST_AUTOFS_RETIREMENT_APPROVED": "true",
        "OS_GUARD_TEST_SERVICE_STOP_APPROVED": "true",
        "OS_GUARD_TEST_AUTOMOUNT_DEPENDENCIES_VERIFIED": "true",
        "OS_GUARD_TEST_ACTIVE_AUTOMOUNTS_CLEARED": "true",
    }

    def harness(self):
        return PolicyServiceHardenHarness(
            self.harden_module,
            self.primary_unit,
            self.secondary_unit,
            self.fixture_policy,
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
        # U-41 is bounded to systemd/process state; no legacy inetd activation
        # path is part of the existing CHECK contract.
        import tempfile

        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory, active=False)
            result = harness.run_action("PREVIEW", harness.environment(fixture))
            assert result["outcome"] == "NO_CHANGE"

    def test_active_automount_dependency_blocks_preview(self):
        import tempfile

        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            with fixture["state"].open("a", encoding="utf-8", newline="\n") as state:
                state.write("nfs-client.target|active|enabled\n")
            result = harness.run_action("PREVIEW", harness.environment(fixture))
            assert result["error"]["code"] == (
                "OPERATIONAL_DEPENDENCY_REQUIRES_MANUAL_REMEDIATION"
            )

    def test_unverified_mount_impact_blocks_preview(self):
        import tempfile

        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            result = harness.run_action(
                "PREVIEW",
                harness.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_ACTIVE_AUTOMOUNTS_CLEARED": "false"},
                ),
            )
            assert result["error"]["code"] == "AUTOFS_OPERATING_EVIDENCE_REQUIRED"


def test_u41_does_not_delete_maps_or_packages():
    source = (ROOT / "modules" / "unix" / "harden" / "U-41.sh").read_text(
        encoding="utf-8"
    )
    for forbidden in ("auto.master", "apt ", "dnf ", "yum ", "rm "):
        assert forbidden not in source
