from pathlib import Path

from harden_service_test_support import ROOT, ServiceHardenContractMixin
from harden_synced_policy_service_test_support import (
    SyncedPolicyServiceHardenHarness,
)


class TestU39Harden(ServiceHardenContractMixin):
    harden_module = ROOT / "modules" / "unix" / "harden" / "U-39.sh"
    primary_unit = "nfs-server.service"
    secondary_unit = "nfs-mountd.service"
    legacy_relative_path = Path("etc/xinetd.d/nfs")
    legacy_content = "# no legacy activation\n"
    fixture_policy = {
        "OS_GUARD_TEST_POLICY_FIXTURE": "true",
        "OS_GUARD_TEST_APPROVED_SERVICE_UNITS": (
            "nfs-server.service\nnfs.service\nnfs-mountd.service"
        ),
        "OS_GUARD_TEST_NFS_RETIREMENT_APPROVED": "true",
        "OS_GUARD_TEST_SERVICE_STOP_APPROVED": "true",
        "OS_GUARD_TEST_EXPORTS_EMPTY_VERIFIED": "true",
        "OS_GUARD_TEST_ACTIVE_NFS_CLIENTS_CLEARED": "true",
        "OS_GUARD_TEST_NFS_DEPENDENCIES_VERIFIED": "true",
    }

    def harness(self):
        return SyncedPolicyServiceHardenHarness(
            self.harden_module,
            self.primary_unit,
            self.secondary_unit,
            self.fixture_policy,
            "OS_GUARD_TEST_NFS_FILE",
            "complete|1|1|0|1|0\n",
            "complete|1|0|1|0|0\n",
        )

    def test_legacy_activation_is_manual(self):
        # U-39 CHECK and remediation are bounded to systemd NFS server units.
        # A synthetic unrelated xinetd file is not an NFS activation source.
        import tempfile

        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory, active=False)
            result = harness.run_action("PREVIEW", harness.environment(fixture))
            assert result["outcome"] == "NO_CHANGE"

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

    def test_active_client_dependency_blocks_preview(self):
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

    def test_exports_and_client_evidence_are_required(self):
        import tempfile

        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            result = harness.run_action(
                "PREVIEW",
                harness.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_EXPORTS_EMPTY_VERIFIED": "false"},
                ),
            )
            assert result["error"]["code"] == "NFS_OPERATING_EVIDENCE_REQUIRED"


def test_u39_does_not_modify_exports_or_unmount_filesystems():
    source = (ROOT / "modules" / "unix" / "harden" / "U-39.sh").read_text(
        encoding="utf-8"
    )
    for forbidden in ("/etc/exports", "umount", "rpcbind"):
        assert forbidden not in source
