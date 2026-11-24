from pathlib import Path

from harden_service_test_support import ROOT, ServiceHardenContractMixin
from harden_synced_policy_service_test_support import SyncedPolicyServiceHardenHarness


class TestU54Harden(ServiceHardenContractMixin):
    harden_module = ROOT / "modules" / "unix" / "harden" / "U-54.sh"
    primary_unit = "vsftpd.service"
    secondary_unit = "proftpd.service"
    legacy_relative_path = Path("etc/xinetd.d/ftp")
    legacy_content = "service ftp\n{\n disable = no\n}\n"
    fixture_policy = {
        "OS_GUARD_TEST_POLICY_FIXTURE": "true",
        "OS_GUARD_TEST_APPROVED_SERVICE_UNITS": (
            "vsftpd.service\nproftpd.service\nftp.service\nftp.socket"
        ),
        "OS_GUARD_TEST_PLAINTEXT_FTP_RETIREMENT_APPROVED": "true",
        "OS_GUARD_TEST_SERVICE_STOP_APPROVED": "true",
        "OS_GUARD_TEST_SECURE_TRANSFER_ALTERNATIVE_VERIFIED": "true",
        "OS_GUARD_TEST_FTP_CLIENT_MIGRATION_VERIFIED": "true",
        "OS_GUARD_TEST_ACTIVE_FTP_SESSIONS_CLEARED": "true",
    }

    def harness(self):
        return SyncedPolicyServiceHardenHarness(
            self.harden_module,
            self.primary_unit,
            self.secondary_unit,
            self.fixture_policy,
            "OS_GUARD_TEST_U54_FILE",
            "complete|4|1|1|0|0\n",
            "complete|4|0|0|0|0\n",
        )

    def test_operating_evidence_is_required(self):
        import tempfile

        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory)
            result = harness.run_action(
                "PREVIEW",
                harness.environment(
                    fixture,
                    extra={"OS_GUARD_TEST_FTP_CLIENT_MIGRATION_VERIFIED": "false"},
                ),
            )
            assert result["error"]["code"] == "FTP_RETIREMENT_EVIDENCE_REQUIRED"

    def test_legacy_activation_is_manual(self):
        import tempfile

        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory, active=True)
            legacy = fixture["root"] / self.legacy_relative_path
            legacy.parent.mkdir(parents=True, exist_ok=True)
            legacy.write_text(self.legacy_content, encoding="utf-8")
            before = legacy.read_bytes()
            result = harness.run_action("PREVIEW", harness.environment(fixture))
            assert result["error"]["code"] == (
                "LEGACY_ACTIVATION_REQUIRES_MANUAL_REMEDIATION"
            )
            assert legacy.read_bytes() == before
