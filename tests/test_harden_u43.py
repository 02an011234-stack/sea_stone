from pathlib import Path
import tempfile

from harden_service_test_support import ROOT, ServiceHardenContractMixin
from harden_synced_policy_service_test_support import SyncedPolicyServiceHardenHarness


class TestU43Harden(ServiceHardenContractMixin):
    harden_module = ROOT / "modules" / "unix" / "harden" / "U-43.sh"
    primary_unit = "ypserv.service"
    secondary_unit = "ypbind.service"
    legacy_relative_path = Path("etc/xinetd.d/ypserv")
    legacy_content = "service ypserv\n"
    fixture_policy = {
        "OS_GUARD_TEST_POLICY_FIXTURE": "true",
        "OS_GUARD_TEST_APPROVED_SERVICE_UNITS": (
            "ypserv.service\nypbind.service\nypxfrd.service\n"
            "rpc.yppasswdd.service\nrpc.ypupdated.service"
        ),
        "OS_GUARD_TEST_NIS_RETIREMENT_APPROVED": "true",
        "OS_GUARD_TEST_SERVICE_STOP_APPROVED": "true",
        "OS_GUARD_TEST_NIS_DEPENDENCIES_VERIFIED": "true",
    }

    def harness(self):
        return SyncedPolicyServiceHardenHarness(
            self.harden_module,
            self.primary_unit,
            self.secondary_unit,
            self.fixture_policy,
            "OS_GUARD_TEST_NIS_FILE",
            "complete|1|1|0|0\n",
            "complete|1|0|0|0\n",
        )

    def test_legacy_activation_is_manual(self):
        harness = self.harness()
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            fixture = harness.create_fixture(directory, active=True)
            legacy = fixture["root"] / self.legacy_relative_path
            legacy.parent.mkdir(parents=True, exist_ok=True)
            legacy.write_text(self.legacy_content, encoding="utf-8")
            result = harness.run_action("PREVIEW", harness.environment(fixture))
            assert result["error"]["code"] == (
                "LEGACY_ACTIVATION_REQUIRES_MANUAL_REMEDIATION"
            )
