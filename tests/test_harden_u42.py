from pathlib import Path

from harden_policy_service_test_support import PolicyServiceHardenHarness
from harden_service_test_support import ROOT, ServiceHardenContractMixin


class TestU42Harden(ServiceHardenContractMixin):
    harden_module = ROOT / "modules" / "unix" / "harden" / "U-42.sh"
    primary_unit = "rpc.statd.service"
    secondary_unit = "rpc.rquotad.service"
    legacy_relative_path = Path("etc/xinetd.d/rpc.statd")
    legacy_content = "service rpc.statd\n{\n disable = no\n}\n"
    fixture_policy = {
        "OS_GUARD_TEST_POLICY_FIXTURE": "true",
        "OS_GUARD_TEST_APPROVED_SERVICE_UNITS": (
            "rpc.statd.service\nrpc.rquotad.service"
        ),
        "OS_GUARD_TEST_SERVICE_STOP_APPROVED": "true",
        "OS_GUARD_TEST_DEPENDENCY_EVIDENCE_VERIFIED": "true",
    }

    def harness(self):
        return PolicyServiceHardenHarness(
            self.harden_module,
            self.primary_unit,
            self.secondary_unit,
            self.fixture_policy,
        )


def test_u42_does_not_expand_scope_to_rpcbind():
    source = (ROOT / "modules" / "unix" / "harden" / "U-42.sh").read_text(
        encoding="utf-8"
    )
    assert "rpcbind" not in source


def test_u42_active_nfs_dependency_is_manual():
    test_case = TestU42Harden()
    harness = test_case.harness()
    import tempfile

    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        fixture = harness.create_fixture(directory)
        with fixture["state"].open("a", encoding="utf-8", newline="\n") as state:
            state.write("nfs-server.service|active|enabled\n")
        result = harness.run_action("PREVIEW", harness.environment(fixture))
        assert result["error"]["code"] == (
            "OPERATIONAL_DEPENDENCY_REQUIRES_MANUAL_REMEDIATION"
        )


def test_u42_policy_fixture_is_required():
    test_case = TestU42Harden()
    harness = test_case.harness()
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


def test_u42_unapproved_rpc_unit_is_blocked():
    test_case = TestU42Harden()
    harness = test_case.harness()
    import tempfile

    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        fixture = harness.create_fixture(directory)
        result = harness.run_action(
            "PREVIEW",
            harness.environment(
                fixture,
                extra={"OS_GUARD_TEST_APPROVED_SERVICE_UNITS": "rpc.rquotad.service"},
            ),
        )
        assert result["error"]["code"] == "SERVICE_SCOPE_NOT_APPROVED"


def test_u42_unverified_dependency_evidence_is_blocked():
    test_case = TestU42Harden()
    harness = test_case.harness()
    import tempfile

    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        fixture = harness.create_fixture(directory)
        result = harness.run_action(
            "PREVIEW",
            harness.environment(
                fixture,
                extra={"OS_GUARD_TEST_DEPENDENCY_EVIDENCE_VERIFIED": "false"},
            ),
        )
        assert result["error"]["code"] == "RPC_OPERATING_EVIDENCE_REQUIRED"
