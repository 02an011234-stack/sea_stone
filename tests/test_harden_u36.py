import tempfile
from pathlib import Path

import pytest

from harden_policy_service_test_support import PolicyServiceHardenHarness
from harden_service_test_support import ROOT


MODULE = ROOT / "modules" / "unix" / "harden" / "U-36.sh"
POLICY = {
    "OS_GUARD_TEST_POLICY_FIXTURE": "true",
    "OS_GUARD_TEST_APPROVED_SERVICE_UNITS": "rsh.socket",
    "OS_GUARD_TEST_SERVICE_STOP_APPROVED": "true",
    "OS_GUARD_TEST_MANAGEMENT_PATH_VERIFIED": "true",
    "OS_GUARD_TEST_DEPENDENCY_EVIDENCE_VERIFIED": "true",
}


def harness():
    return PolicyServiceHardenHarness(MODULE, "rsh.socket", "rlogin.socket", POLICY)


def test_active_r_service_pending_is_never_hardened():
    tool = harness()
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        fixture = tool.create_fixture(directory)
        result = tool.run_action("PREVIEW", tool.environment(fixture))
        assert result["error"]["code"] == "CHECK_STATE_NOT_ACTIONABLE"
        assert fixture["log"].read_text(encoding="utf-8") == ""


def test_fixture_policy_does_not_upgrade_pending_to_vulnerable():
    tool = harness()
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        fixture = tool.create_fixture(directory)
        result = tool.run_action(
            "EXECUTE",
            tool.environment(
                fixture,
                extra={
                    "OS_GUARD_HARDEN_APPROVED": "true",
                    "OS_GUARD_HARDEN_EXPECTED_STATE": "untrusted",
                },
            ),
        )
        assert result["error"]["code"] == "CHECK_STATE_NOT_ACTIONABLE"
        assert "|active|enabled" in fixture["state"].read_text(encoding="utf-8")


def test_inactive_r_services_are_no_change():
    tool = harness()
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        fixture = tool.create_fixture(directory, active=False)
        result = tool.run_action("PREVIEW", tool.environment(fixture))
        assert result["outcome"] == "NO_CHANGE"


def test_uncheckable_check_is_blocked():
    tool = harness()
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        fixture = tool.create_fixture(directory)
        state = Path(directory) / "check.state"
        state.write_text("collection_failed|0|0|0|0|0\n", encoding="utf-8")
        result = tool.run_action(
            "PREVIEW",
            tool.environment(
                fixture,
                extra={"OS_GUARD_TEST_RSERVICE_FILE": state.as_posix()},
            ),
        )
        assert result["error"]["code"] == "CHECK_STATE_NOT_ACTIONABLE"


@pytest.mark.parametrize(
    ("distro", "version"),
    (("rocky", "9.6"), ("rocky", "10.1"), ("ubuntu", "22.04"), ("ubuntu", "24.04")),
)
def test_supported_os_remains_safely_blocked(distro, version):
    tool = harness()
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        fixture = tool.create_fixture(directory)
        result = tool.run_action(
            "PREVIEW",
            tool.environment(fixture, distro=distro, version=version),
        )
        assert result["error"]["code"] == "CHECK_STATE_NOT_ACTIONABLE"


def test_scope_contains_only_existing_check_units():
    source = MODULE.read_text(encoding="utf-8")
    for unit in ("rsh", "rlogin", "rexec", "rsync"):
        assert unit in source
    assert "eval " not in source


def test_unsupported_os_is_blocked():
    tool = harness()
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        fixture = tool.create_fixture(directory)
        result = tool.run_action(
            "PREVIEW",
            tool.environment(fixture, distro="debian", version="13"),
        )
        assert result["error"]["code"] == "UNSUPPORTED_OS_CONFIGURATION"


def test_sensitive_fixture_values_are_not_reported():
    tool = harness()
    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        fixture = tool.create_fixture(directory)
        result = tool.run_action(
            "PREVIEW",
            tool.environment(fixture, extra={"OS_GUARD_TEST_SECRET": "TOPSECRET"}),
        )
        assert "TOPSECRET" not in str(result)
