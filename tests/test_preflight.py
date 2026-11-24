from __future__ import annotations

import json
import ssl
from pathlib import Path

from os_guard_agent.installer import UnixInstaller
from os_guard_agent.models import OperatingCredential
from os_guard_agent.preflight import LocalPreflight, PreflightOptions, run_preflight
from os_guard_agent.token_store import TokenStore


ROOT = Path(__file__).parents[1]


def installed_fixture(tmp_path, distro="ubuntu", version="24.04"):
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc/os-release").write_text(
        f'ID={distro}\nVERSION_ID="{version}"\nVERSION="fixture {version}"\n',
        encoding="utf-8",
    )
    UnixInstaller(ROOT, root=root, test_mode=True).install()
    return root


def options(root, **changes):
    values = {
        "root": root,
        "config_path": Path("/etc/os-guard-agent/agent.toml"),
        "network": False,
        "enforce_ownership": False,
        "enforce_permissions": False,
    }
    values.update(changes)
    return PreflightOptions(**values)


def probe(report, probe_id):
    return next(item for item in report.probes if item.probe_id == probe_id)


def test_preflight_collects_local_results_without_central_ready(tmp_path):
    root = installed_fixture(tmp_path)
    report = run_preflight(options(root))

    assert report.schema_version == "local-preflight-1.0"
    assert report.local_status == "PENDING"
    assert report.central_readiness is None
    assert probe(report, "LOCAL_OS_SUPPORT").status == "PASS"
    assert probe(report, "LOCAL_MODULE_INTEGRITY").status == "PASS"
    assert probe(report, "LOCAL_DURABLE_STORAGE").status == "PASS"
    assert probe(report, "LOCAL_CREDENTIAL_STORE").status == "PENDING"
    assert probe(report, "LOCAL_SERVICE_START_CONDITION").status == "PENDING"
    assert "intentionally inactive" in probe(
        report, "LOCAL_SERVICE_START_CONDITION"
    ).detail
    assert probe(report, "LOCAL_CA_TRUST").status == "NOT_TESTED"
    assert probe(report, "LOCAL_PRIVILEGED_HELPER").status == "PENDING"


def test_service_preflight_requires_a_reloadable_credential(tmp_path):
    root = installed_fixture(tmp_path)
    report = run_preflight(options(root, require_credential=True))
    assert report.local_status == "FAILED"
    assert probe(report, "LOCAL_CREDENTIAL_STORE").blocking is True


def test_valid_credential_is_reloaded_without_exposing_secret(tmp_path):
    root = installed_fixture(tmp_path)
    credential_path = root / "var/lib/os-guard-agent/credentials.json"
    secret = "operating-secret-must-not-appear"
    TokenStore(credential_path).save(
        OperatingCredential("server-1", "agent-1", "credential-1", secret, "expiry")
    )
    report = run_preflight(options(root, require_credential=True))
    serialized = json.dumps(report, default=lambda value: value.__dict__)
    assert probe(report, "LOCAL_CREDENTIAL_STORE").status == "PASS"
    assert probe(report, "LOCAL_SERVICE_START_CONDITION").status == "PASS"
    assert secret not in serialized


def test_corrupt_credential_fails_closed(tmp_path):
    root = installed_fixture(tmp_path)
    (root / "var/lib/os-guard-agent/credentials.json").write_text(
        "not-json", encoding="utf-8"
    )
    report = run_preflight(options(root, require_credential=True))
    assert report.local_status == "FAILED"
    assert probe(report, "LOCAL_CREDENTIAL_STORE").status == "FAIL"


def test_manifest_corruption_is_blocking(tmp_path):
    root = installed_fixture(tmp_path)
    (root / "opt/os-guard-agent/modules/manifest.json").write_text(
        "{}", encoding="utf-8"
    )
    report = run_preflight(options(root))
    assert report.local_status == "FAILED"
    assert probe(report, "LOCAL_MODULE_INTEGRITY").blocking is True


def test_missing_systemd_unit_is_auto_recoverable_failure(tmp_path):
    root = installed_fixture(tmp_path)
    (root / "etc/systemd/system/os-guard-agent.service").unlink()
    report = run_preflight(options(root))
    result = probe(report, "LOCAL_SYSTEMD_SERVICE")
    assert result.status == "FAIL"
    assert result.auto_recoverable is True


def test_unapproved_helper_presence_is_blocking(tmp_path):
    root = installed_fixture(tmp_path)
    helper = root / "usr/libexec/os-guard-check-helper"
    helper.parent.mkdir(parents=True)
    helper.write_text("unapproved", encoding="utf-8")
    report = run_preflight(options(root))
    assert probe(report, "LOCAL_PRIVILEGED_HELPER").status == "FAIL"


def test_storage_self_test_removes_temporary_marker(tmp_path):
    root = installed_fixture(tmp_path)
    state = root / "var/lib/os-guard-agent"
    before = {path.name for path in state.iterdir()}
    report = run_preflight(options(root))
    after = {path.name for path in state.iterdir()}
    assert probe(report, "LOCAL_DURABLE_STORAGE").status == "PASS"
    assert after == before
    assert not any((root / "var/log/os-guard-agent").iterdir())
    assert not any((root / "var/lib/os-guard-agent/outbox").iterdir())


def test_root_execution_is_not_accepted_as_osguard_runtime_validation(tmp_path):
    root = installed_fixture(tmp_path)
    result = LocalPreflight(
        options(root, expected_uid=1001, expected_gid=1001, execution_uid=0)
    )._probe_execution_identity(1001)
    assert result.status == "FAIL"
    assert result.blocking is True
    assert "not executing with the osguard" in result.detail


def test_service_identity_runtime_validation_passes_for_expected_uid(tmp_path):
    root = installed_fixture(tmp_path)
    result = LocalPreflight(
        options(root, expected_uid=1001, expected_gid=1001, execution_uid=1001)
    )._probe_execution_identity(1001)
    assert result.status == "PASS"


def test_osguard_storage_write_failure_is_blocking(tmp_path, monkeypatch):
    root = installed_fixture(tmp_path)
    state = root / "var/lib/os-guard-agent"
    outbox = state / "outbox"
    log = root / "var/log/os-guard-agent"
    original_open = __import__("os").open

    def deny_state_write(path, flags, mode=0o777):
        if str(path).startswith(str(state)) and flags & __import__("os").O_WRONLY:
            raise PermissionError("fixture permission denied")
        return original_open(path, flags, mode)

    monkeypatch.setattr("os_guard_agent.preflight.os.open", deny_state_write)
    result = LocalPreflight(options(root))._probe_storage(state, outbox, log)
    assert result.status == "FAIL"
    assert result.blocking is True


def test_root_owned_credential_is_rejected_for_osguard(tmp_path, monkeypatch):
    root = installed_fixture(tmp_path)
    credential_path = root / "var/lib/os-guard-agent/credentials.json"
    TokenStore(credential_path).save(
        OperatingCredential("server-1", "agent-1", "credential-1", "secret", "expiry")
    )
    actual_stat = credential_path.stat()

    class RootOwnedMetadata:
        st_mode = actual_stat.st_mode
        st_uid = 0
        st_gid = 0

    monkeypatch.setattr(
        "os_guard_agent.preflight.os.stat",
        lambda path, follow_symlinks=False: RootOwnedMetadata(),
    )
    result = LocalPreflight(options(root, enforce_ownership=True))._probe_credential(
        credential_path,
        expected_uid=1001,
        expected_gid=1001,
    )
    assert result.status == "FAIL"
    assert result.administrator_required is True


def test_invalid_configuration_is_blocking(tmp_path):
    root = installed_fixture(tmp_path)
    (root / "etc/os-guard-agent/agent.toml").write_text(
        '[agent]\ncentral_server_url="http://insecure.example"\n', encoding="utf-8"
    )
    report = run_preflight(options(root))
    assert probe(report, "LOCAL_CONFIGURATION").status == "FAIL"
    assert report.local_status == "FAILED"


def test_tls_verification_cannot_be_disabled(tmp_path, monkeypatch):
    root = installed_fixture(tmp_path)

    class UnsafeContext:
        verify_mode = ssl.CERT_NONE
        check_hostname = False

    monkeypatch.setattr(ssl, "create_default_context", lambda: UnsafeContext())
    report = run_preflight(options(root))
    assert probe(report, "LOCAL_CA_TRUST").status == "FAIL"


def test_supported_rocky_versions_are_distinct_fixtures(tmp_path):
    for number, version in enumerate(("9.6", "10.2")):
        root = installed_fixture(tmp_path / str(number), "rocky", version)
        report = run_preflight(options(root))
        assert probe(report, "LOCAL_OS_SUPPORT").status == "PASS"


def test_clock_is_observed_but_not_promoted_to_trusted_time(tmp_path):
    root = installed_fixture(tmp_path)
    report = run_preflight(options(root))
    result = probe(report, "LOCAL_SYSTEM_TIME")
    assert result.status == "WARNING"
    assert "trusted-time evidence is not established" in result.detail
