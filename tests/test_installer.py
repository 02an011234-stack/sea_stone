from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import os_guard_agent.installer as installer_module
from os_guard_agent.ca_trust import verify_ca_fingerprint
from os_guard_agent.installer import (
    InstallError,
    UnixInstaller,
    _cryptography_version_is_supported,
    _parser,
)
from os_guard_agent.models import OperatingCredential
from os_guard_agent.token_store import TokenStore
from test_ca_trust import write_certificate


ROOT = Path(__file__).parents[1]
CURRENT_UID = getattr(os, "geteuid", lambda: 0)()


def write_registration(
    path: Path,
    *,
    url: str = "https://central.example.test/agent-api/v2",
    ca_fingerprint: str = "a" * 64,
) -> None:
    document = {
        "enrollment_id": "enrollment-fixture",
        "token": "fixture-enrollment-token-not-a-real-secret",
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "server_id": "server-fixture",
        "family": "UNIX",
        "schema_version": "2.0",
        "central_server_url": url,
        "ca_sha256_fingerprint": ca_fingerprint,
        "enrollment_header": "X-Enrollment-Token",
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    path.chmod(0o600)


def write_registration_with_ca(
    path: Path,
    *,
    url: str = "https://central.example.test/agent-api/v2",
) -> Path:
    ca_path = path.parent / "os-guard-ca.crt"
    fingerprint = write_certificate(ca_path)
    write_registration(path, url=url, ca_fingerprint=fingerprint)
    return ca_path


def prepare_root(tmp_path: Path, distro: str = "ubuntu", version: str = "24.04") -> Path:
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc/os-release").write_text(
        f'ID={distro}\nVERSION_ID="{version}"\nVERSION="fixture {version}"\n',
        encoding="utf-8",
    )
    return root


def prepare_server_bundle(tmp_path: Path) -> tuple[Path, Path, str]:
    source = tmp_path / "server-bundle"
    for directory in ("src", "modules", "config", "packaging"):
        shutil.copytree(ROOT / directory, source / directory)
    for filename in ("pyproject.toml", "install.sh"):
        shutil.copy2(ROOT / filename, source / filename)

    registration_directory = source / "registration"
    trust_directory = source / "trust"
    wheelhouse = source / "wheelhouse"
    registration_directory.mkdir()
    trust_directory.mkdir()
    wheelhouse.mkdir()
    (wheelhouse / "cryptography-41.0.7-py3-none-any.whl").write_bytes(b"fixture")
    ca_path = trust_directory / "os-guard-ca.crt"
    fingerprint = write_certificate(ca_path)
    registration_path = registration_directory / "registration.json"
    write_registration(registration_path, ca_fingerprint=fingerprint)
    return source, registration_path, fingerprint


def registration_fixture_installer(root: Path, **kwargs) -> UnixInstaller:
    return UnixInstaller(
        ROOT,
        root=root,
        test_mode=True,
        fixture_registration_owner_uids={CURRENT_UID},
        **kwargs,
    )


@pytest.mark.parametrize(
    ("distro", "version"),
    (("ubuntu", "22.04"), ("ubuntu", "24.04"), ("rocky", "9.6"), ("rocky", "10.2")),
)
def test_installer_builds_local_service_layout(tmp_path, distro, version):
    root = prepare_root(tmp_path, distro, version)
    result = UnixInstaller(ROOT, root=root, test_mode=True).install()

    assert result.outcome == "SUCCESS"
    assert result.service_enabled is True
    assert result.service_started is False
    assert result.enrollment_required is True
    assert result.preflight_status == "PENDING"
    assert "intentionally inactive pending enrollment" in result.message
    assert (root / "opt/os-guard-agent/src/os_guard_agent/__main__.py").is_file()
    assert (root / "opt/os-guard-agent/modules/manifest.json").is_file()
    assert (root / "opt/os-guard-agent/.venv/bin/python").is_file()
    assert list(
        (root / "opt/os-guard-agent/.venv/lib").glob(
            "python*/site-packages/os_guard_agent.pth"
        )
    )
    assert (root / "opt/os-guard-agent/pyproject.toml").is_file()
    assert (root / "etc/os-guard-agent/agent.toml").is_file()
    assert (root / "etc/systemd/system/os-guard-agent.service").is_file()
    assert (root / "var/lib/os-guard-agent/outbox").is_dir()
    assert (root / "var/log/os-guard-agent").is_dir()
    assert not (root / "usr/libexec/os-guard-check-helper").exists()


@pytest.mark.parametrize(
    ("version", "supported"),
    (
        ("3.4.8", False),
        ("40.0.2", False),
        ("41.0.0", True),
        ("41.0.7", True),
        ("42.0.0", True),
        ("41.0.0rc1", False),
        ("invalid", False),
    ),
)
def test_cryptography_runtime_version_floor(version, supported):
    assert _cryptography_version_is_supported(version) is supported


def test_installer_help_bootstraps_without_tomllib_or_tomli():
    bootstrap = """
import importlib.abc
import sys

class BlockTomlModules(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in {"tomli", "tomllib"}:
            raise ModuleNotFoundError(f"blocked bootstrap dependency: {fullname}")
        return None

sys.meta_path.insert(0, BlockTomlModules())
sys.path.insert(0, sys.argv[1])
from os_guard_agent.installer import main
main(["--help"])
"""
    completed = subprocess.run(
        [sys.executable, "-c", bootstrap, str(ROOT / "src")],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    assert "--wheelhouse" in completed.stdout
    assert "--registration-file" in completed.stdout


def test_runtime_uses_isolated_venv_and_offline_wheelhouse(tmp_path):
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    (wheelhouse / "cryptography-41.0.7-py3-none-any.whl").write_bytes(b"fixture")
    installer = UnixInstaller(ROOT, root=prepare_root(tmp_path), test_mode=True)

    resolved_wheelhouse = installer._resolve_wheelhouse(wheelhouse)
    venv_command = installer._virtual_environment_command()
    install_command = installer._dependency_install_command(
        "/opt/os-guard-agent/.venv/bin/python",
        resolved_wheelhouse,
    )

    assert "--system-site-packages" not in venv_command
    assert "--no-index" in install_command
    assert "--only-binary=:all:" in install_command
    assert str(resolved_wheelhouse) in install_command
    assert "/opt/os-guard-agent/runtime-requirements.txt" in install_command

    config_command = installer._configuration_validation_command(
        "/etc/os-guard-agent/agent.toml",
        "https://central.example.test/agent-api/v2/",
    )
    assert config_command[0] == "/opt/os-guard-agent/.venv/bin/python"
    assert config_command[-1] == "https://central.example.test/agent-api/v2"


def test_wheelhouse_rejects_missing_cryptography_and_symlinks(tmp_path):
    root = prepare_root(tmp_path)
    installer = UnixInstaller(ROOT, root=root, test_mode=True)
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    (wheelhouse / "tomli-2.0.1-py3-none-any.whl").write_bytes(b"fixture")
    with pytest.raises(InstallError, match="missing cryptography"):
        installer._resolve_wheelhouse(wheelhouse)

    target = tmp_path / "cryptography-41.0.7-py3-none-any.whl"
    target.write_bytes(b"fixture")
    symlink = wheelhouse / target.name
    try:
        symlink.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(InstallError, match="unsafe entry"):
        installer._resolve_wheelhouse(wheelhouse)


def test_runtime_install_failure_prevents_systemd_configuration(tmp_path, monkeypatch):
    root = prepare_root(tmp_path)
    installer = UnixInstaller(ROOT, root=root, test_mode=True)
    systemd_called = False

    def fail_runtime(_wheelhouse=None):
        raise InstallError("offline dependency installation failed")

    def record_systemd_call():
        nonlocal systemd_called
        systemd_called = True
        return True, False

    monkeypatch.setattr(installer, "_install_python_runtime", fail_runtime)
    monkeypatch.setattr(installer, "_configure_systemd", record_systemd_call)

    with pytest.raises(InstallError, match="offline dependency installation failed"):
        installer.install()
    assert systemd_called is False


def test_server_bundle_auto_discovers_registration_wheelhouse_and_ca(tmp_path):
    source, registration_path, fingerprint = prepare_server_bundle(tmp_path)
    root = prepare_root(tmp_path / "host")

    def command_runner(argv):
        if "enroll" in argv:
            TokenStore(root / "var/lib/os-guard-agent/credentials.json").save(
                OperatingCredential(
                    "server-fixture",
                    "agent-fixture",
                    "credential-fixture",
                    "operating-secret",
                    "2099-01-01T00:00:00Z",
                )
            )

    installer = UnixInstaller(
        source,
        root=root,
        test_mode=True,
        fixture_registration_owner_uids={CURRENT_UID},
        command_runner=command_runner,
    )
    result = installer.install()

    assert result.outcome == "SUCCESS"
    assert result.service_started is True
    assert registration_path.exists() is False
    installed_ca = root / "etc/os-guard-agent/os-guard-ca.crt"
    assert installed_ca.is_file()
    assert verify_ca_fingerprint(installed_ca, fingerprint) == fingerprint
    config = (root / "etc/os-guard-agent/agent.toml").read_text(encoding="utf-8")
    assert 'ca_cert_path = "/etc/os-guard-agent/os-guard-ca.crt"' in config


def test_server_bundle_ca_mismatch_fails_before_payload_install(tmp_path):
    source, _registration_path, _fingerprint = prepare_server_bundle(tmp_path)
    registration_path = source / "registration/registration.json"
    document = json.loads(registration_path.read_text(encoding="utf-8"))
    document["ca_sha256_fingerprint"] = "0" * 64
    registration_path.write_text(json.dumps(document), encoding="utf-8")
    registration_path.chmod(0o600)
    root = prepare_root(tmp_path / "host")
    installer = UnixInstaller(
        source,
        root=root,
        test_mode=True,
        fixture_registration_owner_uids={CURRENT_UID},
    )

    with pytest.raises(InstallError, match="fingerprint does not match"):
        installer.install()
    assert not (root / "opt/os-guard-agent").exists()


def test_systemd_unit_runs_as_unprivileged_account_and_is_sandboxed():
    unit = (ROOT / "packaging/systemd/os-guard-agent.service").read_text(encoding="utf-8")
    for required in (
        "User=osguard",
        "Group=osguard",
        "Restart=on-failure",
        "NoNewPrivileges=true",
        "CapabilityBoundingSet=",
        "ProtectSystem=strict",
        "ProtectHome=true",
        "ReadWritePaths=/var/lib/os-guard-agent /var/log/os-guard-agent",
        "ConditionPathExists=/var/lib/os-guard-agent/credentials.json",
    ):
        assert required in unit
    assert "User=root" not in unit


def test_reinstall_preserves_configuration_credential_and_outbox(tmp_path):
    root = prepare_root(tmp_path)
    installer = UnixInstaller(ROOT, root=root, test_mode=True)
    installer.install()
    config = root / "etc/os-guard-agent/agent.toml"
    config.write_text(config.read_text(encoding="utf-8") + "# customer-value\n", encoding="utf-8")
    credential = root / "var/lib/os-guard-agent/credentials.json"
    TokenStore(credential).save(
        OperatingCredential("server-1", "agent-1", "credential-1", "secret", "expiry")
    )
    credential_bytes = credential.read_bytes()
    outbox_entry = root / "var/lib/os-guard-agent/outbox/pending.json"
    outbox_entry.write_text("preserve-outbox-bytes", encoding="utf-8")
    pending_directory = root / "var/lib/os-guard-agent/outbox/pending"
    ack_directory = root / "var/lib/os-guard-agent/outbox/acks"
    pending_directory.mkdir()
    ack_directory.mkdir()
    pending_journal = pending_directory / "message-1.json"
    ack_journal = ack_directory / "message-0.json"
    pending_journal.write_text("pending-journal", encoding="utf-8")
    ack_journal.write_text("ack-journal", encoding="utf-8")

    result = installer.install()

    assert result.outcome == "SUCCESS"
    assert result.service_started is True
    assert "# customer-value" in config.read_text(encoding="utf-8")
    assert credential.read_bytes() == credential_bytes
    assert outbox_entry.read_text(encoding="utf-8") == "preserve-outbox-bytes"
    assert pending_journal.read_text(encoding="utf-8") == "pending-journal"
    assert ack_journal.read_text(encoding="utf-8") == "ack-journal"


def test_uninstall_preserves_state_without_explicit_purge(tmp_path):
    root = prepare_root(tmp_path)
    installer = UnixInstaller(ROOT, root=root, test_mode=True)
    installer.install()
    state_marker = root / "var/lib/os-guard-agent/keep"
    state_marker.write_text("state", encoding="utf-8")

    result = installer.uninstall()

    assert result.outcome == "SUCCESS"
    assert not (root / "opt/os-guard-agent").exists()
    assert not (root / "etc/systemd/system/os-guard-agent.service").exists()
    assert state_marker.is_file()
    assert (root / "etc/os-guard-agent/agent.toml").is_file()


def test_uninstall_purge_removes_only_product_paths(tmp_path):
    root = prepare_root(tmp_path)
    unrelated = root / "etc/unrelated.conf"
    unrelated.write_text("keep", encoding="utf-8")
    installer = UnixInstaller(ROOT, root=root, test_mode=True)
    installer.install()

    installer.uninstall(purge_state=True)

    assert unrelated.read_text(encoding="utf-8") == "keep"
    assert not (root / "etc/os-guard-agent").exists()
    assert not (root / "var/lib/os-guard-agent").exists()
    assert not (root / "var/log/os-guard-agent").exists()


def test_unsupported_os_is_rejected_before_product_install(tmp_path):
    root = prepare_root(tmp_path, "debian", "12")
    with pytest.raises(InstallError, match="unsupported operating system"):
        UnixInstaller(ROOT, root=root, test_mode=True).install()
    assert not (root / "opt/os-guard-agent").exists()


def test_invalid_release_manifest_is_rejected_before_payload_replacement(tmp_path):
    release = tmp_path / "release"
    for directory in ("src", "modules", "config", "packaging"):
        shutil.copytree(ROOT / directory, release / directory)
    shutil.copy2(ROOT / "pyproject.toml", release / "pyproject.toml")
    (release / "modules/manifest.json").write_text("{}", encoding="utf-8")
    root = prepare_root(tmp_path / "fixture")

    with pytest.raises(InstallError, match="Manifest or CHECK module inventory"):
        UnixInstaller(release, root=root, test_mode=True).install()

    assert not (root / "opt/os-guard-agent").exists()


def test_live_filesystem_cannot_use_test_mode():
    with pytest.raises(InstallError, match="test mode"):
        UnixInstaller(ROOT, root=Path("/"), test_mode=True)


def test_alternate_root_requires_explicit_test_mode(tmp_path):
    with pytest.raises(InstallError, match="alternate root"):
        UnixInstaller(ROOT, root=tmp_path)


def test_live_post_install_preflight_is_delegated_to_osguard(tmp_path):
    root = prepare_root(tmp_path)
    observed = []

    def diagnostic_runner(argv):
        observed.append(tuple(argv))
        return {"local_status": "PASS", "probes": []}

    installer = UnixInstaller(
        ROOT,
        root=root,
        test_mode=True,
        diagnostic_runner=diagnostic_runner,
    )
    installer.test_mode = False

    assert installer._run_post_install_preflight(1001, 1001) == "PASS"
    assert observed == [
        (
            "/usr/sbin/runuser",
            "--user",
            "osguard",
            "--",
            "/opt/os-guard-agent/bin/os-guard-preflight",
        )
    ]


def test_payload_stage_failure_keeps_previous_install(tmp_path, monkeypatch):
    root = prepare_root(tmp_path)
    installer = UnixInstaller(ROOT, root=root, test_mode=True)
    installer.install()
    marker = root / "opt/os-guard-agent/existing-release"
    marker.write_text("keep", encoding="utf-8")

    def fail_prepare(_destination):
        raise OSError("fixture failure")

    monkeypatch.setattr(installer, "_prepare_payload", fail_prepare)
    with pytest.raises(OSError, match="fixture failure"):
        installer.install()
    assert marker.read_text(encoding="utf-8") == "keep"


def test_post_install_preflight_failure_restores_previous_payload(tmp_path, monkeypatch):
    root = prepare_root(tmp_path)
    installer = UnixInstaller(ROOT, root=root, test_mode=True)
    installer.install()
    marker = root / "opt/os-guard-agent/existing-release"
    marker.write_text("previous", encoding="utf-8")

    def fail_preflight(_uid, _gid):
        raise InstallError("fixture Preflight failure")

    monkeypatch.setattr(installer, "_run_post_install_preflight", fail_preflight)
    with pytest.raises(InstallError, match="fixture Preflight failure"):
        installer.install()

    assert marker.read_text(encoding="utf-8") == "previous"
    assert not (root / "opt/.os-guard-agent.previous").exists()


def test_payload_recovery_failure_is_reported_separately(tmp_path, monkeypatch):
    root = prepare_root(tmp_path)
    installer = UnixInstaller(ROOT, root=root, test_mode=True)
    installer.install()

    monkeypatch.setattr(
        installer,
        "_run_post_install_preflight",
        lambda _uid, _gid: (_ for _ in ()).throw(InstallError("fixture failure")),
    )
    monkeypatch.setattr(
        installer,
        "_rollback_payload_install",
        lambda _backup, _previous: (_ for _ in ()).throw(
            InstallError("installation failed and previous payload recovery failed")
        ),
    )
    with pytest.raises(InstallError, match="previous payload recovery failed"):
        installer.install()


def test_interrupted_payload_backup_is_recovered_before_retry(tmp_path, monkeypatch):
    root = prepare_root(tmp_path)
    installer = UnixInstaller(ROOT, root=root, test_mode=True)
    installer.install()
    install_path = root / "opt/os-guard-agent"
    backup = root / "opt/.os-guard-agent.previous"
    install_path.replace(backup)
    install_path.mkdir()
    (install_path / "incomplete").write_text("new", encoding="utf-8")
    old_marker = backup / "previous-release"
    old_marker.write_text("old", encoding="utf-8")

    def fail_prepare(_destination):
        raise OSError("stop after interrupted-state recovery")

    monkeypatch.setattr(installer, "_prepare_payload", fail_prepare)
    with pytest.raises(OSError, match="interrupted-state recovery"):
        installer.install()

    assert (install_path / "previous-release").read_text(encoding="utf-8") == "old"
    assert not (install_path / "incomplete").exists()


def test_install_target_symlink_is_rejected(tmp_path):
    root = prepare_root(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    opt = root / "opt"
    try:
        opt.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(InstallError, match="symbolic links"):
        UnixInstaller(ROOT, root=root, test_mode=True).install()
    assert not (outside / "os-guard-agent").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and mode semantics required")
def test_installed_product_modes_on_posix(tmp_path):
    root = prepare_root(tmp_path)
    UnixInstaller(ROOT, root=root, test_mode=True).install()
    expected = {
        root / "etc/os-guard-agent": 0o750,
        root / "etc/os-guard-agent/agent.toml": 0o640,
        root / "var/lib/os-guard-agent": 0o700,
        root / "var/lib/os-guard-agent/outbox": 0o700,
        root / "var/log/os-guard-agent": 0o750,
        root / "etc/systemd/system/os-guard-agent.service": 0o644,
    }
    for path, mode in expected.items():
        assert stat.S_IMODE(path.stat().st_mode) == mode


def test_manifest_remains_check_only_after_install(tmp_path):
    root = prepare_root(tmp_path)
    UnixInstaller(ROOT, root=root, test_mode=True).install()
    manifest = json.loads(
        (root / "opt/os-guard-agent/modules/manifest.json").read_text(encoding="utf-8")
    )
    assert all(set(item["actions"]) == {"CHECK"} for item in manifest["items"])


def test_requested_install_command_accepts_registration_file_and_wheelhouse():
    parsed = _parser().parse_args(
        [
            "--source",
            str(ROOT),
            "--wheelhouse",
            "/tmp/wheelhouse",
            "--ca-certificate",
            "/tmp/os-guard-ca.crt",
            "--registration-file",
            "/tmp/registration.json",
        ]
    )
    assert parsed.action is None
    assert parsed.registration_file == Path("/tmp/registration.json")
    assert parsed.wheelhouse == Path("/tmp/wheelhouse")
    assert parsed.ca_certificate == Path("/tmp/os-guard-ca.crt")


def test_install_enrolls_as_osguard_then_starts_service(tmp_path):
    root = prepare_root(tmp_path)
    registration_path = tmp_path / "registration.json"
    ca_path = write_registration_with_ca(registration_path)
    observed_commands: list[tuple[str, ...]] = []

    def command_runner(argv):
        command = tuple(argv)
        observed_commands.append(command)
        if "enroll" in command:
            TokenStore(root / "var/lib/os-guard-agent/credentials.json").save(
                OperatingCredential(
                    "server-fixture",
                    "agent-fixture",
                    "credential-fixture",
                    "fixture-operating-token",
                    "2099-01-01T00:00:00Z",
                )
            )

    result = registration_fixture_installer(
        root,
        command_runner=command_runner,
    ).install(registration_file=registration_path, ca_certificate=ca_path)

    assert result.outcome == "SUCCESS"
    assert result.service_started is True
    assert result.enrollment_required is False
    assert not registration_path.exists()
    assert any(
        command[:4] == ("/usr/sbin/runuser", "--user", "osguard", "--")
        and "enroll" in command
        for command in observed_commands
    )
    config = (root / "etc/os-guard-agent/agent.toml").read_text(encoding="utf-8")
    assert 'central_server_url = "https://central.example.test/agent-api/v2"' in config
    assert "fixture-enrollment-token" not in config


@pytest.mark.parametrize("failure_kind", ("authentication", "response-loss"))
def test_enrollment_failure_retains_registration_and_does_not_start_service(
    tmp_path,
    failure_kind,
):
    root = prepare_root(tmp_path)
    registration_path = tmp_path / "registration.json"
    ca_path = write_registration_with_ca(registration_path)

    def command_runner(argv):
        if "enroll" in argv:
            raise InstallError(f"fixture {failure_kind}")

    result = registration_fixture_installer(
        root,
        command_runner=command_runner,
    ).install(registration_file=registration_path, ca_certificate=ca_path)

    assert result.outcome == "FAILED"
    assert result.service_enabled is True
    assert result.service_started is False
    assert result.enrollment_required is True
    assert registration_path.exists()
    assert not (root / "var/lib/os-guard-agent/credentials.json").exists()
    assert not list((root / "var/lib/os-guard-agent").glob(".registration.*.json"))
    assert "fixture-enrollment-token" not in result.message


def test_credential_storage_failure_is_reported_without_consuming_registration(
    tmp_path,
):
    root = prepare_root(tmp_path)
    registration_path = tmp_path / "registration.json"
    ca_path = write_registration_with_ca(registration_path)

    result = registration_fixture_installer(
        root,
        command_runner=lambda _argv: None,
    ).install(registration_file=registration_path, ca_certificate=ca_path)

    assert result.outcome == "FAILED"
    assert result.service_started is False
    assert registration_path.exists()
    assert "valid operating credential" in result.message


def test_service_activation_failure_preserves_credential_after_registration_consumption(
    tmp_path,
    monkeypatch,
):
    root = prepare_root(tmp_path)
    registration_path = tmp_path / "registration.json"
    ca_path = write_registration_with_ca(registration_path)

    def command_runner(argv):
        if "enroll" in argv:
            TokenStore(root / "var/lib/os-guard-agent/credentials.json").save(
                OperatingCredential(
                    "server-fixture",
                    "agent-fixture",
                    "credential-fixture",
                    "fixture-operating-token",
                    "2099-01-01T00:00:00Z",
                )
            )

    installer = registration_fixture_installer(
        root,
        command_runner=command_runner,
    )
    monkeypatch.setattr(
        installer,
        "_start_service",
        lambda: (_ for _ in ()).throw(InstallError("fixture service failure")),
    )
    result = installer.install(
        registration_file=registration_path,
        ca_certificate=ca_path,
    )

    assert result.outcome == "FAILED"
    assert result.service_started is False
    assert result.enrollment_required is False
    assert not registration_path.exists()
    stored = TokenStore(root / "var/lib/os-guard-agent/credentials.json").load()
    assert stored.agent_id == "agent-fixture"


def test_existing_credential_prevents_duplicate_enrollment_and_preserves_input(tmp_path):
    root = prepare_root(tmp_path)
    installer = UnixInstaller(ROOT, root=root, test_mode=True)
    installer.install()
    credential_path = root / "var/lib/os-guard-agent/credentials.json"
    credential = OperatingCredential(
        "server-1", "agent-1", "credential-1", "existing-secret", "expiry"
    )
    TokenStore(credential_path).save(credential)
    original_bytes = credential_path.read_bytes()
    registration_path = tmp_path / "registration.json"
    ca_path = write_registration_with_ca(
        registration_path,
        url="https://os-guard.example.com/agent-api/v2",
    )
    observed_commands = []

    result = registration_fixture_installer(
        root,
        command_runner=lambda argv: observed_commands.append(tuple(argv)),
    ).install(registration_file=registration_path, ca_certificate=ca_path)

    assert result.outcome == "SUCCESS"
    assert result.service_started is True
    assert credential_path.read_bytes() == original_bytes
    assert registration_path.exists()
    assert not any("enroll" in command for command in observed_commands)


@pytest.mark.parametrize("contents", ("{", "[]"))
def test_invalid_registration_is_rejected_before_product_install(tmp_path, contents):
    root = prepare_root(tmp_path)
    registration_path = tmp_path / "registration.json"
    registration_path.write_text(contents, encoding="utf-8")
    registration_path.chmod(0o600)

    with pytest.raises(InstallError, match="registration file rejected"):
        registration_fixture_installer(root).install(
            registration_file=registration_path
        )

    assert not (root / "opt/os-guard-agent").exists()


def test_missing_registration_is_rejected_before_product_install(tmp_path):
    root = prepare_root(tmp_path)
    with pytest.raises(InstallError, match="registration file rejected"):
        registration_fixture_installer(root).install(
            registration_file=tmp_path / "missing.json"
        )
    assert not (root / "opt/os-guard-agent").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX file ownership is required")
def test_fixture_registration_owner_must_be_explicitly_allowed(tmp_path):
    root = prepare_root(tmp_path)
    registration_path = tmp_path / "registration.json"
    write_registration(registration_path)

    with pytest.raises(InstallError, match="owner is not permitted"):
        UnixInstaller(
            ROOT,
            root=root,
            test_mode=True,
            fixture_registration_owner_uids=set(),
        ).install(
            registration_file=registration_path
        )


def test_fixture_owner_injection_is_rejected_outside_test_mode():
    with pytest.raises(InstallError, match="only in explicit test mode"):
        UnixInstaller(ROOT, fixture_registration_owner_uids={CURRENT_UID})


@pytest.mark.skipif(os.name != "posix", reason="POSIX sudo identity is required")
def test_operational_sudo_owner_requires_matching_root_invocation(
    tmp_path,
    monkeypatch,
):
    root = prepare_root(tmp_path)
    installer = UnixInstaller(ROOT, root=root, test_mode=True)
    monkeypatch.setattr(installer_module.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1001")
    monkeypatch.setenv("SUDO_USER", "fixture-user")
    monkeypatch.setattr(
        installer_module,
        "pwd",
        SimpleNamespace(
            getpwnam=lambda _name: SimpleNamespace(pw_uid=1001),
        ),
    )

    assert installer._registration_owner_uids() == {0, 1001}


@pytest.mark.skipif(os.name != "posix", reason="POSIX sudo identity is required")
def test_operational_sudo_uid_without_matching_user_is_ignored(tmp_path, monkeypatch):
    root = prepare_root(tmp_path)
    installer = UnixInstaller(ROOT, root=root, test_mode=True)
    monkeypatch.setattr(installer_module.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1001")
    monkeypatch.delenv("SUDO_USER", raising=False)

    assert installer._registration_owner_uids() == {0}


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes are required")
def test_registration_file_with_group_access_is_rejected(tmp_path):
    root = prepare_root(tmp_path)
    registration_path = tmp_path / "registration.json"
    write_registration(registration_path)
    registration_path.chmod(0o640)

    with pytest.raises(InstallError, match="permissions are too broad"):
        registration_fixture_installer(root).install(
            registration_file=registration_path
        )


def test_registration_symlink_is_rejected(tmp_path):
    root = prepare_root(tmp_path)
    target = tmp_path / "registration-target.json"
    link = tmp_path / "registration.json"
    write_registration(target)
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(InstallError, match="symbolic links"):
        registration_fixture_installer(root).install(registration_file=link)


def test_registration_path_traversal_is_rejected(tmp_path):
    root = prepare_root(tmp_path)
    nested = tmp_path / "nested"
    nested.mkdir()
    registration_path = tmp_path / "registration.json"
    write_registration(registration_path)
    traversal_path = nested / ".." / "registration.json"

    with pytest.raises(InstallError, match="path traversal"):
        registration_fixture_installer(root).install(
            registration_file=traversal_path
        )
