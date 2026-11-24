from __future__ import annotations

import json
import os
import shutil
import stat
from pathlib import Path

import pytest

from os_guard_agent.installer import InstallError, UnixInstaller
from os_guard_agent.models import OperatingCredential
from os_guard_agent.token_store import TokenStore


ROOT = Path(__file__).parents[1]


def prepare_root(tmp_path: Path, distro: str = "ubuntu", version: str = "24.04") -> Path:
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc/os-release").write_text(
        f'ID={distro}\nVERSION_ID="{version}"\nVERSION="fixture {version}"\n',
        encoding="utf-8",
    )
    return root


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
    assert (root / "etc/os-guard-agent/agent.toml").is_file()
    assert (root / "etc/systemd/system/os-guard-agent.service").is_file()
    assert (root / "var/lib/os-guard-agent/outbox").is_dir()
    assert (root / "var/log/os-guard-agent").is_dir()
    assert not (root / "usr/libexec/os-guard-check-helper").exists()


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
