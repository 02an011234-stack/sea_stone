"""Root-run local installer for the OS Guard Unix Agent.

This module only prepares local product resources.  Enrollment, CA bootstrap,
installation reporting, and privileged CHECK execution remain separate gates.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Sequence

from .config import ConfigError, load_config
from .preflight import PreflightOptions, run_preflight
from .registration import (
    RegistrationFile,
    RegistrationFileError,
    dispose_registration_file,
    load_registration_file,
)
from .token_store import TokenStore, TokenStoreError

try:
    import grp
    import pwd
except ImportError:  # pragma: no cover - Windows test host
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]


SERVICE_USER = "osguard"
SERVICE_GROUP = "osguard"
UNIT_NAME = "os-guard-agent.service"
CREDENTIAL_PATH = "/var/lib/os-guard-agent/credentials.json"


class InstallError(RuntimeError):
    """Raised when local installation cannot be completed safely."""


@dataclass(frozen=True)
class InstallResult:
    action: str
    outcome: str
    service_enabled: bool
    service_started: bool
    enrollment_required: bool
    preflight_status: str
    message: str


CommandRunner = Callable[[Sequence[str]], None]


def _run_command(argv: Sequence[str]) -> None:
    try:
        subprocess.run(list(argv), check=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        raise InstallError(f"local command failed: {Path(argv[0]).name}") from None


def _run_command_json(argv: Sequence[str]) -> dict[str, object]:
    try:
        completed = subprocess.run(
            list(argv),
            check=False,
            timeout=60,
            capture_output=True,
            text=True,
        )
        payload = json.loads(completed.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        raise InstallError(
            f"local diagnostic command failed: {Path(argv[0]).name}"
        ) from None
    if not isinstance(payload, dict):
        raise InstallError("local diagnostic output is invalid")
    return payload


class UnixInstaller:
    """Install root-owned code and a non-privileged systemd service."""

    def __init__(
        self,
        source: Path,
        *,
        root: Path = Path("/"),
        test_mode: bool = False,
        fixture_registration_owner_uids: set[int] | None = None,
        command_runner: CommandRunner = _run_command,
        diagnostic_runner: Callable[[Sequence[str]], dict[str, object]] = _run_command_json,
    ) -> None:
        self.source = source.resolve()
        self.root = root.resolve()
        self.live_root = self.root == Path("/").resolve()
        self.test_mode = test_mode
        self.fixture_registration_owner_uids = (
            frozenset(fixture_registration_owner_uids)
            if fixture_registration_owner_uids is not None
            else None
        )
        self.command_runner = command_runner
        self.diagnostic_runner = diagnostic_runner
        if self.live_root and test_mode:
            raise InstallError("test mode cannot target the live filesystem")
        if not self.live_root and not test_mode:
            raise InstallError("an alternate root is allowed only in explicit test mode")
        if self.fixture_registration_owner_uids is not None and not test_mode:
            raise InstallError(
                "fixture registration owners are allowed only in explicit test mode"
            )

    def _path(self, absolute: str) -> Path:
        if not absolute.startswith("/"):
            raise InstallError("installer destination must be absolute")
        return self.root / absolute.lstrip("/")

    def _reject_symlink_components(self, path: Path) -> None:
        try:
            relative = path.relative_to(self.root)
        except ValueError:
            raise InstallError("installer path escapes the selected root") from None
        current = self.root
        for component in relative.parts:
            current = current / component
            if current.is_symlink():
                raise InstallError("product path must not contain symbolic links")

    def _validate_source(self) -> None:
        required = (
            self.source / "src" / "os_guard_agent" / "__init__.py",
            self.source / "modules" / "manifest.json",
            self.source / "config" / "agent.toml.example",
            self.source / "packaging" / "systemd" / UNIT_NAME,
            self.source / "packaging" / "unix" / "os-guard-agent",
            self.source / "packaging" / "unix" / "os-guard-preflight",
            self.source / "pyproject.toml",
        )
        if any(not path.is_file() or path.is_symlink() for path in required):
            raise InstallError("release payload is incomplete or contains unsafe links")
        for tree_name in ("src", "modules"):
            tree = self.source / tree_name
            if any(path.is_symlink() for path in tree.rglob("*")):
                raise InstallError("release payload must not contain symbolic links")
        try:
            manifest = json.loads(
                (self.source / "modules" / "manifest.json").read_text(encoding="utf-8")
            )
            items = manifest["items"]
            expected_items = {f"U-{number:02d}" for number in range(1, 68)}
            if (
                not isinstance(items, list)
                or len(items) != 67
                or {item["item_id"] for item in items} != expected_items
            ):
                raise ValueError
            for item in items:
                module = item.get("module")
                if (
                    not isinstance(module, str)
                    or module.startswith("/")
                    or ".." in Path(module).parts
                    or item.get("actions") != ["CHECK"]
                ):
                    raise ValueError
                module_path = self.source / "modules" / module
                if not module_path.is_file() or module_path.is_symlink():
                    raise ValueError
        except (OSError, UnicodeError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            raise InstallError("release Manifest or CHECK module inventory is invalid") from None

    def _require_supported_host(self) -> None:
        os_release = self._path("/etc/os-release")
        try:
            values = {}
            for line in os_release.read_text(encoding="utf-8").splitlines():
                if "=" in line and not line.lstrip().startswith("#"):
                    key, value = line.split("=", 1)
                    values[key.strip()] = value.strip().strip('"')
        except (OSError, UnicodeError):
            raise InstallError("supported OS could not be determined") from None
        distro = values.get("ID", "").lower()
        major = values.get("VERSION_ID", "").split(".", 1)[0]
        if (distro, major) not in {
            ("ubuntu", "22"),
            ("ubuntu", "24"),
            ("rocky", "9"),
            ("rocky", "10"),
        }:
            raise InstallError("unsupported operating system")
        if self.live_root and not Path("/run/systemd/system").is_dir():
            raise InstallError("systemd is required")

    def _ensure_account(self) -> tuple[int | None, int | None]:
        if self.test_mode:
            return None, None
        if pwd is None or grp is None:
            raise InstallError("Unix account APIs are unavailable")
        if os.geteuid() != 0:
            raise InstallError("installation requires root privileges")
        try:
            group = grp.getgrnam(SERVICE_GROUP)
        except KeyError:
            self.command_runner(("/usr/sbin/groupadd", "--system", SERVICE_GROUP))
            group = grp.getgrnam(SERVICE_GROUP)
        try:
            account = pwd.getpwnam(SERVICE_USER)
        except KeyError:
            self.command_runner(
                (
                    "/usr/sbin/useradd",
                    "--system",
                    "--gid",
                    SERVICE_GROUP,
                    "--home-dir",
                    "/var/lib/os-guard-agent",
                    "--shell",
                    "/usr/sbin/nologin",
                    SERVICE_USER,
                )
            )
            account = pwd.getpwnam(SERVICE_USER)
        if account.pw_gid != group.gr_gid or account.pw_shell not in {
            "/usr/sbin/nologin",
            "/sbin/nologin",
            "/bin/false",
        }:
            raise InstallError("existing osguard account does not meet service policy")
        if account.pw_uid == 0 or account.pw_dir != "/var/lib/os-guard-agent":
            raise InstallError("existing osguard account is not a dedicated system identity")
        if set(os.getgrouplist(SERVICE_USER, account.pw_gid)) != {account.pw_gid}:
            raise InstallError("osguard account must not have supplementary groups")
        return account.pw_uid, group.gr_gid

    def _require_runtime(self) -> None:
        if self.test_mode:
            return
        if not Path("/usr/sbin/runuser").is_file():
            raise InstallError("runuser is required for osguard-context diagnostics")
        self.command_runner(
            (
                "/usr/bin/python3",
                "-c",
                "import sys, cryptography; "
                "raise SystemExit(0 if sys.version_info >= (3, 9) else 1)",
            )
        )

    @staticmethod
    def _set_tree_modes(root: Path) -> None:
        root.chmod(0o755)
        for directory in (path for path in root.rglob("*") if path.is_dir()):
            directory.chmod(0o755)
        for file_path in (path for path in root.rglob("*") if path.is_file()):
            mode = 0o755 if file_path.suffix == ".sh" else 0o644
            file_path.chmod(mode)
        for wrapper in (root / "bin" / "os-guard-agent", root / "bin" / "os-guard-preflight"):
            wrapper.chmod(0o755)

    @staticmethod
    def _chown_tree(path: Path, uid: int, gid: int) -> None:
        os.chown(path, uid, gid, follow_symlinks=False)
        for child in path.rglob("*"):
            os.chown(child, uid, gid, follow_symlinks=False)

    def _prepare_payload(self, destination: Path) -> None:
        shutil.copytree(self.source / "src", destination / "src")
        shutil.copytree(self.source / "modules", destination / "modules")
        shutil.copy2(self.source / "pyproject.toml", destination / "pyproject.toml")
        (destination / "bin").mkdir()
        shutil.copy2(
            self.source / "packaging" / "unix" / "os-guard-agent",
            destination / "bin" / "os-guard-agent",
        )
        shutil.copy2(
            self.source / "packaging" / "unix" / "os-guard-preflight",
            destination / "bin" / "os-guard-preflight",
        )
        self._set_tree_modes(destination)

    def _install_python_runtime(self) -> None:
        install_path = self._path("/opt/os-guard-agent")
        virtual_environment = install_path / ".venv"
        site_packages = (
            virtual_environment
            / "lib"
            / f"python{sys.version_info.major}.{sys.version_info.minor}"
            / "site-packages"
        )
        if self.test_mode:
            python_path = virtual_environment / "bin" / "python"
            python_path.parent.mkdir(parents=True)
            python_path.write_text("fixture Python runtime\n", encoding="utf-8")
            python_path.chmod(0o755)
            site_packages.mkdir(parents=True)
            (site_packages / "os_guard_agent.pth").write_text(
                "/opt/os-guard-agent/src\n",
                encoding="utf-8",
            )
            return
        self.command_runner(
            (
                "/usr/bin/python3",
                "-m",
                "venv",
                "--system-site-packages",
                "/opt/os-guard-agent/.venv",
            )
        )
        site_packages.mkdir(parents=True, exist_ok=True)
        (site_packages / "os_guard_agent.pth").write_text(
            "/opt/os-guard-agent/src\n",
            encoding="utf-8",
        )
        self.command_runner(
            (
                "/opt/os-guard-agent/.venv/bin/python",
                "-c",
                "import os_guard_agent, cryptography",
            )
        )

    def _recover_interrupted_payload(self, install_path: Path, backup: Path) -> None:
        if not backup.exists():
            return
        if backup.is_symlink() or not backup.is_dir():
            raise InstallError("stale installer backup is unsafe")
        try:
            if install_path.exists():
                if install_path.is_symlink() or not install_path.is_dir():
                    raise InstallError("incomplete payload path is unsafe")
                shutil.rmtree(install_path)
            backup.replace(install_path)
        except InstallError:
            raise
        except OSError:
            raise InstallError("interrupted payload recovery failed") from None

    def _install_payload(self) -> tuple[Path, bool]:
        install_path = self._path("/opt/os-guard-agent")
        self._reject_symlink_components(install_path.parent)
        install_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        backup = install_path.parent / ".os-guard-agent.previous"
        self._recover_interrupted_payload(install_path, backup)
        stage = Path(tempfile.mkdtemp(prefix=".os-guard-agent.stage.", dir=install_path.parent))
        previous_exists = install_path.exists()
        try:
            self._prepare_payload(stage)
            if previous_exists:
                install_path.replace(backup)
            stage.replace(install_path)
            return backup, previous_exists
        except Exception:
            if not install_path.exists() and backup.exists():
                backup.replace(install_path)
            if stage.exists():
                shutil.rmtree(stage, ignore_errors=True)
            raise

    def _finish_payload_install(self, backup: Path) -> None:
        if backup.exists():
            shutil.rmtree(backup)

    def _rollback_payload_install(self, backup: Path, previous_exists: bool) -> None:
        install_path = self._path("/opt/os-guard-agent")
        try:
            if install_path.exists():
                if install_path.is_symlink() or not install_path.is_dir():
                    raise OSError
                shutil.rmtree(install_path)
            if previous_exists:
                if backup.is_symlink() or not backup.is_dir():
                    raise OSError
                backup.replace(install_path)
            elif backup.exists():
                raise OSError
        except OSError:
            raise InstallError("installation failed and previous payload recovery failed") from None

    @staticmethod
    def _configure_central_url(config_path: Path, central_server_url: str) -> None:
        lines = config_path.read_text(encoding="utf-8").splitlines()
        replacement = f"central_server_url = {json.dumps(central_server_url)}"
        matches = [
            index
            for index, line in enumerate(lines)
            if line.strip().startswith("central_server_url")
        ]
        if len(matches) != 1:
            raise InstallError("Agent configuration Central URL is invalid")
        lines[matches[0]] = replacement
        config_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _install_configuration(
        self,
        service_gid: int | None,
        central_server_url: str | None = None,
    ) -> None:
        config_directory = self._path("/etc/os-guard-agent")
        self._reject_symlink_components(config_directory)
        config_directory.mkdir(mode=0o750, parents=True, exist_ok=True)
        config_directory.chmod(0o750)
        config_path = config_directory / "agent.toml"
        if not config_path.exists():
            shutil.copy2(self.source / "config" / "agent.toml.example", config_path)
            if central_server_url is not None:
                self._configure_central_url(config_path, central_server_url)
        if config_path.is_symlink() or not config_path.is_file():
            raise InstallError("Agent configuration path is unsafe")
        config_path.chmod(0o640)
        if not self.test_mode and service_gid is not None:
            os.chown(config_directory, 0, service_gid)
            os.chown(config_path, 0, service_gid)
        if central_server_url is not None:
            try:
                configured_url = load_config(config_path).central_server_url
            except ConfigError:
                raise InstallError("Agent configuration cannot be validated") from None
            if configured_url != central_server_url.rstrip("/"):
                raise InstallError(
                    "registration Central URL does not match existing configuration"
                )

    def _install_state(self, service_uid: int | None, service_gid: int | None) -> None:
        for absolute, mode in (
            ("/var/lib/os-guard-agent", 0o700),
            ("/var/lib/os-guard-agent/outbox", 0o700),
            ("/var/log/os-guard-agent", 0o750),
        ):
            path = self._path(absolute)
            self._reject_symlink_components(path)
            path.mkdir(mode=mode, parents=True, exist_ok=True)
            if path.is_symlink():
                raise InstallError("product state path must not be a symbolic link")
            path.chmod(mode)
            if not self.test_mode and service_uid is not None and service_gid is not None:
                os.chown(path, service_uid, service_gid)

    def _install_unit(self) -> None:
        unit_path = self._path(f"/etc/systemd/system/{UNIT_NAME}")
        self._reject_symlink_components(unit_path.parent)
        unit_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if unit_path.is_symlink():
            raise InstallError("systemd unit path must not be a symbolic link")
        shutil.copy2(self.source / "packaging" / "systemd" / UNIT_NAME, unit_path)
        unit_path.chmod(0o644)
        if not self.test_mode:
            os.chown(unit_path, 0, 0)

    def _configure_systemd(self) -> tuple[bool, bool]:
        if self.test_mode:
            wants = self._path("/etc/systemd/system/multi-user.target.wants")
            wants.mkdir(mode=0o755, parents=True, exist_ok=True)
            link = wants / UNIT_NAME
            if not link.exists():
                link.write_text("fixture-enabled\n", encoding="utf-8")
            return True, False
        self.command_runner(("/usr/bin/systemctl", "daemon-reload"))
        self.command_runner(("/usr/bin/systemctl", "enable", UNIT_NAME))
        return True, False

    def _registration_owner_uids(self) -> set[int]:
        if self.fixture_registration_owner_uids is not None:
            return set(self.fixture_registration_owner_uids)

        owners = {0}
        if os.name != "posix" or os.geteuid() != 0:
            return owners

        sudo_uid = os.environ.get("SUDO_UID", "")
        sudo_user = os.environ.get("SUDO_USER", "")
        if sudo_uid.isdecimal() and sudo_user and pwd is not None:
            try:
                sudo_account = pwd.getpwnam(sudo_user)
            except KeyError:
                return owners
            numeric_uid = int(sudo_uid)
            if numeric_uid != 0 and sudo_account.pw_uid == numeric_uid:
                owners.add(numeric_uid)
        return owners

    def _load_install_registration(self, path: Path) -> RegistrationFile:
        try:
            return load_registration_file(
                path,
                None,
                allowed_owner_uids=self._registration_owner_uids(),
            )
        except RegistrationFileError as exc:
            raise InstallError(f"registration file rejected: {exc}") from None

    def _stage_registration(
        self,
        source_path: Path,
        service_uid: int | None,
        service_gid: int | None,
    ) -> Path:
        state_directory = self._path("/var/lib/os-guard-agent")
        self._reject_symlink_components(state_directory)
        descriptor, name = tempfile.mkstemp(
            prefix=".registration.",
            suffix=".json",
            dir=state_directory,
        )
        staged_path = Path(name)
        try:
            source_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            source_descriptor = os.open(source_path, source_flags)
            source_metadata = os.fstat(source_descriptor)
            if not stat.S_ISREG(source_metadata.st_mode):
                os.close(source_descriptor)
                raise InstallError("registration source is not a regular file")
            if os.name == "posix" and (
                source_metadata.st_uid not in self._registration_owner_uids()
                or stat.S_IMODE(source_metadata.st_mode) & 0o077
            ):
                os.close(source_descriptor)
                raise InstallError("registration source ownership or permissions changed")
            with os.fdopen(source_descriptor, "rb") as source_file, os.fdopen(
                descriptor, "wb"
            ) as output:
                shutil.copyfileobj(source_file, output)
                output.flush()
                os.fsync(output.fileno())
            staged_path.chmod(0o600)
            if not self.test_mode and service_uid is not None and service_gid is not None:
                os.chown(staged_path, service_uid, service_gid)
            return staged_path
        except Exception:
            try:
                os.close(descriptor)
            except OSError:
                pass
            staged_path.unlink(missing_ok=True)
            raise InstallError("registration file could not be staged safely") from None

    def _enroll_from_registration(
        self,
        source_path: Path,
        service_uid: int | None,
        service_gid: int | None,
    ) -> None:
        staged_path = self._stage_registration(source_path, service_uid, service_gid)
        runtime_path = (
            str(staged_path)
            if self.test_mode
            else f"/var/lib/os-guard-agent/{staged_path.name}"
        )
        try:
            self.command_runner(
                (
                    "/usr/sbin/runuser",
                    "--user",
                    SERVICE_USER,
                    "--",
                    "/opt/os-guard-agent/bin/os-guard-agent",
                    "enroll",
                    "--registration-file",
                    runtime_path,
                )
            )
            TokenStore(self._path(CREDENTIAL_PATH)).load()
        except (InstallError, TokenStoreError):
            raise InstallError(
                "Enrollment did not produce a valid operating credential; registration was retained"
            ) from None
        finally:
            staged_path.unlink(missing_ok=True)

    def _start_service(self, *, restart: bool = False) -> None:
        if not self.test_mode:
            operation = "restart" if restart else "start"
            self.command_runner(("/usr/bin/systemctl", operation, UNIT_NAME))

    def _run_post_install_preflight(
        self,
        service_uid: int | None,
        service_gid: int | None,
    ) -> str:
        if self.test_mode:
            report = run_preflight(
                PreflightOptions(
                    root=self.root,
                    config_path=Path("/etc/os-guard-agent/agent.toml"),
                    expected_uid=service_uid,
                    expected_gid=service_gid,
                    network=False,
                    require_credential=False,
                    enforce_ownership=False,
                    enforce_permissions=False,
                )
            )
            return report.local_status
        payload = self.diagnostic_runner(
            (
                "/usr/sbin/runuser",
                "--user",
                SERVICE_USER,
                "--",
                "/opt/os-guard-agent/bin/os-guard-preflight",
            )
        )
        local_status = payload.get("local_status")
        if local_status not in {"PASS", "PENDING"}:
            raise InstallError("osguard-context post-install Preflight failed")
        return str(local_status)

    def install(self, *, registration_file: Path | None = None) -> InstallResult:
        self._validate_source()
        self._require_supported_host()
        self._require_runtime()
        registration = (
            self._load_install_registration(registration_file)
            if registration_file is not None
            else None
        )
        service_uid, service_gid = self._ensure_account()
        backup, previous_exists = self._install_payload()
        try:
            self._install_python_runtime()
            self._install_configuration(
                service_gid,
                registration.central_server_url if registration is not None else None,
            )
            self._install_state(service_uid, service_gid)
            self._install_unit()
            service_enabled, service_started = self._configure_systemd()
            preflight_status = self._run_post_install_preflight(service_uid, service_gid)
            self._finish_payload_install(backup)
        except Exception as exc:
            try:
                self._rollback_payload_install(backup, previous_exists)
            except InstallError:
                raise
            if isinstance(exc, InstallError):
                raise
            raise InstallError("installation failed; previous payload was restored") from None
        credential_exists = self._path(CREDENTIAL_PATH).is_file()
        if registration_file is not None and not credential_exists:
            try:
                self._enroll_from_registration(
                    registration_file,
                    service_uid,
                    service_gid,
                )
                credential_exists = True
            except InstallError as exc:
                credential_exists = self._path(CREDENTIAL_PATH).is_file()
                return InstallResult(
                    action="INSTALL",
                    outcome="FAILED",
                    service_enabled=service_enabled,
                    service_started=False,
                    enrollment_required=not credential_exists,
                    preflight_status=preflight_status,
                    message=str(exc),
                )
            try:
                dispose_registration_file(registration_file)
            except RegistrationFileError as exc:
                return InstallResult(
                    action="INSTALL",
                    outcome="FAILED",
                    service_enabled=service_enabled,
                    service_started=False,
                    enrollment_required=False,
                    preflight_status=preflight_status,
                    message=f"credential stored but registration disposal failed: {exc}",
                )
            try:
                self._start_service()
                service_started = True
            except InstallError as exc:
                return InstallResult(
                    action="INSTALL",
                    outcome="FAILED",
                    service_enabled=service_enabled,
                    service_started=False,
                    enrollment_required=False,
                    preflight_status=preflight_status,
                    message=f"credential stored but service activation failed: {exc}",
                )
        elif credential_exists:
            try:
                self._start_service(restart=True)
                service_started = True
            except InstallError as exc:
                return InstallResult(
                    action="INSTALL",
                    outcome="FAILED",
                    service_enabled=service_enabled,
                    service_started=False,
                    enrollment_required=False,
                    preflight_status=preflight_status,
                    message=f"existing credential preserved but service restart failed: {exc}",
                )
        return InstallResult(
            action="INSTALL",
            outcome="SUCCESS",
            service_enabled=service_enabled,
            service_started=service_started,
            enrollment_required=not credential_exists,
            preflight_status=preflight_status,
            message=(
                "installed and enabled; service is intentionally inactive pending enrollment"
                if not credential_exists
                else (
                    "installed, enrolled, and service start requested"
                    if registration_file is not None and service_started
                    else "installed; existing credential preserved and service restart requested"
                )
            ),
        )

    def preflight(self, *, network: bool = False) -> InstallResult:
        if self.test_mode:
            report = run_preflight(
                PreflightOptions(
                    root=self.root,
                    config_path=Path("/etc/os-guard-agent/agent.toml"),
                    network=network,
                    require_credential=False,
                    enforce_ownership=False,
                    enforce_permissions=False,
                )
            )
            local_status = report.local_status
            probes = report.probes
        else:
            arguments = [
                "/usr/sbin/runuser",
                "--user",
                SERVICE_USER,
                "--",
                "/opt/os-guard-agent/bin/os-guard-preflight",
            ]
            if network:
                arguments.append("--network")
            payload = self.diagnostic_runner(tuple(arguments))
            local_status = str(payload.get("local_status", "FAILED"))
            probes = ()
        return InstallResult(
            action="PREFLIGHT",
            outcome="SUCCESS" if local_status != "FAILED" else "FAILED",
            service_enabled=True if not self.test_mode else any(
                probe.probe_id == "LOCAL_SYSTEMD_SERVICE" and probe.status == "PASS"
                for probe in probes
            ),
            service_started=False,
            enrollment_required=False if not self.test_mode else any(
                probe.probe_id == "LOCAL_CREDENTIAL_STORE" and probe.status == "PENDING"
                for probe in probes
            ),
            preflight_status=local_status,
            message="local Preflight completed; no Central readiness decision was produced",
        )

    def uninstall(self, *, purge_state: bool = False) -> InstallResult:
        if self.live_root and os.geteuid() != 0:
            raise InstallError("uninstallation requires root privileges")
        if not self.test_mode:
            self.command_runner(("/usr/bin/systemctl", "disable", "--now", UNIT_NAME))
        for absolute in (
            "/etc/systemd/system/multi-user.target.wants/os-guard-agent.service",
            "/etc/systemd/system/os-guard-agent.service",
            "/opt/os-guard-agent",
        ):
            path = self._path(absolute)
            self._reject_symlink_components(path.parent)
            if path.is_symlink() or path.is_file():
                path.unlink(missing_ok=True)
            elif path.is_dir():
                shutil.rmtree(path)
        if purge_state:
            for absolute in (
                "/etc/os-guard-agent",
                "/var/lib/os-guard-agent",
                "/var/log/os-guard-agent",
            ):
                path = self._path(absolute)
                self._reject_symlink_components(path.parent)
                if path.is_symlink():
                    raise InstallError("refusing to purge a symbolic link")
                if path.is_dir():
                    shutil.rmtree(path)
        if not self.test_mode:
            self.command_runner(("/usr/bin/systemctl", "daemon-reload"))
        return InstallResult(
            action="UNINSTALL",
            outcome="SUCCESS",
            service_enabled=False,
            service_started=False,
            enrollment_required=False,
            preflight_status="NOT_RUN",
            message=(
                "product code and service removed; configuration and state preserved"
                if not purge_state
                else "product code, service, configuration, and state removed"
            ),
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="os-guard-install")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path("/"), help=argparse.SUPPRESS)
    parser.add_argument("--test-mode", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--registration-file",
        type=Path,
        help="protected Central registration JSON used for one-time Enrollment",
    )
    subparsers = parser.add_subparsers(dest="action", required=False)
    subparsers.add_parser("install")
    preflight = subparsers.add_parser("preflight")
    preflight.add_argument("--network", action="store_true")
    uninstall = subparsers.add_parser("uninstall")
    uninstall.add_argument("--purge-state", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    action = args.action or "install"
    try:
        installer = UnixInstaller(
            args.source,
            root=args.root,
            test_mode=args.test_mode,
        )
        if action == "install":
            result = installer.install(registration_file=args.registration_file)
        elif action == "preflight":
            result = installer.preflight(network=args.network)
        else:
            result = installer.uninstall(purge_state=args.purge_state)
    except InstallError as exc:
        result = InstallResult(
            action=action.upper(),
            outcome="FAILED",
            service_enabled=False,
            service_started=False,
            enrollment_required=False,
            preflight_status="FAILED",
            message=str(exc),
        )
        print(json.dumps(asdict(result), separators=(",", ":")))
        return 1
    print(json.dumps(asdict(result), separators=(",", ":")))
    return 0 if result.outcome == "SUCCESS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
