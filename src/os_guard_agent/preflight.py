"""Local, pre-enrollment installation and service readiness diagnostics.

The report is deliberately not a Central READY decision and is never sent over
the Agent API by this module.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import socket
import ssl
import stat
import tempfile
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence
from urllib.parse import urlparse

from .config import ConfigError, load_config
from .os_detect import detect_os
from .outbox import OutboxError, OutboxStore
from .token_store import TokenStore, TokenStoreError

try:
    import grp
    import pwd
except ImportError:  # pragma: no cover - Windows test host
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]


@dataclass(frozen=True)
class ProbeResult:
    probe_id: str
    status: str
    detail: str
    blocking: bool
    auto_recoverable: bool
    administrator_required: bool


@dataclass(frozen=True)
class PreflightReport:
    schema_version: str
    observed_at: str
    local_status: str
    central_readiness: None
    probes: tuple[ProbeResult, ...]


@dataclass(frozen=True)
class PreflightOptions:
    root: Path = Path("/")
    config_path: Path = Path("/etc/os-guard-agent/agent.toml")
    expected_uid: int | None = None
    expected_gid: int | None = None
    execution_uid: int | None = None
    network: bool = False
    require_credential: bool = False
    enforce_ownership: bool = True
    enforce_permissions: bool = True
    minimum_free_bytes: int = 100 * 1024 * 1024


def _result(
    probe_id: str,
    status: str,
    detail: str,
    *,
    blocking: bool = False,
    auto_recoverable: bool = False,
    administrator_required: bool = False,
) -> ProbeResult:
    return ProbeResult(
        probe_id,
        status,
        detail,
        blocking,
        auto_recoverable,
        administrator_required,
    )


class LocalPreflight:
    def __init__(self, options: PreflightOptions) -> None:
        self.options = options
        self.root = options.root.resolve()
        self.live_root = self.root == Path("/").resolve()

    def _path(self, path: Path | str) -> Path:
        raw_value = str(path)
        if not raw_value.startswith(("/", "\\")):
            raise ValueError("Preflight paths must be absolute")
        return self.root / raw_value.lstrip("/\\")

    def _has_symlink_component(self, path: Path) -> bool:
        try:
            relative = path.relative_to(self.root)
        except ValueError:
            return True
        current = self.root
        for component in relative.parts:
            current = current / component
            if current.is_symlink():
                return True
        return False

    def _secure_mode(self, path: Path, maximum_mode: int) -> bool:
        if not self.options.enforce_permissions:
            return True
        return stat.S_IMODE(os.stat(path, follow_symlinks=False).st_mode) & ~maximum_mode == 0

    def _identity(self) -> tuple[int | None, int | None, ProbeResult]:
        expected_uid = self.options.expected_uid
        expected_gid = self.options.expected_gid
        if expected_uid is None or expected_gid is None:
            if not self.live_root:
                return None, None, _result(
                    "LOCAL_SERVICE_IDENTITY",
                    "PENDING",
                    "alternate-root service identity was not asserted",
                    administrator_required=True,
                )
            if pwd is None or grp is None:
                return None, None, _result(
                    "LOCAL_SERVICE_IDENTITY",
                    "FAIL",
                    "Unix account APIs are unavailable",
                    blocking=True,
                    administrator_required=True,
                )
            try:
                account = pwd.getpwnam("osguard")
                group = grp.getgrnam("osguard")
            except KeyError:
                return None, None, _result(
                    "LOCAL_SERVICE_IDENTITY",
                    "FAIL",
                    "osguard system account or group is missing",
                    blocking=True,
                    auto_recoverable=True,
                    administrator_required=True,
                )
            expected_uid, expected_gid = account.pw_uid, group.gr_gid
            if account.pw_gid != expected_gid or account.pw_shell not in {
                "/usr/sbin/nologin",
                "/sbin/nologin",
                "/bin/false",
            }:
                return expected_uid, expected_gid, _result(
                    "LOCAL_SERVICE_IDENTITY",
                    "FAIL",
                    "osguard account group or login shell violates service policy",
                    blocking=True,
                    administrator_required=True,
                )
        return expected_uid, expected_gid, _result(
            "LOCAL_SERVICE_IDENTITY",
            "PASS",
            "dedicated non-login service identity is available",
        )

    def _probe_execution_identity(self, expected_uid: int | None) -> ProbeResult:
        actual_uid = self.options.execution_uid
        if actual_uid is None:
            if not self.live_root or os.name != "posix":
                return _result(
                    "LOCAL_RUNTIME_IDENTITY",
                    "NOT_TESTED",
                    "service-account runtime permissions require a POSIX execution context",
                )
            actual_uid = os.geteuid()
        if expected_uid is None:
            return _result(
                "LOCAL_RUNTIME_IDENTITY",
                "FAIL",
                "the expected osguard UID is unavailable",
                blocking=True,
                administrator_required=True,
            )
        if actual_uid != expected_uid:
            return _result(
                "LOCAL_RUNTIME_IDENTITY",
                "FAIL",
                "Preflight is not executing with the osguard service UID",
                blocking=True,
                administrator_required=True,
            )
        return _result(
            "LOCAL_RUNTIME_IDENTITY",
            "PASS",
            "Preflight is executing with the osguard service UID",
        )

    def _probe_os(self) -> ProbeResult:
        info = detect_os(self._path("/etc/os-release"))
        machine = platform.machine().lower()
        if not info.supported:
            return _result(
                "LOCAL_OS_SUPPORT",
                "FAIL",
                info.unsupported_reason or "unsupported operating system",
                blocking=True,
                administrator_required=True,
            )
        if machine not in {"x86_64", "amd64"}:
            return _result(
                "LOCAL_OS_SUPPORT",
                "FAIL",
                "this local installer build is validated only for x86_64",
                blocking=True,
                administrator_required=True,
            )
        return _result(
            "LOCAL_OS_SUPPORT",
            "PASS",
            f"supported {info.distro} {info.version_id} on x86_64",
        )

    def _probe_runtime(self) -> ProbeResult:
        try:
            import cryptography  # noqa: F401
        except ImportError:
            return _result(
                "LOCAL_PYTHON_RUNTIME",
                "FAIL",
                "required cryptography runtime dependency is unavailable",
                blocking=True,
                administrator_required=True,
            )
        if sys.version_info < (3, 9):
            return _result(
                "LOCAL_PYTHON_RUNTIME",
                "FAIL",
                "Python 3.9 or newer is required",
                blocking=True,
                administrator_required=True,
            )
        return _result(
            "LOCAL_PYTHON_RUNTIME",
            "PASS",
            "Python and cryptography runtime dependencies are available",
        )

    def _probe_systemd(self) -> ProbeResult:
        unit = self._path("/etc/systemd/system/os-guard-agent.service")
        enabled = self._path(
            "/etc/systemd/system/multi-user.target.wants/os-guard-agent.service"
        )
        if self._has_symlink_component(unit.parent) or unit.is_symlink() or not unit.is_file() or not self._secure_mode(unit, 0o644):
            return _result(
                "LOCAL_SYSTEMD_SERVICE",
                "FAIL",
                "systemd unit is missing, unsafe, or writable beyond root policy",
                blocking=True,
                auto_recoverable=True,
                administrator_required=True,
            )
        if self.options.enforce_ownership:
            metadata = os.stat(unit, follow_symlinks=False)
            if metadata.st_uid != 0 or metadata.st_gid != 0:
                return _result(
                    "LOCAL_SYSTEMD_SERVICE",
                    "FAIL",
                    "systemd unit is not owned by root",
                    blocking=True,
                    auto_recoverable=True,
                    administrator_required=True,
                )
        if not enabled.exists():
            return _result(
                "LOCAL_SYSTEMD_SERVICE",
                "FAIL",
                "systemd unit is installed but not enabled",
                blocking=True,
                auto_recoverable=True,
                administrator_required=True,
            )
        if self.options.enforce_ownership and not enabled.is_symlink():
            return _result(
                "LOCAL_SYSTEMD_SERVICE",
                "FAIL",
                "systemd enablement link is not a symbolic link",
                blocking=True,
                auto_recoverable=True,
                administrator_required=True,
            )
        if self.options.enforce_ownership:
            try:
                if enabled.resolve(strict=True) != unit.resolve(strict=True):
                    raise OSError
            except OSError:
                return _result(
                    "LOCAL_SYSTEMD_SERVICE",
                    "FAIL",
                    "systemd enablement link does not target the installed unit",
                    blocking=True,
                    auto_recoverable=True,
                    administrator_required=True,
                )
        return _result(
            "LOCAL_SYSTEMD_SERVICE",
            "PASS",
            "systemd unit is installed and enabled",
        )

    def _probe_config(self, expected_gid: int | None):
        path = self._path(self.options.config_path)
        if self._has_symlink_component(path) or path.is_symlink() or not path.is_file() or not self._secure_mode(path, 0o640):
            return None, _result(
                "LOCAL_CONFIGURATION",
                "FAIL",
                "Agent configuration is missing, unsafe, or too broadly accessible",
                blocking=True,
                auto_recoverable=True,
                administrator_required=True,
            )
        if self.options.enforce_ownership:
            metadata = os.stat(path, follow_symlinks=False)
            if expected_gid is None or metadata.st_uid != 0 or metadata.st_gid != expected_gid:
                return None, _result(
                    "LOCAL_CONFIGURATION",
                    "FAIL",
                    "Agent configuration must be owned by root and the osguard group",
                    blocking=True,
                    auto_recoverable=True,
                    administrator_required=True,
                )
        try:
            config = load_config(path)
        except ConfigError:
            return None, _result(
                "LOCAL_CONFIGURATION",
                "FAIL",
                "Agent configuration is invalid",
                blocking=True,
                administrator_required=True,
            )
        return config, _result(
            "LOCAL_CONFIGURATION",
            "PASS",
            "Agent configuration is syntactically valid and requires HTTPS",
        )

    def _probe_integrity(self, expected_uid: int | None) -> ProbeResult:
        install_root = self._path("/opt/os-guard-agent")
        manifest_path = install_root / "modules" / "manifest.json"
        try:
            if self._has_symlink_component(install_root) or install_root.is_symlink() or manifest_path.is_symlink():
                raise ValueError
            document = json.loads(manifest_path.read_text(encoding="utf-8"))
            items = document["items"]
            expected_items = {f"U-{number:02d}" for number in range(1, 68)}
            if {item["item_id"] for item in items} != expected_items:
                raise ValueError
            digest = hashlib.sha256(manifest_path.read_bytes())
            for item in items:
                module = item.get("module")
                if not isinstance(module, str) or module.startswith("/") or ".." in Path(module).parts:
                    raise ValueError
                module_path = install_root / "modules" / module
                if module_path.is_symlink() or not module_path.is_file():
                    raise ValueError
                metadata = os.stat(module_path, follow_symlinks=False)
                if self.options.enforce_permissions and stat.S_IMODE(metadata.st_mode) & 0o022:
                    raise ValueError
                if self.options.enforce_ownership and expected_uid is not None and metadata.st_uid != 0:
                    raise ValueError
                digest.update(module_path.read_bytes())
        except (OSError, UnicodeError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            return _result(
                "LOCAL_MODULE_INTEGRITY",
                "FAIL",
                "Manifest or CHECK module inventory is incomplete or locally writable",
                blocking=True,
                auto_recoverable=True,
                administrator_required=True,
            )
        return _result(
            "LOCAL_MODULE_INTEGRITY",
            "PASS",
            f"local Manifest and 67 CHECK modules are structurally trusted ({digest.hexdigest()[:12]})",
        )

    def _probe_directory(
        self,
        probe_id: str,
        path: Path,
        maximum_mode: int,
        expected_uid: int | None,
        expected_gid: int | None,
    ) -> ProbeResult:
        try:
            if self._has_symlink_component(path) or path.is_symlink() or not path.is_dir() or not self._secure_mode(path, maximum_mode):
                raise OSError
            metadata = os.stat(path, follow_symlinks=False)
            if self.options.enforce_ownership and (
                expected_uid is None
                or expected_gid is None
                or metadata.st_uid != expected_uid
                or metadata.st_gid != expected_gid
            ):
                raise OSError
        except OSError:
            return _result(
                probe_id,
                "FAIL",
                "product directory is missing, unsafe, or owned incorrectly",
                blocking=True,
                auto_recoverable=True,
                administrator_required=True,
            )
        return _result(probe_id, "PASS", "product directory ownership and mode are valid")

    def _probe_storage(
        self,
        state_path: Path,
        outbox_path: Path,
        log_path: Path,
    ) -> ProbeResult:
        marker = f"preflight-{os.getpid()}-{os.urandom(8).hex()}"
        temporary = state_path / f".{marker}.tmp"
        committed = state_path / f".{marker}.check"
        outbox_test_path = outbox_path / f".{marker}.outbox"
        log_temporary = log_path / f".{marker}.tmp"
        log_committed = log_path / f".{marker}.check"
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(temporary, flags, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(marker)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, committed)
            if committed.read_text(encoding="utf-8") != marker:
                raise OSError
            if os.name == "posix":
                directory_fd = os.open(state_path, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            outbox = OutboxStore(outbox_test_path)
            entry = outbox.enqueue(
                "preflight",
                {"message_id": marker, "kind": "non-secret-storage-self-test"},
            )
            outbox.acknowledge(entry, {"status": "ACKNOWLEDGED"})
            if not outbox.is_acked(marker):
                raise OSError
            log_descriptor = os.open(log_temporary, flags, 0o600)
            with os.fdopen(log_descriptor, "w", encoding="utf-8") as stream:
                stream.write(marker)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(log_temporary, log_committed)
            if log_committed.read_text(encoding="utf-8") != marker:
                raise OSError
        except (OSError, OutboxError):
            return _result(
                "LOCAL_DURABLE_STORAGE",
                "FAIL",
                "atomic state write, fsync, rename, or reload self-test failed",
                blocking=True,
                administrator_required=True,
            )
        finally:
            temporary.unlink(missing_ok=True)
            committed.unlink(missing_ok=True)
            log_temporary.unlink(missing_ok=True)
            log_committed.unlink(missing_ok=True)
            if outbox_test_path.is_dir():
                shutil.rmtree(outbox_test_path, ignore_errors=True)
        return _result(
            "LOCAL_DURABLE_STORAGE",
            "PASS",
            "osguard-context state, Outbox, ACK, and log write self-tests succeeded",
        )

    def _probe_credential(
        self,
        credential_path: Path,
        expected_uid: int | None,
        expected_gid: int | None,
    ) -> ProbeResult:
        if not credential_path.exists():
            return _result(
                "LOCAL_CREDENTIAL_STORE",
                "FAIL" if self.options.require_credential else "PENDING",
                "operating credential is not present; enrollment remains required",
                blocking=self.options.require_credential,
                administrator_required=self.options.require_credential,
            )
        try:
            metadata = os.stat(credential_path, follow_symlinks=False)
            if credential_path.is_symlink() or (
                self.options.enforce_permissions
                and stat.S_IMODE(metadata.st_mode) & 0o077
            ):
                raise OSError
            if self.options.enforce_ownership and (
                expected_uid is None
                or expected_gid is None
                or metadata.st_uid != expected_uid
                or metadata.st_gid != expected_gid
            ):
                raise OSError
        except OSError:
            return _result(
                "LOCAL_CREDENTIAL_STORE",
                "FAIL",
                "operating credential ownership or permissions are unsafe",
                blocking=True,
                administrator_required=True,
            )
        try:
            TokenStore(credential_path).load()
        except TokenStoreError:
            return _result(
                "LOCAL_CREDENTIAL_STORE",
                "FAIL",
                "operating credential cannot be safely reloaded",
                blocking=True,
                administrator_required=True,
            )
        return _result(
            "LOCAL_CREDENTIAL_STORE",
            "PASS",
            "operating credential permissions and reload validation succeeded",
        )

    def _probe_service_start_condition(self, credential_path: Path) -> ProbeResult:
        if not credential_path.exists():
            return _result(
                "LOCAL_SERVICE_START_CONDITION",
                "PENDING",
                "service is intentionally inactive until Enrollment creates a credential",
            )
        return _result(
            "LOCAL_SERVICE_START_CONDITION",
            "PASS",
            "credential path exists; ownership, permissions, and content are evaluated separately",
        )

    def _probe_tls(self, url: str) -> ProbeResult:
        parsed = urlparse(url)
        try:
            context = ssl.create_default_context()
            if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
                raise ssl.SSLError
        except (OSError, ssl.SSLError):
            return _result(
                "LOCAL_CA_TRUST",
                "FAIL",
                "verified TLS context could not be created",
                blocking=True,
                administrator_required=True,
            )
        if not self.options.network:
            return _result(
                "LOCAL_CA_TRUST",
                "NOT_TESTED",
                "verified system CA context is available; Central handshake was not requested",
            )
        host = parsed.hostname
        port = parsed.port or 443
        try:
            with socket.create_connection((host, port), timeout=5) as connection:
                with context.wrap_socket(connection, server_hostname=host):
                    pass
        except (OSError, ssl.SSLError):
            return _result(
                "LOCAL_CA_TRUST",
                "FAIL",
                "Central TLS connection or hostname/CA verification failed",
                blocking=True,
                administrator_required=True,
            )
        return _result(
            "LOCAL_CA_TRUST",
            "PASS",
            "Central TLS hostname and CA verification succeeded",
        )

    def _probe_disk_and_time(self, state_path: Path) -> tuple[ProbeResult, ProbeResult]:
        try:
            free = shutil.disk_usage(state_path).free
        except OSError:
            free = 0
        disk = _result(
            "LOCAL_DISK_SPACE",
            "PASS" if free >= self.options.minimum_free_bytes else "FAIL",
            "product state filesystem has sufficient free space" if free >= self.options.minimum_free_bytes else "product state filesystem free space is below the local minimum",
            blocking=free < self.options.minimum_free_bytes,
            administrator_required=free < self.options.minimum_free_bytes,
        )
        now = datetime.now(timezone.utc)
        clock = _result(
            "LOCAL_SYSTEM_TIME",
            "WARNING",
            f"system UTC time observed at {now.isoformat()}; trusted-time evidence is not established by local Preflight",
        )
        return disk, clock

    def _probe_helper(self) -> ProbeResult:
        helper = self._path("/usr/libexec/os-guard-check-helper")
        if not helper.exists():
            return _result(
                "LOCAL_PRIVILEGED_HELPER",
                "PENDING",
                "privileged CHECK Helper is not installed and privileged CHECK remains disabled",
            )
        return _result(
            "LOCAL_PRIVILEGED_HELPER",
            "FAIL",
            "an unapproved privileged Helper is present",
            blocking=True,
            administrator_required=True,
        )

    def run(self) -> PreflightReport:
        probes: list[ProbeResult] = [self._probe_os(), self._probe_runtime()]
        expected_uid, expected_gid, identity = self._identity()
        probes.append(identity)
        probes.append(self._probe_execution_identity(expected_uid))
        probes.append(self._probe_systemd())
        config, config_probe = self._probe_config(expected_gid)
        probes.append(config_probe)
        probes.append(self._probe_integrity(expected_uid))
        state_path = self._path("/var/lib/os-guard-agent")
        outbox_path = self._path("/var/lib/os-guard-agent/outbox")
        log_path = self._path("/var/log/os-guard-agent")
        probes.extend(
            (
                self._probe_directory(
                    "LOCAL_STATE_DIRECTORY", state_path, 0o700, expected_uid, expected_gid
                ),
                self._probe_directory(
                    "LOCAL_OUTBOX_DIRECTORY", outbox_path, 0o700, expected_uid, expected_gid
                ),
                self._probe_directory(
                    "LOCAL_LOG_DIRECTORY", log_path, 0o750, expected_uid, expected_gid
                ),
            )
        )
        if not any(probe.blocking for probe in probes):
            probes.append(self._probe_storage(state_path, outbox_path, log_path))
        else:
            probes.append(
                _result(
                    "LOCAL_DURABLE_STORAGE",
                    "NOT_TESTED",
                    "storage self-test was skipped because prerequisite paths failed",
                )
            )
        credential_path = self._path(
            config.token_store_path if config else "/var/lib/os-guard-agent/credentials.json"
        )
        probes.append(self._probe_service_start_condition(credential_path))
        probes.append(self._probe_credential(credential_path, expected_uid, expected_gid))
        probes.append(
            self._probe_tls(
                config.central_server_url
                if config
                else "https://invalid.local/agent-api/v2"
            )
        )
        probes.extend(self._probe_disk_and_time(state_path))
        probes.append(self._probe_helper())
        if any(probe.blocking and probe.status == "FAIL" for probe in probes):
            status = "FAILED"
        elif any(probe.status in {"PENDING", "WARNING", "NOT_TESTED"} for probe in probes):
            status = "PENDING"
        else:
            status = "PASS"
        return PreflightReport(
            schema_version="local-preflight-1.0",
            observed_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            local_status=status,
            central_readiness=None,
            probes=tuple(probes),
        )


def run_preflight(options: PreflightOptions) -> PreflightReport:
    return LocalPreflight(options).run()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="os-guard-preflight")
    parser.add_argument("--config", type=Path, default=Path("/etc/os-guard-agent/agent.toml"))
    parser.add_argument("--root", type=Path, default=Path("/"), help=argparse.SUPPRESS)
    parser.add_argument("--network", action="store_true")
    parser.add_argument("--service", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    report = run_preflight(
        PreflightOptions(
            root=args.root,
            config_path=args.config,
            network=args.network,
            require_credential=args.service,
        )
    )
    print(json.dumps(asdict(report), separators=(",", ":")))
    return 1 if report.local_status == "FAILED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
