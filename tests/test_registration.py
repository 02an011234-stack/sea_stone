from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from os_guard_agent.__main__ import main
from os_guard_agent.models import OperatingCredential
from os_guard_agent.registration import RegistrationFileError, load_registration_file
from os_guard_agent.registration import validate_enrollment_runtime


def registration_document() -> dict:
    return {
        "enrollment_id": "enrollment-1",
        "token": "one-time-enrollment-secret",
        "expires_at": "2099-10-13T00:00:00Z",
        "server_id": "server-1",
        "family": "UNIX",
        "schema_version": "2.0",
        "central_server_url": "https://central.example/agent-api/v2",
        "ca_sha256_fingerprint": "a" * 64,
        "enrollment_header": "X-Enrollment-Token",
        "format_status": "agent-owner-agreed",
        "contains_agent_binary": False,
    }


def write_registration_file(
    path: Path,
    document: dict | None = None,
    *,
    mode: int = 0o600,
) -> None:
    payload = registration_document() if document is None else document
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.chmod(path, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            descriptor = -1
            json.dump(payload, output, separators=(",", ":"))
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def write_config(path: Path, credential_path: Path) -> None:
    path.write_text(
        "\n".join(
            (
                "[agent]",
                'central_server_url = "https://central.example/agent-api/v2"',
                'agent_id = ""',
                f'log_path = "{(path.parent / "agent.log").as_posix()}"',
                f'token_store_path = "{credential_path.as_posix()}"',
            )
        ),
        encoding="utf-8",
    )


def test_registration_file_enrolls_without_token_argv_and_is_removed_after_success() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        registration_path = root / "registration.json"
        write_registration_file(registration_path)
        config_path = root / "agent.toml"
        write_config(config_path, root / "credentials.json")

        with (
            patch("os_guard_agent.__main__.Agent") as agent_class,
            patch("os_guard_agent.__main__.configure_logging"),
            patch("os_guard_agent.__main__.validate_enrollment_runtime"),
            patch(
                "os_guard_agent.__main__.run_preflight",
                return_value=SimpleNamespace(local_status="PENDING"),
            ),
        ):
            agent_class.return_value.enroll.return_value = OperatingCredential(
                "server-1", "agent-1", "credential-1", "operating-secret", "expiry"
            )
            result = main(
                [
                    "--config",
                    str(config_path),
                    "enroll",
                    "--registration-file",
                    str(registration_path),
                ]
            )

        assert result == 0
        assert not registration_path.exists()
        arguments = agent_class.return_value.enroll.call_args
        assert arguments.args == ("enrollment-1", "one-time-enrollment-secret")
        assert arguments.kwargs == {"expected_server_id": "server-1"}


def test_failed_enrollment_keeps_registration_file_for_explicit_recovery() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        registration_path = root / "registration.json"
        write_registration_file(registration_path)
        config_path = root / "agent.toml"
        write_config(config_path, root / "credentials.json")
        with (
            patch("os_guard_agent.__main__.Agent") as agent_class,
            patch("os_guard_agent.__main__.configure_logging"),
            patch("os_guard_agent.__main__.validate_enrollment_runtime"),
            patch(
                "os_guard_agent.__main__.run_preflight",
                return_value=SimpleNamespace(local_status="PENDING"),
            ),
        ):
            agent_class.return_value.enroll.side_effect = RuntimeError("network failed")
            with pytest.raises(RuntimeError):
                main(
                    [
                        "--config",
                        str(config_path),
                        "enroll",
                        "--registration-file",
                        str(registration_path),
                    ]
                )
        assert registration_path.exists()


def test_failed_preflight_does_not_read_or_consume_registration_file() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        registration_path = root / "registration.json"
        write_registration_file(registration_path)
        config_path = root / "agent.toml"
        write_config(config_path, root / "credentials.json")
        with (
            patch("os_guard_agent.__main__.Agent"),
            patch("os_guard_agent.__main__.configure_logging"),
            patch("os_guard_agent.__main__.validate_enrollment_runtime"),
            patch(
                "os_guard_agent.__main__.run_preflight",
                return_value=SimpleNamespace(local_status="FAILED"),
            ),
            patch("os_guard_agent.__main__.load_registration_file") as load_registration,
        ):
            result = main(
                [
                    "--config",
                    str(config_path),
                    "enroll",
                    "--registration-file",
                    str(registration_path),
                ]
            )

        assert result == 1
        load_registration.assert_not_called()
        assert registration_path.exists()


def test_registration_url_family_expiry_and_fingerprint_are_validated() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "registration.json"
        for key, value in (
            ("family", "WINDOWS"),
            ("expires_at", "2000-01-01T00:00:00Z"),
            ("ca_sha256_fingerprint", "bad"),
            ("central_server_url", "https://other.example/agent-api/v2"),
        ):
            document = registration_document()
            document[key] = value
            write_registration_file(path, document)
            with pytest.raises(RegistrationFileError):
                load_registration_file(
                    path,
                    "https://central.example/agent-api/v2",
                )


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes are required")
def test_registration_file_with_broad_permissions_is_rejected(tmp_path) -> None:
    registration_path = tmp_path / "registration.json"
    write_registration_file(registration_path, mode=0o644)

    with pytest.raises(RegistrationFileError, match="permissions are too broad"):
        load_registration_file(
            registration_path,
            "https://central.example/agent-api/v2",
        )


def test_cli_has_no_enrollment_token_argument() -> None:
    with pytest.raises(SystemExit):
        main(["enroll", "--enrollment-token", "must-not-be-supported"])


def test_root_enrollment_is_rejected_before_credential_write(monkeypatch, tmp_path) -> None:
    import os_guard_agent.registration as registration

    monkeypatch.setattr(registration, "POSIX_RUNTIME", True)
    monkeypatch.setattr(registration.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(
        registration,
        "pwd",
        SimpleNamespace(
            getpwnam=lambda _name: SimpleNamespace(pw_uid=991, pw_gid=991)
        ),
    )
    with pytest.raises(RegistrationFileError, match="must run as the osguard"):
        validate_enrollment_runtime(tmp_path / "credentials.json")
