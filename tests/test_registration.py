from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from os_guard_agent.__main__ import main
from os_guard_agent.models import OperatingCredential
from os_guard_agent.registration import RegistrationFileError, load_registration_file


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
        registration_path.write_text(json.dumps(registration_document()), encoding="utf-8")
        config_path = root / "agent.toml"
        write_config(config_path, root / "credentials.json")

        with (
            patch("os_guard_agent.__main__.Agent") as agent_class,
            patch("os_guard_agent.__main__.configure_logging"),
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
        registration_path.write_text(json.dumps(registration_document()), encoding="utf-8")
        config_path = root / "agent.toml"
        write_config(config_path, root / "credentials.json")
        with (
            patch("os_guard_agent.__main__.Agent") as agent_class,
            patch("os_guard_agent.__main__.configure_logging"),
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
            path.write_text(json.dumps(document), encoding="utf-8")
            with pytest.raises(RegistrationFileError):
                load_registration_file(
                    path,
                    "https://central.example/agent-api/v2",
                )


def test_cli_has_no_enrollment_token_argument() -> None:
    with pytest.raises(SystemExit):
        main(["enroll", "--enrollment-token", "must-not-be-supported"])
