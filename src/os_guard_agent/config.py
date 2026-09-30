"""Agent configuration loading and validation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - used on Python 3.9/3.10
    import tomli as tomllib  # type: ignore[no-redef]


class ConfigError(ValueError):
    """Raised when the Agent configuration is missing or invalid."""


@dataclass(frozen=True)
class AgentConfig:
    central_server_url: str
    agent_id: str | None
    log_path: Path
    log_level: str = "INFO"
    token_store_path: Path = Path("/var/lib/os-guard-agent/credentials.json")
    request_timeout_seconds: float = 10.0
    heartbeat_interval_seconds: float = 30.0
    task_claim_interval_seconds: float = 10.0
    inventory_version: str = "unavailable"
    manifest_path: Path = Path("/opt/os-guard-agent/modules/manifest.json")


def _required_string(values: Mapping[str, Any], key: str) -> str:
    value = values.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"'{key}' must be a non-empty string")
    return value.strip()


def load_config(path: Path) -> AgentConfig:
    try:
        with path.open("rb") as config_file:
            document = tomllib.load(config_file)
    except FileNotFoundError as exc:
        raise ConfigError(f"configuration file not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc

    agent = document.get("agent")
    if not isinstance(agent, dict):
        raise ConfigError("missing [agent] section")

    central_server_url = _required_string(agent, "central_server_url").rstrip("/")
    parsed_url = urlparse(central_server_url)
    if parsed_url.scheme != "https" or not parsed_url.netloc:
        raise ConfigError("'central_server_url' must be a valid HTTPS URL")

    raw_agent_id = agent.get("agent_id")
    if raw_agent_id is not None and not isinstance(raw_agent_id, str):
        raise ConfigError("'agent_id' must be a string")
    agent_id = raw_agent_id.strip() if isinstance(raw_agent_id, str) else None
    agent_id = agent_id or None

    log_path = Path(_required_string(agent, "log_path"))
    log_level = str(agent.get("log_level", "INFO")).upper()
    if log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        raise ConfigError("'log_level' is invalid")

    token_store_path = Path(
        str(agent.get("token_store_path", "/var/lib/os-guard-agent/credentials.json"))
    )
    try:
        request_timeout_seconds = float(agent.get("request_timeout_seconds", 10.0))
    except (TypeError, ValueError):
        raise ConfigError("'request_timeout_seconds' must be a number") from None
    if request_timeout_seconds <= 0:
        raise ConfigError("'request_timeout_seconds' must be greater than zero")
    try:
        heartbeat_interval_seconds = float(agent.get("heartbeat_interval_seconds", 30.0))
    except (TypeError, ValueError):
        raise ConfigError("'heartbeat_interval_seconds' must be a number") from None
    if heartbeat_interval_seconds <= 0:
        raise ConfigError("'heartbeat_interval_seconds' must be greater than zero")
    try:
        task_claim_interval_seconds = float(
            agent.get("task_claim_interval_seconds", 10.0)
        )
    except (TypeError, ValueError):
        raise ConfigError("'task_claim_interval_seconds' must be a number") from None
    if task_claim_interval_seconds <= 0:
        raise ConfigError("'task_claim_interval_seconds' must be greater than zero")
    inventory_version = str(agent.get("inventory_version", "unavailable")).strip()
    if not inventory_version:
        raise ConfigError("'inventory_version' must be a non-empty string")
    manifest_path = Path(
        str(agent.get("manifest_path", "/opt/os-guard-agent/modules/manifest.json"))
    )

    return AgentConfig(
        central_server_url=central_server_url,
        agent_id=agent_id,
        log_path=log_path,
        log_level=log_level,
        token_store_path=token_store_path,
        request_timeout_seconds=request_timeout_seconds,
        heartbeat_interval_seconds=heartbeat_interval_seconds,
        task_claim_interval_seconds=task_claim_interval_seconds,
        inventory_version=inventory_version,
        manifest_path=manifest_path,
    )
