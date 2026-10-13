"""Command-line entry point for the OS Guard Unix Agent."""

from __future__ import annotations

import argparse
import signal
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .agent import Agent
from .api_client import ApiClientError
from .config import ConfigError, load_config
from .log_config import configure_logging
from .registration import (
    RegistrationFileError,
    dispose_registration_file,
    load_registration_file,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="os-guard-agent")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("/etc/os-guard-agent/agent.toml"),
        help="path to the Agent TOML configuration",
    )
    subparsers = parser.add_subparsers(dest="command")
    enroll = subparsers.add_parser(
        "enroll",
        help="enroll using a protected Central registration file",
    )
    enroll.add_argument(
        "--registration-file",
        type=Path,
        required=True,
        help="path to the protected one-time registration file",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    try:
        config = load_config(args.config)
        configure_logging(config.log_path, config.log_level)
        agent = Agent(config)
        if args.command == "enroll":
            registration = load_registration_file(
                args.registration_file,
                config.central_server_url,
            )
            credential = agent.enroll(
                registration.enrollment_id,
                registration.token,
                expected_server_id=registration.server_id,
            )
            dispose_registration_file(args.registration_file)
            return 0
        signal.signal(signal.SIGTERM, lambda *_args: agent.stop())
        signal.signal(signal.SIGINT, lambda *_args: agent.stop())
        return agent.run()
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    except RegistrationFileError as exc:
        print(f"Registration error: {exc}", file=sys.stderr)
        return 1
    except ApiClientError as exc:
        print(f"Agent API error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Agent startup error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
