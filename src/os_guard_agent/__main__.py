"""Command-line entry point for the OS Guard Unix Agent."""

from __future__ import annotations

import argparse
import signal
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .agent import Agent
from .config import ConfigError, load_config
from .log_config import configure_logging


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="os-guard-agent")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("/etc/os-guard-agent/agent.toml"),
        help="path to the Agent TOML configuration",
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
        signal.signal(signal.SIGTERM, lambda *_args: agent.stop())
        signal.signal(signal.SIGINT, lambda *_args: agent.stop())
        return agent.run()
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"Agent startup error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
