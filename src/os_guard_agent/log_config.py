"""Local logging configuration with basic secret redaction."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Final

_SECRET_PATTERNS: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    (
        re.compile(
            r"(?i)(token|password|secret|authorization)(\s*[=:]\s*)([^\s,;]+)"
        ),
        r"\1\2[REDACTED]",
    ),
    (re.compile(r"(?i)(bearer\s+)([A-Za-z0-9._~+/=-]+)"), r"\1[REDACTED]"),
)


class SecretRedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        for pattern, replacement in _SECRET_PATTERNS:
            message = pattern.sub(replacement, message)
        record.msg = message
        record.args = ()
        return True


def configure_logging(log_path: Path, log_level: str) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    redaction_filter = SecretRedactionFilter()

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler.addFilter(redaction_filter)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    stream_handler.addFilter(redaction_filter)

    logging.basicConfig(
        level=getattr(logging, log_level),
        handlers=[file_handler, stream_handler],
        force=True,
    )
