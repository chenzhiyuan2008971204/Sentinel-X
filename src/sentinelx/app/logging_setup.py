"""Structured (JSON Lines) logging.

Usage:
    log = logging.getLogger(__name__)
    log.info("scan started", extra={"ctx": {"job_id": 7}})

Never log file contents or secrets; log identifiers (paths, hashes, ids) only.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

LOG_FILE_NAME = "sentinelx.log.jsonl"
_HANDLER_TAG = "_sentinelx_handler"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "thread": record.threadName,
        }
        ctx = getattr(record, "ctx", None)
        if isinstance(ctx, dict):
            entry["ctx"] = ctx
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False, default=str)


def configure_logging(log_dir: Path, level: str = "INFO", *, console: bool = True) -> Path:
    """Install JSON handlers on the root logger. Idempotent: replaces handlers it added before."""
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / LOG_FILE_NAME
    root = logging.getLogger()
    for h in list(root.handlers):
        if getattr(h, _HANDLER_TAG, False):
            root.removeHandler(h)
            h.close()

    fmt = JsonFormatter()
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(fmt)
    setattr(file_handler, _HANDLER_TAG, True)
    root.addHandler(file_handler)

    if console:
        stream = logging.StreamHandler()
        stream.setFormatter(fmt)
        setattr(stream, _HANDLER_TAG, True)
        root.addHandler(stream)

    root.setLevel(level)
    return log_file
