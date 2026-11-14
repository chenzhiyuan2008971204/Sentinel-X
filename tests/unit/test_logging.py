from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from sentinelx.app.logging_setup import LOG_FILE_NAME, configure_logging

pytestmark = pytest.mark.unit


def _remove_handlers() -> None:
    root = logging.getLogger()
    for h in list(root.handlers):
        if getattr(h, "_sentinelx_handler", False):
            root.removeHandler(h)
            h.close()


def test_json_lines_with_context(tmp_path: Path) -> None:
    log_file = configure_logging(tmp_path, "INFO", console=False)
    try:
        logging.getLogger("sentinelx.test").info("掃描開始", extra={"ctx": {"job_id": 7}})
        try:
            raise ValueError("boom")
        except ValueError:
            logging.getLogger("sentinelx.test").exception("failed")
    finally:
        _remove_handlers()
    lines = [json.loads(x) for x in log_file.read_text(encoding="utf-8").splitlines()]
    assert lines[0]["msg"] == "掃描開始"
    assert lines[0]["ctx"] == {"job_id": 7}
    assert lines[0]["level"] == "INFO"
    assert "ValueError: boom" in lines[1]["exc"]
    assert log_file.name == LOG_FILE_NAME


def test_configure_is_idempotent(tmp_path: Path) -> None:
    try:
        configure_logging(tmp_path, console=True)
        configure_logging(tmp_path, console=True)
        tagged = [h for h in logging.getLogger().handlers if getattr(h, "_sentinelx_handler", False)]
        assert len(tagged) == 2  # one file + one console, not doubled
    finally:
        _remove_handlers()
