from __future__ import annotations

from datetime import UTC, datetime


def utc_now_iso() -> str:
    """UTC timestamp in the persisted format `YYYY-MM-DDTHH:MM:SSZ`."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
