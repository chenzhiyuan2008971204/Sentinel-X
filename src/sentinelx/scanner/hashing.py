from __future__ import annotations

import hashlib
from pathlib import Path

from sentinelx.core.cancel import CancelToken

CHUNK_SIZE = 1024 * 1024


def sha256_file(path: Path, cancel: CancelToken | None = None) -> str:
    """Streaming SHA-256; checks for cancellation between chunks. Never reads the whole file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            if cancel is not None:
                cancel.raise_if_cancelled()
            h.update(chunk)
    return h.hexdigest()
