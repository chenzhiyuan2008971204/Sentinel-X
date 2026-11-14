"""Memory probe for real-time protection (follow-up to engineering audit 8, M4).

The installed app grew from about 235 MB to 780 MB over 36 hours while many new files appeared
(test runs, builds). This probe feeds the real-time scan path a steady stream of NEW harmless
files (text and small "MZ" files in a temporary folder) and also runs the periodic checks
(process guard, ransomware write sampler, autostart watch) the way the app does. It prints the
process memory and the Python allocations that grew, so the cause can be measured, not guessed.

    python packaging/memprobe_realtime.py [batches] [files_per_batch] [report_every]

Harmless data only; ClamAV is skipped (it is a separate process) unless MEMPROBE_CLAMAV=1.
"""

from __future__ import annotations

import gc
import os
import shutil
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

import psutil


def mb() -> tuple[float, float]:
    m = psutil.Process().memory_full_info()
    return m.rss / 2**20, m.private / 2**20


def main() -> None:
    batches = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    per = int(sys.argv[2]) if len(sys.argv) > 2 else 50
    every = int(sys.argv[3]) if len(sys.argv) > 3 else 50
    home = Path(tempfile.mkdtemp(prefix="sx-memprobe-rt-"))
    os.environ["SENTINELX_HOME"] = str(home / "home")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from sentinelx.app.bootstrap import bootstrap
    from sentinelx.core.enums import PrivilegeLevel

    c = bootstrap(None, console_log=False, privilege=PrivilegeLevel.STANDARD)
    p = c.protection
    if not os.environ.get("MEMPROBE_CLAMAV"):
        p._engines = lambda: [e for e in p._other_engines if e.name != "ClamAV"]  # type: ignore[method-assign]
    guard = getattr(p, "_guard", None)
    sampler = getattr(p, "_sampler", None)
    print("engines:", [e.name for e in p._engines()], "guard:", guard is not None, "sampler:", sampler is not None,
          flush=True)

    data = home / "files"
    data.mkdir()
    tracemalloc.start(15)
    base = None
    t0 = time.monotonic()
    n = 0
    for b in range(batches):
        paths = []
        for _ in range(per):
            n += 1
            body = (b"MZ" + bytes(range(256)) * 4 + n.to_bytes(4, "little")) if n % 5 == 0 else (
                f"harmless file {n} " * 30).encode()
            f = data / f"d{n // 1000:04d}" / f"f{n:07d}.{'exe' if n % 5 == 0 else 'txt'}"
            f.parent.mkdir(exist_ok=True)
            f.write_bytes(body)
            paths.append(f)
        p.scan_now(paths)
        for f in paths:  # like a temp folder: files come and go
            f.unlink()
        if (b + 1) % every == 0 or b == 0:
            gc.collect()
            snap = tracemalloc.take_snapshot()
            base = base or snap
            rss, priv = mb()
            py = sum(s.size for s in snap.statistics("filename")) / 2**20
            print(f"batch {b + 1:5d} files {n:7d}  working set {rss:7.1f} MB  private {priv:7.1f} MB  "
                  f"python {py:6.1f} MB  {time.monotonic() - t0:6.0f}s", flush=True)
    print("\nlargest growth since the first batch (Python allocations):")
    for s in snap.compare_to(base, "traceback")[:8]:
        print("  ", s)
        for line in s.traceback.format()[-6:]:
            print("        ", line)
    c.shutdown()
    shutil.rmtree(home, ignore_errors=True)


if __name__ == "__main__":
    main()
