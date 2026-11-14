"""Memory probe for the parts of real-time protection that run on a timer (audit 8, M4 follow-up).

Runs each periodic part many times in a row, as fast as possible, and prints how much the
process memory grew per part. Read-only for the computer: it only lists processes, reads
autostart entries and watches a temporary folder it fills with harmless text files.

    python packaging/memprobe_parts.py [rounds]
"""

from __future__ import annotations

import gc
import os
import shutil
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

import psutil


def priv() -> float:
    return psutil.Process().memory_full_info().private / 2**20


def measure(name: str, fn: Callable[[], object], rounds: int) -> None:
    fn()
    gc.collect()
    start, t0 = priv(), time.monotonic()
    marks = []
    for i in range(rounds):
        fn()
        if (i + 1) % max(1, rounds // 4) == 0:
            gc.collect()
            marks.append(f"{priv() - start:+6.1f}")
    print(f"{name:34s} {rounds:6d} rounds {time.monotonic() - t0:6.1f}s  private growth (MB) by quarter: "
          + " ".join(marks), flush=True)


def main() -> None:
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
    home = Path(tempfile.mkdtemp(prefix="sx-memprobe-parts-"))
    os.environ["SENTINELX_HOME"] = str(home / "home")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from sentinelx.app.bootstrap import bootstrap
    from sentinelx.core.enums import PrivilegeLevel
    from sentinelx.protection.process_guard import ProcessGuard
    from sentinelx.protection.ransomware import WriteSampler

    c = bootstrap(None, console_log=False, privilege=PrivilegeLevel.STANDARD)
    p = c.protection
    print("start: private", f"{priv():.1f} MB", flush=True)

    measure("threat_hashes (guard asks 1/s)", p.threat_hashes, rounds)
    guard = ProcessGuard(lambda: {"0" * 64}, lambda _t: None)
    measure("process guard check (1/s)", guard.check_once, rounds)
    sampler = WriteSampler()
    measure("ransomware write sampler", sampler.snapshot, max(50, rounds // 20))
    measure("ransomware detector tick (1/15s)", p.ransomware.tick, max(50, rounds // 10))
    measure("protection status (page, 1/2s)", p.status, rounds)
    measure("activity list (page, 1/2s)", p.activity, rounds)
    measure("lock entries (page, 1/2s)", p.locks.entries, rounds)

    from sentinelx.protection.autostart import read_entries
    measure("autostart registry/folders read", read_entries, max(50, rounds // 20))

    # real file events through watchdog and the folder scanner (no scanning: batches are dropped)
    from sentinelx.protection.realtime import FolderScanner

    seen = []
    fs = FolderScanner(lambda paths: seen.append(len(paths)), exclude=[])
    fs.start()
    d = home / "watched"
    d.mkdir()
    fs.watch(d)
    n = [0]

    def churn() -> None:
        for _ in range(20):
            n[0] += 1
            f = d / f"t{n[0]:07d}.txt"
            f.write_text("harmless " * 20)
        fs.process_ready(time.monotonic() + 3600)
        for f in d.iterdir():
            f.unlink()

    measure("file events (20 new files each)", churn, max(50, rounds // 10))
    print(f"   batches handed to the scanner: {len(seen)}, files: {sum(seen)}", flush=True)
    fs.stop()
    c.shutdown()
    shutil.rmtree(home, ignore_errors=True)


if __name__ == "__main__":
    main()
