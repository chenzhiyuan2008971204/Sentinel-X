"""Memory probe: a burst of file events through the whole real-time path (audit 8, M4 follow-up).

Seen on the user's computer: the installed app went from 186 MB to 435 MB private memory in
the 10 minutes in which about 30,000 small files appeared in the temp folder, and stayed there.
This probe starts the real protection service on a temporary data folder, watching only one
temporary folder (no drives, no execution lock, no process guard, no resident ClamAV), writes
harmless files into it in bursts, and prints the memory while the events are processed.

    python packaging/memprobe_events.py [files] [burst] [settle_s]
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


def mem() -> str:
    m = psutil.Process().memory_full_info()
    return f"working set {m.rss / 2**20:7.1f} MB  private {m.private / 2**20:7.1f} MB"


def main() -> None:
    total = int(sys.argv[1]) if len(sys.argv) > 1 else 30000
    burst = int(sys.argv[2]) if len(sys.argv) > 2 else 2000
    settle = int(sys.argv[3]) if len(sys.argv) > 3 else 60
    home = Path(tempfile.mkdtemp(prefix="sx-memprobe-ev-"))
    os.environ["SENTINELX_HOME"] = str(home / "home")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from sentinelx.app.bootstrap import bootstrap
    from sentinelx.core.enums import PrivilegeLevel

    c = bootstrap(None, console_log=False, privilege=PrivilegeLevel.STANDARD)
    p = c.protection
    p.update(enabled=True, exec_lock=False, kill_known_threats=False, watch_all_drives=False, watch_downloads=False,
             watch_desktop_documents=False, watch_temp=False, watch_removable=False, watch_autostart=False,
             low_memory=True, ransomware_decoys=False)
    p._fallback_clamav = None  # ClamAV is a separate program; leave it out of this measurement
    d = home / "watched"
    d.mkdir()
    p.start()
    assert p._scanner is not None
    p._scanner.watch(d)
    tracemalloc.start(12)
    gc.collect()
    first = tracemalloc.take_snapshot()
    print("start:   ", mem(), flush=True)
    t0 = time.monotonic()
    n = 0
    while n < total:
        for _ in range(burst):
            n += 1
            sub = d / f"s{n // 1000:03d}"
            sub.mkdir(exist_ok=True)
            (sub / f"f{n:06d}.{'exe' if n % 5 == 0 else 'txt'}").write_bytes(
                (b"MZ" + bytes(range(200)) + n.to_bytes(4, "little")) if n % 5 == 0 else f"harmless {n} ".encode() * 30)
        st = p.status()
        print(f"{time.monotonic() - t0:6.0f}s written {n:6d}  queue {st.queue:6d}  scanned {st.scanned:6d}  {mem()}",
              flush=True)
    end = time.monotonic() + settle
    while time.monotonic() < end:
        time.sleep(10)
        st = p.status()
        print(f"{time.monotonic() - t0:6.0f}s settling       queue {st.queue:6d}  scanned {st.scanned:6d}  {mem()}",
              flush=True)
    shutil.rmtree(d, ignore_errors=True)
    time.sleep(10)
    gc.collect()
    snap = tracemalloc.take_snapshot()
    print("after deleting the files:", mem(), flush=True)
    print("\nlargest Python growth:")
    for s in snap.compare_to(first, "traceback")[:8]:
        print("  ", s)
        for line in s.traceback.format()[-8:]:
            print("        ", line)
    p.stop()
    c.shutdown()
    shutil.rmtree(home, ignore_errors=True)


if __name__ == "__main__":
    main()
