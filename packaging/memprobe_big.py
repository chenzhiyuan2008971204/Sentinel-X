"""Memory probe for LARGE new files in real-time protection (audit 8, M4 follow-up).

The installed app grew most while big files appeared (installers, builds, a Windows ISO). This
probe writes harmless large files (repeated text; every other one starts with "MZ"), feeds
them to the real-time scan path with the given YARA rules loaded, deletes them, and prints the
process memory after every round.

    python packaging/memprobe_big.py <yara_file|-> [rounds] [files_per_round] [size_mb]
"""

from __future__ import annotations

import gc
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

import psutil


def mem() -> str:
    m = psutil.Process().memory_full_info()
    return f"working set {m.rss / 2**20:7.1f} MB  private {m.private / 2**20:7.1f} MB"


def main() -> None:
    yar = Path(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1] != "-" else None
    rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 6
    per = int(sys.argv[3]) if len(sys.argv) > 3 else 6
    size_mb = int(sys.argv[4]) if len(sys.argv) > 4 else 60
    home = Path(tempfile.mkdtemp(prefix="sx-memprobe-big-"))
    os.environ["SENTINELX_HOME"] = str(home / "home")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from sentinelx.app.bootstrap import bootstrap
    from sentinelx.core.enums import PrivilegeLevel

    c = bootstrap(None, console_log=False, privilege=PrivilegeLevel.STANDARD)
    p = c.protection
    if not os.environ.get("MEMPROBE_CLAMAV"):
        p._engines = lambda: [e for e in p._other_engines if e.name != "ClamAV"]  # type: ignore[method-assign]
    if yar is not None:
        row = c.intel.add_rule_file(yar, "probe rules", "probe")
        print(f"{row.rule_count} YARA rules loaded", flush=True)
    print("start:      ", mem(), flush=True)
    data = home / "files"
    data.mkdir()
    n = 0
    for r in range(rounds):
        paths = []
        for _ in range(per):
            n += 1
            head = b"MZ" if n % 2 else b"TX"
            chunk = (f"harmless large test file {n} ".encode() * 40000)[: 1 << 20]
            f = data / f"big{n:04d}.{'exe' if n % 2 else 'bin'}"
            with open(f, "wb") as out:
                out.write(head)
                for _ in range(size_mb):
                    out.write(chunk)
            paths.append(f)
        t0 = time.monotonic()
        p.scan_now(paths)
        for f in paths:
            f.unlink()
        gc.collect()
        print(f"round {r + 1:3d} ({n:4d} files, {time.monotonic() - t0:5.1f}s): {mem()}", flush=True)
    c.shutdown()
    shutil.rmtree(home, ignore_errors=True)


if __name__ == "__main__":
    main()
