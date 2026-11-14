"""Memory probe (engineering audit 8, M4): what does Sentinel X itself hold, and does it grow?

Harmless data only: a temporary data folder, the YARA Forge rules file given on the command
line (optional), and N small text/"MZ" files that are scanned R times by the normal scan
service. Prints the process memory after start, after loading the rules and after every
round, and the largest Python allocations at the end (tracemalloc).

    python packaging/memprobe.py [yara_file] [files] [rounds]
"""

from __future__ import annotations

import gc
import os
import shutil
import sys
import tempfile
import tracemalloc
from pathlib import Path

import psutil


def mb() -> str:
    m = psutil.Process().memory_full_info()
    return f"working set {m.rss / 2**20:6.1f} MB, private {m.private / 2**20:6.1f} MB"


def main() -> None:
    yar = Path(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1] != "-" else None
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 3000
    rounds = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    home = Path(tempfile.mkdtemp(prefix="sx-memprobe-"))
    os.environ["SENTINELX_HOME"] = str(home / "home")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    print("python only:          ", mb(), flush=True)

    from sentinelx.app.bootstrap import bootstrap
    from sentinelx.core.cancel import CancelToken
    from sentinelx.core.enums import PrivilegeLevel

    c = bootstrap(None, console_log=False, privilege=PrivilegeLevel.STANDARD)
    if os.environ.get("MEMPROBE_NO_CLAMAV"):  # ClamAV runs as its own process; skip it to measure faster
        c.scans._engines = [e for e in c.scans._engines if e.name != "ClamAV"]
    print("after start:          ", mb(), "engines:", [e.name for e in c.scans._engines], flush=True)
    if yar is not None:
        row = c.intel.add_rule_file(yar, "probe rules", "probe")
        print(f"after {row.rule_count} YARA rules: ", mb(), flush=True)

    data = home / "files"
    data.mkdir()
    for i in range(n):
        body = (b"MZ" + bytes(range(256)) * 8) if i % 5 == 0 else (f"harmless file {i} " * 40).encode()
        (data / f"f{i:05d}.{'exe' if i % 5 == 0 else 'txt'}").write_bytes(body)

    tracemalloc.start(25)
    first = None
    for r in range(rounds):
        c.scans.run_scan([data], CancelToken(), lambda *_a, **_k: None)
        gc.collect()
        snap = tracemalloc.take_snapshot()
        first = first or snap
        print(f"after scan round {r + 1}:   ", mb(), f"python objects {sum(s.size for s in snap.statistics('filename')) / 2**20:6.1f} MB",
              flush=True)
    print("\nlargest growth between round 1 and the last round (Python allocations):")
    for s in snap.compare_to(first, "lineno")[:12]:
        print("  ", s)
    print("\nlargest Python allocations now:")
    for s in snap.statistics("lineno")[:10]:
        print("  ", s)
    c.shutdown()
    shutil.rmtree(home, ignore_errors=True)


if __name__ == "__main__":
    main()
