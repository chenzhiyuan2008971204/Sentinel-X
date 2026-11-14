"""Read-only long-term memory/CPU measurement of the running Sentinel X (engineering audit 8, M4).

Every INTERVAL seconds, records working set, private memory and CPU time of SentinelX.exe and
clamd.exe to a CSV file. It only reads process information; it changes nothing.

    python packaging/memwatch.py <out.csv> [hours] [interval_s]
"""

from __future__ import annotations

import csv
import sys
import time
from datetime import datetime

import psutil

NAMES = ("sentinelx.exe", "clamd.exe")


def sample() -> list[tuple[str, int, float, float, float]]:
    rows = []
    for p in psutil.process_iter(["pid", "name"]):
        if (p.info["name"] or "").lower() in NAMES:
            try:
                m = p.memory_full_info() if hasattr(p, "memory_full_info") else p.memory_info()
                t = p.cpu_times()
                rows.append((p.info["name"], p.info["pid"], m.rss / 2**20, getattr(m, "private", m.rss) / 2**20,
                             t.user + t.system))
            except psutil.Error:
                continue
    return rows


def main() -> None:
    out = sys.argv[1]
    hours = float(sys.argv[2]) if len(sys.argv) > 2 else 24.0
    interval = float(sys.argv[3]) if len(sys.argv) > 3 else 600.0
    end = time.monotonic() + hours * 3600
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["time", "process", "pid", "working_set_mb", "private_mb", "cpu_seconds"])
        while True:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for name, pid, rss, priv, cpu in sample():
                w.writerow([now, name, pid, f"{rss:.1f}", f"{priv:.1f}", f"{cpu:.1f}"])
            f.flush()
            if time.monotonic() >= end:
                break
            time.sleep(interval)


if __name__ == "__main__":
    main()
