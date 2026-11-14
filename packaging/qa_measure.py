"""Phase 9 measurements for the quality report (not part of the pytest suite; needs real data).

    python packaging/qa_measure.py [--fp-files 300] [--synthetic 3000]

1. False positives: scan harmless signed Windows system files with the real engines
   (ClamAV with the existing per-user signatures, hash intel, PE static analysis) and count
   verdicts. Expected: no CONFIRMED_THREAT, no SUSPICIOUS.
2. Resource usage: scan N small synthetic files; time, peak memory of this process, DB growth.
3. GUI responsiveness: run a scan from the Scan Center page and measure the longest gap
   between 50 ms timer ticks on the GUI thread while it runs.

Uses a temporary data folder; the user's own data is only read (the signature folder).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

import psutil

HOME = Path(tempfile.mkdtemp(prefix="sx-qa-"))
os.environ["SENTINELX_HOME"] = str(HOME)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
SIG_DIR = Path(os.environ["LOCALAPPDATA"]) / "SentinelX" / "clamav-db"


def configure() -> None:
    HOME.mkdir(parents=True, exist_ok=True)
    cfg = {"clamav": {"database_dir": str(SIG_DIR)}} if SIG_DIR.is_dir() else {}
    (HOME / "config.json").write_text(json.dumps(cfg), encoding="utf-8")


def false_positives(n: int) -> dict:
    from sentinelx.app.bootstrap import bootstrap
    from sentinelx.core.cancel import CancelToken

    src = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32"
    files = sorted(p for p in src.iterdir() if p.suffix.lower() in (".exe", ".dll") and p.is_file())[:n]
    sample = Path(tempfile.mkdtemp(prefix="sx-qa-fp-"))
    for f in files:  # copies: the scanner reads them; nothing in System32 is touched
        try:
            shutil.copy2(f, sample / f.name)
        except OSError:
            pass
    c = bootstrap(console_log=False)
    engines = [f"{s.name} {s.version} ({'ok' if s.available else s.detail})" for s in c.scans.engine_statuses()]
    t0 = time.monotonic()
    s = c.scans.run_scan([sample], CancelToken())
    out = {"files": s.files_seen, "status": s.status, "confirmed": s.confirmed, "suspicious": s.suspicious,
           "unknown": s.unknown, "clean": s.clean, "not_assessed": s.files_not_assessed,
           "seconds": round(time.monotonic() - t0, 1), "engines": engines,
           "flagged": [(Path(f.path).name, f.classification.value if f.classification else None, f.detections)
                       for f in c.scans.job_files(s.job_id)
                       if f.classification is not None and f.classification.value in ("CONFIRMED_THREAT", "SUSPICIOUS")]}
    c.shutdown()
    shutil.rmtree(sample, ignore_errors=True)
    return out


def resources(n: int) -> dict:
    from sentinelx.app.bootstrap import bootstrap
    from sentinelx.core.cancel import CancelToken
    from sentinelx.engines.hash_intel import HashIntelEngine
    from sentinelx.engines.pe_static import PEStaticEngine
    from sentinelx.storage.intel_repository import IntelStore

    d = Path(tempfile.mkdtemp(prefix="sx-qa-res-"))
    for i in range(n):
        (d / f"f{i:05d}.txt").write_bytes((b"harmless synthetic file %d\n" % i) * 20)
    probe = bootstrap(console_log=False)
    intel = IntelStore(probe.db)
    probe.shutdown()
    hashes = d.parent / f"{d.name}-intel.txt"
    hashes.write_text("0" * 63 + "1\n", encoding="utf-8")
    c = bootstrap(console_log=False, engines=[HashIntelEngine(intel), PEStaticEngine()])
    c.intel.import_hashes(hashes, "qa", __import__("sentinelx.core.enums", fromlist=["TrustLevel"]).TrustLevel.LOW)
    proc = psutil.Process()
    peak = [proc.memory_info().rss]
    db_before = c.paths.database_file.stat().st_size
    t0 = time.monotonic()
    s = c.scans.run_scan([d], CancelToken(), lambda _p: peak.append(proc.memory_info().rss))
    secs = time.monotonic() - t0
    c.shutdown()
    db_after = c.paths.database_file.stat().st_size + sum(
        p.stat().st_size for p in c.paths.root.glob("sentinelx.db-wal"))
    shutil.rmtree(d, ignore_errors=True)
    return {"files": s.files_seen, "status": s.status, "seconds": round(secs, 1),
            "files_per_second": round(s.files_seen / secs, 1), "peak_rss_mb": round(max(peak) / 2**20, 1),
            "db_growth_mb": round((db_after - db_before) / 2**20, 1)}


def responsiveness(n: int) -> dict:
    from PySide6.QtCore import QElapsedTimer, QTimer
    from PySide6.QtWidgets import QApplication

    from sentinelx.app.bootstrap import bootstrap
    from sentinelx.engines.pe_static import PEStaticEngine
    from sentinelx.gui.scan_page import ScanCenterPage

    app = QApplication.instance() or QApplication(sys.argv[:1])
    d = Path(tempfile.mkdtemp(prefix="sx-qa-gui-"))
    for i in range(n):
        (d / f"g{i:05d}.bin").write_bytes(os.urandom(4096))
    from sentinelx.engines.hash_intel import HashIntelEngine
    from sentinelx.storage.intel_repository import IntelStore

    probe = bootstrap(console_log=False)
    intel = IntelStore(probe.db)
    probe.shutdown()
    c = bootstrap(console_log=False, engines=[HashIntelEngine(intel), PEStaticEngine()])
    lst = d.parent / f"{d.name}-intel.txt"
    lst.write_text("1" * 64 + "\n", encoding="utf-8")
    from sentinelx.core.enums import TrustLevel

    c.intel.import_hashes(lst, "qa-gui", TrustLevel.LOW)
    page = ScanCenterPage(c.scans)
    page.show()
    gaps: list[float] = []
    clock = QElapsedTimer()
    clock.start()
    last = [clock.elapsed()]

    def tick() -> None:
        now = clock.elapsed()
        gaps.append(now - last[0])
        last[0] = now

    timer = QTimer()
    timer.setInterval(50)
    timer.timeout.connect(tick)
    timer.start()
    page.add_target(d)
    started = time.monotonic()
    page.start_scan()
    while page.scanning and time.monotonic() - started < 600:
        app.processEvents()
        time.sleep(0.005)
    timer.stop()
    page.shutdown()
    c.shutdown()
    shutil.rmtree(d, ignore_errors=True)
    gaps.sort()
    return {"files": n, "scan_seconds": round(time.monotonic() - started, 1), "ticks": len(gaps),
            "max_gap_ms": round(max(gaps), 1) if gaps else None,
            "p99_gap_ms": round(gaps[int(len(gaps) * 0.99) - 1], 1) if gaps else None}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fp-files", type=int, default=300)
    ap.add_argument("--synthetic", type=int, default=3000)
    ap.add_argument("--gui-files", type=int, default=1500)
    args = ap.parse_args()
    configure()
    report = {"false_positives": false_positives(args.fp_files), "resources": resources(args.synthetic),
              "gui_responsiveness": responsiveness(args.gui_files)}
    print(json.dumps(report, ensure_ascii=False, indent=2))
    shutil.rmtree(HOME, ignore_errors=True)


if __name__ == "__main__":
    main()
