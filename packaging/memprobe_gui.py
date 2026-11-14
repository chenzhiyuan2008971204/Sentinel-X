"""Memory probe for the window's periodic refreshes (audit 8, M4 follow-up).

Builds the real main window offscreen on a temporary data folder, makes its timers fire much
faster than in the app (status bar 10 s -> 50 ms, protection page 2 s -> 50 ms), switches
between pages, and prints the process memory and Python allocations every few seconds.
Read-only for the computer: nothing is scanned, protection is not started.

    python packaging/memprobe_gui.py [seconds] [report_every_s]
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


def main() -> None:
    seconds = int(sys.argv[1]) if len(sys.argv) > 1 else 120
    every = int(sys.argv[2]) if len(sys.argv) > 2 else 15
    home = Path(tempfile.mkdtemp(prefix="sx-memprobe-gui-"))
    os.environ["SENTINELX_HOME"] = str(home / "home")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication

    from sentinelx.app.bootstrap import bootstrap
    from sentinelx.core.enums import PrivilegeLevel
    from sentinelx.gui import theme
    from sentinelx.gui.main_window import MainWindow, Services

    app = QApplication.instance() or QApplication([])
    app.setStyleSheet(theme.STYLESHEET)
    c = bootstrap(None, console_log=False, privilege=PrivilegeLevel.STANDARD)
    w = MainWindow(Services(c.status, c.scans, c.intel, c.static, c.reviews, c.quarantine, c.monitor, c.reports,
                            c.lab, c.settings, c.signatures, c.protection, c.virustotal, c.sandbox, c.rule_updates),
                   PrivilegeLevel.STANDARD)
    w.show()
    fast = 50
    w._timer.setInterval(fast)
    pages = [w.stack.widget(i) for i in range(w.stack.count())]
    for pg in pages:
        t = getattr(pg, "_timer", None) or getattr(pg, "timer", None)
        if isinstance(t, QTimer):
            t.setInterval(fast)
            t.start()

    tracemalloc.start(10)
    state = {"i": 0, "t0": time.monotonic(), "next": 0.0, "first": None, "base": None}

    def switch() -> None:
        state["i"] += 1
        w.stack.setCurrentIndex(state["i"] % w.stack.count())

    def report() -> None:
        gc.collect()
        m = psutil.Process().memory_full_info()
        snap = tracemalloc.take_snapshot()
        state["first"] = state["first"] or snap
        state["base"] = state["base"] or m.private
        py = sum(s.size for s in snap.statistics("filename")) / 2**20
        print(f"{time.monotonic() - state['t0']:6.0f}s  working set {m.rss / 2**20:7.1f} MB  private "
              f"{m.private / 2**20:7.1f} MB ({(m.private - state['base']) / 2**20:+6.1f})  python {py:6.1f} MB  "
              f"page switches {state['i']}", flush=True)

    sw = QTimer()
    sw.timeout.connect(switch)
    sw.start(300)
    rep = QTimer()
    rep.timeout.connect(report)
    rep.start(every * 1000)
    QTimer.singleShot(seconds * 1000, app.quit)
    report()
    app.exec()
    report()
    snap = tracemalloc.take_snapshot()
    print("\nlargest Python growth:")
    for s in snap.compare_to(state["first"], "lineno")[:10]:
        print("  ", s)
    w.prepare_quit()
    c.shutdown()
    shutil.rmtree(home, ignore_errors=True)


if __name__ == "__main__":
    main()
