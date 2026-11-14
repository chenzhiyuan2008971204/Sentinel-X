"""Audit 4 regression tests: how the Phase 1–5 code behaves next to the Phase 6–7 features."""

from __future__ import annotations

import subprocess
import sys
import threading
from pathlib import Path

import pytest
from pytestqt.qtbot import QtBot

from sentinelx.app.bootstrap import AppContainer
from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import ReportKind
from sentinelx.quarantine.vault import QuarantineVault
from sentinelx.quarantine.win32fs import QuarantineError
from sentinelx.storage.audit import AuditLog
from sentinelx.storage.db import Database

pytestmark = pytest.mark.integration
RULE = 'rule self_test { meta: severity = "high" strings: $a = "SX-SELF-TEST-STRING" condition: $a }'


# ---- D1: scans flagged Sentinel X's own rule copies and reports ----
def test_D1_scan_skips_own_data_folder(make_container, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    from sentinelx.engines.yara_engine import YaraEngine
    from sentinelx.storage.rules_repository import RuleSetStore

    probe = make_container([])  # to get the paths and database of this test home
    store = RuleSetStore(probe.db, probe.paths.yara_rules_dir)
    c = make_container([YaraEngine(store)])
    rule = tmp_path / "self.yar"
    rule.write_text(RULE, encoding="utf-8")
    c.intel.add_rule_file(rule, "selftest", "1")
    sample = tmp_path / "s.txt"
    sample.write_text("xx SX-SELF-TEST-STRING yy", encoding="utf-8")
    run = c.lab.yara_test(RULE, [sample])
    insp = c.lab.inspect(sample)
    c.lab.export_sample(insp.facts.sha256, insp, [run], [ReportKind.JSON, ReportKind.HTML])

    root = c.paths.root
    s = c.scans.run_scan([root.parent], CancelToken())  # e.g. scanning the whole profile folder
    files = c.scans.job_files(s.job_id)
    own = [f for f in files if Path(f.path) == root or root in Path(f.path).parents]
    assert own and all(not f.detections for f in own)
    assert all("Sentinel X 自己的資料資料夾" in (f.not_assessed_reason or "") for f in own)
    assert s.suspicious == 0 and s.confirmed == 0 and s.status == "COMPLETED"


@pytest.mark.security
def test_D1_vault_refuses_own_data_folder(db: Database, tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / "rules").mkdir(parents=True)
    own = home / "rules" / "r.yar"
    own.write_text("rule r { condition: true }", encoding="utf-8")
    import hashlib

    vault = QuarantineVault(home / "vault", db, AuditLog(db), protected_root=home)
    with pytest.raises(QuarantineError) as e:
        vault.quarantine(own, hashlib.sha256(own.read_bytes()).hexdigest(), verdict_id=None, reason="t")
    assert "自己的資料" in e.value.user_message and own.exists()

    outside = tmp_path / "x.txt"
    outside.write_text("x", encoding="utf-8")
    item = vault.quarantine(outside, hashlib.sha256(b"x").hexdigest(), verdict_id=None, reason="t")
    with pytest.raises(QuarantineError) as e2:
        vault.restore(item.id, home / "rules" / "back.txt")
    assert "資料資料夾" in e2.value.user_message


# ---- D2: a hash list import ran on the GUI thread (21 s for 500 000 hashes) ----
@pytest.mark.gui
def test_D2_hash_import_off_gui_thread(qtbot: QtBot, container: AppContainer, tmp_path: Path,
                                       monkeypatch: pytest.MonkeyPatch) -> None:
    from sentinelx.gui.intel_page import ThreatIntelPage

    threads: list[str] = []
    real = container.intel.import_hashes

    def spy(*a, **k):  # type: ignore[no-untyped-def]
        threads.append(threading.current_thread().name)
        return real(*a, **k)

    monkeypatch.setattr(container.intel, "import_hashes", spy)
    p = ThreatIntelPage(container.intel)
    qtbot.addWidget(p)
    f = tmp_path / "l.txt"
    f.write_text("b" * 64 + "\n", encoding="utf-8")
    p.src_name.setText("L")
    p.import_hashes(f)
    qtbot.waitUntil(lambda: not p.importing, timeout=30000)
    assert threads and threading.main_thread().name not in threads
    assert "已匯入 1 筆" in p.hash_msg.text() and p.import_button.isEnabled()


# ---- D3: two processes appending at once forked the audit hash chain ----
WRITER = """
import sys
from pathlib import Path
from sentinelx.storage.db import Database
from sentinelx.storage.audit import AuditLog
db = Database(Path(sys.argv[1])); db.initialize(); a = AuditLog(db)
for i in range(150):
    a.record("RACE", subject=sys.argv[2] + str(i))
db.dispose()
"""


@pytest.mark.security
def test_D3_two_processes_keep_one_chain(tmp_path: Path) -> None:
    path = tmp_path / "race.db"
    d = Database(path)
    d.initialize()
    d.dispose()
    procs = [subprocess.Popen([sys.executable, "-c", WRITER, str(path), tag]) for tag in ("A", "B")]
    assert [p.wait(timeout=120) for p in procs] == [0, 0]
    d = Database(path)
    check = AuditLog(d).verify()
    d.dispose()
    assert check.ok and check.entries == 300, check
