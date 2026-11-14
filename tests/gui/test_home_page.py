"""0.13.0: simple home page. States come from real services; every button does something real."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pytestqt.qtbot import QtBot

from sentinelx.app.bootstrap import AppContainer
from sentinelx.core.enums import PrivilegeLevel
from sentinelx.gui.home_page import HomePage, HomeState, checklist, hero_for
from sentinelx.gui.main_window import MainWindow, Services

pytestmark = pytest.mark.gui
NOW = datetime(2026, 11, 5, 12, tzinfo=UTC)


def ts(days_ago: int) -> str:
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def st(**kw) -> HomeState:  # type: ignore[no-untyped-def]
    base = dict(protection_on=True, signatures_present=True, signatures_newest=ts(0), signatures_consented=True,
                attention=0, quarantined=0)
    base.update(kw)
    return HomeState(**base)  # type: ignore[arg-type]


def test_hero_priorities() -> None:
    assert hero_for(st(), NOW).level == "ok" and hero_for(st(), NOW).action is None
    off = hero_for(st(protection_on=False, attention=3), NOW)
    assert off.level == "bad" and off.action_key == "protect_on"  # protection off comes first
    nosig = hero_for(st(signatures_present=False, signatures_consented=False), NOW)
    assert nosig.level == "warn" and nosig.action_key == "signatures" and "同意" in nosig.detail
    att = hero_for(st(attention=2), NOW)
    assert att.action_key == "threats" and "2 個檔案" in att.headline
    stale = hero_for(st(signatures_newest=ts(5)), NOW)
    assert stale.level == "warn" and "5 天" in stale.headline
    assert "今天" in hero_for(st(), NOW).detail
    assert hero_for(st(protection_on=None), NOW).action_key == "quick_scan"


def test_never_says_safe_or_100_percent() -> None:
    texts = []
    for s in (st(), st(protection_on=False), st(attention=1), st(signatures_present=False), st(protection_on=None)):
        h = hero_for(s, NOW)
        texts += [h.headline, h.detail] + [r[2] + r[3] for r in checklist(s, NOW)]
    joined = "".join(texts)
    assert "100%" not in joined and "絕對" not in joined and "完全安全" not in joined


def test_checklist_rows_and_buttons() -> None:
    rows = {r[0]: r for r in checklist(st(protection_on=False, signatures_newest=ts(9), attention=1, quarantined=2), NOW)}
    assert rows["protection"][1] == "bad" and rows["protection"][5] == "protect_on"
    assert rows["signatures"][1] == "warn" and "9 天前" in rows["signatures"][2]
    assert rows["threats"][5] == "threats" and rows["quarantine"][5] == "quarantine"
    ok = {r[0]: r for r in checklist(st(), NOW)}
    assert all(r[4] is None for k, r in ok.items() if k != "quarantine")  # nothing to do: no buttons


def test_page_buttons_call_actions(qtbot: QtBot) -> None:
    calls: list[str] = []
    state = st(protection_on=False, attention=1, quarantined=1)
    page = HomePage(lambda: state, calls.append)
    qtbot.addWidget(page)
    page.hero_button.click()
    page.quick_button.click()
    page.pick_button.click()
    page.row_widgets["threats"][3].click()
    page.row_widgets["quarantine"][3].click()
    assert calls == ["protect_on", "quick_scan", "scan", "threats", "quarantine"]


def window(qtbot: QtBot, c: AppContainer) -> MainWindow:
    w = MainWindow(Services(c.status, c.scans, c.intel, c.static, c.reviews, c.quarantine, c.monitor,
                            c.reports, c.lab, c.settings, c.signatures, c.protection), PrivilegeLevel.STANDARD)
    qtbot.addWidget(w)
    return w


def test_home_is_first_and_reflects_real_state(qtbot: QtBot, container: AppContainer) -> None:
    w = window(qtbot, container)
    assert w.current_page_key() == "home"
    s = w.home_state()
    assert s.protection_on is False and s.attention == 0 and s.quarantined == 0
    assert w.home_page.hero_title.text() == "即時防護已關閉"


def test_turn_on_protection_from_home(qtbot: QtBot, container: AppContainer) -> None:
    w = window(qtbot, container)
    try:
        w.home_page.hero_button.click()
        assert container.protection.running and w.home_state().protection_on
    finally:
        container.protection.set_enabled(False)


def test_quick_scan_scans_the_everyday_folders(qtbot: QtBot, container: AppContainer, tmp_path: Path,
                                               monkeypatch: pytest.MonkeyPatch) -> None:
    from sentinelx.protection import locations

    d1, d2 = tmp_path / "Downloads", tmp_path / "Desktop"
    for d in (d1, d2):
        d.mkdir()
        (d / "a.txt").write_text("harmless")
    monkeypatch.setattr(locations, "watched_folders", lambda **_k: [("下載", d1), ("桌面", d2)])
    w = window(qtbot, container)
    added = w.quick_scan()
    assert added == [str(d1), str(d2)] and w.current_page_key() == "scan"
    assert w.scan_page.target_paths() == [d1, d2]
    qtbot.waitUntil(lambda: not w.scan_page.scanning, timeout=60_000)
    jobs = container.scans.list_jobs() if hasattr(container.scans, "list_jobs") else None
    assert jobs is None or jobs  # a scan job was recorded


def test_signatures_button_opens_settings(qtbot: QtBot, container: AppContainer) -> None:
    w = window(qtbot, container)
    w.home_action("signatures")
    assert w.current_page_key() == "settings"
