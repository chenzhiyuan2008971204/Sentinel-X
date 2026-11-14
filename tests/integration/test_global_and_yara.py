"""0.16.0: whole-drive protection and YARA Forge rules (fake GitHub; no network)."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import sys
import time
import urllib.error
import zipfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest
from fakes import FakeEngine

from sentinelx.app.bootstrap import AppContainer
from sentinelx.core.enums import Severity
from sentinelx.engines.base import DetectionEngine
from sentinelx.engines.yara_engine import rule_severity
from sentinelx.protection import locations
from sentinelx.services.protection_service import ProtectionService
from sentinelx.services.rule_update_service import API_LATEST, MEMBER, RULE_SET_NAME, RuleUpdateError, RuleUpdateService
from sentinelx.storage.scan_repository import ExclusionRepository, ScanRepository
from sentinelx.storage.verdict_repository import VerdictRepository

pytestmark = pytest.mark.integration
MakeContainer = Callable[[Sequence[DetectionEngine]], AppContainer]
PING = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "PING.EXE"
RULES_V1 = b'rule sx_test_one { meta: score = 85 strings: $a = "SX-RULE-TEST-ONE" condition: $a }\n'
RULES_V2 = RULES_V1 + b'rule sx_test_two { meta: severity = "critical" strings: $b = "SX-RULE-TEST-TWO" condition: $b }\n'


# ---------------- YARA Forge ratings ----------------
def test_rule_severity_mapping() -> None:
    assert rule_severity({"severity": "critical"}) is Severity.HIGH
    assert rule_severity({"severity": "low"}) is Severity.LOW
    assert rule_severity({"score": "85"}) is Severity.HIGH
    assert rule_severity({"score": "75"}) is Severity.MEDIUM
    assert rule_severity({"score": "50"}) is Severity.LOW
    assert rule_severity({"score": "10"}) is Severity.INFO
    assert rule_severity({}) is Severity.MEDIUM
    assert rule_severity({"score": "n/a"}) is Severity.MEDIUM


# ---------------- YARA Forge updater ----------------
def make_zip(rules: bytes, member: str = MEMBER) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(member, rules)
    return buf.getvalue()


OFFICIAL_URL = "https://github.com/YARAHQ/yara-forge/releases/download/20261103/yara-forge-rules-core.zip"


class FakeGitHub:
    def __init__(self, tag: str, data: bytes, *, digest: str | None = None, url: str = OFFICIAL_URL) -> None:
        self.tag, self.data, self.url = tag, data, url
        self.digest = digest if digest is not None else "sha256:" + hashlib.sha256(data).hexdigest()
        self.urls: list[str] = []

    def __call__(self, req, timeout=None):  # type: ignore[no-untyped-def]
        self.urls.append(req.full_url)
        if req.full_url == API_LATEST:
            body = json.dumps({"tag_name": self.tag, "assets": [
                {"name": "yara-forge-rules-core.zip", "size": len(self.data), "digest": self.digest,
                 "browser_download_url": self.url}]}).encode()
        elif req.full_url == self.url:
            body = self.data
        else:
            raise urllib.error.URLError("unexpected url")

        class R(io.BytesIO):
            def __enter__(self):  # type: ignore[no-untyped-def]
                return self

            def __exit__(self, *a):  # type: ignore[no-untyped-def]
                return False

        return R(body)


def updater(c: AppContainer, gh: FakeGitHub) -> RuleUpdateService:
    return RuleUpdateService(c.config, c.config_store, c.audit, c.intel, opener=gh)


def test_requires_consent(make_container: MakeContainer) -> None:
    c = make_container([FakeEngine()])
    gh = FakeGitHub("20261103", make_zip(RULES_V1))
    with pytest.raises(RuleUpdateError, match="同意"):
        updater(c, gh).update()
    assert gh.urls == []  # nothing contacted


def test_install_update_and_replace(make_container: MakeContainer) -> None:
    c = make_container([FakeEngine()])
    u = updater(c, FakeGitHub("20261103", make_zip(RULES_V1)))
    u.set_consent(True)
    assert "20261103" in u.update() and u.installed() == ("20261103", 1)
    assert "已是最新" in u.update()
    u2 = updater(c, FakeGitHub("20261110", make_zip(RULES_V2)))
    assert "20261110" in u2.update() and u2.installed() == ("20261110", 2)
    forge = [r for r in c.intel.rule_sets() if r.name.startswith(RULE_SET_NAME)]
    assert [(r.version, r.enabled) for r in forge] == [("20261110", True)]  # the old version is removed
    assert not u2.due()  # just checked


def test_wrong_digest_is_refused(make_container: MakeContainer) -> None:
    c = make_container([FakeEngine()])
    u = updater(c, FakeGitHub("20261103", make_zip(RULES_V1), digest="sha256:" + "0" * 64))
    u.set_consent(True)
    with pytest.raises(RuleUpdateError, match="SHA-256"):
        u.update()
    assert u.installed() is None


def test_missing_digest_is_refused(make_container: MakeContainer) -> None:
    c = make_container([FakeEngine()])
    u = updater(c, FakeGitHub("20261103", make_zip(RULES_V1), digest=""))
    u.set_consent(True)
    with pytest.raises(RuleUpdateError, match="SHA-256"):
        u.update()


def test_unexpected_archive_is_refused(make_container: MakeContainer) -> None:
    c = make_container([FakeEngine()])
    u = updater(c, FakeGitHub("20261103", make_zip(RULES_V1, member="../../evil.yar")))
    u.set_consent(True)
    with pytest.raises(RuleUpdateError, match="格式"):
        u.update()


def test_bad_rules_keep_the_old_ones(make_container: MakeContainer) -> None:
    c = make_container([FakeEngine()])
    u = updater(c, FakeGitHub("20261103", make_zip(RULES_V1)))
    u.set_consent(True)
    u.update()
    bad = updater(c, FakeGitHub("20261110", make_zip(b'import "console"\nrule x { condition: true }')))
    with pytest.raises(RuleUpdateError, match="保留原本"):
        bad.update()
    assert bad.installed() == ("20261103", 1)


def test_installed_rules_detect(make_container: MakeContainer, tmp_path: Path) -> None:
    from sentinelx.engines.yara_engine import YaraEngine

    c = make_container([FakeEngine()])
    u = updater(c, FakeGitHub("20261103", make_zip(RULES_V1)))
    u.set_consent(True)
    u.update()
    from sentinelx.core.cancel import CancelToken
    from sentinelx.core.models import ScanTarget
    from sentinelx.scanner.hashing import sha256_file
    from sentinelx.storage.rules_repository import RuleSetStore

    f = tmp_path / "t.bin"
    f.write_bytes(b"xx SX-RULE-TEST-ONE xx")
    eng = YaraEngine(RuleSetStore(c.db, c.paths.yara_rules_dir))
    t = ScanTarget(f, sha256_file(f), f.stat().st_size)
    r = eng.scan_batch([t], CancelToken())[t]
    assert r.detections and r.detections[0].severity_hint is Severity.HIGH  # score 85


# ---------------- whole-drive protection ----------------
def test_noise_filter() -> None:
    windir = os.environ.get("SystemRoot", r"C:\Windows")
    assert locations.noisy(windir + r"\System32\kernel32.dll")
    assert not locations.noisy(windir + r"\Temp\dropper.exe")
    assert locations.noisy(r"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Cache\Cache_Data\f_0001")
    assert locations.noisy(r"C:\pagefile.sys") and locations.noisy(r"D:\x\events.etl")
    assert not locations.noisy(r"C:\Users\u\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\a.lnk")
    assert not locations.noisy(r"D:\Games\setup.exe")


def test_fixed_drives_lists_c() -> None:
    drives = [str(d).upper() for d in locations.fixed_drives()]
    assert any(d.startswith("C:") for d in drives)


class Reg:
    HKEY_CURRENT_USER = REG_SZ = 1

    class K:
        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *a) -> None:  # type: ignore[no-untyped-def]
            pass

    def CreateKey(self, *_a):  # type: ignore[no-untyped-def]  # noqa: N802
        return self.K()

    OpenKey = CreateKey  # noqa: N815

    def SetValueEx(self, *a) -> None:  # type: ignore[no-untyped-def]  # noqa: N802
        pass

    def DeleteValue(self, *a) -> None:  # type: ignore[no-untyped-def]  # noqa: N802
        pass


def whole_drive_service(c: AppContainer, drive: Path, lock_areas: list[Path]) -> ProtectionService:
    return ProtectionService(c.paths, c.config, c.config_store, c.engines, ScanRepository(c.db),
                             ExclusionRepository(c.db), VerdictRepository(c.db), c.quarantine, c.audit, clamd=None,
                             removable=list, registry=Reg(), drives=lambda: [drive], lock_areas=lambda: lock_areas)


def test_whole_drive_watch_scans_anywhere_and_skips_noise(make_container: MakeContainer, tmp_path: Path) -> None:
    c = make_container([FakeEngine()])
    drive = tmp_path / "drive"
    deep = drive / "Games" / "Mods" / "x"
    deep.mkdir(parents=True)
    s = whole_drive_service(c, drive, [])
    s.start()
    try:
        assert s.status().folders == (f"磁碟 {drive.drive}：{drive}",)
        f = deep / "mod.dll"
        f.write_bytes(b"MZ harmless")
        noise = deep / "debug.log"
        noise.write_text("x")
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and s.status().scanned == 0:
            s.process_pending(time.monotonic() + 10)
            s.process_pending(time.monotonic() + 20)
            time.sleep(0.2)
        assert s.status().scanned >= 1  # a file deep in an unlisted folder was scanned
        assert all("debug.log" not in a.path for a in s.activity())
    finally:
        s.stop()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows ACLs")
def test_execution_lock_in_desktop_and_documents(make_container: MakeContainer, tmp_path: Path) -> None:
    from sentinelx.protection.exec_lock import can_execute

    c = make_container([FakeEngine()])
    drive, desktop, other = tmp_path / "drive", tmp_path / "drive" / "Desktop", tmp_path / "drive" / "Program Files"
    for d in (desktop, other):
        d.mkdir(parents=True)
    s = whole_drive_service(c, drive, [desktop])
    s.start()
    try:
        on_desk, elsewhere = desktop / "tool.exe", other / "app.exe"
        shutil.copyfile(PING, on_desk)
        shutil.copyfile(PING, elsewhere)
        s.notify_file(str(on_desk))
        s.notify_file(str(elsewhere))
        assert not can_execute(on_desk)  # files the user brings in are locked until checked
        assert can_execute(elsewhere)  # installers' own folders are never locked
    finally:
        s.stop()
    assert can_execute(on_desk)


def test_settings_have_whole_drive_on_by_default(make_container: MakeContainer) -> None:
    c = make_container([FakeEngine()])
    assert c.config.protection.watch_all_drives is True


def _unused(_: Any) -> None:  # keep imports honest for type checkers
    pass


def test_audit8_l3_download_only_from_the_official_address(make_container: MakeContainer) -> None:
    c = make_container([FakeEngine()])
    gh = FakeGitHub("20261103", make_zip(RULES_V1), url="https://example.com/yara-forge-rules-core.zip")
    u = updater(c, gh)
    u.set_consent(True)
    with pytest.raises(RuleUpdateError, match="官方位置"):
        u.update()
    assert gh.urls == [API_LATEST]  # nothing downloaded from the other address
