from __future__ import annotations

import logging
import os
from collections.abc import Callable, Iterator, Sequence

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from fakes import FakeEngine  # noqa: E402

from sentinelx.app.bootstrap import AppContainer, bootstrap  # noqa: E402
from sentinelx.app.paths import HOME_ENV, AppPaths  # noqa: E402
from sentinelx.core.enums import PrivilegeLevel  # noqa: E402
from sentinelx.engines.base import DetectionEngine  # noqa: E402
from sentinelx.storage.db import Database  # noqa: E402


def _drop_log_handlers() -> None:
    # Release the rotating log file so tmp_path can be cleaned up on Windows.
    root = logging.getLogger()
    for h in list(root.handlers):
        if getattr(h, "_sentinelx_handler", False):
            root.removeHandler(h)
            h.close()


@pytest.fixture
def app_paths(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> AppPaths:
    monkeypatch.setenv(HOME_ENV, str(tmp_path_factory.mktemp("sxhome") / "home"))
    return AppPaths.default()


@pytest.fixture
def db(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Database]:
    # Separate directory: tests scan tmp_path and must not see the DB/WAL files.
    d = Database(tmp_path_factory.mktemp("db") / "test.db")
    d.initialize()
    yield d
    d.dispose()


@pytest.fixture
def make_container(app_paths: AppPaths) -> Iterator[Callable[[Sequence[DetectionEngine]], AppContainer]]:
    made: list[AppContainer] = []

    def make(engines: Sequence[DetectionEngine]) -> AppContainer:
        c = bootstrap(app_paths, console_log=False, privilege=PrivilegeLevel.STANDARD, engines=engines)
        made.append(c)
        return c

    yield make
    for c in made:
        c.shutdown()
    _drop_log_handlers()


@pytest.fixture
def fake_engine() -> FakeEngine:
    return FakeEngine()


@pytest.fixture
def container(make_container: Callable[[Sequence[DetectionEngine]], AppContainer], fake_engine: FakeEngine) -> AppContainer:
    return make_container([fake_engine])


@pytest.fixture(autouse=True)
def _no_real_virtualbox(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests never touch the real sandbox VM; sandbox tests inject a fake VBoxManage runner."""
    monkeypatch.setattr("sentinelx.sandbox.vbox.find_vboxmanage", lambda: None)
    # ... and never ask the internet for the newest VirtualBox (tests that need it pass their own).
    monkeypatch.setattr("sentinelx.sandbox.vbox_version.newest_release", lambda: None)


@pytest.fixture(autouse=True)
def _no_real_autostart(monkeypatch: pytest.MonkeyPatch) -> None:
    """Protection tests never read this computer's autostart entries; autostart tests inject a reader."""
    monkeypatch.setattr("sentinelx.services.protection_service.read_entries", lambda: [])


@pytest.fixture(autouse=True)
def _no_real_user_folders(monkeypatch: pytest.MonkeyPatch) -> None:
    """Protection tests never watch this computer's Pictures, Videos, Music or OneDrive."""
    monkeypatch.setattr("sentinelx.protection.ransomware.user_folders", lambda: [])
