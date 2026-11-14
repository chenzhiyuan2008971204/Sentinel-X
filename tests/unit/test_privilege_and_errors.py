from __future__ import annotations

import sys
import threading

import pytest

from sentinelx.app.exception_handler import ExceptionHandler, user_message_for
from sentinelx.app.privilege import detect_privilege
from sentinelx.core.enums import PrivilegeLevel
from sentinelx.core.errors import ConfigError, DatabaseError, SentinelXError

pytestmark = pytest.mark.unit


def test_privilege_probe_mapping() -> None:
    assert detect_privilege(lambda: True) is PrivilegeLevel.ADMINISTRATOR
    assert detect_privilege(lambda: False) is PrivilegeLevel.STANDARD


def test_privilege_probe_failure_is_unknown_not_admin() -> None:
    def boom() -> bool:
        raise OSError("no token")

    assert detect_privilege(boom) is PrivilegeLevel.UNKNOWN


@pytest.mark.windows
@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
def test_real_privilege_detection_returns_known_level() -> None:
    assert detect_privilege() in (PrivilegeLevel.STANDARD, PrivilegeLevel.ADMINISTRATOR)


def test_error_hierarchy_and_messages() -> None:
    assert issubclass(ConfigError, SentinelXError)
    assert user_message_for(DatabaseError("x")) == DatabaseError.user_message
    assert user_message_for(SentinelXError("x", user_message="自訂")) == "自訂"
    assert "記錄檔" in user_message_for(RuntimeError("bug"))


def test_handler_logs_and_notifies(caplog: pytest.LogCaptureFixture) -> None:
    got: list[tuple[str, str]] = []
    h = ExceptionHandler(lambda m, d: got.append((m, d)))
    try:
        raise ConfigError("bad file")
    except ConfigError as exc:
        h.handle(type(exc), exc, exc.__traceback__)
    assert got == [(ConfigError.user_message, "ConfigError: bad file")]
    assert any(r.levelname == "CRITICAL" for r in caplog.records)


def test_handler_catches_thread_exceptions() -> None:
    got: list[str] = []
    h = ExceptionHandler(lambda m, d: got.append(d))
    h.install()
    try:
        t = threading.Thread(target=lambda: (_ for _ in ()).throw(RuntimeError("in thread")))
        t.start()
        t.join()
    finally:
        h.uninstall()
    assert got == ["RuntimeError: in thread"]
    assert threading.excepthook is not h._thread_hook


def test_notifier_failure_does_not_propagate() -> None:
    def bad(_m: str, _d: str) -> None:
        raise RuntimeError("notifier broke")

    h = ExceptionHandler(bad)
    exc = RuntimeError("original")
    h.handle(RuntimeError, exc, None)  # must not raise
