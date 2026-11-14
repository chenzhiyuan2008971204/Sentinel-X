"""One instance per data folder (audit R16) and the restart command."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from sentinelx.app.instance import RESTARTED_FLAG, InstanceLock, restart_command

pytestmark = pytest.mark.gui


def test_lock_is_exclusive_and_released(tmp_path: Path) -> None:
    a, b = InstanceLock(tmp_path), InstanceLock(tmp_path)
    assert a.acquire() and not b.acquire()
    a.release()
    assert b.acquire()
    b.release()


def test_stale_lock_from_dead_process_is_taken(tmp_path: Path) -> None:
    code = ("import sys, os; from pathlib import Path; from sentinelx.app.instance import InstanceLock; "
            "l = InstanceLock(Path(sys.argv[1])); assert l.acquire(); os._exit(0)")  # exits without unlocking
    subprocess.run([sys.executable, "-c", code, str(tmp_path)], check=True, timeout=60)
    assert (tmp_path / "sentinelx.lock").exists()
    assert InstanceLock(tmp_path).acquire()


def test_restart_command_fixed_arguments() -> None:
    assert restart_command("py.exe", False) == ("py.exe", ["-m", "sentinelx", RESTARTED_FLAG])
    assert restart_command("SentinelX.exe", True) == ("SentinelX.exe", [RESTARTED_FLAG])


def test_second_instance_refused(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    held = InstanceLock(home)
    assert held.acquire()
    env = {**os.environ, "SENTINELX_HOME": str(home), "QT_QPA_PLATFORM": "offscreen"}
    try:
        rc = subprocess.run([sys.executable, "-m", "sentinelx", "--smoke-test", "200"], env=env,
                            capture_output=True, timeout=120).returncode
    finally:
        held.release()
    assert rc == 3
    rc2 = subprocess.run([sys.executable, "-m", "sentinelx", "--smoke-test", "200"], env=env,
                         capture_output=True, timeout=120).returncode
    assert rc2 == 0
