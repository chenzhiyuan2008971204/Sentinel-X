"""Thin, testable wrapper around VBoxManage (VirtualBox's command-line tool).

Every call has a time limit and a fixed argument list (no shell). The command runner can be
replaced in tests, so the logic is verified without VirtualBox.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

CREATE_NO_WINDOW = 0x08000000
SNAPSHOT = "clean"


class VBoxError(Exception):
    """A VirtualBox command failed; `reason` is shown to the user (zh-TW)."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason} {detail}".strip())
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class Result:
    code: int
    out: str
    err: str


Runner = Callable[[Sequence[str], float], Result]


def find_vboxmanage() -> Path | None:
    for base in (os.environ.get("VBOX_MSI_INSTALL_PATH"), os.environ.get("VBOX_INSTALL_PATH"),
                 str(Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Oracle" / "VirtualBox")):
        if base:
            p = Path(base) / "VBoxManage.exe"
            if p.is_file():
                return p
    return None


def _default_runner(args: Sequence[str], timeout: float) -> Result:
    try:
        r = subprocess.run(list(args), stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout,
                           creationflags=CREATE_NO_WINDOW if sys.platform == "win32" else 0)
    except subprocess.TimeoutExpired as exc:
        raise VBoxError("VirtualBox 指令逾時", " ".join(args[1:3])) from exc
    except OSError as exc:
        raise VBoxError("無法執行 VirtualBox", str(exc)) from exc
    dec = lambda b: (b or b"").decode("utf-8", "replace")  # noqa: E731
    return Result(r.returncode, dec(r.stdout), dec(r.stderr))


def _as_dir(path: str) -> str:
    return path if path.endswith(("\\", "/")) else path + "\\"


class VBox:
    def __init__(self, exe: Path | None = None, runner: Runner | None = None) -> None:
        self.exe = exe or find_vboxmanage()
        self._run = runner or _default_runner

    @property
    def available(self) -> bool:
        return self.exe is not None

    def run(self, *args: str, timeout: float = 120, check: bool = True) -> Result:
        if self.exe is None:
            raise VBoxError("沒有安裝 VirtualBox")
        r = self._run([str(self.exe), *args], timeout)
        if check and r.code != 0:
            raise VBoxError("VirtualBox 指令失敗", (r.err or r.out).strip()[-400:])
        return r

    # ---- state ----
    def version(self) -> str | None:
        try:
            return self.run("--version", timeout=30).out.strip() or None
        except VBoxError:
            return None

    def info(self, vm: str) -> dict[str, str] | None:
        r = self.run("showvminfo", vm, "--machinereadable", timeout=60, check=False)
        if r.code != 0:
            return None
        out: dict[str, str] = {}
        for line in r.out.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                out[k.strip().strip('"')] = v.strip().strip('"')
        return out

    def exists(self, vm: str) -> bool:
        return self.info(vm) is not None

    def state(self, vm: str) -> str | None:
        i = self.info(vm)
        return i.get("VMState") if i else None

    def has_snapshot(self, vm: str, name: str = SNAPSHOT) -> bool:
        r = self.run("snapshot", vm, "list", "--machinereadable", timeout=60, check=False)
        return r.code == 0 and f'="{name}"' in r.out

    # ---- lifecycle ----
    def start(self, vm: str) -> None:
        self.run("startvm", vm, "--type", "headless", timeout=180)

    def poweroff(self, vm: str) -> None:
        if self.state(vm) in ("running", "paused", "stuck", "starting"):
            self.run("controlvm", vm, "poweroff", timeout=120, check=False)
            self.wait_state(vm, ("poweroff", "aborted", "saved"), 120)

    def acpi_shutdown(self, vm: str, timeout: float = 600) -> None:
        if self.state(vm) == "running":
            self.run("controlvm", vm, "acpipowerbutton", timeout=60, check=False)
            if not self.wait_state(vm, ("poweroff",), timeout):
                self.poweroff(vm)

    def wait_state(self, vm: str, states: Sequence[str], timeout: float, poll: float = 2.0) -> bool:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.state(vm) in states:
                return True
            time.sleep(poll)
        return False

    def restore_clean(self, vm: str) -> None:
        self.poweroff(vm)
        self.run("snapshot", vm, "restore", SNAPSHOT, timeout=300)

    def take_clean(self, vm: str) -> None:
        if self.has_snapshot(vm):
            self.run("snapshot", vm, "delete", SNAPSHOT, timeout=600)
        self.run("snapshot", vm, "take", SNAPSHOT, "--description", "Sentinel X clean state", timeout=600)

    def unregister_delete(self, vm: str) -> None:
        if self.exists(vm):
            self.poweroff(vm)
            self.run("unregistervm", vm, "--delete-all", timeout=600)

    # ---- guest control (needs Guest Additions) ----
    def guest_ready(self, vm: str) -> bool:
        r = self.run("guestproperty", "get", vm, "/VirtualBox/GuestInfo/OS/LoggedInUsers", timeout=30, check=False)
        return r.code == 0 and "Value:" in r.out and r.out.strip().split()[-1] not in ("0", "set")

    def wait_guest(self, vm: str, timeout: float, poll: float = 5.0) -> bool:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.guest_ready(vm):
                return True
            time.sleep(poll)
        return False

    def _cred(self, user: str, password_file: Path) -> list[str]:
        return ["--username", user, "--passwordfile", str(password_file)]

    # VirtualBox 7 treats a target without a trailing backslash as a file name and refuses an
    # existing folder ("already exists and is a directory"), so folders always end with "\".
    def copy_to(self, vm: str, user: str, pw: Path, src: Path, dest_dir: str) -> None:
        self.run("guestcontrol", vm, "copyto", *self._cred(user, pw), "--target-directory", _as_dir(dest_dir),
                 str(src), timeout=300)

    def copy_from(self, vm: str, user: str, pw: Path, src: str, dest_dir: Path) -> None:
        self.run("guestcontrol", vm, "copyfrom", *self._cred(user, pw), "--target-directory", _as_dir(str(dest_dir)),
                 src, timeout=300)

    def mkdir(self, vm: str, user: str, pw: Path, path: str) -> None:
        self.run("guestcontrol", vm, "mkdir", *self._cred(user, pw), "--parents", path, timeout=60)

    def exec(self, vm: str, user: str, pw: Path, exe: str, args: Sequence[str], timeout: float) -> Result:
        # VirtualBox 7.2 builds the program's command line from --exe itself; what follows "--" is
        # only the arguments. Repeating the program there (seen in the VM) made cscript and
        # PowerShell treat their own path as the script to run.
        return self.run("guestcontrol", vm, "run", *self._cred(user, pw), "--exe", exe,
                        "--timeout", str(int(timeout * 1000)), "--wait-stdout", "--wait-stderr", "--", *args,
                        timeout=timeout + 60, check=False)
