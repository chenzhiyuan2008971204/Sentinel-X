"""Autostart watch: notices programs that newly set themselves to start with Windows.

Most malware makes itself start again after every restart ("persistence"). Sentinel X reads the
usual places, read-only, every 30 seconds:
- the Run / RunOnce registry keys (this user and all users, 32- and 64-bit views)
- the Startup folders (this user and all users)
- scheduled tasks (the task files in C:\\Windows\\System32\\Tasks when readable, otherwise
  Windows' Get-ScheduledTask, read every 5 minutes because it takes a few seconds)
- services that start automatically (HKLM\\SYSTEM\\CurrentControlSet\\Services)

The first reading is the baseline and is saved, so entries added while Sentinel X was not
running are found at the next start. Nothing is changed or removed here; new entries are
reported and their program is scanned by the caller. Not covered: other autostart places
(e.g. WMI subscriptions, browser extensions, Winlogon/AppInit values, drivers), tasks the user
may not read, and an entry that is added and removed again between two readings.
"""

from __future__ import annotations

import json
import logging
import ntpath
import os
import re
import threading
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)
INTERVAL_S = 30.0
MAX_TASK_FILES = 5000
MAX_TASK_BYTES = 256 * 1024
RUN_KEYS = (
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
)
SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"
_PROGRAM_SUFFIXES = (".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".scr",
                     ".com", ".cpl", ".lnk", ".jar", ".msi", ".pif")
# Programs that only start another file: the file they are given is what matters.
_HOSTS = {"rundll32.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
          "regsvr32.exe", "conhost.exe", "javaw.exe", "java.exe", "explorer.exe"}


@dataclass(frozen=True)
class AutostartEntry:
    location: str  # human-readable place, e.g. "登錄機碼 Run（目前使用者）"
    name: str
    command: str

    @property
    def key(self) -> str:
        return f"{self.location}|{self.name}|{self.command}".lower()

    def program(self) -> Path | None:
        return command_program(self.command)


def _expand(s: str) -> str:
    s = os.path.expandvars(s.strip())
    s = re.sub(r"^\\\?\?\\", "", s)  # \??\C:\...
    if s.lower().startswith("\\systemroot\\"):
        s = os.environ.get("SystemRoot", r"C:\Windows") + s[11:]
    elif s.lower().startswith("system32\\"):
        s = os.environ.get("SystemRoot", r"C:\Windows") + "\\" + s
    return s


def _split(command: str) -> list[str]:
    """Windows command line -> parts (quotes respected, no escaping rules beyond that)."""
    parts: list[str] = []
    for m in re.finditer(r'"([^"]*)"|(\S+)', command):
        parts.append(m.group(1) if m.group(1) is not None else m.group(2))
    return parts


def _resolve(token: str, exists: Callable[[str], bool]) -> str | None:
    token = _expand(token).strip().rstrip(",")
    if not token:
        return None
    if ntpath.isabs(token):
        return token
    if "\\" not in token and "/" not in token:  # bare name: look in System32 / Windows
        root = os.environ.get("SystemRoot", r"C:\Windows")
        for d in (ntpath.join(root, "System32"), root):
            for cand in (token, token + ".exe"):
                p = ntpath.join(d, cand)
                if exists(p):
                    return p
    return None


def command_program(command: str, exists: Callable[[str], bool] = os.path.exists) -> Path | None:
    """The file an autostart command starts. For script hosts (rundll32, powershell, wscript, ...)
    it is the script or DLL they are given, when one is named; otherwise the host itself."""
    cmd = _expand(command)
    parts = _split(cmd)
    if not parts:
        return None
    first = parts[0]
    # Unquoted path with spaces: C:\Program Files\App\app.exe /x
    if not cmd.lstrip().startswith('"') and not exists(first):
        low = cmd.lower()
        for suf in _PROGRAM_SUFFIXES:
            i = low.find(suf)
            if i > 0 and (i + len(suf) == len(low) or low[i + len(suf)] in ' ",'):
                first = cmd[: i + len(suf)].strip('"')
                parts = [first, *_split(cmd[i + len(suf):])]
                break
    host = _resolve(first, exists)
    if host is None:
        return None
    if ntpath.basename(host).lower() in _HOSTS:
        for arg in parts[1:]:
            a = arg.split(",")[0]
            if a.startswith(("-", "/")) or not a.lower().endswith(_PROGRAM_SUFFIXES):
                continue
            target = _resolve(a, exists)
            if target is not None:
                return Path(target)
    return Path(host)


# ---------------- reading the system (read-only) ----------------
def _registry_entries(reg: Any) -> list[AutostartEntry]:
    out: list[AutostartEntry] = []
    for hive, who in ((reg.HKEY_CURRENT_USER, "目前使用者"), (reg.HKEY_LOCAL_MACHINE, "所有使用者")):
        for sub in RUN_KEYS:
            kind = "RunOnce" if sub.endswith("RunOnce") else "Run"
            bits = "，32 位元" if "WOW6432Node" in sub else ""
            try:
                with reg.OpenKey(hive, sub) as k:
                    i = 0
                    while True:
                        try:
                            name, value, _t = reg.EnumValue(k, i)
                        except OSError:
                            break
                        i += 1
                        if isinstance(value, str) and value.strip():
                            out.append(AutostartEntry(f"登錄機碼 {kind}（{who}{bits}）", name, value))
            except OSError:
                continue
    return out


def _service_entries(reg: Any) -> list[AutostartEntry]:
    out: list[AutostartEntry] = []
    try:
        root = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, SERVICES_KEY)
    except OSError:
        return out
    with root:
        i = 0
        while True:
            try:
                name = reg.EnumKey(root, i)
            except OSError:
                break
            i += 1
            try:
                with reg.OpenKey(root, name) as k:
                    start = reg.QueryValueEx(k, "Start")[0]
                    typ = reg.QueryValueEx(k, "Type")[0]
                    image = reg.QueryValueEx(k, "ImagePath")[0]
            except OSError:
                continue
            # automatic, user-mode services (own process or shared); drivers are not read here
            if start == 2 and isinstance(typ, int) and typ & 0x30 and isinstance(image, str):
                out.append(AutostartEntry("服務（開機自動啟動）", name, image))
    return out


def _startup_entries(folders: list[Path]) -> list[AutostartEntry]:
    out: list[AutostartEntry] = []
    for d in folders:
        try:
            for p in sorted(d.iterdir()):
                if p.is_file() and p.name.lower() != "desktop.ini":
                    out.append(AutostartEntry("啟動資料夾", p.name, str(p)))
        except OSError:
            continue
    return out


def task_command(xml_bytes: bytes) -> str | None:
    """Command of a scheduled task file (first Exec action), or None."""
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return None
    for el in root.iter():
        if el.tag.endswith("Exec"):
            cmd = args = ""
            for c in el:
                if c.tag.endswith("Command"):
                    cmd = (c.text or "").strip()
                elif c.tag.endswith("Arguments"):
                    args = (c.text or "").strip()
            if cmd:
                quoted = cmd if cmd.startswith('"') else f'"{cmd}"'
                return f"{quoted} {args}".strip()
    return None


def _task_entries(tasks_dir: Path) -> list[AutostartEntry]:
    out: list[AutostartEntry] = []
    n = 0
    for dirpath, _dirs, files in os.walk(tasks_dir, onerror=lambda _e: None):
        for f in files:
            n += 1
            if n > MAX_TASK_FILES:
                return out
            p = Path(dirpath) / f
            try:
                if p.is_symlink() or p.stat().st_size > MAX_TASK_BYTES:
                    continue
                data = p.read_bytes()
            except OSError:
                continue  # many tasks are readable only by administrators
            cmd = task_command(data)
            if cmd:
                out.append(AutostartEntry("排程工作", "\\" + str(p.relative_to(tasks_dir)), cmd))
    return out


_TASKS_PS = ("$ErrorActionPreference='SilentlyContinue';"
             "@(Get-ScheduledTask | ?{ $_.State -ne 'Disabled' } | %{ $t=$_; $t.Actions | ?{ $_.Execute } | %{ "
             "[pscustomobject]@{n=$t.TaskPath+$t.TaskName; c=$_.Execute; a=$_.Arguments} } }) | ConvertTo-Json -Compress")


def powershell_tasks(run: Callable[[list[str]], str] | None = None) -> list[AutostartEntry]:
    """Scheduled tasks through Windows' own Get-ScheduledTask: unlike the task files, it works
    without administrator rights. About 3 seconds, so callers cache it (TaskCache)."""
    import subprocess  # noqa: PLC0415

    def _run(args: list[str]) -> str:
        r = subprocess.run(args, capture_output=True, timeout=60, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return r.stdout.decode("utf-8", "replace")

    root = os.environ.get("SystemRoot", r"C:\Windows")
    ps = ntpath.join(root, r"System32\WindowsPowerShell\v1.0\powershell.exe")
    out = (run or _run)([ps, "-NoProfile", "-NonInteractive", "-Command",
                         "[Console]::OutputEncoding=[Text.Encoding]::UTF8;" + _TASKS_PS])
    try:
        data = json.loads(out) if out.strip() else []
    except ValueError:
        return []
    if isinstance(data, dict):
        data = [data]
    entries = []
    for x in data:
        cmd, args = (x.get("c") or "").strip().strip('"'), (x.get("a") or "").strip()
        if cmd:
            quoted = cmd if cmd.startswith('"') else f'"{cmd}"'
            entries.append(AutostartEntry("排程工作", str(x.get("n") or ""), f"{quoted} {args}".strip()))
    return entries


class TaskCache:
    def __init__(self, read: Callable[[], list[AutostartEntry]] = powershell_tasks, ttl_s: float = 300.0,
                 clock: Callable[[], float] | None = None) -> None:
        import time  # noqa: PLC0415

        self._read, self._ttl, self._clock = read, ttl_s, clock or time.monotonic
        self._at: float | None = None
        self._value: list[AutostartEntry] = []

    def __call__(self) -> list[AutostartEntry]:
        now = self._clock()
        if self._at is None or now - self._at >= self._ttl:
            self._value, self._at = self._read(), now
        return self._value


_tasks = TaskCache()


def startup_folders() -> list[Path]:
    out = []
    appdata, progdata = os.environ.get("APPDATA"), os.environ.get("ProgramData")
    if appdata:
        out.append(Path(appdata) / r"Microsoft\Windows\Start Menu\Programs\Startup")
    if progdata:
        out.append(Path(progdata) / r"Microsoft\Windows\Start Menu\Programs\StartUp")
    return out


def read_entries(reg: Any = None, folders: list[Path] | None = None, tasks_dir: Path | None = None) -> list[AutostartEntry]:
    if reg is None:
        import winreg as reg  # noqa: PLC0415
    root = os.environ.get("SystemRoot", r"C:\Windows")
    entries = _registry_entries(reg) + _service_entries(reg)
    entries += _startup_entries(startup_folders() if folders is None else folders)
    task_files = _task_entries(tasks_dir or Path(root) / "System32" / "Tasks")
    # The task files are readable only with administrator rights; otherwise ask Windows.
    entries += task_files if task_files or tasks_dir is not None else _tasks()
    return entries


# ---------------- watching ----------------
class AutostartWatch:
    """Calls on_new(entry) for every autostart entry not in the saved baseline."""

    def __init__(self, baseline_file: Path, on_new: Callable[[AutostartEntry], None],
                 read: Callable[[], list[AutostartEntry]] = read_entries, interval_s: float = INTERVAL_S) -> None:
        self._file = baseline_file
        self._on_new = on_new
        self._read = read
        self._interval = interval_s
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._known: dict[str, AutostartEntry] | None = None
        self._check_lock = threading.Lock()  # one reading at a time (the thread and direct callers)
        self.last_error = ""

    def _load(self) -> dict[str, AutostartEntry] | None:
        try:
            data = json.loads(self._file.read_text(encoding="utf-8"))
            return {e.key: e for e in (AutostartEntry(**x) for x in data["entries"])}
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def _save(self) -> None:
        assert self._known is not None
        tmp = self._file.with_suffix(".tmp")
        tmp.write_text(json.dumps({"entries": [asdict(e) for e in self._known.values()]}, ensure_ascii=False),
                       encoding="utf-8")
        os.replace(tmp, self._file)

    def entries(self) -> list[AutostartEntry]:
        return sorted((self._known or {}).values(), key=lambda e: (e.location, e.name.lower()))

    def check_once(self) -> list[AutostartEntry]:
        """One reading. The first reading ever only records the baseline."""
        with self._check_lock:
            return self._check_once()

    def _check_once(self) -> list[AutostartEntry]:
        current = {e.key: e for e in self._read()}
        if self._known is None:
            self._known = self._load()
            if self._known is None:  # first run: everything present now is the baseline
                self._known = current
                self._save()
                return []
        new = [e for k, e in current.items() if k not in self._known]
        changed = new or len(current) != len(self._known) or current.keys() != self._known.keys()
        self._known = current  # removed entries are forgotten; if they come back they are new again
        if changed:
            self._save()
        for e in new:
            try:
                self._on_new(e)
            except Exception:  # noqa: BLE001 - one bad entry must not stop the watch
                log.exception("autostart handler failed for %s", e.name)
        return new

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="sentinelx-autostart", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(10)
            self._thread = None

    @property
    def running(self) -> bool:
        return self._thread is not None

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.check_once()
                self.last_error = ""
            except Exception as exc:  # noqa: BLE001
                self.last_error = str(exc)
                log.exception("autostart check failed")
            self._stop.wait(self._interval)
