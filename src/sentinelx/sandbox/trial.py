"""Trial runs in the sandbox VM, building and rebuilding the VM.

Layout (outside %LOCALAPPDATA% on purpose, in the user's profile):
    %USERPROFILE%\\SentinelX-Sandbox\\
        iso\\               the Windows evaluation ISO (kept for rebuilds)
        vm\\                VirtualBox files of the sandbox VM
        state.json         when the VM was built, from which ISO
        guest.pw           guest account password, encrypted with DPAPI
        runs\\              reports copied back from the VM

The guest account exists only inside a VM that has no network adapter, so its password only keeps
the VM's desktop locked; it is still encrypted at rest and written in plain text only for the
seconds a VBoxManage call needs it (VBoxManage reads it from a file), then deleted.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import shutil
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from sentinelx.core.cancel import CancelToken, ScanCancelled
from sentinelx.core.secret_store import SecretFile
from sentinelx.sandbox import vbox_version
from sentinelx.sandbox.vbox import VBox, VBoxError
from sentinelx.sandbox.vbox_version import Version, VersionCheck

log = logging.getLogger(__name__)

VM_NAME = "SentinelX-Sandbox"
GUEST_USER = "sxsandbox"
GUEST_DIR = r"C:\SX"
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
MONITOR = Path(__file__).with_name("guest_monitor.ps1")
MEMORY_MB = 4096
DISK_MB = 65536
HOSTNAME = "SXSANDBOX"
REBUILD_AFTER = timedelta(days=80)  # the evaluation lasts 90 days
EVAL_DAYS = 90
INSTALL_TIMEOUT_S = 5 * 3600  # 1 vCPU: copying Windows alone takes over an hour
DEFAULT_SECONDS = 120
TS = "%Y-%m-%dT%H:%M:%SZ"

Progress = Callable[[str], None]

_DRIVES = "C D E F G H I J K L M N O P"
# Run in the VM's Windows PE (see Sandbox._answer_template). Disk 0 is the VM's empty virtual disk.
DIRECT_INSTALL_COMMANDS = (
    'cmd.exe /c "(echo select disk 0&echo clean&echo convert gpt&echo create partition efi size=260'
    "&echo format quick fs=fat32 label=System&echo assign letter=S&echo create partition msr size=16"
    "&echo create partition primary&echo format quick fs=ntfs label=Windows&echo assign letter=W)"
    '>X:\\sx-disk.txt&diskpart /s X:\\sx-disk.txt"',
    f'cmd.exe /c "for %i in ({_DRIVES}) do @if exist %i:\\sources\\install.wim '
    'dism /apply-image /imagefile:%i:\\sources\\install.wim /index:1 /applydir:W:\\"',
    'cmd.exe /c "bcdboot W:\\Windows /s S: /f UEFI"',
    f'cmd.exe /c "mkdir W:\\Windows\\Panther&for %i in ({_DRIVES}) do @if exist %i:\\autounattend.xml '
    'copy /y %i:\\autounattend.xml W:\\Windows\\Panther\\unattend.xml"',
    # VirtualBox's post-install script and Guest Additions, so the first start needs no disc.
    f'cmd.exe /c "for %i in ({_DRIVES}) do @if exist %i:\\VBOXPOST.CMD (mkdir W:\\SXSetup'
    '&copy /y %i:\\VBOXPOST.CMD W:\\SXSetup\\&xcopy /e /i /y /q %i:\\vboxadditions W:\\SXSetup\\vboxadditions)"',
    # Windows runs SetupComplete.cmd with system rights at the end of setup, before anyone signs in:
    # the Guest Additions install and POST_INSTALL (account group, activation) need those rights.
    'cmd.exe /c "mkdir W:\\Windows\\Setup\\Scripts&(echo subst E: C:\\SXSetup'
    '&echo call C:\\SXSetup\\VBOXPOST.CMD --vista-or-newer&echo subst E: /d)'
    '>W:\\Windows\\Setup\\Scripts\\SetupComplete.cmd"',
    # Shut down instead of restarting: with the disc attached the firmware would start the installer
    # again. Sentinel X removes the disc and starts the VM from its disk (see Sandbox.build).
    "wpeutil shutdown",
)
# First sign-in, only if SetupComplete.cmd did not run (VBOXPOST.CMD writes that log). The copied
# folder stands in for the disc (VBOXPOST.CMD looks for E:\vboxadditions).
FIRST_LOGON = ("cmd.exe /c if not exist C:\\vboxpostinstall.log (subst E: C:\\SXSetup &amp; "
               "C:\\SXSetup\\VBOXPOST.CMD --vista-or-newer)")
# Run by VBOXPOST.CMD after the Guest Additions. Windows 11 24H2+ created the account in no group at
# all (seen in the VM), so it is added here; then the evaluation is activated online.
POST_INSTALL = (f"net localgroup Administrators {GUEST_USER} /add & net localgroup Users {GUEST_USER} /add & "
                "cscript //nologo C:\\Windows\\System32\\slmgr.vbs /ato")
ACTIVATION_TIMEOUT_S = 1800
SETUP_RESTART_S = 75 * 60  # running this long without the Guest Additions reporting: restart Windows once


def default_dir() -> Path:
    return Path(os.environ.get("USERPROFILE", str(Path.home()))) / "SentinelX-Sandbox"


@dataclass(frozen=True)
class SandboxStatus:
    virtualbox: str | None  # version, or None if not installed
    iso: Path | None
    vm_exists: bool
    ready: bool  # VM built and clean snapshot present
    built_at: str | None
    days_left: int | None  # of the 90-day evaluation
    rebuild_due: bool
    detail: str
    version_check: VersionCheck | None = None  # from the last known newest release; no network


class Sandbox:
    def __init__(self, base: Path | None = None, vbox: VBox | None = None, *, vm_name: str = VM_NAME,
                 now: Callable[[], datetime] = lambda: datetime.now(UTC),
                 latest: Callable[[], Version | None] | None = None) -> None:
        self.base = base or default_dir()
        self._latest = latest  # newest VirtualBox release; default: vbox_version.newest_release
        self.vbox = vbox or VBox()
        self.vm = vm_name
        self._now = now
        self._pw = SecretFile(self.base / "guest.pw")

    # ---------- state ----------
    def _state(self) -> dict[str, Any]:
        try:
            return json.loads((self.base / "state.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save_state(self, **kv: Any) -> None:
        self.base.mkdir(parents=True, exist_ok=True)
        st = self._state() | kv
        tmp = self.base / "state.json.tmp"
        tmp.write_text(json.dumps(st, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, self.base / "state.json")

    def guest_user(self) -> str:
        """The account trial runs use: the everyday user once the VM looks lived-in."""
        return str(self._state().get("guest_user") or GUEST_USER)

    def iso(self) -> Path | None:
        p = self._state().get("iso")
        if p and Path(p).is_file():
            return Path(p)
        found = list((self.base / "iso").glob("*.iso")) if (self.base / "iso").is_dir() else []
        # newest first: evaluation ISOs expire, and a fresh download replaces an older one
        return max(found, key=lambda f: (f.stat().st_mtime, f.name)) if found else None

    def check_virtualbox(self, *, online: bool = True, installed: str | None = None) -> VersionCheck:
        """Compare the installed VirtualBox with the newest release (audit 8, M6). With online=True
        the newest release is read again when the last reading is over a day old."""
        st = self._state()
        latest = vbox_version.parse(st.get("vbox_latest"))
        checked = st.get("vbox_checked")
        fresh = False
        if checked:
            try:
                age = (self._now() - datetime.strptime(checked, TS).replace(tzinfo=UTC)).total_seconds()
                fresh = 0 <= age < vbox_version.CHECK_EVERY_S
            except ValueError:
                pass
        if online and not fresh:
            got = (self._latest or vbox_version.newest_release)()
            if got is not None:
                latest, fresh = got, True
                self._save_state(vbox_latest=vbox_version.show(got), vbox_checked=self._now().strftime(TS))
        if installed is None:
            installed = self.vbox.version() if self.vbox.available else None
        return vbox_version.evaluate(installed, latest, checked_online=fresh)

    def _require_current_virtualbox(self, progress: Progress = lambda _m: None) -> None:
        chk = self.check_virtualbox()
        if not chk.ok:
            raise VBoxError(chk.message)
        if not chk.checked_online:
            progress("無法連線確認 VirtualBox 最新版，改用已知版本比較（你的版本不比它舊）…")

    def status(self) -> SandboxStatus:
        ver = self.vbox.version() if self.vbox.available else None
        chk = self.check_virtualbox(online=False, installed=ver) if ver else None
        iso = self.iso()
        exists = bool(ver) and self.vbox.exists(self.vm)
        ready = exists and self.vbox.has_snapshot(self.vm)
        built = self._state().get("built_at")
        days_left = due = None
        if built:
            age = self._now() - datetime.strptime(built, TS).replace(tzinfo=UTC)
            days_left = max(0, EVAL_DAYS - age.days)
            due = age >= REBUILD_AFTER
        if not ver:
            detail = "尚未安裝 VirtualBox。"
        elif chk is not None and not chk.ok:
            detail = chk.message
        elif not iso:
            detail = "找不到 Windows 安裝映像檔（ISO）。"
        elif not ready:
            detail = "試跑室還沒建立。"
        elif due:
            detail = f"試用期剩 {days_left} 天，需要重建。"
        else:
            detail = f"可以使用；Windows 試用期剩 {days_left} 天，到期前會自動重建。"
        return SandboxStatus(ver, iso, exists, ready, built, days_left, bool(due), detail, chk)

    # ---------- password file for VBoxManage ----------
    def _password(self) -> str:
        pw = self._pw.load()
        if not pw:
            pw = secrets.token_urlsafe(18)
            self.base.mkdir(parents=True, exist_ok=True)
            self._pw.save(pw)
        return pw

    class _PwFile:
        def __init__(self, sandbox: Sandbox) -> None:
            self.path = sandbox.base / f".pw-{uuid.uuid4().hex}"
            self._pw = sandbox._password()

        def __enter__(self) -> Path:
            self.path.write_text(self._pw, encoding="ascii")
            return self.path

        def __exit__(self, *exc: object) -> None:
            try:
                self.path.unlink()
            except OSError:
                pass

    # ---------- build ----------
    def build(self, progress: Progress = lambda _m: None, cancel: CancelToken | None = None) -> None:
        """Create the VM from the ISO with an unattended install, then save the clean snapshot.
        Takes 30-90 minutes. Any previous sandbox VM is deleted first."""
        cancel = cancel or CancelToken()
        iso = self.iso()
        if not self.vbox.available:
            raise VBoxError("沒有安裝 VirtualBox")
        if iso is None:
            raise VBoxError("找不到 Windows 安裝映像檔（ISO）")
        self._require_current_virtualbox()
        vm_dir = self.base / "vm"
        progress("刪除舊的試跑室…")
        self.vbox.unregister_delete(self.vm)
        if vm_dir.exists():
            shutil.rmtree(vm_dir, ignore_errors=True)
        vm_dir.mkdir(parents=True, exist_ok=True)
        v = self.vbox
        progress("建立虛擬機…")
        v.run("createvm", "--name", self.vm, "--ostype", "Windows11_64", "--register", "--basefolder", str(vm_dir))
        v.run("modifyvm", self.vm, "--memory", str(MEMORY_MB), "--cpus", "1",  # 2+ vCPUs hang in UEFI under Hyper-V (NEM)
              "--firmware", "efi64", "--tpm-type", "2.0",
              "--graphicscontroller", "vboxsvga", "--vram", "128", "--nic1", "none", "--audio-enabled", "off",
              "--clipboard-mode", "disabled", "--drag-and-drop", "disabled", "--usb-ohci", "off", "--usb-ehci", "off",
              "--usb-xhci", "off")
        for args in (("inituefivarstore",), ("enrollmssignatures",), ("enrollorclpk",), ("secureboot", "--enable")):
            v.run("modifynvram", self.vm, *args, check=False)
        disk = vm_dir / self.vm / "disk.vdi"
        v.run("createmedium", "disk", "--filename", str(disk), "--size", str(DISK_MB), "--format", "VDI")
        v.run("storagectl", self.vm, "--name", "SATA", "--add", "sata", "--controller", "IntelAhci", "--portcount", "2")
        v.run("storageattach", self.vm, "--storagectl", "SATA", "--port", "0", "--device", "0", "--type", "hdd",
              "--medium", str(disk))
        cancel.raise_if_cancelled()
        progress("自動安裝 Windows（約 1～2 小時，可以繼續用電腦）…")
        template = self._answer_template()
        extra = [f"--script-template={template}"] if template else []
        with self._PwFile(self) as pw:
            v.run("unattended", "install", self.vm, f"--iso={iso}", f"--user={GUEST_USER}", *extra,
                  f"--user-password-file={pw}", f"--admin-password-file={pw}", "--full-user-name=Sandbox",
                  "--install-additions", "--locale=en_US", "--country=US", "--time-zone=UTC",
                  f"--hostname={HOSTNAME}.local", f"--post-install-command={POST_INSTALL}", timeout=600)
        # Disk first: while it is empty the firmware falls through to the installer disc; after the
        # direct install (see _answer_template) it starts the new Windows instead of the installer again.
        v.run("modifyvm", self.vm, "--boot1", "disk", "--boot2", "dvd", "--boot3", "none", "--boot4", "none")
        v.start(self.vm)
        progress("把 Windows 複製到虛擬硬碟（1 顆 CPU，約 15～30 分鐘）…")
        if not self._wait(lambda: v.state(self.vm) == "poweroff", INSTALL_TIMEOUT_S, cancel, 15):
            raise VBoxError("複製 Windows 逾時")
        self._detach_installer_disc()
        # Network only while building: the evaluation must activate online with Microsoft, or it
        # reports "grace time expired" at once and powers off every hour (seen in the VM). No
        # sample exists yet; the adapter is removed again before the clean snapshot.
        v.run("modifyvm", self.vm, "--nic1", "nat")
        progress("第一次啟動新的 Windows，完成設定（約 20～40 分鐘）…")
        v.start(self.vm)
        self._running_since = self._clock()
        if not self._wait(self._ready_or_restart, INSTALL_TIMEOUT_S, cancel, 15):
            raise VBoxError("Windows 安裝逾時（超過 5 小時）")
        progress("等待 Windows 完成首次設定並向微軟啟用試用版…")
        self._wait(lambda: False, 180, cancel, 5)  # let first-logon tasks settle
        if not self._wait(self._activated, ACTIVATION_TIMEOUT_S, cancel, 60):
            raise VBoxError("Windows 試用版無法啟用（需要網路連到微軟）")
        progress("移除虛擬機的網路卡…")
        self._shutdown()
        v.run("modifyvm", self.vm, "--nic1", "none")
        v.start(self.vm)
        self._running_since = self._clock()
        if not self._wait(self._ready_or_restart, 3600, cancel, 15):
            raise VBoxError("移除網路卡後虛擬機沒有回應")
        self._wait(lambda: False, 120, cancel, 5)
        if (self.vbox.info(self.vm) or {}).get("nic1", "none") != "none":
            raise VBoxError("虛擬機仍有網路卡，不儲存快照")
        with self._PwFile(self) as pw:
            r = v.exec(self.vm, GUEST_USER, pw, r"C:\Windows\System32\cmd.exe", ["/c", f"mkdir {GUEST_DIR}"], 120)
            if r.code not in (0, 1):
                raise VBoxError("無法控制虛擬機（Guest Additions 未就緒）", r.err[-200:])
        progress("儲存乾淨快照…")
        # Snapshot of the shut-down VM: after restoring a running snapshot the Guest Additions
        # refused every guest session ("Failed to accept session ... VERR_NOT_FOUND", seen in the
        # VM). Each trial run starts Windows from a clean shutdown instead.
        self._shutdown()
        v.take_clean(self.vm)
        self._save_state(built_at=self._now().strftime(TS), iso=str(iso))
        progress("試跑室建立完成。")

    def _answer_template(self) -> Path | None:
        """VirtualBox's own Windows answer-file template, changed so Windows Setup's hardware check
        never runs. In the windowsPE pass (the installer's mini-system) the virtual disk is
        partitioned and Windows is copied onto it with Windows' own tools (diskpart, dism,
        bcdboot), the answer file is placed for the first start, and the VM restarts into the new
        Windows, which then finishes setup from that answer file as usual.
        Why: with Memory Integrity on, VirtualBox VMs only start with 1 CPU on this kind of host,
        and Windows 11 Setup refuses 1 CPU; Windows itself runs fine on 1. Everything happens
        inside the VM. None = use VirtualBox's template unchanged."""
        if self.vbox.exe is None:
            return None
        src = Path(self.vbox.exe).parent / "UnattendedTemplates" / "win_nt6_unattended.xml"
        try:
            text = src.read_text(encoding="utf-8")
        except OSError:
            return None
        pe_start = text.find('<settings pass="windowsPE">')
        pe_end = text.find("</settings>", pe_start)
        a_start = text.find("<RunAsynchronous>", pe_start)
        a_end = text.find("</RunAsynchronous>", a_start)
        if min(pe_start, pe_end, a_start, a_end) < 0 or a_end > pe_end:
            return None
        block = "<RunSynchronous>" + "".join(
            f'<RunSynchronousCommand wcm:action="add"><Order>{i}</Order><Path>{escape(c)}</Path></RunSynchronousCommand>'
            for i, c in enumerate(DIRECT_INSTALL_COMMANDS, 1)) + "</RunSynchronous>"
        text = text[:a_start] + block + text[a_end + len("</RunAsynchronous>"):]
        text = text.replace("cmd.exe /c @@VBOX_INSERT_AUXILIARY_INSTALL_DIR@@VBOXPOST.CMD --vista-or-newer", FIRST_LOGON)
        # Windows 11 24H2 put the account in no group at all for "administrators;users" (seen
        # inside the VM), so the Guest Additions installer had no rights. One group works.
        text = text.replace("<Group>administrators;users</Group>", "<Group>Administrators</Group>")
        out = self.base / "win_unattended.xml"
        out.write_text(text, encoding="utf-8")
        return out

    def _guest_responds(self) -> bool:
        """PowerShell actually starts in the guest. Right after the VM boots, the signed-in user is
        reported before that works, and starting PowerShell can exceed the Guest Additions' start
        limit ("Starting process failed with rc=VERR_TIMEOUT", seen in the VM)."""
        with self._PwFile(self) as pw:
            r = self.vbox.exec(self.vm, GUEST_USER, pw, POWERSHELL, ["-NoProfile", "-Command", "exit 0"], 120)
        return r.code == 0

    def _shutdown(self) -> None:
        """Shut Windows down cleanly from inside. The VM's Windows ignored the ACPI power button
        (seen: 10 minutes, then a hard power-off); "shutdown /s" took about a minute."""
        with self._PwFile(self) as pw:
            self.vbox.exec(self.vm, GUEST_USER, pw, r"C:\Windows\System32\shutdown.exe", ["/s", "/t", "0", "/f"], 60)
        if not self.vbox.wait_state(self.vm, ("poweroff",), 300):
            self.vbox.acpi_shutdown(self.vm)

    def _activated(self) -> bool:
        """Windows reports the evaluation as licensed (slmgr /dli, readable without elevation)."""
        with self._PwFile(self) as pw:
            r = self.vbox.exec(self.vm, GUEST_USER, pw, r"C:\Windows\System32\cscript.exe",
                               ["//nologo", r"C:\Windows\System32\slmgr.vbs", "/dli"], 120)
        return r.code == 0 and "License Status: Licensed" in r.out

    def _ready_or_restart(self) -> bool:
        """Guest signed in? During first setup the Guest Additions are installed after sign-in and
        only report the signed-in user after a restart; Windows may also power the VM off on its
        own (seen on the user's computer). A powered-off VM is started again."""
        if self.vbox.guest_ready(self.vm):
            return True
        now = self._clock()
        if self.vbox.state(self.vm) == "poweroff":
            self._restarts = getattr(self, "_restarts", 0) + 1
            if self._restarts > 5:
                raise VBoxError("虛擬機一直自己關機")
            self.vbox.start(self.vm)
            self._running_since = now
        elif now - getattr(self, "_running_since", now) > SETUP_RESTART_S:
            # Seen in the VM: the Guest Additions were installed at the end of setup, but their
            # service only starts after a restart, which nothing else triggers. Windows is shut
            # down cleanly; the next poll starts it again.
            self.vbox.run("controlvm", self.vm, "acpipowerbutton", timeout=60, check=False)
            self._running_since = now
        elif not hasattr(self, "_running_since"):
            self._running_since = now
        return False

    def _detach_installer_disc(self) -> None:
        """Remove the installer disc so the VM starts the copied Windows from its disk."""
        for key, value in (self.vbox.info(self.vm) or {}).items():
            if value.lower().endswith((".viso", ".iso")) and key.count("-") >= 2:
                ctl, port, dev = key.rsplit("-", 2)
                self.vbox.run("storageattach", self.vm, "--storagectl", ctl, "--port", port, "--device", dev,
                              "--medium", "none", timeout=120)

    # ---------- looking like a real, used computer ----------
    def _clock(self) -> float:
        import time

        return time.monotonic()

    def _wait(self, cond: Callable[[], bool], timeout: float, cancel: CancelToken, poll: float) -> bool:
        import time

        end = time.monotonic() + timeout
        while time.monotonic() < end:
            cancel.raise_if_cancelled()
            if cond():
                return True
            time.sleep(poll)
        return False

    # ---------- trial run ----------
    def run_file(self, sample: Path, seconds: int = DEFAULT_SECONDS, progress: Progress = lambda _m: None,
                 cancel: CancelToken | None = None) -> dict[str, Any]:
        """Run one file in a fresh copy of the VM and return the monitor's report (dict)."""
        cancel = cancel or CancelToken()
        if not self.status().ready:
            raise VBoxError("試跑室還沒建立")
        progress("檢查 VirtualBox 是否為最新版…")
        self._require_current_virtualbox(progress)
        v = self.vbox
        runs = self.base / "runs"
        runs.mkdir(parents=True, exist_ok=True)
        try:
            progress("還原乾淨的虛擬機…")
            v.restore_clean(self.vm)
            v.start(self.vm)
            if not self._wait(lambda: v.guest_ready(self.vm) and self._guest_responds(), 600, cancel, 5):
                raise VBoxError("虛擬機沒有在 10 分鐘內就緒")
            cancel.raise_if_cancelled()
            user = GUEST_USER
            token = "".join(secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(8))
            staged = runs / f"{token}.ps1"
            shutil.copyfile(MONITOR, staged)
            with self._PwFile(self) as pw:
                progress("把檔案放進虛擬機…")
                v.copy_to(self.vm, user, pw, staged, GUEST_DIR)
                try:
                    v.copy_to(self.vm, user, pw, sample, GUEST_DIR)
                except VBoxError:
                    # Defender in the VM may block or remove the file as it arrives; the monitor
                    # still runs and reports that detection.
                    log.info("sample copy into the sandbox failed; continuing to collect detections")
                progress(f"在虛擬機裡執行並觀察 {seconds} 秒…")
                guest_sample = f"{GUEST_DIR}\\{sample.name}"
                out = f"{GUEST_DIR}\\{token}.json"
                args = ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", f"{GUEST_DIR}\\{token}.ps1",
                        "-Sample", guest_sample, "-Seconds", str(seconds), "-OutJson", out, "-NoMouse"]
                for attempt in range(3):
                    r = v.exec(self.vm, user, pw, POWERSHELL, args, seconds + 600)
                    # Only a monitor that never started is tried again (the sample has not run then).
                    if not (r.code != 0 and "flags 0x1" in r.err):
                        break
                    log.info("sandbox monitor did not start (attempt %d); trying again", attempt + 1)
                    self._wait(lambda: False, 20, cancel, 5)
                cancel.raise_if_cancelled()
                dest = runs / uuid.uuid4().hex
                dest.mkdir()
                v.copy_from(self.vm, user, pw, out, dest)
            report = json.loads((dest / f"{token}.json").read_text(encoding="utf-8-sig"))
            if not isinstance(report, dict):
                raise VBoxError("試跑報告格式錯誤")
            return report
        except ScanCancelled:
            raise
        finally:
            progress("還原虛擬機（試跑過程的所有變更都會消失）…")
            try:
                v.restore_clean(self.vm)
            except VBoxError:
                log.exception("sandbox restore failed")
