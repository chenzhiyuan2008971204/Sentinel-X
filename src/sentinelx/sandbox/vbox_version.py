"""Is the installed VirtualBox new enough to run unknown files in? (engineering audit 8, M6)

A trial run is only as safe as VirtualBox itself: a "VM escape" bug lets a program inside the VM
reach the real computer, and VirtualBox fixes such bugs in its maintenance releases. Before every
build and trial run, the installed version is compared with:

- OLDEST_ALLOWED: the release Sentinel X was verified with (VirtualBox 7.2.22, 2026-11-08). The
  trial-run code depends on VirtualBox 7.2 behaviour, and older releases miss security fixes.
- The newest stable release, read from Oracle's own one-line file LATEST-STABLE.TXT (HTTPS, fixed
  address, nothing about the computer is sent). Remembered for a day; when it cannot be read,
  the last known value (or OLDEST_ALLOWED) is used and the user is told it could not be checked.

An older VirtualBox stops the run with a message to update it. Nothing is installed or updated
automatically.
"""

from __future__ import annotations

import logging
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

log = logging.getLogger(__name__)

Version = tuple[int, int, int]

OLDEST_ALLOWED: Version = (7, 2, 22)
LATEST_URL = "https://download.virtualbox.org/virtualbox/LATEST-STABLE.TXT"
DOWNLOAD_PAGE = "https://www.virtualbox.org/wiki/Downloads"
CHECK_EVERY_S = 24 * 3600
_MAX_BYTES = 64

_VERSION = re.compile(r"^\s*(\d{1,3})\.(\d{1,3})\.(\d{1,4})")


def parse(text: str | None) -> Version | None:
    """'7.2.22r170000' or '7.2.22' -> (7, 2, 22); anything else -> None."""
    m = _VERSION.match(text or "")
    return (int(m[1]), int(m[2]), int(m[3])) if m else None


def show(v: Version) -> str:
    return ".".join(map(str, v))


def fetch_latest(opener: Callable[..., object] = urllib.request.urlopen, timeout: float = 15) -> Version | None:
    """The newest stable VirtualBox release from Oracle, or None if it cannot be read."""
    req = urllib.request.Request(LATEST_URL, headers={"User-Agent": "SentinelX-sandbox-check"})
    try:
        with opener(req, timeout=timeout) as r:  # type: ignore[attr-defined]
            if getattr(r, "geturl", lambda: LATEST_URL)() != LATEST_URL:
                return None  # redirected elsewhere: do not trust it
            text = r.read(_MAX_BYTES).decode("ascii", "replace")
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        log.info("could not read the newest VirtualBox version: %s", exc)
        return None
    # The whole file is one version number; anything else is not used.
    return parse(text) if re.fullmatch(r"\s*\d{1,3}\.\d{1,3}\.\d{1,4}\s*", text) else None


def newest_release() -> Version | None:
    """What the sandbox asks by default (tests replace this one, never fetch_latest)."""
    return fetch_latest()


@dataclass(frozen=True)
class VersionCheck:
    installed: Version | None
    required: Version  # the oldest version accepted now
    latest_known: Version | None  # newest stable release, if ever read
    checked_online: bool  # the newest release was read just now or within a day
    ok: bool

    @property
    def message(self) -> str:
        if self.installed is None:
            return "無法讀取 VirtualBox 的版本，為了安全不試跑。"
        if not self.ok:
            return (f"VirtualBox {show(self.installed)} 太舊，為了安全不試跑：舊版可能有讓虛擬機裡的程式跑到你電腦上的漏洞。"
                    f"請到 {DOWNLOAD_PAGE} 更新到 {show(self.required)} 或更新版本，再回來試跑。")
        if not self.checked_online and self.latest_known is None:
            return f"VirtualBox {show(self.installed)}；試跑前會先向官方網站確認是否為最新版。"
        if not self.checked_online:
            return (f"VirtualBox {show(self.installed)}；最近一天沒有確認到最新版（上次已知最新：{show(self.required)}），"
                    "試跑前會再確認一次，連不上網路時用已知版本比較。")
        return f"VirtualBox {show(self.installed)} 是最新版。"


def evaluate(installed_text: str | None, latest: Version | None, *, checked_online: bool) -> VersionCheck:
    installed = parse(installed_text)
    required = max(OLDEST_ALLOWED, latest) if latest else OLDEST_ALLOWED
    ok = installed is not None and installed >= required
    return VersionCheck(installed, required, latest, checked_online, ok)
