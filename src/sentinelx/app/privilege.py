"""Privilege detection and the user-triggered "restart as administrator".

The app always starts unelevated. Elevation only happens when the user presses the button,
through the normal Windows UAC prompt (ShellExecuteW "runas"). The relaunch passes a fixed,
internal argument list; nothing user- or file-derived is ever forwarded.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Callable

from sentinelx.core.enums import PrivilegeLevel

log = logging.getLogger(__name__)

ELEVATED_FLAG = "--elevated"


def _windows_is_admin() -> bool:
    import ctypes

    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def detect_privilege(probe: Callable[[], bool] | None = None) -> PrivilegeLevel:
    """Return the current privilege level; UNKNOWN when it cannot be determined."""
    if probe is None:
        if sys.platform != "win32":
            return PrivilegeLevel.UNKNOWN
        probe = _windows_is_admin
    try:
        return PrivilegeLevel.ADMINISTRATOR if probe() else PrivilegeLevel.STANDARD
    except Exception:  # noqa: BLE001 - any failure means "unknown", never "admin"
        log.warning("privilege probe failed", exc_info=True)
        return PrivilegeLevel.UNKNOWN


def elevation_command(executable: str, frozen: bool) -> tuple[str, str]:
    """(program, parameters) for the elevated relaunch. Fixed arguments only."""
    if frozen:
        return executable, ELEVATED_FLAG
    return executable, f"-m sentinelx {ELEVATED_FLAG}"


def relaunch_elevated() -> bool:
    """Ask Windows to start an elevated copy (UAC prompt). True if the request was accepted.
    The caller should then quit this instance."""
    import ctypes

    program, params = elevation_command(sys.executable, bool(getattr(sys, "frozen", False)))
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", program, params, None, 1)
    ok = int(rc) > 32  # <= 32 means error, including the user cancelling UAC
    log.info("elevation requested", extra={"ctx": {"accepted": ok, "code": int(rc)}})
    return ok
