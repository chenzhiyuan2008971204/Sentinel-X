"""Centralized exception hierarchy.

Every error raised deliberately by Sentinel X derives from SentinelXError so callers
(and the global exception handler) can tell expected failures from bugs.
"""

from __future__ import annotations


class SentinelXError(Exception):
    """Base class for all Sentinel X errors.

    `user_message` is safe to show in the GUI (zh-TW); `str(exc)` is the technical detail.
    """

    user_message: str = "發生未預期的錯誤。"

    def __init__(self, detail: str, *, user_message: str | None = None) -> None:
        super().__init__(detail)
        if user_message is not None:
            self.user_message = user_message


class ConfigError(SentinelXError):
    user_message = "設定檔無法讀取或內容無效。"


class DatabaseError(SentinelXError):
    user_message = "資料庫發生錯誤。"


class AuditIntegrityError(DatabaseError):
    user_message = "稽核紀錄的雜湊鏈不一致，紀錄可能遭到竄改。"


class PrivilegeError(SentinelXError):
    user_message = "無法判斷或變更執行權限。"
