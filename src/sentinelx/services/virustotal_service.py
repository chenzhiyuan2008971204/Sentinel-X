"""VirusTotal settings for the GUI: consent, the encrypted API key, a connection test.

The key is typed by the user into the settings page and saved encrypted (DPAPI). It is never
logged, never written to the audit log and never shown again; the audit log only records that a
key was saved or removed.
"""

from __future__ import annotations

from dataclasses import dataclass

from sentinelx.app.config import AppConfig, ConfigStore
from sentinelx.core.enums import AuditActor
from sentinelx.core.secret_store import SecretFile
from sentinelx.engines.virustotal import EICAR_SHA256, PER_DAY, VirusTotalEngine, VtClient, VtError
from sentinelx.storage.audit import AuditLog

SIGNUP_URL = "https://www.virustotal.com/gui/join-us"
KEY_PAGE_URL = "https://www.virustotal.com/gui/my-apikey"


@dataclass(frozen=True)
class VtStatus:
    consented: bool
    has_key: bool
    active: bool
    used_today: int
    per_day: int


class VirusTotalService:
    def __init__(self, config: AppConfig, store: ConfigStore, audit: AuditLog, secret: SecretFile) -> None:
        self._config = config
        self._store = store
        self._audit = audit
        self._secret = secret
        self.client: VtClient | None = None
        self.engine: VirusTotalEngine | None = None

    def attach(self, client: VtClient, engine: VirusTotalEngine) -> None:
        self.client, self.engine = client, engine

    # ---- state ----
    def key(self) -> str | None:
        return self._secret.load() if self._config.virustotal.consented else None

    def enabled(self) -> bool:
        return self._config.virustotal.consented and self._config.engines.virustotal and self._secret.exists()

    def status(self) -> VtStatus:
        return VtStatus(self._config.virustotal.consented, self._secret.exists(), self.enabled(),
                        self.client.used_today() if self.client else 0, PER_DAY)

    # ---- user actions ----
    def set_consent(self, on: bool) -> None:
        self._config.virustotal.consented = on
        self._store.save(self._config)
        self._audit.record("VIRUSTOTAL_CONSENT", actor=AuditActor.USER, detail={"consent": on})

    def save_key(self, key: str) -> None:
        key = key.strip()
        if not (len(key) == 64 and all(c in "0123456789abcdefABCDEF" for c in key)):
            raise ValueError("API 金鑰格式不正確：應該是 64 個英文字母或數字（0-9、a-f）。")
        self._secret.save(key)
        self._audit.record("VIRUSTOTAL_KEY_SAVED", actor=AuditActor.USER, detail={"stored": "DPAPI"})

    def delete_key(self) -> None:
        self._secret.delete()
        self._audit.record("VIRUSTOTAL_KEY_REMOVED", actor=AuditActor.USER)

    def test_connection(self) -> str:
        """Look up the EICAR test file's hash (a harmless, well-known test file). Raises ValueError."""
        if self.engine is None or not self.enabled():
            raise ValueError("請先勾選同意並儲存 API 金鑰。")
        try:
            rep = self.engine.report(EICAR_SHA256, use_cache=False)
        except VtError as exc:
            raise ValueError(exc.reason) from exc
        return (f"連線成功。測試檔 EICAR：{rep['engines_total']} 家防毒中 {rep['malicious']} 家判定惡意"
                "（這是預期的結果，代表查詢正常）。")
