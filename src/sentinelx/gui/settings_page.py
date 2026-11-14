"""Settings page: scan limits, engines, behaviour monitoring and logging.

Every control maps to a field of `AppConfig`; nothing here is decorative. The page says
honestly when a change takes effect (after a restart, or at the next monitoring start) and
offers the restart. Settings that are not implemented (other UI languages) are not shown.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import QLocale, Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from sentinelx.app.config import AppConfig
from sentinelx.gui import theme
from sentinelx.gui.confirm import Confirm, ask
from sentinelx.gui.widgets import BusyBar, muted, title
from sentinelx.gui.workers import TaskRunner
from sentinelx.services.settings_service import SettingsService
from sentinelx.services.signature_service import MIRROR, SignatureService, UpdateResult
from sentinelx.services.virustotal_service import KEY_PAGE_URL, SIGNUP_URL, VirusTotalService
from sentinelx.services.rule_update_service import RuleUpdateError, RuleUpdateService

Opener = Callable[[Path], bool]
Restarter = Callable[[], bool]


def _open(path: Path) -> bool:
    return QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))


def _restart_app() -> bool:
    from PySide6.QtWidgets import QApplication

    from sentinelx.app.instance import restart

    if not restart():
        return False
    QApplication.quit()
    return True


# No thousands separators: at UI font sizes "," and "." look alike, and a limit must not be misread.
_LOCALE = QLocale("zh_TW")


def _spin(lo: int, hi: int) -> QSpinBox:
    s = QSpinBox()
    s.setLocale(_LOCALE)
    s.setRange(lo, hi)
    s.setGroupSeparatorShown(False)
    return s


class SettingsPage(QWidget):
    def __init__(self, service: SettingsService, confirm: Confirm = ask, opener: Opener = _open,
                 restarter: Restarter = _restart_app, signatures: SignatureService | None = None,
                 virustotal: VirusTotalService | None = None,
                 rule_updates: RuleUpdateService | None = None) -> None:
        super().__init__()
        self.setObjectName("page_settings")
        self._svc = service
        self._sig = signatures
        self.runner = TaskRunner(self)
        self.confirm = confirm
        self.opener = opener
        self.restarter = restarter

        outer = QVBoxLayout(self)
        outer.setContentsMargins(32, 28, 32, 20)
        outer.setSpacing(10)
        outer.addWidget(title(self.tr("設定")))
        outer.addWidget(muted(self.tr("大部分人只需要看最上面的「病毒碼」。其他是進階設定，用預設值就好；"
                                      "改了要按下方「儲存變更」，部分設定要重新啟動才生效。")))
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        body = QWidget()
        lay = QVBoxLayout(body)
        lay.setContentsMargins(0, 0, 8, 0)
        lay.setSpacing(14)
        if signatures is not None:
            lay.addWidget(self._signature_group())
        self._vt = virustotal
        if virustotal is not None:
            lay.addWidget(self._vt_group())
        self._rules = rule_updates
        if rule_updates is not None:
            lay.addWidget(self._rules_group())
        advanced = QLabel(self.tr("進階設定（不確定的話不用改）"))
        advanced.setObjectName("sectionTitle")
        lay.addWidget(advanced)
        for group, text in (
            (self._scan_group(), "掃描時的限制。太大的檔案不會被完整檢查，結果會標示「未完成評估」，不會當成安全。"),
            (self._engine_group(), "用來判斷檔案的檢查方式。ClamAV 用病毒碼比對；YARA 用規則；雜湊情報比對已知檔案；"
                                   "PE 分析看程式結構。建議全部開啟。"),
            (self._monitor_group(), "「行為監控」頁面使用的設定：觀察電腦上的程式和連線，只記錄不阻擋。"),
            (self._general_group(), "程式記錄的詳細程度，以及資料存放的位置。"),
        ):
            form = group.layout()
            if isinstance(form, QFormLayout):
                form.insertRow(0, muted(self.tr(text)))
            lay.addWidget(group)
        lay.addStretch(1)
        scroll.setWidget(body)
        outer.addWidget(scroll, 1)

        row = QHBoxLayout()
        self.save_button = QPushButton(self.tr("儲存變更"))
        self.save_button.clicked.connect(self.save)
        self.discard_button = QPushButton(self.tr("捨棄變更"))
        self.discard_button.clicked.connect(self.reload)
        self.defaults_button = QPushButton(self.tr("填入預設值"))
        self.defaults_button.clicked.connect(self.fill_defaults)
        self.restart_button = QPushButton(self.tr("重新啟動 Sentinel X"))
        self.restart_button.clicked.connect(self.restart)
        for b in (self.save_button, self.discard_button, self.defaults_button):
            row.addWidget(b)
        row.addStretch(1)
        row.addWidget(self.restart_button)
        outer.addLayout(row)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        self.status_label.setTextFormat(Qt.TextFormat.PlainText)
        outer.addWidget(self.status_label)
        self.reload()

    # ---------- groups ----------
    def _scan_group(self) -> QGroupBox:
        g = QGroupBox(self.tr("掃描"))
        f = QFormLayout(g)
        f.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.FieldsStayAtSizeHint)
        self.max_size = _spin(1, 4096)
        self.max_depth = _spin(1, 1024)
        self.max_files = _spin(1, 2_147_483_647)  # QSpinBox maximum
        self.engine_timeout = _spin(1, 3600)
        self.yara_timeout = _spin(1, 3600)
        self.follow_links = QCheckBox(self.tr("跟隨符號連結與交接點（只跟隨指向掃描範圍內的連結）"))
        f.addRow(self.tr("單檔大小上限（MB）"), self.max_size)
        f.addRow(self.tr("最大資料夾深度"), self.max_depth)
        f.addRow(self.tr("每次掃描檔案上限"), self.max_files)
        f.addRow(self.tr("引擎逾時（秒）"), self.engine_timeout)
        f.addRow(self.tr("YARA 比對逾時（秒）"), self.yara_timeout)
        f.addRow("", self.follow_links)
        f.addRow("", muted(self.tr("超過大小上限的檔案會列為「未完成評估」，不會被當成乾淨。單一 YARA 比對無法中途停止，"
                                   "較短的 YARA 逾時能讓取消與關閉更快。")))
        return g

    def _engine_group(self) -> QGroupBox:
        g = QGroupBox(self.tr("偵測引擎"))
        f = QFormLayout(g)
        self.use_clamav = QCheckBox("ClamAV")
        self.use_yara = QCheckBox("YARA")
        self.use_intel = QCheckBox(self.tr("雜湊情報"))
        self.use_pe = QCheckBox(self.tr("PE 靜態分析"))
        boxes = QHBoxLayout()
        for cb in (self.use_clamav, self.use_yara, self.use_intel, self.use_pe):
            boxes.addWidget(cb)
        boxes.addStretch(1)
        f.addRow(self.tr("啟用"), boxes)
        self.backend = QComboBox()
        self.backend.addItem(self.tr("clamscan（每批啟動一次，預設）"), "clamscan")
        self.backend.addItem(self.tr("clamd（連到本機已啟動的服務）"), "clamd")
        f.addRow(self.tr("ClamAV 執行方式"), self.backend)
        self.clamscan_path = QLineEdit()
        self.clamscan_path.setPlaceholderText(self.tr("空白 = 自動尋找"))
        f.addRow(self.tr("clamscan.exe 路徑"), self._with_browse(self.clamscan_path, folder=False))
        self.db_dir = QLineEdit()
        self.db_dir.setPlaceholderText(self.tr("空白 = 資料資料夾中的 clamav-db，否則用 ClamAV 預設位置"))
        f.addRow(self.tr("病毒碼資料夾"), self._with_browse(self.db_dir, folder=True))
        self.clamd_host = QLineEdit()
        self.clamd_port = _spin(1, 65535)
        hp = QHBoxLayout()
        hp.addWidget(self.clamd_host, 1)
        hp.addWidget(QLabel(self.tr("連接埠")))
        hp.addWidget(self.clamd_port)
        f.addRow(self.tr("clamd 主機（僅限本機）"), hp)
        return g

    def _signature_group(self) -> QGroupBox:
        g = QGroupBox(self.tr("病毒碼（ClamAV）"))
        v = QVBoxLayout(g)
        self.sig_status = QLabel()
        self.sig_status.setWordWrap(True)
        self.sig_status.setTextFormat(Qt.TextFormat.PlainText)
        v.addWidget(self.sig_status)
        assert self._sig is not None
        self.sig_consent = QCheckBox(self.tr("允許從 ClamAV 官方伺服器（{0}，Cisco Talos 營運）下載病毒碼").format(MIRROR))
        self.sig_consent.setChecked(self._sig.consented)
        self.sig_consent.toggled.connect(self._consent_changed)
        v.addWidget(self.sig_consent)
        self.sig_auto = QCheckBox(self.tr("每天自動更新病毒碼（Sentinel X 執行中或在系統匣時）"))
        self.sig_auto.setChecked(self._sig.auto_update)
        self.sig_auto.toggled.connect(self._auto_changed)
        v.addWidget(self.sig_auto)
        v.addWidget(muted(self.tr("必須先勾選上方的同意才會連網。第一次約數百 MB，之後每天通常只下載幾 MB。"
                                  "下載內容只有 ClamAV 病毒碼，不會傳送你的檔案。自動更新失敗會在 2 小時後重試，並在系統匣通知。")))
        self.sig_schedule = QLabel()
        self.sig_schedule.setObjectName("muted")
        self.sig_schedule.setWordWrap(True)
        v.addWidget(self.sig_schedule)
        row = QHBoxLayout()
        self.sig_update_button = QPushButton(self.tr("立即更新病毒碼"))
        self.sig_update_button.clicked.connect(self.start_signature_update)
        row.addWidget(self.sig_update_button)
        row.addStretch(1)
        v.addLayout(row)
        self.sig_busy = BusyBar(self.runner)
        v.addWidget(self.sig_busy)
        self.sig_output = QLabel()
        self.sig_output.setWordWrap(True)
        self.sig_output.setTextFormat(Qt.TextFormat.PlainText)
        self.sig_output.setObjectName("muted")
        v.addWidget(self.sig_output)
        self.runner.busy_changed.connect(lambda _b: self.refresh_signatures())
        return g

    def _vt_group(self) -> QGroupBox:
        g = QGroupBox(self.tr("VirusTotal（查詢全球 70 多家防毒的判斷）"))
        v = QVBoxLayout(g)
        v.addWidget(muted(self.tr(
            "檢查程式、安裝檔、壓縮檔與文件時，把檔案的「指紋」（SHA-256）送到 VirusTotal，看其他防毒公司怎麼判斷。"
            "只送指紋，不會上傳檔案本身。免費帳號每分鐘 4 次、每天 500 次，超過時該檔案只是不查，不影響其他檢查。")))
        self.vt_consent = QCheckBox(self.tr("允許把檔案的 SHA-256 送到 virustotal.com 查詢"))
        self.vt_consent.toggled.connect(self._vt_consent_changed)
        v.addWidget(self.vt_consent)
        steps = QHBoxLayout()
        self.vt_signup_button = QPushButton(self.tr("1. 註冊免費帳號"))
        self.vt_signup_button.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(SIGNUP_URL)))
        self.vt_keypage_button = QPushButton(self.tr("2. 打開我的 API 金鑰頁面"))
        self.vt_keypage_button.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(KEY_PAGE_URL)))
        steps.addWidget(self.vt_signup_button)
        steps.addWidget(self.vt_keypage_button)
        steps.addStretch(1)
        v.addLayout(steps)
        row = QHBoxLayout()
        self.vt_key = QLineEdit()
        self.vt_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.vt_key.setPlaceholderText(self.tr("3. 貼上 API 金鑰（64 個字元）"))
        self.vt_save_button = QPushButton(self.tr("儲存金鑰"))
        self.vt_save_button.clicked.connect(self._vt_save)
        self.vt_delete_button = QPushButton(self.tr("刪除金鑰"))
        self.vt_delete_button.clicked.connect(self._vt_delete)
        self.vt_test_button = QPushButton(self.tr("4. 測試連線"))
        self.vt_test_button.clicked.connect(self.vt_test)
        row.addWidget(self.vt_key, 1)
        for b in (self.vt_save_button, self.vt_delete_button, self.vt_test_button):
            row.addWidget(b)
        v.addLayout(row)
        v.addWidget(muted(self.tr("金鑰以 Windows 加密（DPAPI）存在你的帳號下，只有你能解開；存好後不會再顯示。")))
        self.vt_status = QLabel()
        self.vt_status.setWordWrap(True)
        self.vt_status.setTextFormat(Qt.TextFormat.PlainText)
        v.addWidget(self.vt_status)
        self.runner.busy_changed.connect(lambda _b: self.refresh_vt())
        self.refresh_vt()
        return g

    def _rules_group(self) -> QGroupBox:
        g = QGroupBox(self.tr("YARA 規則（YARA Forge 公開規則）"))
        v = QVBoxLayout(g)
        v.addWidget(muted(self.tr(
            "YARA 規則是資安研究者寫的「病毒特徵描述」。YARA Forge 收集了許多資安團隊的規則並做過測試，"
            "這裡用的是誤判最少的「核心」版（約 5000 條）。同意後每週自動更新；下載會核對 GitHub 公布的檔案指紋。")))
        self.rules_consent = QCheckBox(self.tr("允許從 GitHub（YARAHQ/yara-forge）下載 YARA 規則"))
        self.rules_consent.toggled.connect(self._rules_consent_changed)
        v.addWidget(self.rules_consent)
        row = QHBoxLayout()
        self.rules_update_button = QPushButton(self.tr("立即更新 YARA 規則"))
        self.rules_update_button.clicked.connect(self.rules_update)
        row.addWidget(self.rules_update_button)
        row.addStretch(1)
        v.addLayout(row)
        self.rules_status = QLabel()
        self.rules_status.setWordWrap(True)
        self.rules_status.setTextFormat(Qt.TextFormat.PlainText)
        v.addWidget(self.rules_status)
        self.runner.busy_changed.connect(lambda _b: self.refresh_rules())
        self.refresh_rules()
        return g

    def refresh_rules(self) -> None:
        if self._rules is None:
            return
        on = self._rules.consented
        self.rules_consent.blockSignals(True)
        self.rules_consent.setChecked(on)
        self.rules_consent.blockSignals(False)
        cur = self._rules.installed()
        if cur:
            text, color = self.tr("使用中：版本 {0}，{1} 條規則。").format(*cur), theme.OK
        elif on:
            text, color = self.tr("已同意，還沒下載規則：按「立即更新 YARA 規則」。"), theme.WARN
        else:
            text, color = self.tr("未啟用：尚未同意下載。"), theme.TEXT_MUTED
        self.rules_status.setText(text)
        self.rules_status.setStyleSheet(f"color: {color};")
        self.rules_update_button.setEnabled(on and not self.runner.busy)

    def _rules_consent_changed(self, on: bool) -> None:
        assert self._rules is not None
        self._rules.set_consent(on)
        self.refresh_rules()

    def rules_update(self) -> None:
        if self._rules is None or self.runner.busy:
            return
        svc = self._rules

        def job(_c: object) -> object:
            try:
                return svc.update()
            except RuleUpdateError as exc:
                raise ValueError(exc.reason) from exc

        def done(r: object) -> None:
            self._status(str(r), theme.OK)
            self.refresh_rules()

        def failed(m: str) -> None:
            self._status(self.tr("YARA 規則更新失敗：{0}").format(m), theme.BAD)
            self.refresh_rules()

        self.runner.run(job, done, failed, self.tr("下載並檢查 YARA 規則…"), cancellable=False)

    def refresh_vt(self) -> None:
        if self._vt is None:
            return
        st = self._vt.status()
        self.vt_consent.blockSignals(True)
        self.vt_consent.setChecked(st.consented)
        self.vt_consent.blockSignals(False)
        if st.active:
            text, color = self.tr("已啟用：今天已查詢 {0}/{1} 次。").format(st.used_today, st.per_day), theme.OK
        elif not st.consented:
            text, color = self.tr("未啟用：尚未同意。"), theme.TEXT_MUTED
        else:
            text, color = self.tr("未啟用：還沒有儲存 API 金鑰。"), theme.WARN
        self.vt_status.setText(text)
        self.vt_status.setStyleSheet(f"color: {color};")
        busy = self.runner.busy
        self.vt_save_button.setEnabled(st.consented and not busy)
        self.vt_key.setEnabled(st.consented)
        self.vt_delete_button.setEnabled(st.has_key and not busy)
        self.vt_test_button.setEnabled(st.active and not busy)

    def _vt_consent_changed(self, on: bool) -> None:
        assert self._vt is not None
        self._vt.set_consent(on)
        self.refresh_vt()

    def _vt_save(self) -> None:
        assert self._vt is not None
        try:
            self._vt.save_key(self.vt_key.text())
        except ValueError as exc:
            self._status(str(exc), theme.BAD)
            return
        finally:
            self.vt_key.clear()  # never keep the key in the widget
        self._status(self.tr("API 金鑰已加密儲存。可以按「測試連線」確認。"), theme.OK)
        self.refresh_vt()

    def _vt_delete(self) -> None:
        assert self._vt is not None
        if not self.confirm(self, self.tr("刪除金鑰"), self.tr("確定要刪除已儲存的 VirusTotal API 金鑰嗎？刪除後不會再查詢。")):
            return
        self._vt.delete_key()
        self._status(self.tr("已刪除 API 金鑰。"), theme.OK)
        self.refresh_vt()

    def vt_test(self) -> None:
        if self._vt is None or self.runner.busy:
            return
        vt = self._vt

        def done(r: object) -> None:
            self._status(str(r), theme.OK)
            self.refresh_vt()

        def failed(m: str) -> None:
            self._status(self.tr("VirusTotal 測試失敗：{0}").format(m), theme.BAD)
            self.refresh_vt()

        self.runner.run(lambda _c: vt.test_connection(), done, failed, self.tr("連線到 VirusTotal…"), cancellable=False)

    def refresh_signatures(self) -> None:
        if self._sig is None:
            return
        st = self._sig.status()
        if st.freshclam is None:
            text = self.tr("找不到 freshclam.exe：ClamAV 尚未安裝，或 clamscan 路徑設定錯誤。")
        elif st.present:
            text = self.tr("病毒碼資料夾：{0}\n檔案：{1}\n最後更新（UTC）：{2}").format(
                st.database_dir, "、".join(st.files), st.newest)
        elif st.engine_ready:
            text = self.tr("ClamAV 目前使用其他位置的病毒碼，可以正常使用。\n"
                           "要改由 Sentinel X 管理，可下載到：{0}").format(st.database_dir)
        else:
            text = self.tr("病毒碼資料夾：{0}\n尚未下載病毒碼：在下載之前，ClamAV 無法使用。").format(st.database_dir)
        self.sig_status.setText(text)
        self.sig_status.setStyleSheet(f"color: {theme.OK if (st.present or st.engine_ready) else theme.WARN};")
        self.sig_update_button.setEnabled(not self.runner.busy and self._sig.consented and st.freshclam is not None)
        self.sig_auto.setEnabled(self._sig.consented)
        if not self._sig.consented:
            sched = self.tr("自動更新：尚未同意下載，不會連網。")
        elif not self._sig.auto_update:
            sched = self.tr("自動更新：已關閉。")
        elif self._sig.updating:
            sched = self.tr("自動更新：正在更新…")
        else:
            nxt = self._sig.next_auto()
            sched = self.tr("自動更新：開啟。上次成功（UTC）：{0}；下次（UTC）：{1}").format(
                self._sig.last_success or self.tr("尚無"), nxt or self.tr("啟動約 1 分鐘後"))
        self.sig_schedule.setText(sched)

    def _auto_changed(self, on: bool) -> None:
        assert self._sig is not None
        if on != self._sig.auto_update:
            self._sig.set_auto_update(on)
        self.refresh_signatures()

    def _consent_changed(self, on: bool) -> None:
        assert self._sig is not None
        if on != self._sig.consented:
            self._sig.set_consent(on)
        self.refresh_signatures()

    def start_signature_update(self) -> None:
        if self._sig is None or self.runner.busy:
            return
        sig = self._sig
        self.sig_output.clear()

        def done(r: object) -> None:
            res: UpdateResult = r  # type: ignore[assignment]
            if res.ok:
                self._status(self.tr("病毒碼更新完成（{0} 秒）。").format(res.duration_s), theme.OK)
            else:
                self._status(self.tr("病毒碼更新失敗（freshclam 結束代碼 {0}），詳細內容見下方。").format(res.exit_code),
                             theme.BAD)
            self.sig_output.setText("\n".join(res.output_tail[-8:]))

        def failed(m: str) -> None:
            self._status(self.tr("病毒碼更新：{0}").format(m), theme.WARN)

        self.runner.run(lambda c: sig.update(c), done, failed,
                        self.tr("下載病毒碼中…（第一次約數百 MB，可能需要數分鐘）"))

    @property
    def busy(self) -> bool:
        return self.runner.busy

    def shutdown(self) -> None:
        self.runner.shutdown()

    def _monitor_group(self) -> QGroupBox:
        g = QGroupBox(self.tr("行為監控"))
        f = QFormLayout(g)
        self.poll = QDoubleSpinBox()
        self.poll.setLocale(_LOCALE)
        self.poll.setRange(1.0, 60.0)
        self.poll.setDecimals(1)
        self.retention = _spin(1_000, 10_000_000)
        f.addRow(self.tr("輪詢間隔（秒）"), self.poll)
        f.addRow(self.tr("保留事件數（超過時刪除最舊的）"), self.retention)
        self.src = {k: QCheckBox(t) for k, t in (
            ("processes", self.tr("程序")), ("network", self.tr("網路連線")), ("folders", self.tr("資料夾監看")),
            ("sysmon", "Sysmon"), ("security_log", self.tr("安全性記錄")), ("defender_log", "Defender"))}
        boxes = QHBoxLayout()
        for cb in self.src.values():
            boxes.addWidget(cb)
        boxes.addStretch(1)
        f.addRow(self.tr("資料來源"), boxes)
        f.addRow("", muted(self.tr("要監看的資料夾在「行為監控」頁面設定。")))
        return g

    def _general_group(self) -> QGroupBox:
        g = QGroupBox(self.tr("一般"))
        f = QFormLayout(g)
        self.log_level = QComboBox()
        for lv, text in (("INFO", "INFO（建議）"), ("DEBUG", "DEBUG（除錯，記錄較多）"), ("WARNING", "WARNING"),
                         ("ERROR", "ERROR")):
            self.log_level.addItem(text, lv)
        f.addRow(self.tr("記錄等級"), self.log_level)
        root = QLabel(str(self._svc.data_root))
        root.setTextFormat(Qt.TextFormat.PlainText)
        root.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        f.addRow(self.tr("資料位置"), root)
        btns = QHBoxLayout()
        self.open_data_button = QPushButton(self.tr("開啟資料資料夾"))
        self.open_data_button.clicked.connect(lambda: self._open(self._svc.data_root))
        self.open_logs_button = QPushButton(self.tr("開啟記錄資料夾"))
        self.open_logs_button.clicked.connect(lambda: self._open(self._svc.log_dir))
        btns.addWidget(self.open_data_button)
        btns.addWidget(self.open_logs_button)
        btns.addStretch(1)
        f.addRow("", btns)
        return g

    def _with_browse(self, edit: QLineEdit, *, folder: bool) -> QWidget:
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        h.addWidget(edit, 1)
        b = QPushButton(self.tr("選擇…"))

        def pick() -> None:
            if folder:
                p = QFileDialog.getExistingDirectory(self, self.tr("選擇資料夾"), edit.text())
            else:
                p, _ = QFileDialog.getOpenFileName(self, self.tr("選擇 clamscan.exe"), edit.text(), "clamscan.exe (*.exe)")
            if p:
                edit.setText(str(Path(p)))

        b.clicked.connect(pick)
        h.addWidget(b)
        return w

    # ---------- data ----------
    def load(self, c: AppConfig) -> None:
        s = c.scan
        self.max_size.setValue(s.max_file_size_mb)
        self.max_depth.setValue(s.max_depth)
        self.max_files.setValue(min(s.max_files_per_job, self.max_files.maximum()))
        self.engine_timeout.setValue(s.engine_timeout_s)
        self.yara_timeout.setValue(s.yara_timeout_s)
        self.follow_links.setChecked(s.follow_reparse_points)
        e = c.engines
        self.use_clamav.setChecked(e.clamav)
        self.use_yara.setChecked(e.yara)
        self.use_intel.setChecked(e.hash_intel)
        self.use_pe.setChecked(e.pe_static)
        self.backend.setCurrentIndex(self.backend.findData(c.clamav.backend))
        self.clamscan_path.setText(c.clamav.clamscan_path or "")
        self.db_dir.setText(c.clamav.database_dir or "")
        self.clamd_host.setText(c.clamav.clamd_host)
        self.clamd_port.setValue(c.clamav.clamd_port)
        m = c.monitor
        self.poll.setValue(m.poll_interval_s)
        self.retention.setValue(m.retention_events)
        for k, cb in self.src.items():
            cb.setChecked(getattr(m, k))
        self.log_level.setCurrentIndex(self.log_level.findData(c.log_level))

    def form_config(self) -> AppConfig:
        """The configuration as shown in the form (fields not on the page come from the current one)."""
        c = self._svc.current()
        c.scan.max_file_size_mb = self.max_size.value()
        c.scan.max_depth = self.max_depth.value()
        if self.max_files.value() != min(c.scan.max_files_per_job, self.max_files.maximum()):
            c.scan.max_files_per_job = self.max_files.value()  # unchanged in the form: keep the stored value
        c.scan.engine_timeout_s = self.engine_timeout.value()
        c.scan.yara_timeout_s = self.yara_timeout.value()
        c.scan.follow_reparse_points = self.follow_links.isChecked()
        c.engines.clamav = self.use_clamav.isChecked()
        c.engines.yara = self.use_yara.isChecked()
        c.engines.hash_intel = self.use_intel.isChecked()
        c.engines.pe_static = self.use_pe.isChecked()
        c.clamav.backend = self.backend.currentData()
        c.clamav.clamscan_path = self.clamscan_path.text()
        c.clamav.database_dir = self.db_dir.text()
        c.clamav.clamd_host = self.clamd_host.text().strip()
        c.clamav.clamd_port = self.clamd_port.value()
        c.monitor.poll_interval_s = self.poll.value()
        c.monitor.retention_events = self.retention.value()
        for k, cb in self.src.items():
            setattr(c.monitor, k, cb.isChecked())
        c.log_level = self.log_level.currentData()
        return c

    def reload(self) -> None:
        self.load(self._svc.current())
        self.refresh_signatures()
        self._status(self.tr("顯示目前的設定。"), theme.TEXT_MUTED)
        self._update_restart()

    def fill_defaults(self) -> None:
        self.load(self._svc.defaults())
        self._status(self.tr("已填入預設值，按「儲存變更」才會套用。"), theme.WARN)

    def save(self) -> None:
        cfg = self.form_config()
        if cfg.scan.follow_reparse_points and not self._svc.current().scan.follow_reparse_points:
            if not self.confirm(self, self.tr("跟隨連結"), self.tr(
                    "開啟後，掃描會跟隨指向掃描範圍內的符號連結與交接點。範圍外的連結仍不會跟隨。\n\n確定要開啟嗎？")):
                self.follow_links.setChecked(False)
                return
        try:
            changed = self._svc.save(cfg)
        except ValueError as exc:
            self._status(self.tr("無法儲存：{0}").format(exc), theme.BAD)
            return
        if not changed:
            self._status(self.tr("沒有變更。"), theme.TEXT_MUTED)
            return
        msg = self.tr("已儲存 {0} 項變更。").format(len(changed))
        if self._svc.restart_pending:
            msg += self.tr("重新啟動 Sentinel X 後生效。")
        self._status(msg, theme.OK)
        self._update_restart()

    def restart(self) -> None:
        if not self.confirm(self, self.tr("重新啟動"), self.tr(
                "要重新啟動 Sentinel X 嗎？進行中的掃描與監控會停止。")):
            return
        if not self.restarter():
            self._status(self.tr("無法重新啟動，請手動關閉並重新開啟 Sentinel X。"), theme.BAD)

    def _open(self, path: Path) -> None:
        if not self.opener(path):
            self._status(self.tr("系統無法開啟 {0}").format(path), theme.BAD)

    def _update_restart(self) -> None:
        self.restart_button.setEnabled(self._svc.restart_pending)
        self.restart_button.setToolTip("" if self._svc.restart_pending else self.tr("目前沒有需要重新啟動才會生效的變更"))

    def _status(self, text: str, color: str) -> None:
        self.status_label.setText(text)
        self.status_label.setStyleSheet(f"color: {color};")
