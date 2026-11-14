# 開發者說明

## 環境設定

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

## 執行

```powershell
.\.venv\Scripts\python.exe -m sentinelx
```

測試時不想動到正式資料，可設定 `SENTINELX_HOME` 指向其他資料夾：

```powershell
$env:SENTINELX_HOME = "$env:TEMP\sx-dev"; .\.venv\Scripts\python.exe -m sentinelx
```

## ClamAV（開發機）

```powershell
winget install --id Cisco.ClamAV -e
```

病毒碼放在使用者資料夾，不需要管理員權限：

```powershell
$db = "$env:LOCALAPPDATA\SentinelX\clamav-db"; New-Item -ItemType Directory -Force $db | Out-Null
"DatabaseDirectory $db`nDatabaseMirror database.clamav.net" | Set-Content -Encoding ascii "$env:LOCALAPPDATA\SentinelX\freshclam.conf"
& 'C:\Program Files\ClamAV\freshclam.exe' "--config-file=$env:LOCALAPPDATA\SentinelX\freshclam.conf"
```

Sentinel X 會自動使用 `%LOCALAPPDATA%\SentinelX\clamav-db`；也可在 `config.json` 的 `clamav.database_dir` 指定其他位置。
沒有 ClamAV 時，`needs_clamav` 標記的測試會被略過並列出原因。

## 測試

```powershell
.\.venv\Scripts\python.exe -m pytest -rs --cov=sentinelx
```

GUI 測試使用 Qt 的 offscreen 平台（conftest 自動設定），不會跳出視窗。
`-rs` 會列出所有被略過的測試及原因；略過不算通過。

## 研究實驗室與報告（Phase 7）

- PE 結構與簽章由獨立程序解析：`python -I -m sentinelx.research.worker <路徑> <大小上限>`（打包後為 `--research-worker`）。
  程序先把自己放進 Windows job object（記憶體 1 GB、不能再啟動程序），只輸出 JSON。可直接執行這個指令除錯。
- 報告文件模型在 `reporting/document.py`；`builders.py` 產生內容，`writers.py` 輸出 JSON／HTML／PDF。
  所有字串都視為不可信：HTML 靠 Jinja2 自動跳脫加 CSP，PDF 的段落先做 XML 跳脫。
- PDF 需要可嵌入的中文字型，見 `writers.font_candidates()`。

## 打包與安裝檔（Phase 9）

需要：專案 venv（含 `pyinstaller==6.22.3`）、已安裝的 ClamAV（`winget install Cisco.ClamAV`）、
Inno Setup 6（`winget install JRSoftware.InnoSetup --scope user`）。

```powershell
.\.venv\Scripts\python.exe packaging\build.py            # 資料夾版 + 安裝檔
.\.venv\Scripts\python.exe packaging\build.py --no-installer
powershell -ExecutionPolicy Bypass -File packaging\install_test.ps1 -Setup dist\SentinelX-0.9.1-setup.exe
.\.venv\Scripts\python.exe packaging\qa_measure.py        # 誤判、資源、介面回應時間的量測
```

- `packaging/sentinelx.spec`：PyInstaller 單一資料夾、無主控台視窗、不使用 UPX（減少防毒誤判）。
- `build.py` 只複製 ClamAV 執行所需的檔案（執行檔、DLL、憑證、授權），寫入 `clamav\SOURCE.txt`（GPL 原始碼位置）
  與 `THIRD_PARTY_NOTICES.txt`，並檢查：打包後的程式能啟動、獨立分析程序能從無主控台的執行檔回傳 JSON、內附 ClamAV 版本正確。
- `installer.iss`：只安裝給目前使用者（不需要系統管理員），解除安裝不刪除 `%LOCALAPPDATA%\SentinelX`。
- 打包後的程式以 `SentinelX.exe --research-worker` 啟動獨立分析程序，以 `--restarted`／`--elevated` 等待舊視窗交出執行鎖。
- 版本號只改兩處：`src/sentinelx/__init__.py` 與 `pyproject.toml`，並在 CHANGELOG 加上同版本的段落；
  `tests/unit/test_version_consistency.py` 會檢查三者一致。

## 分層規則

- `core`：純邏輯，不做 I/O，不 import GUI 或資料庫。
- `storage`：SQLAlchemy 模型與資料庫，`orm.py` 必須與 `DATABASE_SCHEMA.md` 一致。
- `services`：GUI 唯一可以呼叫的業務介面。
- `gui`：只負責顯示，不直接碰 `storage` 或引擎。
- `app/bootstrap.py`：唯一組裝具體實作的地方（依賴注入）。
