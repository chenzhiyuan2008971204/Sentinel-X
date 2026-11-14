# Sentinel X 研究版（Research Edition）

Windows 10／11 上的資安研究平台：多引擎掃描（ClamAV、YARA、雜湊情報、PE 靜態分析）、
有依據的風險判定與人工審查、安全的隔離區、被動行為監控、研究實驗室，以及含原始證據的 JSON／HTML／PDF 報告。
介面為繁體中文。

- 不保證偵測所有威脅；「未發現」不代表安全。
- 不執行被分析的檔案，不自動永久刪除（只有使用者在隔離區確認後才能刪除），不停用 Windows Defender，行為監控只觀察不動作。

## 文件

| 文件 | 內容 |
|---|---|
| [docs/USER_MANUAL.md](docs/USER_MANUAL.md) | 使用手冊（安裝、病毒碼、YARA 規則更新、各頁面） |
| [docs/DEVELOPER.md](docs/DEVELOPER.md) | 開發與打包 |
| [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md) | 第三方套件與授權 |
| [RELEASE_NOTES.md](RELEASE_NOTES.md) | 發行說明 |
| [QUALITY_REPORT.md](QUALITY_REPORT.md) | 最終品質報告（測試、已知與安全限制） |
| [SYSTEM_ARCHITECTURE.md](SYSTEM_ARCHITECTURE.md)、[SECURITY_DESIGN.md](SECURITY_DESIGN.md)、[DATABASE_SCHEMA.md](DATABASE_SCHEMA.md)、[TEST_STRATEGY.md](TEST_STRATEGY.md) | 設計文件 |
| [ENGINEERING_AUDIT.md](ENGINEERING_AUDIT.md)、[CHANGELOG.md](CHANGELOG.md) | 稽核紀錄與變更紀錄 |

## 快速開始（原始碼）

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m sentinelx
```

建置安裝檔：`.\.venv\Scripts\python.exe packaging\build.py`（需要 ClamAV 與 Inno Setup 6，見開發者說明）。

## 開發流程

本專案以分階段方式開發（`prompts/phase-*.md`，在 Claude Code 中以 `/phase N` 執行，`/audit` 進行工程稽核）。
`CLAUDE.md` 保存所有階段都必須遵守的規則。

## 授權（License）

Sentinel X 以 [GNU General Public License v3.0](LICENSE)（GPL-3.0-only）授權。
內附的第三方元件各自保留自己的授權，見 `docs/DEPENDENCIES.md` 與安裝目錄中的 `THIRD_PARTY_NOTICES.txt`
（例如 ClamAV 為 GPLv2，以未修改的獨立程式形式附帶）。

Sentinel X is licensed under the GNU General Public License v3.0 (GPL-3.0-only). Bundled third-party
components keep their own licenses (see `THIRD_PARTY_NOTICES.txt`).

## 下載與建置（Releases and builds）

正式安裝檔一律由 GitHub Actions 從本儲存庫的原始碼自動建置（`.github/workflows/build.yml`）：
執行全部自動測試、下載官方 ClamAV 並核對 SHA-256、打包並產生安裝檔。只從本專案的 GitHub Releases 下載安裝檔。

Release installers are built only by GitHub Actions from this repository's source
(`.github/workflows/build.yml`): all tests run, the official ClamAV release is downloaded and its
SHA-256 checked, then the package and installer are built. Download installers only from this
project's GitHub Releases.

## Code signing policy

Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by
[SignPath Foundation](https://signpath.org) — **applied for; not granted yet.** Until it is granted,
release installers are unsigned.

- Committers and reviewers: [repository members](../../graphs/contributors)
- Approvers: the repository owner
- Every signed release is built by GitHub Actions from this repository and approved manually.

## Privacy policy

Sentinel X does not send information about you or your computer anywhere on its own. It connects
to other systems only for the features below, and only after you turn the feature on or start it:

| Feature | Connects to | What is sent |
|---|---|---|
| Virus signature updates (ClamAV), after you agree in Settings | `database.clamav.net` (Cisco Talos) | Standard update requests; no files |
| VirusTotal hash lookups, after you agree and enter your own API key | `www.virustotal.com` | The SHA-256 of files; **files are never uploaded** |
| YARA Forge public rules, after you agree in Settings | `api.github.com`, `github.com` (YARAHQ/yara-forge) | Standard download requests |
| Trial-run room (VirtualBox), when you build it or start a trial run | `download.virtualbox.org` | A request for the newest VirtualBox version number (at most once a day) |

While the trial-run room is being built, its virtual machine is connected to the internet once to
activate the Windows evaluation with Microsoft; no file you test exists in it at that time, and the
network adapter is removed before any trial run. Sentinel X has no telemetry, no analytics and no
accounts. Scan results, quarantine and logs stay on your computer.

隱私：Sentinel X 不會自己把你或你電腦的資料傳出去；只有上表的功能在你開啟或執行時才會連線，
VirusTotal 只送出檔案的 SHA-256、不上傳檔案。沒有遙測、沒有分析、沒有帳號；掃描結果、隔離區與紀錄都只留在你的電腦。
