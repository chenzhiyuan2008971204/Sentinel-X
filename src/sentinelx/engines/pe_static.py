"""PE static analysis (pefile). Never loads or runs the analyzed file.

Non-PE files -> SKIPPED (not applicable). PE files -> metadata in `info`, plus anomaly
records. Anomalies are LOW/MEDIUM/INFO only and every explanation says an anomaly is not a
malware verdict. A missing signature is recorded as a fact in `info`, never as a detection.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pefile

from sentinelx.core.cancel import CancelToken
from sentinelx.core.enums import EngineOutcomeKind, Severity, SignatureStatus
from sentinelx.core.models import DetectionRecord, DetectionResult, EngineStatus, ScanTarget
from sentinelx.engines.authenticode import SignatureInfo, verify_signature

ENGINE_NAME = "PEStatic"
ENGINE_VERSION = f"1.0 (pefile {pefile.__version__})"
HIGH_ENTROPY = 7.2
PACKER_SECTIONS = frozenset({
    "UPX0", "UPX1", "UPX2", ".aspack", ".adata", "MPRESS1", "MPRESS2", ".petite",
    ".nsp0", ".nsp1", ".nsp2", "FSG!", ".themida", ".vmp0", ".vmp1", ".enigma1", ".enigma2",
})
MAX_IMPORT_FUNCS = 300
MAX_WARNINGS = 20
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000
NOT_A_VERDICT = "此為結構特徵，不代表檔案是惡意程式。"
_ONE_DAY = timedelta(days=1)

_MACHINES = {0x14C: "x86", 0x8664: "x64", 0xAA64: "ARM64", 0x1C4: "ARMNT"}
_SUBSYSTEMS = {1: "Native", 2: "Windows GUI", 3: "Windows Console", 9: "Windows CE", 10: "EFI Application",
               11: "EFI Boot Driver", 12: "EFI Runtime Driver", 14: "Xbox", 16: "Windows Boot"}

Verifier = Callable[[Path], SignatureInfo]


def _section_name(s: Any) -> str:
    return s.Name.rstrip(b"\x00").decode("latin-1", "replace")


class PEStaticEngine:
    name = ENGINE_NAME

    def __init__(self, *, verifier: Verifier = verify_signature, now: Callable[[], datetime] | None = None) -> None:
        self._verify = verifier
        self._now = now or (lambda: datetime.now(UTC))

    def availability(self, refresh: bool = False) -> EngineStatus:
        return EngineStatus(ENGINE_NAME, True, version=ENGINE_VERSION, rules_version="anomaly-rules-1",
                            detail="PE 靜態分析（不執行檔案；只提供結構證據，不能單獨判定惡意）",
                            detection_capable=False)

    def scan_batch(self, targets: Sequence[ScanTarget], cancel: CancelToken) -> dict[ScanTarget, DetectionResult]:
        out: dict[ScanTarget, DetectionResult] = {}
        for t in targets:
            cancel.raise_if_cancelled()
            started = time.monotonic()
            try:
                res = self.analyze(t)
            except OSError as exc:
                out[t] = DetectionResult(ENGINE_NAME, EngineOutcomeKind.ERROR, ENGINE_VERSION, "anomaly-rules-1",
                                         error=f"無法讀取檔案：{exc.strerror or exc}")
                continue
            except Exception as exc:  # noqa: BLE001 - parser bug on hostile input must be an error, not clean
                out[t] = DetectionResult(ENGINE_NAME, EngineOutcomeKind.ERROR, ENGINE_VERSION, "anomaly-rules-1",
                                         error=f"PE 分析失敗：{type(exc).__name__}: {exc}")
                continue
            out[t] = replace(res, duration_ms=int((time.monotonic() - started) * 1000))
        return out

    def analyze(self, t: ScanTarget) -> DetectionResult:
        base: dict[str, Any] = dict(engine_name=ENGINE_NAME, engine_version=ENGINE_VERSION,
                                    rules_version="anomaly-rules-1")
        with open(t.path, "rb") as f:
            magic = f.read(2)
        if magic != b"MZ":
            return DetectionResult(kind=EngineOutcomeKind.SKIPPED, info={"is_pe": False}, **base)

        try:
            pe = pefile.PE(str(t.path), fast_load=True)
        except pefile.PEFormatError as exc:
            det = self._det(t, "PE.Malformed", Severity.LOW,
                            f"檔案以 MZ 開頭但 PE 結構無法解析（{exc}）。可能是 DOS 程式、損壞的檔案或刻意變形的檔案。{NOT_A_VERDICT}",
                            {"error": str(exc)})
            return DetectionResult(kind=EngineOutcomeKind.FINDINGS, detections=(det,),
                                   info={"is_pe": False, "parse_error": str(exc)}, **base)
        try:
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"],
            ])
            info, dets = self._inspect(pe, t)
        finally:
            pe.close()

        sig = self._verify(t.path)
        info["signature"] = {"status": sig.status.value, "message": sig.message,
                             "code": f"0x{sig.code:08X}" if sig.code is not None else None,
                             "source": sig.source}
        if sig.status is SignatureStatus.INVALID:
            dets.append(self._det(t, "PE.Signature.Invalid", Severity.MEDIUM,
                                  f"數位簽章存在但驗證失敗：{sig.message}。{NOT_A_VERDICT}",
                                  {"code": info["signature"]["code"]}))
        kind = EngineOutcomeKind.FINDINGS if dets else EngineOutcomeKind.NO_FINDINGS
        return DetectionResult(kind=kind, detections=tuple(dets), info=info, **base)

    def _inspect(self, pe: pefile.PE, t: ScanTarget) -> tuple[dict[str, Any], list[DetectionRecord]]:
        fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
        dets: list[DetectionRecord] = []
        ts = fh.TimeDateStamp
        ts_iso = datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if ts else None
        ep = oh.AddressOfEntryPoint
        is_dotnet = hasattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR")

        sections = []
        ep_section = None
        for s in pe.sections:
            name = _section_name(s)
            entropy = round(s.get_entropy(), 3)
            chars = s.Characteristics
            writable, executable = bool(chars & IMAGE_SCN_MEM_WRITE), bool(chars & IMAGE_SCN_MEM_EXECUTE)
            sections.append({"name": name, "virtual_address": hex(s.VirtualAddress), "virtual_size": s.Misc_VirtualSize,
                             "raw_size": s.SizeOfRawData, "entropy": entropy,
                             "writable": writable, "executable": executable})
            if s.contains_rva(ep):
                ep_section = name
            if writable and executable:
                dets.append(self._det(t, "PE.Anomaly.WritableExecutableSection", Severity.LOW,
                                      f"區段 {name} 同時可寫入與可執行，常見於自我修改或加殼程式，部分正常程式也有。{NOT_A_VERDICT}",
                                      {"section": name}))
            if entropy > HIGH_ENTROPY and s.SizeOfRawData > 1024:
                dets.append(self._det(t, "PE.Anomaly.HighEntropySection", Severity.LOW,
                                      f"區段 {name} 亂度 {entropy}（> {HIGH_ENTROPY}），內容可能經過壓縮或加密；安裝程式與壓縮資源也常見。{NOT_A_VERDICT}",
                                      {"section": name, "entropy": entropy}))
            if name in PACKER_SECTIONS:
                dets.append(self._det(t, "PE.Anomaly.PackerSectionName", Severity.LOW,
                                      f"區段名稱 {name} 符合已知加殼工具。加殼本身是合法技術。{NOT_A_VERDICT}",
                                      {"section": name}))

        if ep and ep_section is None:
            dets.append(self._det(t, "PE.Anomaly.EntryPointOutsideSections", Severity.MEDIUM,
                                  f"程式進入點 {hex(ep)} 不在任何區段內，屬於不尋常的結構。{NOT_A_VERDICT}",
                                  {"entry_point": hex(ep)}))

        imports: dict[str, list[str]] = {}
        total_funcs = 0
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = entry.dll.decode("latin-1", "replace") if entry.dll else "?"
            names = []
            for imp in entry.imports:
                total_funcs += 1
                if total_funcs <= MAX_IMPORT_FUNCS:
                    names.append(imp.name.decode("latin-1", "replace") if imp.name else f"#{imp.ordinal}")
            imports[dll] = names
        if not imports and not is_dotnet and not pe.is_dll():
            dets.append(self._det(t, "PE.Anomaly.NoImports", Severity.LOW,
                                  f"執行檔沒有匯入任何函式，可能是加殼或手動解析 API；部分特殊程式也會這樣。{NOT_A_VERDICT}", {}))

        if ts and datetime.fromtimestamp(ts, UTC) > self._now().replace(microsecond=0) + _ONE_DAY:
            dets.append(self._det(t, "PE.Anomaly.FutureTimestamp", Severity.INFO,
                                  f"編譯時間戳記 {ts_iso} 在未來。可重現建置（reproducible build）常把它設成雜湊值，不一定可疑。{NOT_A_VERDICT}",
                                  {"timestamp": ts_iso}))

        exports = len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else 0
        version_info: dict[str, str] = {}
        for fi in getattr(pe, "FileInfo", []) or []:
            for entry in fi:
                for st in getattr(entry, "StringTable", []):
                    for k, v in st.entries.items():
                        version_info[k.decode("latin-1", "replace")] = v.decode("utf-8", "replace")[:200]
        overlay_off = pe.get_overlay_data_start_offset()
        try:
            imphash = pe.get_imphash() or None
        except Exception:  # noqa: BLE001 - imphash is optional metadata
            imphash = None

        info: dict[str, Any] = {
            "is_pe": True,
            "machine": _MACHINES.get(fh.Machine, hex(fh.Machine)),
            "is_64bit": oh.Magic == 0x20B,
            "is_dll": pe.is_dll(),
            "is_driver": pe.is_driver(),
            "is_dotnet": is_dotnet,
            "subsystem": _SUBSYSTEMS.get(oh.Subsystem, str(oh.Subsystem)),
            "compile_timestamp": ts_iso,
            "entry_point": hex(ep),
            "entry_point_section": ep_section,
            "image_base": hex(oh.ImageBase),
            "sections": sections,
            "imports": imports,
            "import_function_count": total_funcs,
            "export_count": exports,
            "imphash": imphash,
            "version_info": version_info,
            "overlay_bytes": (t.size - overlay_off) if overlay_off else 0,
            "has_security_directory": bool(
                oh.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].Size
            ),
            "parser_warnings": pe.get_warnings()[:MAX_WARNINGS],
        }
        return info, dets

    @staticmethod
    def _det(t: ScanTarget, rule: str, sev: Severity, text: str, evidence: dict[str, Any]) -> DetectionRecord:
        return DetectionRecord(ENGINE_NAME, ENGINE_VERSION, rule, sev, evidence, t.sha256, text)
