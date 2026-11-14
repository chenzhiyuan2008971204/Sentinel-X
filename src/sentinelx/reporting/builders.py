"""Build report documents from Research Lab results and stored scan evidence.

Every builder puts the readable view in `sections` and the unmodified source data in
`evidence`. Times are UTC (ISO-8601, as stored).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from typing import TYPE_CHECKING, Any

from sentinelx.core.enums import Classification, EngineOutcomeKind
from sentinelx.core.models import DetectionResult
from sentinelx.core.risk import CLASS_TEXT
from sentinelx.core.serialize import result_to_dict
from sentinelx.reporting.document import fields, new_document, table, text

if TYPE_CHECKING:
    from sentinelx.research.compare import Comparison
    from sentinelx.research.yara_lab import YaraTestRun
    from sentinelx.services.lab_service import HashLookup, SampleInspection
    from sentinelx.storage.research_repository import EvidenceRun, JobEvidence, StoredVerdict, TimelineEvent

OUTCOME_TEXT = {EngineOutcomeKind.FINDINGS: "有發現", EngineOutcomeKind.NO_FINDINGS: "未發現",
                EngineOutcomeKind.SKIPPED: "不適用", EngineOutcomeKind.ERROR: "無法評估"}
MAX_SECTION_ROWS = 1000
IMPORT_PREVIEW = 40


def _verdict_dict(v: StoredVerdict | None) -> dict[str, Any] | None:
    if v is None:
        return None
    d = asdict(v)
    d["classification"] = v.classification.value
    return d


def _detection_rows(results: list[tuple[str, int | None, DetectionResult]]) -> list[list[Any]]:
    rows: list[list[Any]] = []
    for when, job, r in results:
        ver = r.engine_version or "—"
        if r.detections:
            for d in r.detections:
                rows.append([when, job, r.engine_name, ver, r.rules_version, OUTCOME_TEXT[r.kind], d.rule_id,
                             d.severity_hint.value, d.timestamp, d.confidence_explanation])
        else:
            rows.append([when, job, r.engine_name, ver, r.rules_version, OUTCOME_TEXT[r.kind], r.error or "—",
                         "—", "—", "—"])
    return rows


DET_COLUMNS = ["掃描時間", "掃描 #", "引擎", "引擎版本", "規則／病毒碼版本", "結果", "規則 ID／錯誤", "嚴重度提示",
               "偵測時間", "說明"]


def _signature_sections(sig: dict[str, Any] | None, label: str = "") -> list[dict[str, Any]]:
    if not sig:
        return [text(f"數位簽章{label}", ["無法檢查簽章（分析程序失敗）。"])]
    out = [fields(f"數位簽章{label}", [
        ("狀態", sig.get("status")), ("說明", sig.get("message")), ("簽章來源", {"EMBEDDED": "內嵌簽章", "CATALOG": "系統目錄檔"}
                                                                   .get(sig.get("source") or "", "—")),
        ("目錄檔", sig.get("catalog_file")), ("驗證代碼", sig.get("code")), ("有時間戳記", sig.get("timestamped")),
        ("簽署時間（時間戳記）", sig.get("signing_time")), ("備註", sig.get("notes")),
    ])]
    chain = sig.get("chain") or []
    if chain:
        out.append(table(f"憑證鏈{label}（簽署者在前）", ["主體", "簽發者", "序號", "生效", "到期", "SHA-1 指紋"],
                         [[c["subject"], c["issuer"], c["serial"], c["not_before"], c["not_after"], c["sha1"]] for c in chain],
                         "未簽署或簽章無效本身不代表惡意；有效簽章也只證明檔案來源與未被竄改，不證明安全。"))
    return out


def _pe_sections(info: dict[str, Any], dets: list[dict[str, Any]], label: str = "") -> list[dict[str, Any]]:
    out = [fields(f"PE 標頭{label}", [
        ("架構", info.get("machine")), ("64 位元", info.get("is_64bit")), ("DLL", info.get("is_dll")),
        ("驅動程式", info.get("is_driver")), (".NET", info.get("is_dotnet")), ("子系統", info.get("subsystem")),
        ("編譯時間戳記", info.get("compile_timestamp")), ("進入點", info.get("entry_point")),
        ("進入點所在區段", info.get("entry_point_section")), ("映像基底", info.get("image_base")),
        ("imphash", info.get("imphash")), ("匯入 DLL 數", len(info.get("imports", {}))),
        ("匯入函式數", info.get("import_function_count")), ("匯出數", info.get("export_count")),
        ("附加資料（overlay）位元組", info.get("overlay_bytes")), ("有安全性目錄", info.get("has_security_directory")),
        ("解析器警告", info.get("parser_warnings")),
    ])]
    out.append(table(f"區段{label}", ["名稱", "虛擬位址", "虛擬大小", "原始大小", "亂度", "可寫入", "可執行"],
                     [[s["name"], s["virtual_address"], s["virtual_size"], s["raw_size"], s["entropy"], s["writable"],
                       s["executable"]] for s in info.get("sections", [])]))
    imports = info.get("imports", {})
    out.append(table(f"匯入{label}", ["DLL", "函式數", f"函式（前 {IMPORT_PREVIEW} 個）"],
                     [[dll, len(fn), ", ".join(fn[:IMPORT_PREVIEW]) + (" …" if len(fn) > IMPORT_PREVIEW else "")]
                      for dll, fn in imports.items()], "完整清單見原始證據。"))
    vi = info.get("version_info") or {}
    if vi:
        out.append(table(f"版本資訊{label}（由檔案自述，可被偽造）", ["欄位", "值"], [[k, v] for k, v in vi.items()]))
    out.append(table(f"結構特徵{label}", ["規則", "嚴重度提示", "說明"],
                     [[d["rule_id"], d["severity_hint"], d["confidence_explanation"]] for d in dets],
                     "結構特徵不是惡意判定，只是需要搭配其他證據解讀的事實。"))
    return out


def _yara_rows(run: YaraTestRun) -> list[list[Any]]:
    rows: list[list[Any]] = []
    for t in run.results:
        if t.error:
            rows.append([str(t.path), t.sha256, "—", "—", "—", t.error])
        elif not t.hits:
            rows.append([str(t.path), t.sha256, "（未命中）", "—", "—", "—"])
        for h in t.hits:
            strs = "; ".join(f"{s.identifier}@{s.offset}（{s.length} bytes）" for s in h.strings) or "（條件命中，無字串）"
            excerpt = "; ".join(f"{s.identifier}: {s.text}" for s in h.strings[:3])
            rows.append([str(t.path), t.sha256, h.rule, strs, excerpt, f"共 {h.string_instances} 處"])
    return rows


def yara_run_dict(run: YaraTestRun) -> dict[str, Any]:
    d = asdict(run)
    for t in d["results"]:
        t["path"] = str(t["path"])
    return d


def _timeline_table(tl: list[TimelineEvent]) -> dict[str, Any]:
    return table("分析時間軸（UTC）", ["時間", "類別", "事件", "細節"], [[e.at, e.category, e.title, e.detail] for e in tl])


def sample_report(lookup: HashLookup, inspection: SampleInspection | None, evidence: list[EvidenceRun],
                  timeline: list[TimelineEvent], yara_runs: list[YaraTestRun], versions: dict[str, Any]) -> dict[str, Any]:
    sha = lookup.sha256
    sections: list[dict[str, Any]] = []
    ev: dict[str, Any] = {"sha256": sha}
    if inspection is not None:
        f = inspection.facts
        sections.append(fields("樣本基本資料", [
            ("檔名", f.path.name), ("路徑", str(f.path)), ("大小（位元組）", f.size), ("MD5", f.md5), ("SHA-1", f.sha1),
            ("SHA-256", f.sha256), ("類型（依檔頭判斷）", f.file_type), ("修改時間（UTC）", f.modified),
            ("建立時間（UTC）", f.created), ("檢視時間（UTC）", inspection.inspected_at),
        ]))
        if f.motw:
            sections.append(table("下載來源標記（Zone.Identifier）", ["欄位", "值"], [[k, v] for k, v in f.motw.items()],
                                  "此標記由下載程式寫入，可被修改；ZoneId 3 代表來自網際網路。"))
        else:
            sections.append(text("下載來源標記（Zone.Identifier）", ["檔案沒有 Zone.Identifier 資料流。"]))
        ev["file"] = {**asdict(f), "path": str(f.path)}
    else:
        sections.append(fields("樣本基本資料", [("SHA-256", sha), ("說明", "只依雜湊值查詢資料庫，沒有檢視檔案本身。")]))

    sections.append(table("本機威脅情報", ["來源", "版本", "可信度", "分類", "標籤"],
                          [[m.source, m.source_version, m.trust.value, m.verdict.value, m.label] for m in lookup.intel],
                          "不在任何本機情報中代表「未知」，不代表安全。"))
    ev["intel"] = [{**asdict(m), "trust": m.trust.value, "verdict": m.verdict.value} for m in lookup.intel]

    if inspection is not None:
        sig = inspection.signature.to_dict() if inspection.signature else None
        sections += _signature_sections(sig)
        pe = inspection.pe
        if pe is not None and pe.info.get("is_pe"):
            sections += _pe_sections(pe.info, result_to_dict(pe)["detections"])
        elif pe is not None and pe.kind is EngineOutcomeKind.SKIPPED:
            sections.append(text("PE 結構", ["不是 PE 檔案，沒有 PE 結構可分析。"]))
        elif pe is not None:
            sections.append(text("PE 結構", [pe.error or "PE 結構無法解析。",
                                             *(d.confidence_explanation for d in pe.detections)]))
        sections.append(fields("分析程序", [
            ("隔離分析程序", "是（獨立程序，限制記憶體 1 GB，禁止再啟動其他程序）" if inspection.worker_confined else "否"),
            ("耗時（毫秒）", inspection.worker_ms), ("錯誤", inspection.worker_error),
            ("分析期間檔案內容改變", inspection.sha_changed),
        ]))
        ev["pe_result"] = result_to_dict(pe) if pe else None
        ev["signature"] = sig
        ev["worker"] = {"confined": inspection.worker_confined, "duration_ms": inspection.worker_ms,
                        "error": inspection.worker_error, "sha_changed": inspection.sha_changed}

    if lookup.latest is not None:
        path, v = lookup.latest
        sections.append(fields("目前判定（資料庫中最新）", [
            ("檔案路徑", path), ("分類", f"{CLASS_TEXT[v.classification]}（{v.classification.value}）"),
            ("信心", v.confidence), ("判定規則", v.assessor_version), ("判定時間（UTC）", v.created_at),
            ("說明", v.explanation),
        ]))
    else:
        sections.append(text("目前判定", ["資料庫中沒有此雜湊的判定（尚未掃描過）。研究實驗室本身不產生判定。"]))
    ev["latest_verdict"] = {"path": lookup.latest[0], **(_verdict_dict(lookup.latest[1]) or {})} if lookup.latest else None

    rows = _detection_rows([(e.scanned_at, e.job_id, e.result) for e in evidence])
    sections.append(table("已儲存的偵測證據", DET_COLUMNS, rows[:MAX_SECTION_ROWS],
                          "每一列為一次掃描中一個引擎的結果；版本為掃描當時記錄的版本。"
                          + (f" 只列出前 {MAX_SECTION_ROWS} 列。" if len(rows) > MAX_SECTION_ROWS else "")))
    ev["stored_evidence"] = [{"job_id": e.job_id, "scanned_at": e.scanned_at, "path": e.path,
                              "result": result_to_dict(e.result)} for e in evidence]

    for i, run in enumerate(yara_runs, 1):
        sections.append(table(f"YARA 規則測試 {i}", ["檔案", "SHA-256", "規則", "命中字串與位移", "內容片段", "備註"],
                              _yara_rows(run),
                              f"測試規則 SHA-256 {run.rule_sha256}，{run.rule_count} 條規則，libyara {run.yara_version}。"
                              "測試規則沒有加入掃描，也不影響任何判定。"))
    ev["yara_tests"] = [yara_run_dict(r) for r in yara_runs]

    sections.append(_timeline_table(timeline))
    ev["timeline"] = [asdict(e) for e in timeline]
    title = f"樣本研究報告：{inspection.facts.path.name}" if inspection else f"雜湊研究報告：{sha[:16]}…"
    return new_document("SAMPLE", title, "SAMPLE", sha, versions, sections, ev)


def comparison_report(cmp: Comparison, a: SampleInspection | None, b: SampleInspection | None,
                      versions: dict[str, Any]) -> dict[str, Any]:
    bd = cmp.bytes
    sections = [
        fields("比較對象", [("檔案 A", str(cmp.path_a)), ("A 的 SHA-256", cmp.sha256_a), ("A 大小", bd.size_a),
                         ("檔案 B", str(cmp.path_b)), ("B 的 SHA-256", cmp.sha256_b), ("B 大小", bd.size_b),
                         ("內容完全相同", cmp.identical)]),
        fields("位元組比較（相同位移）", [("第一個不同的位移", bd.first_difference), ("共同長度", bd.common_length),
                                   ("共同長度內不同的位元組", bd.differing_bytes),
                                   ("相同位移位元組相同比例", f"{bd.same_offset_ratio:.2%}"),
                                   ("說明", "只比較相同位移的位元組，不是相似度演算法；插入或刪除資料會讓之後的位移全部錯開。")]),
    ]
    if cmp.pe is not None:
        p = cmp.pe
        sections.append(table("PE 標頭差異", ["欄位", "A", "B"], [list(x) for x in p.fields]))
        status = {"only_a": "只在 A", "only_b": "只在 B", "changed": "不同", "same": "相同"}
        sections.append(table("區段差異", ["區段", "狀態", "A（原始大小／亂度）", "B（原始大小／亂度）"],
                              [[s.name, status[s.status],
                                f"{s.a['raw_size']}／{s.a['entropy']}" if s.a else "—",
                                f"{s.b['raw_size']}／{s.b['entropy']}" if s.b else "—"] for s in p.sections]))
        sections.append(table("匯入差異", ["DLL", "狀態", "B 新增的函式", "B 缺少的函式"],
                              [[i.dll, status[i.status], ", ".join(i.added), ", ".join(i.removed)] for i in p.imports]))
        sections.append(table("版本資訊差異", ["欄位", "A", "B"], [list(x) for x in p.version_info]))
        sections.append(fields("簽章狀態", [("A", p.signature[0]), ("B", p.signature[1])]))
    else:
        sections.append(text("PE 結構差異", ["兩個檔案不都是可解析的 PE 檔，沒有結構比較。"]))
    if cmp.notes:
        sections.append(text("備註", list(cmp.notes)))
    for label, insp in (("A", a), ("B", b)):
        if insp is not None:
            sections += _signature_sections(insp.signature.to_dict() if insp.signature else None, f"（{label}）")
    ev: dict[str, Any] = {"comparison": _comparison_dict(cmp)}
    for label, insp in (("a", a), ("b", b)):
        if insp is not None:
            ev[f"file_{label}"] = {**asdict(insp.facts), "path": str(insp.facts.path)}
            ev[f"pe_result_{label}"] = result_to_dict(insp.pe) if insp.pe else None
            ev[f"signature_{label}"] = insp.signature.to_dict() if insp.signature else None
    ref = f"{cmp.sha256_a}:{cmp.sha256_b}"
    return new_document("COMPARISON", f"檔案比較報告：{cmp.path_a.name} ↔ {cmp.path_b.name}", "COMPARISON", ref,
                        versions, sections, ev)


def _comparison_dict(cmp: Comparison) -> dict[str, Any]:
    d = asdict(cmp)
    d["path_a"], d["path_b"] = str(cmp.path_a), str(cmp.path_b)
    return d


def scan_job_report(job: JobEvidence, versions: dict[str, Any]) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    attention: list[list[Any]] = []
    det_rows: list[tuple[str, int | None, DetectionResult]] = []
    det_paths: list[str] = []
    run_versions: set[tuple[str, str, str]] = set()
    for f in job.files:
        cls = f.verdict.classification if f.verdict else None
        counts[cls.value if cls else "NO_VERDICT"] += 1
        for r in f.results:
            run_versions.add((r.engine_name, r.engine_version or "—", r.rules_version or "—"))
            if r.detections or r.kind is EngineOutcomeKind.ERROR:
                det_rows.append((job.started_at, job.id, r))
                det_paths.append(f.path)
        if cls is not Classification.CLEAN:
            dets = [f"{d.engine_name}: {d.rule_id}" for r in f.results for d in r.detections]
            errs = [f"{r.engine_name}: {r.error}" for r in f.results if r.kind is EngineOutcomeKind.ERROR]
            attention.append([f.path, f.sha256, f"{CLASS_TEXT[cls]}（{cls.value}）" if cls else "未判定（排除或無法讀取）",
                              f.verdict.confidence if f.verdict else "—", dets, errs or f.not_assessed_reason])
    sections = [
        fields("掃描摘要", [("掃描編號", job.id), ("狀態", job.status), ("開始（UTC）", job.started_at),
                        ("結束（UTC）", job.finished_at), ("掃描目標", job.targets), ("看到的檔案", job.files_seen),
                        ("完整評估", job.files_assessed), ("未完成評估", job.files_not_assessed),
                        ("錯誤摘要", job.error_summary), ("選項", job.options)]),
        table("掃描當時的判定統計", ["分類", "檔案數"],
              [[CLASS_TEXT[Classification(k)] if k != "NO_VERDICT" else "未判定", n] for k, n in sorted(counts.items())]),
        table("需要注意的檔案（非「未發現威脅」）", ["路徑", "SHA-256", "分類", "信心", "偵測", "錯誤／原因"],
              attention[:MAX_SECTION_ROWS],
              "判定為掃描當時的結果；之後的人工審查請見威脅中心。"
              + (f" 只列出前 {MAX_SECTION_ROWS} 個。" if len(attention) > MAX_SECTION_ROWS else "")
              + " 未發現威脅的檔案只列在 JSON 版的原始證據中。"),
    ]
    rows = _detection_rows(det_rows)
    for row, path in zip(rows, det_paths, strict=False):
        row.insert(2, path)
    sections.append(table("偵測與錯誤證據", ["掃描時間", "掃描 #", "路徑", *DET_COLUMNS[2:]], rows[:MAX_SECTION_ROWS]))
    sections.append(table("掃描當時的引擎版本", ["引擎", "引擎版本", "規則／病毒碼版本"], sorted(run_versions)))
    ev = {"job": {k: getattr(job, k) for k in ("id", "started_at", "finished_at", "status", "targets", "options",
                                               "files_seen", "files_assessed", "files_not_assessed", "error_summary")},
          "files": [{"path": f.path, "sha256": f.sha256, "size": f.size, "assessed": f.assessed,
                     "not_assessed_reason": f.not_assessed_reason, "verdict": _verdict_dict(f.verdict),
                     "results": [result_to_dict(r) for r in f.results]} for f in job.files]}
    return new_document("SCAN_JOB", f"掃描報告：掃描 #{job.id}", "SCAN_JOB", str(job.id), versions, sections, ev)
