"""YARA rule tester for the Research Lab.

Compiles rule text the user is writing and matches it against files the user picked. The
test rules are never registered, never enabled for scanning and never change a verdict.
Same safety limits as the scanning engine: module allowlist, no `include`, size limit,
match timeout, symlinks and junctions not followed. Files are matched from memory.
"""

from __future__ import annotations

import hashlib
import os
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import yara

from sentinelx.core.cancel import CancelToken
from sentinelx.scanner.walker import is_reparse_point
from sentinelx.storage.rules_repository import validate_rule_source

MAX_RULE_BYTES = 1024 * 1024
MAX_TARGETS = 500
MAX_STRINGS = 20
MAX_INSTANCES = 10
EXCERPT_BYTES = 32


@dataclass(frozen=True)
class StringHit:
    identifier: str
    offset: int
    length: int
    hex: str  # up to EXCERPT_BYTES of the matched data
    text: str  # printable ASCII rendering, other bytes as "."


@dataclass(frozen=True)
class RuleHit:
    rule: str
    tags: tuple[str, ...]
    meta: dict[str, str]
    strings: tuple[StringHit, ...]
    string_instances: int  # total instances, including ones not listed


@dataclass(frozen=True)
class TargetResult:
    path: Path
    sha256: str | None
    size: int | None
    hits: tuple[RuleHit, ...] = ()
    error: str | None = None
    duration_ms: int = 0


@dataclass(frozen=True)
class YaraTestRun:
    rule_sha256: str
    rule_count: int
    yara_version: str
    timeout_s: int
    results: tuple[TargetResult, ...]
    skipped: tuple[str, ...] = field(default=())  # targets not tested, with the reason

    @property
    def matched(self) -> int:
        return sum(1 for r in self.results if r.hits)


def _printable(b: bytes) -> str:
    return "".join(chr(c) if 0x20 <= c < 0x7F else "." for c in b)


def compile_test_rules(source: str) -> tuple[yara.Rules, int]:
    if len(source.encode("utf-8")) > MAX_RULE_BYTES:
        raise ValueError("規則內容超過 1 MB。")
    v = validate_rule_source(source)
    if not v.ok:
        raise ValueError(v.error or "規則無效")
    return yara.compile(source=source, includes=False), v.rule_count


def expand_targets(paths: Sequence[Path]) -> tuple[list[Path], list[str]]:
    """Files given directly, plus the regular files directly inside given folders (not recursive)."""
    files: list[Path] = []
    skipped: list[str] = []
    for p in paths:
        try:
            st = os.lstat(p)
        except OSError as exc:
            skipped.append(f"{p}：無法讀取（{exc.strerror or exc}）")
            continue
        if is_reparse_point(st):
            skipped.append(f"{p}：符號連結或交接點，不跟隨")
            continue
        if p.is_dir():
            try:
                children = sorted(p.iterdir())
            except OSError as exc:
                skipped.append(f"{p}：無法列出資料夾（{exc.strerror or exc}）")
                continue
            for c in children:
                try:
                    cst = os.lstat(c)
                except OSError:
                    continue
                if is_reparse_point(cst):
                    skipped.append(f"{c}：符號連結或交接點，不跟隨")
                elif c.is_file():
                    files.append(c)
        elif p.is_file():
            files.append(p)
    if len(files) > MAX_TARGETS:
        skipped.append(f"另有 {len(files) - MAX_TARGETS} 個檔案超過單次上限 {MAX_TARGETS}，未測試")
        files = files[:MAX_TARGETS]
    return files, skipped


def run_test(source: str, targets: Sequence[Path], *, max_bytes: int, timeout_s: int = 30,
             cancel: CancelToken | None = None) -> YaraTestRun:
    cancel = cancel or CancelToken()
    rules, count = compile_test_rules(source)
    files, skipped = expand_targets(targets)
    if not files:
        raise ValueError("沒有可測試的檔案。" + (" " + "；".join(skipped) if skipped else ""))
    results = []
    for f in files:
        cancel.raise_if_cancelled()
        results.append(_match_one(rules, f, max_bytes, timeout_s))
    return YaraTestRun(hashlib.sha256(source.encode("utf-8")).hexdigest(), count, yara.YARA_VERSION, timeout_s,
                       tuple(results), tuple(skipped))


def _match_one(rules: yara.Rules, path: Path, max_bytes: int, timeout_s: int) -> TargetResult:
    started = time.monotonic()
    try:
        st = os.lstat(path)
        if is_reparse_point(st):
            return TargetResult(path, None, None, error="符號連結或交接點，不跟隨")
        if st.st_size > max_bytes:
            return TargetResult(path, None, st.st_size, error="超過大小上限")
        data = path.read_bytes()
    except OSError as exc:
        return TargetResult(path, None, None, error=f"無法讀取：{exc.strerror or exc}")
    sha = hashlib.sha256(data).hexdigest()
    try:
        matches = rules.match(data=data, timeout=timeout_s)
    except yara.TimeoutError:
        return TargetResult(path, sha, len(data), error=f"比對逾時（{timeout_s} 秒）")
    except yara.Error as exc:
        return TargetResult(path, sha, len(data), error=f"比對失敗：{exc}")
    hits = []
    for m in matches:
        strings: list[StringHit] = []
        total = 0
        for s in m.strings:
            total += len(s.instances)
            for inst in s.instances[:MAX_INSTANCES]:
                if len(strings) >= MAX_STRINGS:
                    break
                chunk = data[inst.offset: inst.offset + min(inst.matched_length, EXCERPT_BYTES)]
                strings.append(StringHit(s.identifier, inst.offset, inst.matched_length, chunk.hex(" "),
                                         _printable(chunk)))
        hits.append(RuleHit(m.rule, tuple(m.tags), {k: str(v) for k, v in (m.meta or {}).items()},
                            tuple(strings), total))
    return TargetResult(path, sha, len(data), tuple(hits), None, int((time.monotonic() - started) * 1000))
