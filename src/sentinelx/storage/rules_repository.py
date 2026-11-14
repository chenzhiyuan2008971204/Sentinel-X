"""YARA rule-set storage and validation.

Rule files are copied into `<data root>\\rules\\yara` when registered, and their SHA-256 is
pinned in the `rule_sets` table. A copy whose hash no longer matches is refused at load
time, so editing the original file (or the copy) cannot silently change active rules.
"""

from __future__ import annotations

import hashlib
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

import yara
from sqlalchemy import select

from sentinelx.core.timeutil import utc_now_iso
from sentinelx.storage.db import Database
from sentinelx.storage.orm import RuleSet

# Modules a rule may import. `console` (prints) and `tests` (debug) are deliberately excluded;
# anything libyara does not know (e.g. `cuckoo`, `magic` on Windows builds) fails compilation.
ALLOWED_MODULES = frozenset({"pe", "elf", "math", "hash", "time", "string", "dotnet"})
MAX_RULE_FILE_BYTES = 16 * 1024 * 1024  # curated public sets (YARA Forge core) are ~8 MB
# Not anchored to line start: YARA accepts `import` anywhere at top level, including after a
# rule on the same line. Matching inside comments/strings can only cause a false rejection.
_IMPORT_RE = re.compile(r'\bimport\s+"([^"]+)"')
_NAME_RE = re.compile(r"[^0-9A-Za-z_]")


@dataclass(frozen=True)
class RuleValidation:
    ok: bool
    rule_count: int
    error: str | None = None


def validate_rule_source(source: str) -> RuleValidation:
    bad = sorted(set(_IMPORT_RE.findall(source)) - ALLOWED_MODULES)
    if bad:
        return RuleValidation(False, 0, f"不支援或不允許的 YARA 模組：{', '.join(bad)}")
    try:
        rules = yara.compile(source=source, includes=False)
    except yara.SyntaxError as exc:
        return RuleValidation(False, 0, f"YARA 語法錯誤：{exc}")
    except yara.Error as exc:
        return RuleValidation(False, 0, f"YARA 編譯失敗：{exc}")
    count = sum(1 for _ in rules)
    if count == 0:
        return RuleValidation(False, 0, "檔案中沒有任何 YARA 規則。")
    return RuleValidation(True, count)


def namespace_for(name: str) -> str:
    ns = _NAME_RE.sub("_", name).strip("_") or "rules"
    return ns if not ns[0].isdigit() else f"r_{ns}"


@dataclass(frozen=True)
class RuleSetRow:
    id: int
    name: str
    version: str
    path: Path
    sha256: str
    enabled: bool
    validated_at: str | None
    validation_error: str | None
    rule_count: int

    @property
    def valid(self) -> bool:
        return self.validation_error is None


class RuleSetStore:
    def __init__(self, db: Database, rules_dir: Path) -> None:
        self._db = db
        self._dir = rules_dir
        self._count_cache: dict[str, int] = {}  # pinned sha256 -> rule count (avoid recompiling)

    def _rule_count(self, r: RuleSet) -> int:
        sha = r.sha256_of_rules or ""
        if sha not in self._count_cache:
            p = Path(r.path)
            self._count_cache[sha] = (
                validate_rule_source(p.read_text(encoding="utf-8", errors="replace")).rule_count
                if p.is_file() else 0
            )
        return self._count_cache[sha]

    def _row(self, r: RuleSet) -> RuleSetRow:
        count = self._rule_count(r) if r.validation_error is None else 0
        return RuleSetRow(r.id, r.name, r.version or "", Path(r.path), r.sha256_of_rules or "", bool(r.enabled),
                          r.validated_at, r.validation_error, count)

    def list(self) -> list[RuleSetRow]:
        with self._db.session() as s:
            return [self._row(r) for r in s.scalars(select(RuleSet).order_by(RuleSet.id))]

    def add_from_file(self, source: Path, name: str | None = None, version: str | None = None) -> RuleSetRow:
        """Copy, validate and register a rule file. Invalid files are registered disabled
        with the validation error, so the user sees why. Raises ValueError for unusable input."""
        if not source.is_file():
            raise ValueError("找不到規則檔。")
        if source.stat().st_size > MAX_RULE_FILE_BYTES:
            raise ValueError("規則檔超過 16 MB 上限。")
        raw = source.read_bytes()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("規則檔必須是 UTF-8 文字檔。") from exc
        sha = hashlib.sha256(raw).hexdigest()
        name = (name or source.stem).strip() or source.stem
        version = (version or "").strip() or f"{utc_now_iso()[:10].replace('-', '')}-{sha[:8]}"
        if any(namespace_for(r.name) == namespace_for(name) for r in self.list()):
            raise ValueError(f"已有同名的規則集「{name}」，請換一個名稱。")
        result = validate_rule_source(text)

        self._dir.mkdir(parents=True, exist_ok=True)
        with self._db.session() as s:
            r = RuleSet(kind="YARA", name=name, version=version, path="", sha256_of_rules=sha,
                        enabled=1 if result.ok else 0, validated_at=utc_now_iso(),
                        validation_error=result.error)
            s.add(r)
            s.flush()
            dest = self._dir / f"{r.id:04d}-{namespace_for(name)}.yar"
            shutil.copyfile(source, dest)
            r.path = str(dest)
            return self._row(r)

    def set_enabled(self, rule_set_id: int, enabled: bool) -> RuleSetRow:
        with self._db.session() as s:
            r = s.get(RuleSet, rule_set_id)
            if r is None:
                raise ValueError("找不到這個規則集。")
            if enabled and r.validation_error is not None:
                raise ValueError("規則集驗證失敗，不能啟用。")
            r.enabled = 1 if enabled else 0
            return self._row(r)

    def remove(self, rule_set_id: int) -> RuleSetRow | None:
        """Unregister and delete Sentinel X's own copy (never the user's original file)."""
        with self._db.session() as s:
            r = s.get(RuleSet, rule_set_id)
            if r is None:
                return None
            row = self._row(r)
            s.delete(r)
        copy = row.path
        if copy.is_file() and self._dir in copy.parents:
            copy.unlink()
        return row

    def load_enabled(self) -> tuple[list[tuple[RuleSetRow, str]], list[str]]:
        """Enabled rule sets with their source text, read once and verified against the
        pinned hash (no gap between check and use), plus problems found."""
        ok: list[tuple[RuleSetRow, str]] = []
        problems: list[str] = []
        for row in self.list():
            if not row.enabled:
                continue
            try:
                raw = row.path.read_bytes()
            except OSError as exc:
                problems.append(f"{row.name}：無法讀取規則檔（{exc.strerror}）")
                continue
            if hashlib.sha256(raw).hexdigest() != row.sha256:
                problems.append(f"{row.name}：規則檔內容已被變更，已停止使用")
                continue
            ok.append((row, raw.decode("utf-8")))
        return ok, problems
