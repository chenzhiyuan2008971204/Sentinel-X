"""Scan exclusions: exact path, path prefix (folder), extension, SHA-256."""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from sentinelx.core.enums import ExclusionKind

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def norm_path(p: str | Path) -> str:
    """Case-insensitive, absolute, separator-normalized form used for comparisons."""
    return os.path.normcase(os.path.abspath(str(p)))


def validate_exclusion(kind: ExclusionKind, value: str) -> str:
    """Return the canonical stored value, or raise ValueError with a zh-TW message."""
    kind = ExclusionKind(kind)
    v = value.strip()
    if not v:
        raise ValueError("排除值不可為空白。")
    if kind is ExclusionKind.SHA256:
        v = v.lower()
        if not _SHA256.fullmatch(v):
            raise ValueError("SHA-256 必須是 64 個十六進位字元。")
        return v
    if kind is ExclusionKind.EXTENSION:
        v = v.lower()
        if not v.startswith("."):
            v = "." + v
        if any(c in v for c in "\\/:*?\"<>| ") or len(v) < 2:
            raise ValueError("副檔名格式不正確，例如：.log")
        return v
    # PATH / PATH_PREFIX
    if not Path(v).is_absolute():
        raise ValueError("路徑必須是完整路徑，例如：C:\\Data\\logs")
    return os.path.abspath(v)


@dataclass
class ExclusionSet:
    paths: set[str] = field(default_factory=set)
    prefixes: list[str] = field(default_factory=list)
    extensions: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)
    internal: list[str] = field(default_factory=list)  # Sentinel X's own data folder (always skipped)

    @classmethod
    def from_pairs(cls, pairs: Iterable[tuple[ExclusionKind, str]]) -> ExclusionSet:
        s = cls()
        for raw_kind, value in pairs:
            kind = ExclusionKind(raw_kind)
            if kind is ExclusionKind.PATH:
                s.paths.add(norm_path(value))
            elif kind is ExclusionKind.PATH_PREFIX:
                s.prefixes.append(norm_path(value).rstrip("\\/"))
            elif kind is ExclusionKind.EXTENSION:
                s.extensions.add(value.lower())
            elif kind is ExclusionKind.SHA256:
                s.hashes.add(value.lower())
        return s

    def match_path(self, path: Path) -> str | None:
        n = norm_path(path)
        for pre in self.internal:
            if n == pre or n.startswith(pre + os.sep):
                return "Sentinel X 自己的資料資料夾（規則、報告、資料庫、隔離區），不掃描"
        if n in self.paths:
            return "符合排除路徑"
        for pre in self.prefixes:
            if n == pre or n.startswith(pre + os.sep):
                return "位於排除資料夾內"
        if path.suffix.lower() in self.extensions:
            return f"排除的副檔名 {path.suffix.lower()}"
        return None

    def match_hash(self, sha256: str) -> bool:
        return sha256 in self.hashes
