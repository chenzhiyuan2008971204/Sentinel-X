"""Safe file enumeration.

- Reparse points (symlinks, junctions, mount points) are not followed by default.
  When following is enabled, only targets that resolve inside a scan root are followed,
  and every real directory is visited at most once (loop protection).
- Depth, file-count and file-size limits are enforced here.
- Permission and other OS errors become skip entries with a reason; they never abort the walk.
"""

from __future__ import annotations

import os
import stat as stat_mod
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from sentinelx.app.config import ScanLimits
from sentinelx.core.cancel import CancelToken
from sentinelx.scanner.exclusions import ExclusionSet

FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def is_reparse_point(st: os.stat_result) -> bool:
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT) or stat_mod.S_ISLNK(st.st_mode)


@dataclass(frozen=True)
class WalkEntry:
    path: Path
    stat: os.stat_result | None
    skip_reason: str | None = None  # None = regular file to be scanned
    excluded: bool = False

    @property
    def is_file(self) -> bool:
        return self.skip_reason is None


def _os_error_reason(exc: OSError) -> str:
    if isinstance(exc, PermissionError):
        return "權限不足，無法存取"
    if isinstance(exc, FileNotFoundError):
        return "路徑不存在或已被移除"
    return f"無法存取：{exc.strerror or type(exc).__name__}"


class Walker:
    def __init__(self, limits: ScanLimits, exclusions: ExclusionSet | None = None) -> None:
        self._limits = limits
        self._excl = exclusions or ExclusionSet()

    def walk(self, roots: Sequence[Path], cancel: CancelToken) -> Iterator[WalkEntry]:
        abs_roots = [Path(os.path.abspath(r)) for r in roots]
        real_roots = []
        for r in abs_roots:
            try:
                real_roots.append(Path(os.path.realpath(r)))
            except OSError:
                pass
        visited: set[str] = set()
        files_yielded = 0
        max_bytes = self._limits.max_file_size_mb * 1024 * 1024

        def inside_roots(p: Path) -> bool:
            return any(p == rr or rr in p.parents for rr in real_roots)

        def classify_file(path: Path, st: os.stat_result) -> WalkEntry:
            if not stat_mod.S_ISREG(st.st_mode):
                return WalkEntry(path, st, "不是一般檔案")
            if st.st_size > max_bytes:
                return WalkEntry(path, st, f"超過大小上限 {self._limits.max_file_size_mb} MB")
            return WalkEntry(path, st)

        for root in abs_roots:
            cancel.raise_if_cancelled()
            try:
                st = os.lstat(root)
            except OSError as exc:
                yield WalkEntry(root, None, _os_error_reason(exc))
                continue
            reason = self._excl.match_path(root)
            if reason:
                yield WalkEntry(root, st, reason, excluded=True)
                continue
            if is_reparse_point(st) and not self._limits.follow_reparse_points:
                yield WalkEntry(root, st, "符號連結或交接點，未跟隨")
                continue
            try:
                target_st = os.stat(root)
            except OSError as exc:
                yield WalkEntry(root, st, _os_error_reason(exc))
                continue
            if not stat_mod.S_ISDIR(target_st.st_mode):
                entry = classify_file(root, target_st)
                if entry.is_file:
                    files_yielded += 1
                yield entry
                continue

            stack: list[tuple[Path, int]] = [(root, 0)]
            while stack:
                cancel.raise_if_cancelled()
                directory, depth = stack.pop()
                try:
                    real = os.path.normcase(os.path.realpath(directory))
                except OSError as exc:
                    yield WalkEntry(directory, None, _os_error_reason(exc))
                    continue
                if real in visited:
                    continue
                visited.add(real)
                try:
                    with os.scandir(directory) as it:
                        entries = list(it)
                except OSError as exc:
                    yield WalkEntry(directory, None, _os_error_reason(exc))
                    continue

                for de in sorted(entries, key=lambda e: e.name.lower()):
                    cancel.raise_if_cancelled()
                    path = Path(de.path)
                    try:
                        lst = de.stat(follow_symlinks=False)
                    except OSError as exc:
                        yield WalkEntry(path, None, _os_error_reason(exc))
                        continue
                    reason = self._excl.match_path(path)
                    if reason:
                        yield WalkEntry(path, lst, reason, excluded=True)
                        continue

                    st = lst
                    if is_reparse_point(lst):
                        if not self._limits.follow_reparse_points:
                            yield WalkEntry(path, lst, "符號連結或交接點，未跟隨")
                            continue
                        try:
                            target = Path(os.path.realpath(path, strict=True))
                            st = os.stat(path)
                        except OSError as exc:
                            yield WalkEntry(path, lst, _os_error_reason(exc))
                            continue
                        if not inside_roots(target):
                            yield WalkEntry(path, lst, "連結目標位於掃描範圍外，未跟隨")
                            continue

                    if stat_mod.S_ISDIR(st.st_mode):
                        if depth + 1 > self._limits.max_depth:
                            yield WalkEntry(path, st, f"超過最大深度 {self._limits.max_depth}")
                        else:
                            stack.append((path, depth + 1))
                        continue

                    if files_yielded >= self._limits.max_files_per_job:
                        yield WalkEntry(path, st, f"超過單次掃描檔案數上限 {self._limits.max_files_per_job}，其餘檔案未掃描")
                        return
                    entry = classify_file(path, st)
                    if entry.is_file:
                        files_yielded += 1
                    yield entry
