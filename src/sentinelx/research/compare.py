"""Compare two files: hashes, a byte-level summary, and PE structure differences.

The byte summary compares bytes at the same offsets only. It is not a similarity algorithm
(insertions shift every later byte); it says where the files start to differ and how much
of the common length is identical.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinelx.core.cancel import CancelToken

CHUNK = 1024 * 1024
PE_FIELDS = (
    ("machine", "架構"), ("is_dll", "DLL"), ("is_dotnet", ".NET"), ("subsystem", "子系統"),
    ("compile_timestamp", "編譯時間"), ("entry_point", "進入點"), ("entry_point_section", "進入點區段"),
    ("image_base", "映像基底"), ("imphash", "imphash"), ("import_function_count", "匯入函式數"),
    ("export_count", "匯出數"), ("overlay_bytes", "附加資料位元組"),
)


@dataclass(frozen=True)
class ByteDiff:
    size_a: int
    size_b: int
    identical: bool
    first_difference: int | None  # offset, None when the common part is identical
    differing_bytes: int  # within the common length
    common_length: int

    @property
    def same_offset_ratio(self) -> float:
        return 1.0 if self.common_length == 0 else 1 - self.differing_bytes / self.common_length


@dataclass(frozen=True)
class SectionDiff:
    name: str
    status: str  # "only_a", "only_b", "changed", "same"
    a: dict[str, Any] | None
    b: dict[str, Any] | None


@dataclass(frozen=True)
class ImportDiff:
    dll: str
    status: str  # "only_a", "only_b", "changed"
    added: tuple[str, ...] = ()  # in B but not A
    removed: tuple[str, ...] = ()  # in A but not B


@dataclass(frozen=True)
class PEDiff:
    fields: tuple[tuple[str, Any, Any], ...]  # (label, a, b) for differing fields only
    sections: tuple[SectionDiff, ...]
    imports: tuple[ImportDiff, ...]
    version_info: tuple[tuple[str, str | None, str | None], ...]
    signature: tuple[str | None, str | None]


@dataclass(frozen=True)
class Comparison:
    path_a: Path
    path_b: Path
    sha256_a: str
    sha256_b: str
    bytes: ByteDiff
    pe: PEDiff | None = None
    notes: tuple[str, ...] = field(default=())

    @property
    def identical(self) -> bool:
        return self.sha256_a == self.sha256_b


def byte_diff(a: Path, b: Path, cancel: CancelToken | None = None) -> ByteDiff:
    cancel = cancel or CancelToken()
    size_a, size_b = a.stat().st_size, b.stat().st_size
    first: int | None = None
    differing = 0
    offset = 0
    with open(a, "rb") as fa, open(b, "rb") as fb:
        while True:
            cancel.raise_if_cancelled()
            ca, cb = fa.read(CHUNK), fb.read(CHUNK)
            n = min(len(ca), len(cb))
            if n == 0:
                break
            if ca[:n] != cb[:n]:
                # XOR as big integers: zero bytes are equal positions (runs in C, not per byte).
                x = (int.from_bytes(ca[:n], "big") ^ int.from_bytes(cb[:n], "big")).to_bytes(n, "big")
                differing += n - x.count(0)
                if first is None:
                    first = offset + (n - len(x.lstrip(b"\x00")))
            offset += n
            if len(ca) != len(cb):
                break
    common = min(size_a, size_b)
    identical = size_a == size_b and differing == 0
    if first is None and size_a != size_b:
        first = common
    return ByteDiff(size_a, size_b, identical, first, differing, common)


def _section_key(s: dict[str, Any]) -> tuple[Any, ...]:
    return (s.get("virtual_size"), s.get("raw_size"), s.get("entropy"), s.get("writable"), s.get("executable"))


def pe_diff(a: dict[str, Any], b: dict[str, Any]) -> PEDiff:
    fields = tuple((label, a.get(k), b.get(k)) for k, label in PE_FIELDS if a.get(k) != b.get(k))

    def by_name(info: dict[str, Any]) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for i, s in enumerate(info.get("sections", [])):
            name = s.get("name", "")
            out[name if name not in out else f"{name}#{i}"] = s
        return out

    sa, sb = by_name(a), by_name(b)
    sections = []
    for name in list(sa) + [n for n in sb if n not in sa]:
        x, y = sa.get(name), sb.get(name)
        status = "only_a" if y is None else "only_b" if x is None else ("same" if _section_key(x) == _section_key(y) else "changed")
        sections.append(SectionDiff(name, status, x, y))

    ia = {k.lower(): (k, set(v)) for k, v in a.get("imports", {}).items()}
    ib = {k.lower(): (k, set(v)) for k, v in b.get("imports", {}).items()}
    imports = []
    for key in sorted(set(ia) | set(ib)):
        if key not in ib:
            imports.append(ImportDiff(ia[key][0], "only_a", removed=tuple(sorted(ia[key][1]))))
        elif key not in ia:
            imports.append(ImportDiff(ib[key][0], "only_b", added=tuple(sorted(ib[key][1]))))
        else:
            added, removed = ib[key][1] - ia[key][1], ia[key][1] - ib[key][1]
            if added or removed:
                imports.append(ImportDiff(ia[key][0], "changed", tuple(sorted(added)), tuple(sorted(removed))))

    va, vb = a.get("version_info", {}), b.get("version_info", {})
    version = tuple((k, va.get(k), vb.get(k)) for k in sorted(set(va) | set(vb)) if va.get(k) != vb.get(k))
    sig = (a.get("signature", {}).get("status"), b.get("signature", {}).get("status"))
    return PEDiff(fields, tuple(sections), tuple(imports), version, sig)
