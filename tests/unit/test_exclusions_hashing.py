from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from sentinelx.core.cancel import CancelToken, ScanCancelled
from sentinelx.core.enums import ExclusionKind
from sentinelx.scanner import hashing
from sentinelx.scanner.exclusions import ExclusionSet, validate_exclusion

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("kind", "value", "expected"),
    [
        (ExclusionKind.EXTENSION, "LOG", ".log"),
        (ExclusionKind.EXTENSION, ".tmp", ".tmp"),
        (ExclusionKind.SHA256, "A" * 64, "a" * 64),
        (ExclusionKind.PATH_PREFIX, "C:\\Data\\logs", "C:\\Data\\logs"),
    ],
)
def test_validate_ok(kind: ExclusionKind, value: str, expected: str) -> None:
    assert validate_exclusion(kind, value) == expected


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        (ExclusionKind.EXTENSION, "a/b"),
        (ExclusionKind.EXTENSION, "  "),
        (ExclusionKind.SHA256, "abc"),
        (ExclusionKind.PATH, "relative\\path"),
        (ExclusionKind.PATH_PREFIX, "..\\escape"),
    ],
)
def test_validate_rejects(kind: ExclusionKind, value: str) -> None:
    with pytest.raises(ValueError):
        validate_exclusion(kind, value)


def test_plain_string_kind_accepted() -> None:
    # Qt hands enum userData back as plain str; validation must not fall through to "path".
    assert validate_exclusion("SHA256", "B" * 64) == "b" * 64  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        validate_exclusion("NOT_A_KIND", "x")  # type: ignore[arg-type]


def test_prefix_respects_boundary_and_case() -> None:
    s = ExclusionSet.from_pairs([(ExclusionKind.PATH_PREFIX, "C:\\Data\\Logs")])
    assert s.match_path(Path("c:\\data\\logs\\a.txt"))
    assert s.match_path(Path("C:\\Data\\Logs"))
    assert s.match_path(Path("C:\\Data\\LogsArchive\\a.txt")) is None


def test_extension_and_exact_path() -> None:
    s = ExclusionSet.from_pairs([(ExclusionKind.EXTENSION, ".log"), (ExclusionKind.PATH, "C:\\x\\keep.txt")])
    assert s.match_path(Path("C:\\any\\APP.LOG"))
    assert s.match_path(Path("C:\\X\\KEEP.TXT"))
    assert s.match_path(Path("C:\\x\\other.txt")) is None


def test_hash_streaming_matches_hashlib(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hashing, "CHUNK_SIZE", 7)
    data = bytes(range(256)) * 50
    p = tmp_path / "f.bin"
    p.write_bytes(data)
    assert hashing.sha256_file(p) == hashlib.sha256(data).hexdigest()


def test_hash_cancel_between_chunks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hashing, "CHUNK_SIZE", 4)
    p = tmp_path / "f.bin"
    p.write_bytes(b"x" * 100)
    tok = CancelToken()
    tok.cancel()
    with pytest.raises(ScanCancelled):
        hashing.sha256_file(p, tok)
