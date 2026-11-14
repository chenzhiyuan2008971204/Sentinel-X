from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from fakes import make_tree

from sentinelx.app.config import ScanLimits
from sentinelx.core.cancel import CancelToken, ScanCancelled
from sentinelx.core.enums import ExclusionKind
from sentinelx.scanner.exclusions import ExclusionSet
from sentinelx.scanner.walker import Walker, WalkEntry

pytestmark = pytest.mark.integration


def walk(roots: list[Path], limits: ScanLimits | None = None, excl: ExclusionSet | None = None) -> list[WalkEntry]:
    return list(Walker(limits or ScanLimits(), excl).walk(roots, CancelToken()))


def files_of(entries: list[WalkEntry]) -> set[Path]:
    return {e.path for e in entries if e.is_file}


def make_junction(link: Path, target: Path) -> None:
    if sys.platform != "win32":
        pytest.skip("junctions are Windows-only")
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True)
    if r.returncode != 0:
        pytest.skip(f"cannot create junction: {r.stderr!r}")


def test_recursive_walk_finds_all_files(tmp_path: Path) -> None:
    f = make_tree(tmp_path)
    assert files_of(walk([tmp_path])) == set(f.values())


def test_single_file_target(tmp_path: Path) -> None:
    f = make_tree(tmp_path)
    assert files_of(walk([f["clean"]])) == {f["clean"]}


def test_missing_root_reported(tmp_path: Path) -> None:
    [e] = walk([tmp_path / "nope"])
    assert not e.is_file and "不存在" in (e.skip_reason or "")


def test_depth_limit(tmp_path: Path) -> None:
    f = make_tree(tmp_path)
    entries = walk([tmp_path], ScanLimits(max_depth=1))
    assert f["deep"] not in files_of(entries)
    assert any("最大深度" in (e.skip_reason or "") for e in entries)


def test_size_limit(tmp_path: Path) -> None:
    big = tmp_path / "big.bin"
    with open(big, "wb") as fh:
        fh.truncate(2 * 1024 * 1024)  # sparse, no real disk usage
    [e] = walk([tmp_path], ScanLimits(max_file_size_mb=1))
    assert not e.is_file and "大小上限" in (e.skip_reason or "")


def test_max_files_limit(tmp_path: Path) -> None:
    for i in range(5):
        (tmp_path / f"{i}.txt").write_text("x")
    entries = walk([tmp_path], ScanLimits(max_files_per_job=3))
    assert len(files_of(entries)) == 3
    assert "上限" in (entries[-1].skip_reason or "")


def test_exclusions_prefix_and_extension(tmp_path: Path) -> None:
    f = make_tree(tmp_path)
    ex = ExclusionSet.from_pairs([(ExclusionKind.PATH_PREFIX, str(tmp_path / "sub")), (ExclusionKind.EXTENSION, ".txt")])
    entries = walk([tmp_path], excl=ex)
    assert files_of(entries) == set()  # bad/deep under sub, clean/cjk are .txt
    excluded = [e for e in entries if e.excluded]
    assert {e.path for e in excluded} >= {tmp_path / "sub", f["clean"], f["cjk"]}


def test_cancel_stops_walk(tmp_path: Path) -> None:
    make_tree(tmp_path)
    tok = CancelToken()
    tok.cancel()
    with pytest.raises(ScanCancelled):
        list(Walker(ScanLimits()).walk([tmp_path], tok))


@pytest.mark.security
def test_permission_error_does_not_abort(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    f = make_tree(tmp_path)
    real_scandir = os.scandir
    locked = str(tmp_path / "sub")

    def fake_scandir(path: os.PathLike[str] | str):  # type: ignore[no-untyped-def]
        if os.fspath(path) == locked:
            raise PermissionError(13, "Access is denied")
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", fake_scandir)
    entries = walk([tmp_path])
    assert f["clean"] in files_of(entries)
    assert any(e.path == tmp_path / "sub" and "權限不足" in (e.skip_reason or "") for e in entries)


@pytest.mark.security
@pytest.mark.windows
def test_junction_to_outside_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("outside root")
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_text("a")
    make_junction(root / "link", outside)

    entries = walk([root])
    assert files_of(entries) == {root / "a.txt"}
    assert any(e.path == root / "link" and "未跟隨" in (e.skip_reason or "") for e in entries)

    # Even with following enabled, a target outside the scan root is refused.
    entries = walk([root], ScanLimits(follow_reparse_points=True))
    assert files_of(entries) == {root / "a.txt"}
    assert any("範圍外" in (e.skip_reason or "") for e in entries)


@pytest.mark.security
@pytest.mark.windows
def test_junction_loop_is_visited_once(tmp_path: Path) -> None:
    root = tmp_path / "root"
    (root / "d").mkdir(parents=True)
    (root / "d" / "f.txt").write_text("f")
    make_junction(root / "d" / "loop", root)  # points back up: a cycle
    entries = walk([root], ScanLimits(follow_reparse_points=True, max_depth=50))
    assert files_of(entries) == {root / "d" / "f.txt"}


@pytest.mark.security
@pytest.mark.windows
def test_root_that_is_junction_not_followed(tmp_path: Path) -> None:
    target = tmp_path / "t"
    target.mkdir()
    (target / "x.txt").write_text("x")
    make_junction(tmp_path / "j", target)
    [e] = walk([tmp_path / "j"])
    assert not e.is_file and "未跟隨" in (e.skip_reason or "")
