"""Research Lab logic on harmless synthetic files: facts, comparison, YARA tester."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

from sentinelx.core.cancel import CancelToken, ScanCancelled
from sentinelx.research import compare as cmp
from sentinelx.research import yara_lab
from sentinelx.research.sample import detect_type, file_facts, read_motw

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(("head", "expected"), [
    (b"MZ\x90\x00", "MZ/PE"), (b"%PDF-1.7", "PDF"), (b"PK\x03\x04", "ZIP"), (b"\x7fELF", "ELF"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE"), (b"hello world\n", "文字檔"), (b"", "空檔案"),
    (b"\x00\x01\x02\xff", "未知"), (b"#!/bin/sh", "shebang"),
])
def test_detect_type(head: bytes, expected: str) -> None:
    assert expected in detect_type(head)


def test_iso_magic_at_offset() -> None:
    head = b"\x00" * 0x8001 + b"CD001"
    assert "ISO" in detect_type(head)


def test_file_facts_hashes(tmp_path: Path) -> None:
    p = tmp_path / "a.bin"
    data = b"harmless" * 300_000  # spans several read chunks
    p.write_bytes(data)
    f = file_facts(p, 10 * 1024 * 1024)
    assert f.sha256 == hashlib.sha256(data).hexdigest()
    assert f.md5 == hashlib.md5(data).hexdigest() and f.sha1 == hashlib.sha1(data).hexdigest()
    assert f.size == len(data) and f.modified and f.motw is None


def test_file_facts_refuses_dir_and_oversize(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="一般檔案"):
        file_facts(tmp_path, 1024)
    p = tmp_path / "big.bin"
    p.write_bytes(b"x" * 2048)
    with pytest.raises(ValueError, match="大小上限"):
        file_facts(p, 1024)


def test_file_facts_cancel(tmp_path: Path) -> None:
    p = tmp_path / "a.bin"
    p.write_bytes(b"x" * 10)
    tok = CancelToken()
    tok.cancel()
    with pytest.raises(ScanCancelled):
        file_facts(p, 1024, tok)


@pytest.mark.windows
@pytest.mark.skipif(sys.platform != "win32", reason="NTFS alternate data streams")
def test_motw_parsed_and_bounded(tmp_path: Path) -> None:
    p = tmp_path / "dl.exe"
    p.write_bytes(b"MZ")
    with open(f"{p}:Zone.Identifier", "w", encoding="utf-8") as f:
        f.write("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.invalid/<script>x</script>\r\n")
        f.write("".join(f"K{i}=v\r\n" for i in range(100)))
    m = read_motw(p)
    assert m is not None and m["ZoneId"] == "3" and m["HostUrl"].endswith("<script>x</script>")
    assert len(m) <= 20


# ---------------- comparison ----------------

def test_byte_diff_identical(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    a.write_bytes(b"same content")
    b.write_bytes(b"same content")
    d = cmp.byte_diff(a, b)
    assert d.identical and d.first_difference is None and d.differing_bytes == 0 and d.same_offset_ratio == 1.0


def test_byte_diff_offsets_across_chunks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cmp, "CHUNK", 7)
    base = bytearray(b"0123456789" * 5)
    other = bytearray(base)
    other[13] ^= 0xFF
    other[40] ^= 0x01
    a, b = tmp_path / "a", tmp_path / "b"
    a.write_bytes(bytes(base))
    b.write_bytes(bytes(other))
    d = cmp.byte_diff(a, b)
    assert not d.identical and d.first_difference == 13 and d.differing_bytes == 2 and d.common_length == 50


def test_byte_diff_prefix_and_size(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    a.write_bytes(b"abcdef")
    b.write_bytes(b"abcdefXYZ")
    d = cmp.byte_diff(a, b)
    assert not d.identical and d.first_difference == 6 and d.differing_bytes == 0 and d.size_b == 9


def test_pe_diff() -> None:
    a = {"machine": "x64", "imphash": "aa", "sections": [{"name": ".text", "virtual_size": 1, "raw_size": 512,
                                                          "entropy": 6.0, "writable": False, "executable": True},
                                                         {"name": ".old", "raw_size": 1, "entropy": 1.0}],
         "imports": {"KERNEL32.dll": ["CreateFileW", "ReadFile"]}, "version_info": {"ProductName": "A"},
         "signature": {"status": "VALID"}}
    b = {"machine": "x64", "imphash": "bb", "sections": [{"name": ".text", "virtual_size": 1, "raw_size": 1024,
                                                          "entropy": 7.9, "writable": True, "executable": True},
                                                         {"name": "UPX0", "raw_size": 1, "entropy": 1.0}],
         "imports": {"kernel32.dll": ["CreateFileW", "VirtualAlloc"], "WS2_32.dll": ["connect"]},
         "version_info": {"ProductName": "B"}, "signature": {"status": "UNSIGNED"}}
    d = cmp.pe_diff(a, b)
    assert ("imphash", "aa", "bb") in d.fields and all(f[0] != "架構" for f in d.fields)
    st = {s.name: s.status for s in d.sections}
    assert st == {".text": "changed", ".old": "only_a", "UPX0": "only_b"}
    imp = {i.dll.lower(): i for i in d.imports}
    assert imp["kernel32.dll"].added == ("VirtualAlloc",) and imp["kernel32.dll"].removed == ("ReadFile",)
    assert imp["ws2_32.dll"].status == "only_b"
    assert d.version_info == (("ProductName", "A", "B"),) and d.signature == ("VALID", "UNSIGNED")


# ---------------- YARA tester ----------------

RULE = 'rule marker { meta: severity = "low" strings: $m = "SX-LAB-MARKER" condition: $m }'


def test_yara_match_offsets_and_excerpt(tmp_path: Path) -> None:
    p = tmp_path / "sample.bin"
    p.write_bytes(b"\x00\x01" + b"SX-LAB-MARKER" + b"\xff" + b"SX-LAB-MARKER")
    run = yara_lab.run_test(RULE, [p], max_bytes=1024)
    [t] = run.results
    [h] = t.hits
    assert h.rule == "marker" and h.meta == {"severity": "low"} and h.string_instances == 2
    assert [s.offset for s in h.strings] == [2, 16]
    assert h.strings[0].text == "SX-LAB-MARKER" and h.strings[0].hex.startswith("53 58")
    assert run.matched == 1 and run.rule_sha256 == hashlib.sha256(RULE.encode()).hexdigest()


def test_yara_excerpt_hides_non_printable(tmp_path: Path) -> None:
    p = tmp_path / "s.bin"
    p.write_bytes(b"A\x00<\x1bB")
    run = yara_lab.run_test('rule r { strings: $h = { 41 00 3C 1B 42 } condition: $h }', [p], max_bytes=1024)
    assert run.results[0].hits[0].strings[0].text == "A.<.B"


@pytest.mark.security
@pytest.mark.parametrize(("source", "msg"), [
    ('import "console" rule r { condition: console.log("x") }', "不允許"),
    ('include "C:\\\\Windows\\\\win.ini" rule r { condition: true }', "YARA"),
    ("rule r { condition: }", "語法"),
    ("// nothing", "沒有任何"),
])
def test_yara_rejects_bad_rules(tmp_path: Path, source: str, msg: str) -> None:
    p = tmp_path / "s.bin"
    p.write_bytes(b"x")
    with pytest.raises(ValueError, match=msg):
        yara_lab.run_test(source, [p], max_bytes=1024)


def test_yara_rule_size_limit(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="1 MB"):
        yara_lab.compile_test_rules("//" + "x" * (yara_lab.MAX_RULE_BYTES + 1))


def test_yara_folder_not_recursive_and_capped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(yara_lab, "MAX_TARGETS", 3)
    for i in range(5):
        (tmp_path / f"f{i}.txt").write_bytes(b"SX-LAB-MARKER" if i == 0 else b"clean")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "deep.txt").write_bytes(b"SX-LAB-MARKER")
    run = yara_lab.run_test(RULE, [tmp_path], max_bytes=1024)
    assert len(run.results) == 3 and all(r.path.parent == tmp_path for r in run.results)
    assert any("上限" in s for s in run.skipped)


def test_yara_oversize_file_is_error_not_clean(tmp_path: Path) -> None:
    p = tmp_path / "big.bin"
    p.write_bytes(b"SX-LAB-MARKER" + b"x" * 4096)
    [t] = yara_lab.run_test(RULE, [p], max_bytes=1024).results
    assert t.error and not t.hits


def test_yara_no_targets(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="沒有可測試"):
        yara_lab.run_test(RULE, [tmp_path / "missing"], max_bytes=1024)


def test_yara_cancel(tmp_path: Path) -> None:
    p = tmp_path / "s.bin"
    p.write_bytes(b"x")
    tok = CancelToken()
    tok.cancel()
    with pytest.raises(ScanCancelled):
        yara_lab.run_test(RULE, [p], max_bytes=1024, cancel=tok)


@pytest.mark.security
@pytest.mark.windows
@pytest.mark.skipif(sys.platform != "win32", reason="junctions are Windows-only")
def test_yara_does_not_follow_junction(tmp_path: Path) -> None:
    import subprocess

    target = tmp_path / "real"
    target.mkdir()
    (target / "x.txt").write_bytes(b"SX-LAB-MARKER")
    link = tmp_path / "link"
    rc = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True).returncode
    if rc != 0:
        pytest.skip("could not create a junction")
    files, skipped = yara_lab.expand_targets([link])
    assert files == [] and any("交接點" in s for s in skipped)
