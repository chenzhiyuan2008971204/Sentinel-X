from __future__ import annotations

import pytest

from sentinelx.core.enums import Severity
from sentinelx.engines.clamav import classify_signature, parse_scan_output, parse_version
from sentinelx.scanner.exclusions import norm_path

pytestmark = pytest.mark.unit


def test_parse_version_full() -> None:
    assert parse_version("ClamAV 1.5.4/27800/Sun Nov  1 09:00:00 2026\n") == (
        "1.5.4", "27800", "Sun Nov  1 09:00:00 2026",
    )


def test_parse_version_without_database() -> None:
    assert parse_version("ClamAV 1.5.4") == ("1.5.4", None, None)


@pytest.mark.parametrize("text", ["", "clamscan: command not found", "ClamAV"])
def test_parse_version_garbage(text: str) -> None:
    assert parse_version(text) == (None, None, None)


def test_parse_scan_output() -> None:
    out = "\n".join([
        "LibClamAV Warning: something unrelated",
        r"C:\a\clean.txt: OK",
        r"C:\a\eicar.com: Eicar-Test-Signature FOUND",
        r"C:\a\locked.db: Can't open file or directory ERROR",
        r"C:\a\empty.txt: Empty file",
        r"C:\中文\報告.txt: OK",
        "",
        "----------- SCAN SUMMARY -----------",
        r"C:\a\ghost.txt: OK",
    ])
    r = parse_scan_output(out)
    assert r[norm_path(r"C:\a\clean.txt")].kind == "OK"
    found = r[norm_path(r"C:\a\eicar.com")]
    assert found.kind == "FOUND" and found.signature == "Eicar-Test-Signature"
    err = r[norm_path(r"C:\a\locked.db")]
    assert err.kind == "ERROR" and err.message == "Can't open file or directory"
    assert r[norm_path(r"C:\a\empty.txt")].kind == "OK"
    assert r[norm_path(r"C:\中文\報告.txt")].kind == "OK"
    assert norm_path(r"C:\a\ghost.txt") not in r  # after summary marker


def test_path_case_insensitive_lookup() -> None:
    r = parse_scan_output(r"C:\Dir\File.TXT: OK")
    assert norm_path(r"c:\dir\file.txt") in r


def test_signature_classification() -> None:
    assert classify_signature("Win.Trojan.Agent-1")[0] is Severity.HIGH
    assert classify_signature("PUA.Win.Tool.Foo")[0] is Severity.MEDIUM
    assert classify_signature("Heuristics.Encrypted.PDF")[0] is Severity.MEDIUM
