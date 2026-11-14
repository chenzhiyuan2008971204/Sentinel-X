"""The vault's "only this user" check understands SDDL account aliases (found on GitHub's build
machines, 2026-11-14: they run as the built-in Administrator, whose ACE Windows writes as "LA",
so the quarantine refused to start there; it would for any user of that account)."""

from __future__ import annotations

import pytest

from sentinelx.quarantine import win32fs

pytestmark = [pytest.mark.integration, pytest.mark.security]


def test_builtin_administrator_alias_is_the_same_account() -> None:
    admin = win32fs.full_sid("LA")
    assert admin.startswith("S-1-5-21-") and admin.endswith("-500")
    assert win32fs.dacl_is_private("D:PAI(A;OICI;FA;;;LA)", admin)


def test_aliases_of_other_accounts_are_still_rejected() -> None:
    admin = win32fs.full_sid("LA")
    for other in ("WD", "BA", "BU", "AU", "SY"):  # Everyone, Administrators, Users, Authenticated Users, SYSTEM
        assert not win32fs.dacl_is_private(f"D:PAI(A;OICI;FA;;;LA)(A;OICI;FA;;;{other})", admin)
    assert not win32fs.dacl_is_private("D:PAI(A;OICI;FA;;;LA)", "S-1-5-21-1-2-3-1001")  # someone else
    assert win32fs.full_sid("ZZ") == "ZZ"  # unknown text is never turned into a match
