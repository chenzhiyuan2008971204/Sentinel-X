"""The version shown in the app, the package metadata and the newest CHANGELOG entry agree.

Added in Phase 9 after the 0.8.0 and 0.8.1 commits were found still reporting 0.7.2.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

from sentinelx import __version__

pytestmark = pytest.mark.unit
ROOT = Path(__file__).resolve().parents[2]


def test_versions_agree() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    newest = re.search(r"^## \[([^\]]+)\]", (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), re.M)
    assert newest is not None
    assert __version__ == project == newest.group(1)
