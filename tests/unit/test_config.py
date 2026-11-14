from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from sentinelx.app.config import AppConfig, ClamAVSettings, ConfigStore
from sentinelx.core.errors import ConfigError

pytestmark = pytest.mark.unit


def test_first_load_creates_defaults(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path / "config.json")
    cfg = store.load()
    assert cfg == AppConfig()
    assert (tmp_path / "config.json").exists()
    assert cfg.language == "zh_TW"
    assert cfg.scan.follow_reparse_points is False
    assert cfg.signature_updates_consented is False


def test_roundtrip(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path / "config.json")
    cfg = AppConfig(log_level="DEBUG")
    cfg.clamav.backend = "clamd"
    store.save(cfg)
    assert store.load() == cfg


def test_corrupt_json_raises_and_is_not_overwritten(tmp_path: Path) -> None:
    p = tmp_path / "config.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError):
        ConfigStore(p).load()
    assert p.read_text(encoding="utf-8") == "{not json"


def test_unknown_key_rejected(tmp_path: Path) -> None:
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"disable_defender": True}), encoding="utf-8")
    with pytest.raises(ConfigError):
        ConfigStore(p).load()


def test_out_of_range_limit_rejected(tmp_path: Path) -> None:
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"scan": {"max_file_size_mb": 0}}), encoding="utf-8")
    with pytest.raises(ConfigError):
        ConfigStore(p).load()


@pytest.mark.security
@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "example.com", "::"])
def test_clamd_host_must_be_loopback(host: str) -> None:
    with pytest.raises(ValidationError):
        ClamAVSettings(clamd_host=host)


@pytest.mark.parametrize("host", ["127.0.0.1", "127.5.5.5", "::1", "localhost"])
def test_clamd_loopback_accepted(host: str) -> None:
    assert ClamAVSettings(clamd_host=host).clamd_host == host
