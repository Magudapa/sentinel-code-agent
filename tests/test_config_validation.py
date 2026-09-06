"""Config validation — malicious/typo'd .sentinel.yml must fail loudly, never silently weaken."""

from __future__ import annotations

import pytest

from sentinel.config import ConfigError, SentinelConfig, load_config, validate_config


def _write(tmp_path, body: str):
    p = tmp_path / ".sentinel.yml"
    p.write_text(body, encoding="utf-8")
    return str(p)


def test_defaults_are_valid(tmp_path):
    cfg = load_config(str(_write(tmp_path, "model:\n  provider: ollama\n")))
    assert cfg.model.provider == "ollama"
    assert cfg.model.timeout == 120


def test_unknown_top_level_key_rejected(tmp_path):
    p = _write(tmp_path, "fake_pass: true\n")
    with pytest.raises(ConfigError):
        load_config(p)


def test_unknown_provider_rejected(tmp_path):
    p = _write(tmp_path, "model:\n  provider: chatgpt-openai-cloud\n")
    with pytest.raises(ConfigError):
        load_config(p)


def test_zero_timeout_rejected(tmp_path):
    p = _write(tmp_path, "model:\n  timeout: 0\n")
    with pytest.raises(ConfigError):
        load_config(p)


def test_negative_timeout_rejected(tmp_path):
    p = _write(tmp_path, "model:\n  timeout: -5\n")
    with pytest.raises(ConfigError):
        load_config(p)


def test_bad_temperature_rejected(tmp_path):
    p = _write(tmp_path, "model:\n  temperature: 3.5\n")
    with pytest.raises(ConfigError):
        load_config(p)


def test_bad_threshold_severity_rejected(tmp_path):
    p = _write(tmp_path, "thresholds:\n  max_severity_posted: purple\n")
    with pytest.raises(ConfigError):
        load_config(p)


def test_bad_analyzer_timeout_rejected(tmp_path):
    p = _write(tmp_path, "resources:\n  analyzer_timeout: 0.5\n")
    with pytest.raises(ConfigError):
        load_config(p)


def test_required_analyzers_must_be_list(tmp_path):
    p = _write(tmp_path, "resources:\n  required_analyzers: semgrep\n")
    with pytest.raises(ConfigError):
        load_config(p)


def test_valid_resources_accepted(tmp_path):
    p = _write(tmp_path, "resources:\n  required_analyzers: [bandit, ruff]\n  analyzer_timeout: 60\n")
    cfg = load_config(p)
    assert cfg.resources["required_analyzers"] == ["bandit", "ruff"]


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(str(tmp_path / "does-not-exist.yml"))


def test_validate_defaults_pass():
    cfg = validate_config(SentinelConfig())
    assert cfg.model.provider == "ollama"