"""Sentinel configuration loading from .sentinel.yml."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import yaml

DEFAULT_MODEL = "qwen2.5-coder:7b"


@dataclass
class ModelConfig:
    provider: str = "ollama"  # 'ollama' | 'openai'
    model: str = DEFAULT_MODEL
    base_url: str = "http://localhost:11434"
    api_key: str | None = None
    temperature: float = 0.1
    max_tokens: int = 1024


@dataclass
class Thresholds:
    max_severity_posted: str = "info"  # findings at or above this get posted
    min_severity_autofix: str = "high"


@dataclass
class AutoFixConfig:
    enabled: bool = False
    max_severity: str = "high"
    target_branch: str | None = None
    require_tests: bool = True


@dataclass
class SentinelConfig:
    model: ModelConfig = field(default_factory=ModelConfig)
    thresholds: Thresholds = field(default_factory=Thresholds)
    auto_fix: AutoFixConfig = field(default_factory=AutoFixConfig)
    ignore_paths: list[str] = field(default_factory=list)
    custom_rules: dict = field(default_factory=dict)
    memory_enabled: bool = True
    memory_dir: str = ".sentinel-memory"


def _load_yaml(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return data


def load_config(path: str | None = None) -> SentinelConfig:
    """Load config from explicit path, or from .sentinel.yml in CWD, or defaults."""
    cfg = SentinelConfig()
    if path is not None and not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")
    if path is None and os.path.exists(".sentinel.yml"):
        path = ".sentinel.yml"
    if not path:
        return cfg

    data = _load_yaml(path)

    model = data.get("model", {})
    cfg.model.provider = model.get("provider", cfg.model.provider)
    cfg.model.model = model.get("model", cfg.model.model)
    cfg.model.base_url = model.get("base_url", cfg.model.base_url)
    cfg.model.api_key = model.get("api_key", os.environ.get("OPENAI_API_KEY"))
    cfg.model.temperature = model.get("temperature", cfg.model.temperature)
    cfg.model.max_tokens = model.get("max_tokens", cfg.model.max_tokens)

    th = data.get("thresholds", {})
    cfg.thresholds.max_severity_posted = th.get("max_severity_posted", cfg.thresholds.max_severity_posted)
    cfg.thresholds.min_severity_autofix = th.get("min_severity_autofix", cfg.thresholds.min_severity_autofix)

    af = data.get("auto_fix", {})
    cfg.auto_fix.enabled = af.get("enabled", cfg.auto_fix.enabled)
    cfg.auto_fix.max_severity = af.get("max_severity", cfg.auto_fix.max_severity)
    cfg.auto_fix.target_branch = af.get("target_branch")
    cfg.auto_fix.require_tests = af.get("require_tests", cfg.auto_fix.require_tests)

    cfg.ignore_paths = data.get("ignore_paths", [])
    cfg.custom_rules = data.get("custom_rules", {})
    cfg.memory_enabled = data.get("memory_enabled", True)
    cfg.memory_dir = data.get("memory_dir", ".sentinel-memory")

    return cfg