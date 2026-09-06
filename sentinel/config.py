"""Sentinel configuration loading from .sentinel.yml."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

DEFAULT_MODEL = "qwen2.5-coder:3b"


@dataclass
class ModelConfig:
    provider: str = "ollama"  # 'ollama' | 'openai'
    model: str = DEFAULT_MODEL
    base_url: str = "http://localhost:11434"
    api_key: str | None = None
    temperature: float = 0.1
    max_tokens: int = 1024
    timeout: int = 120  # seconds per AI call (explain, fix-plan, …)


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
    resources: dict = field(default_factory=dict)


class ConfigError(ValueError):
    pass


_VALID_PROVIDERS = ("ollama", "openai")
_VALID_SEVERITIES = ("info", "low", "medium", "high", "critical")


def validate_config(cfg: SentinelConfig) -> SentinelConfig:
    """Validate ranges/types. Raises ConfigError on invalid input."""
    if cfg.model.provider not in _VALID_PROVIDERS:
        raise ConfigError(f"model.provider must be one of {_VALID_PROVIDERS}, got {cfg.model.provider!r}")
    if cfg.model.model.strip() == "":
        raise ConfigError("model.model cannot be empty")
    if not isinstance(cfg.model.max_tokens, int) or cfg.model.max_tokens < 1:
        raise ConfigError("model.max_tokens must be a positive integer")
    if not isinstance(cfg.model.timeout, int) or cfg.model.timeout < 1:
        raise ConfigError("model.timeout must be a positive integer (seconds)")
    if not isinstance(cfg.model.temperature, (int, float)) or not 0.0 <= cfg.model.temperature <= 2.0:
        raise ConfigError("model.temperature must be within [0.0, 2.0]")
    for sev in (cfg.thresholds.max_severity_posted, cfg.thresholds.min_severity_autofix):
        if sev not in _VALID_SEVERITIES:
            raise ConfigError(f"threshold severity must be one of {_VALID_SEVERITIES}, got {sev!r}")
    if not isinstance(cfg.ignore_paths, list) or not all(isinstance(p, str) for p in cfg.ignore_paths):
        raise ConfigError("ignore_paths must be a list of strings")
    if not isinstance(cfg.model.base_url, str) or not cfg.model.base_url.startswith(("http://", "https://")):
        raise ConfigError("model.base_url must start with http:// or https://")
    res = cfg.resources or {}
    if not isinstance(res, dict):
        raise ConfigError("resources must be a mapping")
    if "analyzer_timeout" in res and (not isinstance(res["analyzer_timeout"], int) or res["analyzer_timeout"] < 1):
        raise ConfigError("resources.analyzer_timeout must be a positive integer")
    ra = res.get("required_analyzers")
    if ra is not None and (not isinstance(ra, list) or not all(isinstance(a, str) for a in ra)):
        raise ConfigError("resources.required_analyzers must be a list of analyzer names")
    if "max_explanations" in res and (not isinstance(res["max_explanations"], int) or res["max_explanations"] < 0):
        raise ConfigError("resources.max_explanations must be a non-negative integer")
    adt = res.get("allowed_test_dirs")
    if adt is not None and (not isinstance(adt, list) or not all(isinstance(p, str) for p in adt)):
        raise ConfigError("resources.allowed_test_dirs must be a list of directory paths")
    return cfg


def _load_yaml(path: str) -> dict:
    from .yamlsafe import load_yaml_strict

    with open(path, encoding="utf-8") as fh:
        data = load_yaml_strict(fh.read()) or {}
    return data


def load_config(path: str | None = None) -> SentinelConfig:
    """Load config from explicit path, or from .sentinel.yml in CWD, or defaults."""
    cfg = SentinelConfig()
    if path is not None and not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")
    if path is None and os.path.exists(".sentinel.yml"):
        path = ".sentinel.yml"
    if not path:
        return validate_config(cfg)

    data = _load_yaml(path)
    if not isinstance(data, dict):
        raise ConfigError(f"Config file must be a mapping, got {type(data).__name__}")

    known = {"model", "thresholds", "auto_fix", "ignore_paths", "custom_rules",
             "memory_enabled", "memory_dir", "resources"}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"unexpected config keys: {', '.join(sorted(unknown))} (allowed: {', '.join(sorted(known))})")

    model = data.get("model", {}) or {}
    cfg.model.provider = model.get("provider", cfg.model.provider)
    cfg.model.model = model.get("model", cfg.model.model)
    cfg.model.base_url = model.get("base_url", cfg.model.base_url)
    cfg.model.api_key = model.get("api_key", os.environ.get("OPENAI_API_KEY"))
    cfg.model.temperature = model.get("temperature", cfg.model.temperature)
    cfg.model.max_tokens = model.get("max_tokens", cfg.model.max_tokens)
    cfg.model.timeout = model.get("timeout", cfg.model.timeout)

    th = data.get("thresholds", {}) or {}
    cfg.thresholds.max_severity_posted = th.get("max_severity_posted", cfg.thresholds.max_severity_posted)
    cfg.thresholds.min_severity_autofix = th.get("min_severity_autofix", cfg.thresholds.min_severity_autofix)

    af = data.get("auto_fix", {}) or {}
    cfg.auto_fix.enabled = af.get("enabled", cfg.auto_fix.enabled)
    cfg.auto_fix.max_severity = af.get("max_severity", cfg.auto_fix.max_severity)
    cfg.auto_fix.target_branch = af.get("target_branch")
    cfg.auto_fix.require_tests = af.get("require_tests", cfg.auto_fix.require_tests)

    cfg.ignore_paths = data.get("ignore_paths", []) or []
    cfg.custom_rules = data.get("custom_rules", {}) or {}
    cfg.memory_enabled = data.get("memory_enabled", True)
    cfg.memory_dir = data.get("memory_dir", ".sentinel-memory")
    cfg.resources = data.get("resources", {}) or {}

    return validate_config(cfg)