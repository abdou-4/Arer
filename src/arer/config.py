"""
config.py - loads config/rules.yaml and config/lists/*.txt into one validated object.

Everything tunable lives in config files, so changing a weight needs no code edit.
Bad config fails LOUDLY at startup, instead of silently producing wrong scores.
"""
from __future__ import annotations

import logging
import os
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, model_validator

from .models import Category, Level

log = logging.getLogger("phishscope.config")

# src/arer/config.py -> project root is 2 levels above src/
DEFAULT_CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"

LIST_FILES = {
    "suspicious_tlds": "suspicious_tlds.txt",
    "executable_ext": "executable_ext.txt",
    "macro_ext": "macro_ext.txt",
    "archive_ext": "archive_ext.txt",
    "shorteners": "shorteners.txt",
    "free_mail": "free_mail.txt",
    "brands": "brands.txt",
    "bad_mailers": "bad_mailers.txt",
}


class ConfigError(Exception):
    """Raised when rules.yaml or a list file is missing or invalid."""


class Limits(BaseModel):
    max_json_mb: int = Field(20, gt=0, le=500)
    analyzer_timeout_s: int = Field(10, gt=0, le=300)


class Thresholds(BaseModel):
    suspicious: int = 20
    likely_phishing: int = 45
    malicious: int = 70

    @model_validator(mode="after")
    def _ordered(self):
        if not (0 < self.suspicious < self.likely_phishing < self.malicious <= 100):
            raise ValueError("thresholds must satisfy 0 < suspicious < likely_phishing < malicious <= 100")
        return self


class Override(BaseModel):
    finding: str
    min_level: Level


class Config(BaseModel):
    limits: Limits = Field(default_factory=Limits)
    thresholds: Thresholds = Field(default_factory=Thresholds)
    caps: dict[str, int]
    weights: dict[str, int]
    overrides: list[Override] = Field(default_factory=list)
    lists: dict[str, frozenset[str]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check(self):
        valid_cats = {c.value for c in Category}
        for cat, cap in self.caps.items():
            if cat not in valid_cats:
                raise ValueError(f"caps: unknown category '{cat}'")
            if cap < 0:
                raise ValueError(f"caps: '{cat}' must be >= 0")
        for fid, w in self.weights.items():
            if fid.split(".", 1)[0] not in valid_cats:
                raise ValueError(f"weights: '{fid}' has unknown category prefix")
            if w < 0:
                raise ValueError(f"weights: '{fid}' must be >= 0")
        for o in self.overrides:
            if o.finding not in self.weights:
                raise ValueError(f"overrides: '{o.finding}' is not in weights")
        return self

    # ---- helpers used by pipeline / analyzers ---------------------------- #
    def weight_for(self, finding_id: str) -> int:
        """Points for a finding id. Unknown ids score 0 and are logged (typo guard)."""
        if finding_id not in self.weights:
            log.warning("finding id '%s' has no weight in rules.yaml", finding_id)
            return 0
        return self.weights[finding_id]

    def cap_for(self, category: str) -> int:
        return self.caps.get(category, 0)

    def in_list(self, name: str, value: str) -> bool:
        return value.strip().lower() in self.lists.get(name, frozenset())


def _read_list(path: Path) -> frozenset[str]:
    items = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            items.add(line)
    return frozenset(items)


def load_config(config_dir: str | Path | None = None) -> Config:
    """Load and validate config. Dir: argument > $PHISHSCOPE_CONFIG > ./config"""
    base = Path(config_dir or os.environ.get("PHISHSCOPE_CONFIG") or DEFAULT_CONFIG_DIR)
    rules = base / "rules.yaml"
    if not rules.is_file():
        raise ConfigError(f"rules.yaml not found in {base}")
    try:
        data = yaml.safe_load(rules.read_text(encoding="utf-8")) or {}   # safe_load only
    except yaml.YAMLError as e:
        raise ConfigError(f"rules.yaml is not valid YAML: {e}") from e
    if not isinstance(data, dict):
        raise ConfigError("rules.yaml must be a mapping at the top level")

    lists = {}
    for key, fname in LIST_FILES.items():
        p = base / "lists" / fname
        if p.is_file():
            lists[key] = _read_list(p)
        else:
            log.warning("list file missing: %s (treated as empty)", p)
            lists[key] = frozenset()
    data["lists"] = lists

    try:
        return Config.model_validate(data)
    except Exception as e:                      # pydantic ValidationError
        raise ConfigError(f"invalid rules.yaml: {e}") from e


@lru_cache(maxsize=1)
def get_config() -> Config:
    """Cached default config for normal use."""
    return load_config()
