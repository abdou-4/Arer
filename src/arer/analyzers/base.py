"""
analyzers/base.py - the contract every check follows, and the registry.

To add a check:
    1. create analyzers/mycheck.py
    2. subclass Analyzer, decorate with @register
    3. return a list of Finding from run()
Nothing else to edit. The pipeline discovers it automatically.
"""
from __future__ import annotations

import importlib
import pkgutil
from abc import ABC, abstractmethod

from ..config import Config
from ..models import Category, Email, Finding

_REGISTRY: dict[str, "Analyzer"] = {}


class Analyzer(ABC):
    name: str = ""                       # unique, e.g. "auth"

    @abstractmethod
    def run(self, email: Email, cfg: Config) -> list[Finding]:
        """Inspect the email. Return findings (empty list = nothing suspicious).
        Rules: never modify `email`, never touch the network, never open attachments."""

    # helper so analyzers stay short; category comes from the id prefix
    def finding(self, fid: str, summary: str, confidence: float = 1.0,
                source: str = "rule", **evidence) -> Finding:
        return Finding(id=fid, category=Category(fid.split(".", 1)[0]),
                       summary=summary, evidence=evidence,
                       confidence=confidence, source=source)


def register(cls: type[Analyzer]) -> type[Analyzer]:
    """Class decorator: instantiate once and add to the registry."""
    inst = cls()
    inst.name = inst.name or cls.__name__.lower()
    if inst.name in _REGISTRY:
        raise ValueError(f"duplicate analyzer name '{inst.name}'")
    _REGISTRY[inst.name] = inst
    return cls


def discover() -> None:
    """Import every module in this package so their @register decorators run."""
    from . import __name__ as pkg
    package = importlib.import_module(pkg)
    for m in pkgutil.iter_modules(package.__path__):
        if not m.name.startswith("_") and m.name != "base":
            importlib.import_module(f"{pkg}.{m.name}")


def get_analyzers(skip: set[str] | None = None) -> list[Analyzer]:
    discover()
    skip = skip or set()
    return [a for n, a in sorted(_REGISTRY.items()) if n not in skip]
