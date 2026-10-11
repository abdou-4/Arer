"""
loader.py - reads a parser JSON file from disk and returns a validated Email.

This is the trust boundary between the filesystem and the analyzers: nothing
unvalidated gets past here. It never opens, runs or fetches anything inside the email.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from pathlib import Path

from pydantic import ValidationError

from .config import Config, get_config
from .models import Email

log = logging.getLogger("phishscope.loader")


class LoadError(Exception):
    """A file could not be turned into an Email. The message is safe to show."""


def load_email(path: str | Path, cfg: Config | None = None) -> Email:
    cfg = cfg or get_config()
    p = Path(path)

    if not p.is_file():
        raise LoadError(f"not a file: {p}")
    if p.suffix.lower() != ".json":
        raise LoadError(f"expected a .json parser output, got '{p.suffix}': {p.name}")

    max_bytes = cfg.limits.max_json_mb * 1024 * 1024
    size = p.stat().st_size
    if size > max_bytes:
        raise LoadError(f"{p.name} is {size / 1e6:.1f} MB, limit is {cfg.limits.max_json_mb} MB")

    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except UnicodeDecodeError as e:
        raise LoadError(f"{p.name}: not valid UTF-8") from e
    except json.JSONDecodeError as e:
        raise LoadError(f"{p.name}: invalid JSON ({e.msg} at line {e.lineno})") from e

    if not isinstance(raw, dict):
        raise LoadError(f"{p.name}: top level must be a JSON object")
    if not {"envelope", "body"} & raw.keys():
        raise LoadError(f"{p.name}: does not look like parser output (no 'envelope' or 'body')")

    try:
        return Email.from_parser_json(raw)
    except ValidationError as e:
        raise LoadError(f"{p.name}: failed validation ({e.error_count()} errors)") from e


def load_dir(directory: str | Path, cfg: Config | None = None
             ) -> Iterator[tuple[Path, Email | None, str | None]]:
    """
    Yield (path, email, error) for every *.json in a folder.
    One bad file never stops the batch: it yields (path, None, "reason").
    """
    cfg = cfg or get_config()
    d = Path(directory)
    if not d.is_dir():
        raise LoadError(f"not a directory: {d}")
    for p in sorted(d.glob("*.json")):
        try:
            yield p, load_email(p, cfg), None
        except LoadError as e:
            log.warning("skipped %s: %s", p.name, e)
            yield p, None, str(e)
