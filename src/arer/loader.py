"""
loader.py - reads a parser JSON file from disk and returns a validated Email.

This is the trust boundary between the filesystem and the analyzers: nothing
unvalidated gets past here. It never opens, runs or fetches anything inside the email.
"""
from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator
from pathlib import Path

from pydantic import ValidationError

from .config import Config, get_config
from .models import Email

EMAIL_SUFFIXES = {".eml", ".msg"}
SCAN_SUFFIXES = EMAIL_SUFFIXES | {".json"}

log = logging.getLogger("phishscope.loader")

_HEADER_LINE = re.compile(rb"^(?:From |[A-Za-z][A-Za-z0-9\-]{1,40}:)")
_NOT_MAIL = {".txt", ".csv", ".md", ".py", ".sh", ".yaml", ".yml", ".zip", ".gz", ".bz2", ".tar", ".tgz",
             ".7z", ".rar", ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".db", ".log", ".cfg", ".toml"}


def looks_like_mail(path: Path) -> bool:
    """True if the first line looks like an e-mail header. Lets us read files named like 00001.7c53... (no .eml)."""
    try:
        with Path(path).open("rb") as fh:
            head = fh.read(4096)
    except OSError:
        return False
    first = head.lstrip(b"\r\n").split(b"\n", 1)[0]
    return bool(_HEADER_LINE.match(first))


def is_mail_candidate(p: Path) -> bool:
    """A file worth scanning: known extension, or an extension-less/odd-named file that looks like mail."""
    if not p.is_file() or p.is_symlink() or p.name.startswith(".") or p.name.endswith(".report.json"):
        return False
    s = p.suffix.lower()
    if s in SCAN_SUFFIXES:
        return True
    return s not in _NOT_MAIL and p.name != "labels.csv" and looks_like_mail(p)


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

    return _build(raw, p.name)


def _build(raw: dict, name: str) -> Email:
    try:
        return Email.from_parser_json(raw)
    except ValidationError as e:
        raise LoadError(f"{name}: failed validation ({e.error_count()} errors)") from e


def load_any(path: str | Path, cfg: Config | None = None, trust: str | None = None) -> Email:
    """
    The one call the CLI uses.
      .json       -> read existing parser output
      .eml / .msg -> run YOUR mail_parser.parse_mail_file() in memory, no temp file
    `trust` is the trusted mail-server string that enables routing.sender_ip.
    """
    cfg = cfg or get_config()
    p = Path(path)
    suffix = p.suffix.lower()
    if suffix == ".json":
        return load_email(p, cfg)
    if suffix not in EMAIL_SUFFIXES and not (suffix not in _NOT_MAIL and p.is_file() and looks_like_mail(p)):
        raise LoadError(f"{p.name}: unsupported type '{p.suffix}' (use .eml, .msg or .json)")
    if not p.is_file():
        raise LoadError(f"not a file: {p}")
    max_bytes = cfg.limits.max_eml_mb * 1024 * 1024
    if p.stat().st_size > max_bytes:
        raise LoadError(f"{p.name} is {p.stat().st_size / 1e6:.1f} MB, limit is {cfg.limits.max_eml_mb} MB")

    from .mail_parser import parse_mail_file, to_json     # lazy: .json scans never need it
    try:
        # payload is embedded only so magic bytes can be read; Attachment.from_raw drops it
        data = parse_mail_file(p, trust=trust, include_attachment_payload=True)
        raw = json.loads(to_json(data, None))              # same round-trip as a saved file
    except Exception as e:                                 # noqa: BLE001 - library errors vary
        raise LoadError(f"{p.name}: parser failed ({type(e).__name__}: {str(e)[:150]})") from e
    return _build(raw, p.name)


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
