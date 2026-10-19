"""
util/defang.py - make hostile text safe to print, log and paste into tickets.

Two separate problems:
  1. defang()    : stop IOCs (URLs, IPs, domains, emails) from being clickable/auto-resolved.
  2. safe_text() : stop terminal tricks (ANSI escapes, control chars, RTL-override spoofing).
Every string that originates from an email must pass through both before display.
"""
from __future__ import annotations

import re
from typing import Any

# --- 1. defanging ----------------------------------------------------------
_SCHEME = re.compile(r"\b(h)tt(ps?)://", re.I)
_FTP = re.compile(r"\bftp://", re.I)
# IPv4, or domain-like token ending in an alphabetic TLD (also catches file names
# like invoice.pdf - harmless over-defanging, and it makes a.exe.pdf obvious)
_HOST = re.compile(
    r"(?<![\w\[])((?:\d{1,3}\.){3}\d{1,3}|(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24})(?![\w\]])",
    re.I,
)


def defang(text: str) -> str:
    """hxxps://evil[.]com/login , user[@]evil[.]com , 1[.]2[.]3[.]4"""
    if not text:
        return text
    text = _SCHEME.sub(lambda m: f"{m.group(1)}xx{m.group(2)}://", text)
    text = _FTP.sub("fxp://", text)
    text = text.replace("@", "[@]")
    return _HOST.sub(lambda m: m.group(1).replace(".", "[.]"), text)


# --- 2. terminal / log safety ----------------------------------------------
# C0/C1 control chars (includes ESC, so ANSI sequences die) + bidi override/isolate chars
_UNSAFE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\u200b-\u200f\ufeff]")


def safe_text(s: Any, max_len: int = 300) -> str:
    """Single-line, printable, length-limited. Dangerous chars shown as <U+XXXX>."""
    s = "" if s is None else str(s)
    s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    s = _UNSAFE.sub(lambda m: f"<U+{ord(m.group()):04X}>", s)
    return s if len(s) <= max_len else s[: max_len - 1] + "…"


def clean(s: Any, max_len: int = 300) -> str:
    """The one call to use for display: safe_text then defang."""
    return defang(safe_text(s, max_len))


def clean_deep(obj: Any) -> Any:
    """Apply clean() to every string inside nested dicts/lists (for JSON reports)."""
    if isinstance(obj, str):
        return defang(_UNSAFE.sub(lambda m: f"<U+{ord(m.group()):04X}>", obj))
    if isinstance(obj, dict):
        return {k: clean_deep(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [clean_deep(v) for v in obj]
    return obj
