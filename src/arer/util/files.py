"""
util/files.py - look at file bytes WITHOUT opening or running anything.

sniff()        : what the first bytes say the file really is
zip_members()  : list file names inside a zip (reads only the directory, never extracts)
"""
from __future__ import annotations

import io
import zipfile

SIGNATURES: list[tuple[bytes, str]] = [
    (b"%PDF", "pdf"), (b"\x89PNG", "png"), (b"\xff\xd8\xff", "jpeg"), (b"GIF8", "gif"),
    (b"PK\x03\x04", "zip"), (b"PK\x05\x06", "zip"), (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"), (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (b"\x7fELF", "elf"), (b"\x1f\x8b", "gzip"), (b"{\\rtf", "rtf"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "lnk"), (b"MZ", "mz"),
]
MAX_MEMBERS = 200


def sniff(head: bytes) -> str:
    """'' when unknown (for example plain text)."""
    for sig, kind in SIGNATURES:
        if head.startswith(sig):
            return kind
    return ""


def zip_members(data: bytes) -> tuple[list[str], bool]:
    """(member names, any member encrypted). Reads the central directory only."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()[:MAX_MEMBERS]
            return [i.filename[:300] for i in infos], any(i.flag_bits & 0x1 for i in infos)
    except (zipfile.BadZipFile, ValueError, OSError, NotImplementedError, EOFError):
        return [], False
