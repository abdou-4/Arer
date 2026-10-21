"""
attachments.py - judge attachments from names, declared types, and the first bytes.

Nothing is opened, extracted or executed. For zip files we read only the list of member
names. Findings: executables, double extensions, macro Office files, archives hiding
executables or encrypted, HTML/SVG attachments, and files whose bytes contradict their name.
"""
from __future__ import annotations

import re

from ..models import Attachment, Email
from .base import Analyzer, register

DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png", "gif", "csv", "zip"}
HTML_EXT = {"html", "htm", "xhtml", "shtml", "svg", "mht", "mhtml"}
BIDI = re.compile(r"[\u202a-\u202e\u2066-\u2069]")
# extension -> real types that are acceptable for it
EXPECT = {"pdf": {"pdf"}, "png": {"png"}, "jpg": {"jpeg"}, "jpeg": {"jpeg"}, "gif": {"gif"},
          "zip": {"zip"}, "docx": {"zip"}, "xlsx": {"zip"}, "pptx": {"zip"}, "docm": {"zip"},
          "xlsm": {"zip"}, "rar": {"rar"}, "7z": {"7z"},
          "doc": {"ole", "rtf", "zip"}, "xls": {"ole", "zip"}, "ppt": {"ole", "zip"}}
REAL_EXEC = {"mz", "elf"}


def exts_of(filename: str) -> list[str]:
    """['pdf', 'exe'] for 'invoice.pdf   .exe'. Whitespace and bidi tricks removed first."""
    n = re.sub(r"\s+", "", BIDI.sub("", filename.lower()))
    return re.findall(r"\.([a-z0-9]{1,10})", n)


@register
class Attachments(Analyzer):
    name = "attachments"

    def run(self, email: Email, cfg):
        L = cfg.lists
        exec_ext, macro_ext = L.get("executable_ext", frozenset()), L.get("macro_ext", frozenset())
        arch_ext = L.get("archive_ext", frozenset())
        hits: dict[str, dict] = {}

        def hit(fid, conf, summary, a: Attachment, **extra):
            h = hits.setdefault(fid, {"conf": 0.0, "summary": summary, "items": []})
            if conf > h["conf"]:
                h["conf"], h["summary"] = conf, summary
            if len(h["items"]) < 5:
                h["items"].append({"filename": a.filename[:100], "sha256": a.sha256, "size": a.size_bytes, **extra})

        for a in email.attachments:
            exts = exts_of(a.filename) or ([a.extension.lstrip(".")] if a.extension else [])
            last = exts[-1] if exts else ""
            ct = a.content_type.lower()

            # executables, by name or by real content
            if last in exec_ext:
                hit("attachment.executable", 1.0, f"Executable/script attachment ({last})", a)
            elif a.sniffed in REAL_EXEC:
                hit("attachment.executable", 1.0, "Attachment content is a program, whatever its name says", a, real_type=a.sniffed)

            # double extension / right-to-left override
            if BIDI.search(a.filename):
                hit("attachment.double_extension", 1.0, "File name contains a right-to-left override (spoofed extension)", a)
            elif len(exts) >= 2 and exts[-2] in DOC_EXT and (last in exec_ext or last in macro_ext or last in HTML_EXT):
                hit("attachment.double_extension", 1.0, f"Double extension: looks like .{exts[-2]}, is really .{last}", a)

            # macro Office
            if (last in macro_ext or "macroenabled" in ct
                    or any(m.lower().endswith("vbaproject.bin") for m in a.members)):
                hit("attachment.macro_office", 1.0, "Office document that can contain macros", a)

            # HTML / SVG attachments (HTML smuggling, fake login pages)
            if last in HTML_EXT or ct.startswith(("text/html", "image/svg")):
                hit("attachment.html_or_svg", 1.0, f"HTML/SVG file attached ({last or ct})", a)

            # archives
            if last in arch_ext or a.sniffed in ("zip", "rar", "7z"):
                bad = [m for m in a.members if (exts_of(m) or [""])[-1] in exec_ext]
                if bad:
                    hit("attachment.archive_with_exe", 1.0, "Archive contains an executable/script", a, inside=bad[:5])
                if a.encrypted:
                    hit("attachment.encrypted_archive", 0.8, "Password-protected archive (cannot be inspected)", a)

            # extension vs real content
            if a.sniffed and last in EXPECT and a.sniffed not in EXPECT[last]:
                hit("attachment.magic_mismatch", 1.0 if a.sniffed in REAL_EXEC else 0.7,
                    f"Named .{last} but the content is {a.sniffed}", a, real_type=a.sniffed)

        return [self.finding(fid, h["summary"], h["conf"], attachments=h["items"])
                for fid, h in sorted(hits.items())]
