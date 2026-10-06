"""Extract everything mail-parser 4.8.0 exposes from .eml / .msg files.

Public API
----------
parse_mail_file(path, trust=None, ...) -> dict   # one email  -> JSON-ready dict
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from mailparser import MailParser
from mailparser.exceptions import MailParserError

OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # Outlook .msg container
SUPPORTED_SUFFIXES = {".eml", ".msg"}

URL_RE = re.compile(r"""https?://[^\s<>"'\)\]]+""", re.IGNORECASE)
HREF_RE = re.compile(
    r"""<a\s[^>]*?href\s*=\s*["']?([^"'\s>]+)["']?[^>]*>(.*?)</a>""",
    re.IGNORECASE | re.DOTALL,
)
TAG_RE = re.compile(r"<[^>]+>")

# Headers a SOC analyst almost always wants at hand (looked up case-insensitively
# in the raw header list, so duplicates are preserved).
SECURITY_HEADERS = (
    "return-path", "sender", "reply-to", "in-reply-to", "references",
    "authentication-results", "received-spf", "dkim-signature",
    "arc-authentication-results", "arc-seal", "arc-message-signature",
    "x-originating-ip", "x-mailer", "user-agent", "x-priority", "importance",
    "list-unsubscribe", "x-spam-status", "x-spam-score", "x-ms-exchange-organization-authas",
    "x-original-to", "disposition-notification-to", "errors-to",
)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def json_default(obj: Any) -> Any:
    """Make datetimes, bytes, sets, etc. JSON-serialisable."""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, (bytes, bytearray)):
        return base64.b64encode(bytes(obj)).decode("ascii")
    if isinstance(obj, (set, frozenset)):
        return sorted(obj, key=str)
    return str(obj)


def _hashes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _addresses(pairs: list[tuple[str, str]]) -> list[dict[str, str]]:
    """mail-parser returns [(display_name, address)] -> list of dicts."""
    out = []
    for name, addr in pairs or []:
        domain = addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""
        out.append({"name": name, "address": addr, "domain": domain})
    return out


def detect_format(path: Path) -> str:
    with path.open("rb") as fh:
        head = fh.read(8)
    if head == OLE2_MAGIC or path.suffix.lower() == ".msg":
        return "msg"
    return "eml"


def _load(path: Path, fmt: str) -> MailParser:
    if fmt == "msg":
        # needs: pip install "mail-parser[outlook]"  (extract-msg backend)
        return MailParser.from_file_msg(str(path))
    return MailParser.from_file(str(path))


# --------------------------------------------------------------------------- #
# sections
# --------------------------------------------------------------------------- #
def _attachments(parser: MailParser, include_payload: bool) -> list[dict[str, Any]]:
    result = []
    for att in parser.attachments:
        payload = att.get("payload") or ""
        try:
            if att.get("binary"):
                raw = base64.b64decode(payload, validate=False)
            else:
                raw = payload.encode(att.get("charset") or "utf-8", errors="replace")
        except (binascii.Error, LookupError):
            raw = payload.encode("utf-8", errors="replace")

        item = {
            "filename": att.get("filename"),
            "safe_filename": att.get("safe_filename"),
            "extension": Path(att.get("filename") or "").suffix.lower(),
            "content_type": att.get("mail_content_type"),
            "content_id": att.get("content-id"),
            "content_disposition": att.get("content-disposition"),
            "charset": att.get("charset"),
            "content_transfer_encoding": att.get("content_transfer_encoding"),
            "is_binary": att.get("binary"),
            "size_bytes": len(raw),
            "hashes": _hashes(raw),
        }
        if include_payload:
            item["payload"] = payload  # base64 if binary, text otherwise
        result.append(item)
    return result


def _indicators(parser: MailParser) -> dict[str, Any]:
    """URLs / link mismatches pulled from the bodies (not a mail-parser feature,
    but it is the first thing a phishing detector needs)."""
    text = "\n".join(parser.text_plain or [])
    html = "\n".join(parser.text_html or [])

    urls = set(URL_RE.findall(text)) | set(URL_RE.findall(html))

    mismatches = []
    for href, label in HREF_RE.findall(html):
        shown = TAG_RE.sub("", label).strip()
        if URL_RE.match(shown) and URL_RE.match(href):
            host = lambda u: re.sub(r"^https?://", "", u, flags=re.I).split("/")[0].lower()
            if host(shown) != host(href):
                mismatches.append({"href": href, "displayed_text": shown})

    domains = sorted({re.sub(r"^https?://", "", u, flags=re.I).split("/")[0].split(":")[0].lower()
                      for u in urls})
    return {
        "urls": sorted(urls),
        "url_domains": domains,
        "href_text_mismatches": mismatches,
    }


# --------------------------------------------------------------------------- #
# main entry point
# --------------------------------------------------------------------------- #
def parse_mail_file(
    path: str | Path,
    trust: str | None = None,
    include_attachment_payload: bool = False,
    include_library_views: bool = False,
    attachments_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Parse one .eml/.msg file and return a JSON-serialisable dict.

    trust                       trusted mail-server string for get_server_ipaddress()
    include_attachment_payload  embed attachment content (base64) in the JSON
    include_library_views       also embed mail-parser's own `mail` / `mail_partial` dicts
    attachments_dir             if set, write attachments to disk there (parser.write_attachments)
    """
    path = Path(path)
    raw = path.read_bytes()
    fmt = detect_format(path)
    parser = _load(path, fmt)

    raw_headers = [[k, str(v)] for k, v in (parser.message.items() if parser.message else [])]
    lowered = {}
    for k, v in raw_headers:
        lowered.setdefault(k.lower(), []).append(v)

    result: dict[str, Any] = {
        "file": {
            "path": str(path.resolve()),
            "name": path.name,
            "format": fmt,
            "size_bytes": len(raw),
            "hashes": _hashes(raw),
            "parsed_at": datetime.now(timezone.utc).isoformat(),
            "mail_parser_version": "4.8.0",
        },
        "envelope": {
            "subject": parser.subject,
            "message_id": parser.message_id,
            "date": parser.date,
            "timezone": parser.timezone,
            "from": _addresses(parser.from_),
            "to": _addresses(parser.to),
            "cc": _addresses(parser.cc),
            "bcc": _addresses(parser.bcc),
            "reply_to": _addresses(parser.reply_to),
            "delivered_to": _addresses(parser.delivered_to),
            "to_domains": parser.to_domains,
            "return_path": parser.return_path,
            "x_mailer": parser.x_mailer,
            "user_agent": parser.user_agent,
            "x_original_to": parser.x_original_to,
        },
        "headers": {
            "parsed": parser.headers,          # mail-parser's dict (duplicates merged)
            "raw_ordered": raw_headers,        # every header, original order, duplicates kept
            "security": {h: lowered[h] for h in SECURITY_HEADERS if h in lowered},
        },
        "routing": {
            "received": parser.received,       # parsed hops (from/by/with/id/date/hop/delay)
            "received_raw": parser.received_raw,
            "sender_ip": parser.get_server_ipaddress(trust) if trust else None,
        },
        "body": {
            "text_plain": parser.text_plain,
            "text_html": parser.text_html,
            "text_not_managed": parser.text_not_managed,
            "combined": parser.body,
        },
        "attachments": _attachments(parser, include_attachment_payload),
        "defects": {
            "has_defects": parser.has_defects,
            "defects": parser.defects,
            "categories": parser.defects_categories,
            "address_header_defects": parser.address_header_defects,
            "received_header_defects": parser.received_header_defects,
            "date_header_defects": parser.date_header_defects,
        },
        "indicators": _indicators(parser),
    }

    if attachments_dir and parser.attachments:
        out = Path(attachments_dir)
        out.mkdir(parents=True, exist_ok=True)
        parser.write_attachments(str(out))
        result["attachments_written_to"] = str(out.resolve())

    if include_library_views:
        strip = lambda d: {k: v for k, v in d.items() if k != "attachments"} | {
            "attachments": [{k: v for k, v in a.items() if k != "payload"} for a in d.get("attachments", [])]
        }
        result["library_views"] = {
            "mail": strip(parser.mail),
            "mail_partial": strip(parser.mail_partial),
            "message_as_string": parser.message_as_string,
        }

    return result


def to_json(data: dict[str, Any], indent: int | None = 2) -> str:
    return json.dumps(data, indent=indent, ensure_ascii=False, default=json_default)


__all__ = ["parse_mail_file", "to_json", "MailParserError", "SUPPORTED_SUFFIXES"]
