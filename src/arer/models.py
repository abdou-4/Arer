"""
models.py - data contracts for PhishScope (src/arer/models.py)

Two halves:
  1. INPUT  : Email and its sub-models. Mirror the JSON written by mail_parser.py.
  2. OUTPUT : Finding, Verdict. What analyzers return and what scoring produces.

Design rules
  * The parser JSON is untrusted. Every field is optional with a safe default,
    unknown keys are ignored, and wrong types are coerced instead of crashing.
  * Lists are length-capped so a hostile email cannot exhaust memory.
  * Analyzers read helper properties (email.from_domain, email.auth_results ...)
    and never dig through raw dicts themselves.
"""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# --------------------------------------------------------------------------- #
# Limits (hostile-input protection). Tune in config.py later if needed.
# --------------------------------------------------------------------------- #
MAX_ADDRESSES = 200
MAX_HOPS = 100
MAX_URLS = 2000
MAX_ATTACHMENTS = 100
MAX_BODY_CHARS = 2_000_000
MAX_HEADER_VALUE = 20_000


def _s(v: Any) -> str:
    """Coerce anything to str. None -> ''."""
    return "" if v is None else str(v)


def _as_list(v: Any) -> list:
    """Coerce a scalar / None to a list."""
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


class _Base(BaseModel):
    # ignore unknown keys, so a parser change never breaks loading
    model_config = ConfigDict(extra="ignore", populate_by_name=True)


# =========================================================================== #
# INPUT MODELS (mirror the parser JSON)
# =========================================================================== #

class Address(_Base):
    """One mailbox: {"name": "...", "address": "...", "domain": "..."}"""
    name: str = ""
    address: str = ""
    domain: str = ""

    @field_validator("name", "address", "domain", mode="before")
    @classmethod
    def _str(cls, v):
        return _s(v).strip()

    @field_validator("address", "domain", mode="after")
    @classmethod
    def _lower(cls, v):
        return v.lower()


class FileInfo(_Base):
    """parsed["file"]: where the sample came from, and its hashes."""
    path: str = ""
    name: str = ""
    format: str = "eml"
    size_bytes: int = 0
    md5: str = ""
    sha1: str = ""
    sha256: str = ""

    @classmethod
    def from_raw(cls, raw: dict) -> "FileInfo":
        raw = raw or {}
        h = raw.get("hashes") or {}
        return cls(
            path=_s(raw.get("path")), name=_s(raw.get("name")),
            format=_s(raw.get("format")) or "eml",
            size_bytes=raw.get("size_bytes") or 0,
            md5=_s(h.get("md5")), sha1=_s(h.get("sha1")), sha256=_s(h.get("sha256")),
        )


class Envelope(_Base):
    """parsed["envelope"]: the headers an analyst reads first."""
    subject: str = ""
    message_id: str = ""
    date: str = ""                      # ISO-8601 string, may be empty
    timezone: str = ""
    from_: list[Address] = Field(default_factory=list, alias="from")
    to: list[Address] = Field(default_factory=list)
    cc: list[Address] = Field(default_factory=list)
    bcc: list[Address] = Field(default_factory=list)
    reply_to: list[Address] = Field(default_factory=list)
    delivered_to: list[Any] = Field(default_factory=list)
    to_domains: list[str] = Field(default_factory=list)
    return_path: str = ""
    x_mailer: str = ""
    user_agent: str = ""
    x_original_to: str = ""

    @field_validator("subject", "message_id", "date", "timezone", "return_path",
                     "x_mailer", "user_agent", "x_original_to", mode="before")
    @classmethod
    def _str(cls, v):
        return _s(v)[:MAX_HEADER_VALUE]

    @field_validator("from_", "to", "cc", "bcc", "reply_to", mode="before")
    @classmethod
    def _addr_list(cls, v):
        return _as_list(v)[:MAX_ADDRESSES]


class Hop(_Base):
    """One Received header, parsed. `hop` 1 = the oldest (first sender)."""
    hop: int = 0
    from_: str = Field("", alias="from")
    by: str = ""
    with_: str = Field("", alias="with")
    via: str = ""
    id: str = ""
    date: str = ""
    date_utc: str = ""
    delay: float | None = None          # seconds since previous hop

    @field_validator("from_", "by", "with_", "via", "id", "date", "date_utc",
                     mode="before")
    @classmethod
    def _str(cls, v):
        return _s(v)[:MAX_HEADER_VALUE]


class Routing(_Base):
    received: list[Hop] = Field(default_factory=list)       # parsed hops
    received_raw: list[str] = Field(default_factory=list)   # untouched header text
    sender_ip: str | None = None

    @field_validator("received", "received_raw", mode="before")
    @classmethod
    def _cap(cls, v):
        return _as_list(v)[:MAX_HOPS]


class Headers(_Base):
    """
    parsed       : header name -> value (str, or list for repeated headers)
    raw_ordered  : [[name, value], ...] in file order
    security     : lower-cased subset (auth-results, received-spf, return-path...)
    """
    parsed: dict[str, Any] = Field(default_factory=dict)
    raw_ordered: list[list[str]] = Field(default_factory=list)
    security: dict[str, list[str]] = Field(default_factory=dict)

    @field_validator("raw_ordered", mode="before")
    @classmethod
    def _cap(cls, v):
        return _as_list(v)[:2000]


class Body(_Base):
    text_plain: list[str] = Field(default_factory=list)
    text_html: list[str] = Field(default_factory=list)
    text_not_managed: list[str] = Field(default_factory=list)
    combined: str = ""

    @field_validator("text_plain", "text_html", "text_not_managed", mode="before")
    @classmethod
    def _parts(cls, v):
        return [_s(x)[:MAX_BODY_CHARS] for x in _as_list(v)[:50]]

    @field_validator("combined", mode="before")
    @classmethod
    def _comb(cls, v):
        return _s(v)[:MAX_BODY_CHARS]


class Attachment(_Base):
    """
    The sample had none, so this accepts several likely key names. Once you
    parse an email WITH attachments, check the real keys and trim the aliases.
    Content is never stored here, only metadata and hashes.
    """
    filename: str = Field("", validation_alias="filename")
    content_type: str = Field("", validation_alias="mail_content_type")
    size_bytes: int = 0
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    magic_bytes: str = ""               # hex of first bytes, if your parser adds it
    is_archive: bool = False

    @classmethod
    def from_raw(cls, raw: dict) -> "Attachment":
        raw = raw or {}
        h = raw.get("hashes") or {}
        return cls(
            filename=_s(raw.get("filename") or raw.get("name"))[:500],
            content_type=_s(raw.get("content_type") or raw.get("mail_content_type")
                            or raw.get("mime_type")),
            size_bytes=raw.get("size_bytes") or raw.get("size") or 0,
            md5=_s(h.get("md5") or raw.get("md5")),
            sha1=_s(h.get("sha1") or raw.get("sha1")),
            sha256=_s(h.get("sha256") or raw.get("sha256")),
            magic_bytes=_s(raw.get("magic_bytes")),
            is_archive=bool(raw.get("is_archive", False)),
        )


class Defects(_Base):
    """Structural problems mail-parser noticed. Malformed mail is itself a signal."""
    has_defects: bool = False
    defects: list[Any] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    address_header_defects: list[Any] = Field(default_factory=list)
    received_header_defects: list[Any] = Field(default_factory=list)
    date_header_defects: list[Any] = Field(default_factory=list)


class Indicators(_Base):
    """Pre-extracted IOCs from the parser. urls.py can re-extract for more depth."""
    urls: list[str] = Field(default_factory=list)
    url_domains: list[str] = Field(default_factory=list)
    href_text_mismatches: list[Any] = Field(default_factory=list)

    @field_validator("urls", "url_domains", "href_text_mismatches", mode="before")
    @classmethod
    def _cap(cls, v):
        return _as_list(v)[:MAX_URLS]


class Email(_Base):
    """The one object every analyzer receives. Read-only by convention."""
    file: FileInfo = Field(default_factory=FileInfo)
    envelope: Envelope = Field(default_factory=Envelope)
    headers: Headers = Field(default_factory=Headers)
    routing: Routing = Field(default_factory=Routing)
    body: Body = Field(default_factory=Body)
    attachments: list[Attachment] = Field(default_factory=list)
    defects: Defects = Field(default_factory=Defects)
    indicators: Indicators = Field(default_factory=Indicators)

    # ---- build from the parser's raw dict (handles the non-flat parts) ---- #
    @classmethod
    def from_parser_json(cls, raw: dict) -> "Email":
        raw = dict(raw or {})
        raw["file"] = FileInfo.from_raw(raw.get("file") or {})
        atts = _as_list(raw.get("attachments"))[:MAX_ATTACHMENTS]
        raw["attachments"] = [Attachment.from_raw(a) for a in atts
                              if isinstance(a, dict)]
        return cls.model_validate(raw)

    # ---- convenience accessors: analyzers use these ---------------------- #
    @property
    def from_addr(self) -> Address | None:
        return self.envelope.from_[0] if self.envelope.from_ else None

    @property
    def from_domain(self) -> str:
        return self.from_addr.domain if self.from_addr else ""

    @property
    def reply_to_domain(self) -> str:
        r = self.envelope.reply_to
        return r[0].domain if r else ""

    @property
    def return_path_domain(self) -> str:
        rp = self.envelope.return_path
        return rp.rsplit("@", 1)[-1].strip("<> ").lower() if "@" in rp else ""

    @property
    def message_id_domain(self) -> str:
        mid = self.envelope.message_id.strip("<> ")
        return mid.rsplit("@", 1)[-1].lower() if "@" in mid else ""

    @property
    def auth_results(self) -> str:
        """Authentication-Results header(s), unfolded into one line."""
        vals = self.headers.security.get("authentication-results", [])
        return " ".join(" ".join(v.split()) for v in vals)

    @property
    def received_spf(self) -> str:
        vals = self.headers.security.get("received-spf", [])
        return " ".join(" ".join(v.split()) for v in vals)

    @property
    def hop_count(self) -> int:
        return len(self.routing.received)

    @property
    def body_html(self) -> str:
        return "\n".join(self.body.text_html)

    @property
    def body_text(self) -> str:
        return "\n".join(self.body.text_plain)

    @property
    def is_partial(self) -> bool:
        """True when too little data exists to judge (stripped headers, etc.)."""
        return not self.from_addr or (not self.body.combined and not self.attachments)


# =========================================================================== #
# OUTPUT MODELS (what analyzers return, what scoring produces)
# =========================================================================== #

class Category(str, Enum):
    AUTH = "auth"
    SENDER = "sender"
    HEADERS = "headers"
    URL = "url"
    ATTACHMENT = "attachment"
    BODY = "body"
    AI = "ai"


class Level(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    LIKELY_PHISHING = "LIKELY_PHISHING"
    MALICIOUS = "MALICIOUS"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"

    @property
    def rank(self) -> int:
        order = ["INSUFFICIENT_DATA", "CLEAN", "SUSPICIOUS",
                 "LIKELY_PHISHING", "MALICIOUS"]
        return order.index(self.value)


class Finding(BaseModel):
    """
    One piece of evidence. Analyzers create these WITHOUT a weight. The pipeline
    fills `weight` from rules.yaml by `id`, so tuning needs no code change.
    """
    id: str                              # "auth.dmarc_fail"  (also the rules.yaml key)
    category: Category
    summary: str                         # analyst-readable sentence
    evidence: dict[str, Any] = Field(default_factory=dict)  # IOCs / raw values
    weight: int = 0                      # filled in by the pipeline
    confidence: float = Field(1.0, ge=0.0, le=1.0)  # <1 for ML / heuristics
    source: str = "rule"                 # rule | feed | xgb | bert ...


class Verdict(BaseModel):
    """Final result for one email."""
    sha256: str = ""                     # identifies the sample
    subject: str = ""
    score: int = Field(0, ge=0, le=100)
    level: Level = Level.CLEAN
    by_category: dict[str, int] = Field(default_factory=dict)   # after caps
    findings: list[Finding] = Field(default_factory=list)
    overridden_by: str | None = None     # finding id that forced the level
    analyzer_errors: list[str] = Field(default_factory=list)    # crashed analyzers
