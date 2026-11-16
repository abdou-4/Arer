"""
alert.py - the stable, versioned JSON alert record (Phase 6.1a + R3 v2).

One record per alert-worthy e-mail: SUSPICIOUS, LIKELY_PHISHING, MALICIOUS
(the ALERT_EXITS allowlist in arer.exitcodes) and - since R1.4 - also every
analysis that failed part-way, so damaged/evasive mail is never silently
dropped. CLEAN is not an alert and INSUFFICIENT_DATA is a no-decision.

The record is what Phase 6.2 dispositions, 6.3 export and any external tooling
(SOAR, SIEM, mail-drop watchers) read, so its shape is frozen by tests:

- keys never move, shrink or change type within a schema version;
- additions are a deliberate change: update the golden (UPDATE_GOLDEN=1) and
  document the new field in docs/alert-record.md;
- any incompatible change mints a new marker and a second golden file;
  readers dispatch on the top-level "schema" string.

Schema v2 (R3) keeps every v1 field and adds: config_hash (the effective
tuning fingerprint, complementing logic_hash), engine/parser versions, a
structured analysis block (completeness + analyzer errors), top-3 reasons
with their points, a structured indicator block, a normalized body
fingerprint (for campaign clustering), the campaign id, the identity-verification
flag, and privacy-aware sender fields: v2 stores the sender DOMAIN, and a
plaintext address only when the operator explicitly passes --store-sender
(R4.5). v2 stores attacker-controlled values RAW and defangs exactly once at
serialization; v1 records (older queues) keep their stored defanged form and
read back unchanged.

All attacker-controlled strings pass through clean_deep() on output, exactly
like the scan report in report.py.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple

import pydantic
from pydantic import BaseModel, Field

from .config import config_hash
from .history.store import logic_hash
from .models import Email, Level, Verdict
from .util.defang import clean_deep


def engine_version() -> str:
    """The arer distribution version ('unknown' when run from a source tree
    without installed metadata - still a stable, honest value)."""
    from importlib.metadata import PackageNotFoundError, version
    try:
        return version("arer")
    except PackageNotFoundError:
        return "unknown"


def parser_version() -> str:
    """The installed mail-parser backend version (R6.6)."""
    from importlib.metadata import PackageNotFoundError, version
    try:
        return version("mail-parser")
    except PackageNotFoundError:
        return "unknown"

SCHEMA_V1 = "arer.alert.v1"
SCHEMA_V2 = "arer.alert.v2"
SCHEMA_VERSION = SCHEMA_V2             # what the producer writes today
KNOWN_SCHEMAS = (SCHEMA_V1, SCHEMA_V2)  # readers dispatch on this tuple; v3 appends, never replaces

_ALERT_LEVELS = {Level.SUSPICIOUS, Level.LIKELY_PHISHING, Level.MALICIOUS}


class AlertCollisionError(RuntimeError):
    """An alert event file already exists with DIFFERENT content under the
    same event ID. The existing record is preserved untouched and the new
    record is written under a suffixed name for investigation (R1.1)."""


def is_alert_level(level: Level) -> bool:
    """True for every level a script should treat as an alert (exit >= 3, minus the no-decision case)."""
    return level in _ALERT_LEVELS


class ScanSubject(BaseModel):
    """What the e-mail claims about itself - attacker-controlled, defanged on output.

    v2 privacy (R4.5): `from` is EMPTY unless the operator passed
    --store-sender; the sender DOMAIN is always available in `from_domain`."""

    model_config = pydantic.ConfigDict(populate_by_name=True)   # build with from_="..." in code

    from_: str = Field("", alias="from")
    message_id: str = ""
    date: str = ""
    from_domain: str = ""               # v2: always present, safe to store/display


class Alert(BaseModel):
    schema_: str = Field(SCHEMA_V2, alias="schema")
    alert_id: str                       # identifies one alert event (uuid4 hex)
    generated_utc: str                  # ISO-8601 UTC with Z suffix
    source_file: str                    # file name the e-mail was scanned from
    logic_hash: str                     # links the record to the analyzer CODE baseline
    scan: ScanSubject
    verdict: Verdict

    # ---- v2 additions (optional so v1 records validate unchanged) ---------- #
    config_hash: str = ""               # fingerprint of the effective scoring CONFIG (R3.2)
    engine_version: str = ""            # arer version that produced the record
    parser_version: str = ""            # mail-parser backend version
    sha256_verified: bool = True        # R1.6: native mail = True, parser-JSON = False
    analysis_complete: bool = True      # R1.4: False when analyzers failed
    analysis_errors: list[str] = Field(default_factory=list)   # same list as verdict.analyzer_errors
    reasons: list[dict] = Field(default_factory=list)          # top-3 {finding, category, weight, confidence, points}
    indicators: dict = Field(default_factory=dict)             # structured IOC block (R3.3)
    body_fingerprint: str = ""          # normalized-body fingerprint (R5 campaign keys)
    campaign_id: str = ""               # set by the campaign layer (R5), "" = unassigned


def _top_reasons(v: Verdict, n: int = 3) -> list[dict]:
    """Structured top findings: id, category, weight, confidence, points -
    agree with the scoring (weight * confidence), never re-derived by
    parsing evidence strings."""
    return [{"finding": f.id, "category": f.category.value, "weight": f.weight,
             "confidence": f.confidence, "points": round(f.weight * f.confidence)}
            for f in v.findings[:n]]


def _indicators(email: Email | None) -> dict:
    """The structured indicator block (R3.3): kind + normalized value, no
    string-splitting of evidence prose. Inline attachments are flagged so
    campaign clustering (R5) can skip ubiquitous logos/pixels."""
    if email is None:
        return {}
    atts = [{"sha256": a.sha256, "inline": a.content_disposition == "inline" or bool(a.content_id),
             "filename": a.filename, "size_bytes": a.size_bytes}
            for a in email.attachments if a.sha256]
    # url domains: use the parser's list when present, and derive the host
    # from every URL so plain-text bodies contribute domains too
    domains = list(dict.fromkeys(email.indicators.url_domains))
    from urllib.parse import urlsplit
    for u in email.indicators.urls:
        try:
            host = (urlsplit(u).hostname or "").lower()
            if host and host not in domains:
                domains.append(host)
        except ValueError:
            continue
    return {
        "urls": list(email.indicators.urls[:200]),
        "url_domains": domains[:100],
        "sender_domain": email.from_domain or "",
        "attachments": atts[:100],
    }


def _body_fingerprint(email: Email | None) -> str:
    """Deterministic normalized-body fingerprint (R5): lowercase, all
    whitespace collapsed, URLs and addresses removed - so boilerplate-only
    differences do not create a fingerprint, and common footers contribute
    the same value everywhere (R5 excludes them by recording it)."""
    import hashlib as _sha
    import re as _re
    if email is None:
        return ""
    text = email.body.combined or ""
    if not text:
        return ""
    text = _re.sub(r"https?://\S+", " ", text, flags=_re.I)
    text = _re.sub(r"\S+@\S+", " ", text)
    text = _re.sub(r"\s+", " ", text).strip().lower()
    return _sha.sha256(text.encode("utf-8")).hexdigest()[:16]


def build_alert(v: Verdict, email: Email | None, source_file: str, cfg,
                *, alert_id: str | None = None, now: datetime | None = None,
                store_sender: bool = False) -> Alert:
    """Assemble the record (schema v2). alert_id/now are injectable so tests
    are byte-stable.

    Sender privacy (R4.5): the plaintext address is stored ONLY with
    store_sender=True; the default record carries the sender DOMAIN. The
    analysis block mirrors verdict.analyzer_errors (R1.4), and the structured
    reasons/indicators are computed from the verdict and the parsed mail -
    never by re-parsing evidence strings."""
    sender = email.from_addr if email else None
    return Alert(
        alert_id=alert_id or uuid.uuid4().hex,
        generated_utc=(now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        source_file=source_file,
        logic_hash=logic_hash(cfg),
        scan=ScanSubject(
            from_=(sender.address if sender else "") if store_sender else "",
            from_domain=sender.domain if sender else "",
            message_id=email.envelope.message_id if email else "",
            date=email.envelope.date if email else ""),
        verdict=v,
        config_hash=config_hash(cfg),
        engine_version=engine_version(),
        parser_version=(email.file.mail_parser_version if email else "") or parser_version(),
        sha256_verified=bool(email.file.sha256_verified) if email else False,
        analysis_complete=not v.analyzer_errors,
        analysis_errors=list(v.analyzer_errors),
        reasons=_top_reasons(v),
        indicators=_indicators(email),
        body_fingerprint=_body_fingerprint(email),
        campaign_id="",
    )


def to_json(a: Alert, defang: bool = True, indent: int = 2) -> str:
    data = a.model_dump(mode="json", by_alias=True)
    if defang:
        data = clean_deep(data)
        data["schema"] = a.schema_           # machine-readable marker: never defanged
    return json.dumps(data, indent=indent, ensure_ascii=False)


def alert_path(a: Alert, directory: Path) -> Path:
    """The record file for one alert event: `<alert_id>.alert.json`.

    R1.1: the file name is the immutable event ID, NOT the source file name.
    A second mail that happens to arrive under the same file name can never
    overwrite the first record, and a disposition sidecar can never attach
    to a different message by accident."""
    return Path(directory) / f"{a.alert_id}.alert.json"


def write_alert(a: Alert, directory: Path, defang: bool = True) -> Path:
    """Atomically write one alert record under its event ID.

    Atomic pattern (R1.1): the JSON is written to a temp file in the same
    directory, flushed and closed, then os.replace()d into a previously
    unused final name - a crash mid-write can never leave a half-written
    record, and an existing record is never silently overwritten:

    - no existing file      -> plain replace of the temp file;
    - same event, same mail -> idempotent no-op (the record stays as-is);
    - same ID, other mail   -> AlertCollisionError; BOTH records are kept
      (the existing one untouched, the new one under a `<id>.<rand>.alert.json`
      name) so nothing is lost for investigation.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    dest = alert_path(a, directory)
    tmp = directory / f".{a.alert_id}.{uuid.uuid4().hex[:8]}.tmp"
    try:
        tmp.write_text(to_json(a, defang=defang), encoding="utf-8")
        if dest.exists():
            existing = read_alert(dest)
            if existing.alert_id == a.alert_id and existing.verdict.sha256 == a.verdict.sha256:
                return dest                       # the same event already stored
            alt = directory / f"{a.alert_id}.{uuid.uuid4().hex[:8]}.alert.json"
            os.replace(tmp, alt)                  # preserve BOTH records
            raise AlertCollisionError(
                f"{dest.name}: an alert record with this event ID already exists for mail "
                f"{existing.verdict.sha256[:12]} (new record preserved as {alt.name})")
        os.replace(tmp, dest)
    finally:
        if tmp.exists():
            tmp.unlink()
    return dest


# --------------------------------------------------------------------------- #
# Phase 6.1b: reading records back. The producer side above freezes the shape;
# this side freezes how a reader treats the folder of records - the queue
# Phase 6.2 dispositions walks. Rules (docs/alert-record.md):
#   - dispatch on the top-level "schema" marker, never trust the file name;
#   - unknown schema -> explicit error, not a silent mis-read;
#   - unknown extra keys are ignored (additions must be optional for readers);
#   - one bad file never stops a directory scan.
# --------------------------------------------------------------------------- #

class AlertError(ValueError):
    """A record could not be read. Message always names the file."""


class AlertRead(NamedTuple):
    """One *.alert.json file, parsed or not. Exactly one of alert/error is set."""
    path: Path
    alert: Alert | None
    error: str | None


def read_alert(path: Path) -> Alert:
    """Parse and validate one record file, or raise AlertError naming it."""
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as e:
        raise AlertError(f"{path.name}: cannot read file ({e})") from None
    except json.JSONDecodeError as e:
        raise AlertError(f"{path.name}: not valid JSON ({e.msg} at line {e.lineno})") from None
    if not isinstance(data, dict):
        raise AlertError(f"{path.name}: not a JSON object")
    schema = data.get("schema")
    if not schema:
        raise AlertError(f"{path.name}: missing the 'schema' marker")
    if schema not in KNOWN_SCHEMAS:
        raise AlertError(f"{path.name}: unsupported schema '{schema}' "
                         f"(this arer reads: {', '.join(KNOWN_SCHEMAS)})")
    try:
        return Alert.model_validate(data)
    except pydantic.ValidationError as e:
        fields = ", ".join(sorted({".".join(str(x) for x in err["loc"]) or "(root)" for err in e.errors()}))
        raise AlertError(f"{path.name}: invalid {schema} record (bad field(s): {fields})") from None


def read_alerts(directory: Path) -> list[AlertRead]:
    """Every *.alert.json in the folder, sorted by name. Missing/empty folder -> [].
    Broken records come back with alert=None and error set; they never stop the scan."""
    directory = Path(directory)
    if not directory.is_dir():
        return []
    reads = []
    for p in sorted(directory.glob("*.alert.json")):
        if not p.is_file() or p.is_symlink():
            continue
        try:
            reads.append(AlertRead(p, read_alert(p), None))
        except AlertError as e:
            reads.append(AlertRead(p, None, str(e)))
    return reads
