"""
alert.py - Phase 6.1a: the stable, versioned JSON alert record.

One record per alert-worthy e-mail: the levels that exit >= 3 in
docs/cli-contract.md (SUSPICIOUS, LIKELY_PHISHING, MALICIOUS). CLEAN is not an
alert and INSUFFICIENT_DATA is a no-decision, not an alert.

The record is what Phase 6.2 dispositions, 6.3 export and any external tooling
(SOAR, SIEM, mail-drop watchers) read, so its shape is frozen by
tests/test_alert.py and tests/golden/alert_v1.json:

- keys never move, shrink or change type within a schema version;
- additions are a deliberate change: update the golden (UPDATE_GOLDEN=1) and
  document the new field in docs/alert-record.md;
- any incompatible change mints a new marker (arer.alert.v2) and a second
  golden file; readers dispatch on the top-level "schema" string.

All attacker-controlled strings pass through clean_deep() before serialisation,
exactly like the scan report in report.py.
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

from .history.store import logic_hash
from .models import Email, Level, Verdict
from .util.defang import clean_deep

SCHEMA_VERSION = "arer.alert.v1"
KNOWN_SCHEMAS = (SCHEMA_VERSION,)      # readers dispatch on this tuple; v2 appends, never replaces

_ALERT_LEVELS = {Level.SUSPICIOUS, Level.LIKELY_PHISHING, Level.MALICIOUS}


class AlertCollisionError(RuntimeError):
    """An alert event file already exists with DIFFERENT content under the
    same event ID. The existing record is preserved untouched and the new
    record is written under a suffixed name for investigation (R1.1)."""


def is_alert_level(level: Level) -> bool:
    """True for every level a script should treat as an alert (exit >= 3, minus the no-decision case)."""
    return level in _ALERT_LEVELS


class ScanSubject(BaseModel):
    """What the e-mail claims about itself - attacker-controlled, defanged on output."""

    model_config = pydantic.ConfigDict(populate_by_name=True)   # build with from_="..." in code

    from_: str = Field("", alias="from")
    message_id: str = ""
    date: str = ""


class Alert(BaseModel):
    schema_: str = Field(SCHEMA_VERSION, alias="schema")
    alert_id: str                       # identifies one alert event (uuid4 hex)
    generated_utc: str                  # ISO-8601 UTC with Z suffix
    source_file: str                    # file name the e-mail was scanned from
    logic_hash: str                     # links the record to the rules baseline (docs/evaluations.md)
    scan: ScanSubject
    verdict: Verdict


def build_alert(v: Verdict, email: Email | None, source_file: str, cfg,
                *, alert_id: str | None = None, now: datetime | None = None) -> Alert:
    """Assemble the record. alert_id/now are injectable so tests are byte-stable."""
    sender = email.from_addr if email else None
    return Alert(
        alert_id=alert_id or uuid.uuid4().hex,
        generated_utc=(now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        source_file=source_file,
        logic_hash=logic_hash(cfg),
        scan=ScanSubject(
            from_=sender.address if sender else "",
            message_id=email.envelope.message_id if email else "",
            date=email.envelope.date if email else ""),
        verdict=v,
    )


def to_json(a: Alert, defang: bool = True, indent: int = 2) -> str:
    data = a.model_dump(mode="json", by_alias=True)
    if defang:
        data = clean_deep(data)
        data["schema"] = SCHEMA_VERSION      # machine-readable marker: never defanged
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
