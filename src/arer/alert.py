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
import uuid
from datetime import datetime, timezone

import pydantic
from pydantic import BaseModel, Field

from .history.store import logic_hash
from .models import Email, Level, Verdict
from .util.defang import clean_deep

SCHEMA_VERSION = "arer.alert.v1"

_ALERT_LEVELS = {Level.SUSPICIOUS, Level.LIKELY_PHISHING, Level.MALICIOUS}


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
