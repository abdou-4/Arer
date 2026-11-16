"""
disposition.py - Phase 6.2: the analyst's decision about one alert record.

One disposition per alert record, stored as a SIDECAST file next to it:

    salad.eml.alert.json  ->  salad.eml.disposition.json

The alert record itself is never mutated: it is the machine's statement about
the mail (frozen byte-for-byte by tests/test_alert.py), and the disposition is
the human's answer to it. Keyed by alert_id, so a renamed folder member keeps
its link. No sidecar means the alert is `new`.

Vocabulary (frozen): acknowledged | benign | phishing. The note is the
analyst's own words and is stored verbatim - pasted IOCs must not be mangled.

Reading rules mirror the alert record reader (src/arer/alert.py, 6.1b):
dispatch on the top-level "schema" marker, unknown schema is an explicit
error, unknown extra keys are ignored, errors name the file.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, NamedTuple

import pydantic
from pydantic import BaseModel, Field, field_validator

SCHEMA_VERSION = "arer.disposition.v1"
KNOWN_SCHEMAS = (SCHEMA_VERSION,)      # readers dispatch on this tuple

STATUSES = ("acknowledged", "benign", "phishing")
Status = Literal["acknowledged", "benign", "phishing"]

DISPOSITION_SUFFIX = ".disposition.json"   # sits beside "<...>.alert.json"


class DispositionError(ValueError):
    """A disposition file could not be read. Message always names the file."""


class Disposition(BaseModel):
    schema_: str = Field(SCHEMA_VERSION, alias="schema")
    alert_id: str                       # links to the alert record (never re-minted)
    mail_sha256: str = ""               # copied from verdict.sha256 for grepping/export
    status: Status
    note: str = ""                      # analyst's words, verbatim
    set_utc: str                        # when this disposition was set, ISO-8601 UTC Z

    @field_validator("status", mode="before")
    @classmethod
    def _known_status(cls, v):
        if v not in STATUSES:
            raise ValueError(f"status must be one of: {', '.join(STATUSES)}")
        return v


class DispositionRead(NamedTuple):
    """(record file, sidecar path, disposition | None, error | None).
    alert with no sidecar -> disposition None, error None (status `new`)."""
    alert_path: Path
    disposition_path: Path
    disposition: Disposition | None
    error: str | None


def build_disposition(alert_id: str, status: str, mail_sha256: str = "", note: str = "",
                      *, now: datetime | None = None) -> Disposition:
    """Assemble the record. `now` is injectable so tests are byte-stable."""
    return Disposition(
        alert_id=alert_id, mail_sha256=mail_sha256, status=status, note=note,
        set_utc=(now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"))


def to_json(d: Disposition, indent: int = 2) -> str:
    data = d.model_dump(mode="json", by_alias=True)
    return json.dumps(data, indent=indent, ensure_ascii=False)


def disposition_path(alert_path: Path) -> Path:
    """`<anything>.alert.json` -> `<anything>.disposition.json`; anything else
    gets the suffix appended (`x.json` -> `x.json.disposition.json`)."""
    name = alert_path.name
    if name.endswith(".alert.json"):
        name = name[: -len(".alert.json")] + DISPOSITION_SUFFIX
    else:
        name = name + DISPOSITION_SUFFIX
    return alert_path.with_name(name)


def load_disposition(path: Path) -> Disposition:
    """Parse and validate one disposition file, or raise DispositionError naming it."""
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as e:
        raise DispositionError(f"{path.name}: cannot read file ({e})") from None
    except json.JSONDecodeError as e:
        raise DispositionError(f"{path.name}: not valid JSON ({e.msg} at line {e.lineno})") from None
    if not isinstance(data, dict):
        raise DispositionError(f"{path.name}: not a JSON object")
    schema = data.get("schema")
    if not schema:
        raise DispositionError(f"{path.name}: missing the 'schema' marker")
    if schema not in KNOWN_SCHEMAS:
        raise DispositionError(f"{path.name}: unsupported schema '{schema}' "
                               f"(this arer reads: {', '.join(KNOWN_SCHEMAS)})")
    try:
        return Disposition.model_validate(data)
    except pydantic.ValidationError as e:
        fields = ", ".join(sorted({".".join(str(x) for x in err["loc"]) or "(root)" for err in e.errors()}))
        raise DispositionError(f"{path.name}: invalid {schema} record (bad field(s): {fields})") from None


def read_disposition(alert_path: Path) -> Disposition | None:
    """The sidecar of one alert record. None when absent; DispositionError when
    present but unreadable."""
    p = disposition_path(alert_path)
    if not p.is_file():
        return None
    return load_disposition(p)


def write_disposition(d: Disposition, alert_path: Path) -> Path:
    p = disposition_path(alert_path)
    p.write_text(to_json(d), encoding="utf-8")
    return p
