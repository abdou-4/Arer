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
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, NamedTuple

import pydantic
from pydantic import BaseModel, Field, field_validator

SCHEMA_V1 = "arer.disposition.v1"
SCHEMA_V2 = "arer.disposition.v2"
SCHEMA_VERSION = SCHEMA_V2             # what the writer produces today
KNOWN_SCHEMAS = (SCHEMA_V1, SCHEMA_V2)  # readers dispatch on this tuple

STATUSES = ("acknowledged", "benign", "phishing")
Status = Literal["acknowledged", "benign", "phishing"]

# R2/R4 provenance: where a decision came from. v1 sidecars (no provenance
# field) read back as provenance "" and are treated as legacy_unverified by
# every trust decision - they can never authorize an IOC export or become a
# training label.
ANALYST = "analyst"
PROVENANCES = ("analyst", "import", "tool", "legacy_unverified")

DISPOSITION_SUFFIX = ".disposition.json"   # sits beside "<...>.alert.json"


class DispositionError(ValueError):
    """A disposition file could not be read. Message always names the file."""


class Disposition(BaseModel):
    schema_: str = Field(SCHEMA_V2, alias="schema")
    alert_id: str                       # links to the alert record (never re-minted)
    mail_sha256: str = ""               # copied from verdict.sha256 for grepping/export
    status: Status
    note: str = ""                      # analyst's words, verbatim
    set_utc: str                        # when this disposition was set, ISO-8601 UTC Z
    # ---- v2 additions (optional so v1 sidecars validate unchanged) -------- #
    provenance: str = ""                # analyst | import | tool | legacy_unverified; "" = legacy
    analyst: str = ""                   # analyst identity for analyst-originated decisions

    @field_validator("status", mode="before")
    @classmethod
    def _known_status(cls, v):
        if v not in STATUSES:
            raise ValueError(f"status must be one of: {', '.join(STATUSES)}")
        return v

    @property
    def effective_provenance(self) -> str:
        """The provenance a trust decision may rely on: an explicit one, or
        legacy_unverified for v1 sidecars that predate the field."""
        return self.provenance if self.provenance in PROVENANCES else "legacy_unverified"

    def is_analyst_confirmed_phishing(self) -> bool:
        """The R4.1 export gate, in one place: a current, valid,
        analyst-originated true_positive decision. Import, tool,
        legacy_unverified, acknowledged, benign and unreviewed never pass."""
        return self.status == "phishing" and self.effective_provenance == "analyst"


class DispositionRead(NamedTuple):
    """(record file, sidecar path, disposition | None, error | None).
    alert with no sidecar -> disposition None, error None (status `new`)."""
    alert_path: Path
    disposition_path: Path
    disposition: Disposition | None
    error: str | None


def build_disposition(alert_id: str, status: str, mail_sha256: str = "", note: str = "",
                      *, now: datetime | None = None, provenance: str = ANALYST,
                      analyst: str = "") -> Disposition:
    """Assemble the record. `now` is injectable so tests are byte-stable.
    Writer default: provenance=analyst (the CLI passes the local analyst id)."""
    return Disposition(
        alert_id=alert_id, mail_sha256=mail_sha256, status=status, note=note,
        set_utc=(now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        provenance=provenance, analyst=analyst)


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


def read_disposition(alert_path: Path, alert: "Alert | None" = None,
                     *, expect_alert_id: str = "", expect_mail_sha256: str = "") -> Disposition | None:
    """The sidecar of one alert record (alert is an arer.alert.Alert). None when absent; DispositionError when
    present but unreadable OR when it does not belong to the alert (R1.2).

    Linkage validation (R1.2): pass the alert record (or its alert_id and
    mail sha256) and the sidecar must name EXACTLY that alert_id, and exactly
    that sha256 when the alert has one. An orphan, stale or mismatched
    sidecar is an integrity error - its status is NEVER silently applied,
    and a mismatch is never "repaired" by copying the old decision onto the
    new alert. All queue commands (list, stats, export, campaigns, set-group)
    go through this same validation path.
    """
    p = disposition_path(alert_path)
    if not p.is_file():
        return None
    d = load_disposition(p)
    aid = expect_alert_id or (getattr(alert, "alert_id", "") if alert is not None else "")
    sha = expect_mail_sha256 or (getattr(getattr(alert, "verdict", None), "sha256", "")
                                 if alert is not None else "")
    if aid and d.alert_id != aid:
        raise DispositionError(
            f"{p.name}: alert_id mismatch - sidecar says '{d.alert_id[:12]}', "
            f"record says '{aid[:12]}'. The disposition was NOT applied "
            "(delete or rewrite the sidecar; see docs/dispositions.md).")
    if sha and d.mail_sha256 and d.mail_sha256 != sha:
        raise DispositionError(
            f"{p.name}: mail sha256 mismatch - sidecar says '{d.mail_sha256[:12]}', "
            f"record says '{sha[:12]}'. The disposition was NOT applied "
            "(delete or rewrite the sidecar; see docs/dispositions.md).")
    return d


def write_disposition(d: Disposition, alert_path: Path) -> Path:
    """Atomically write the sidecar, the same pattern as write_alert (R1.1):
    temp file in the SAME directory, flush, close, os.replace - a crash or a
    full disk mid-write can never destroy the analyst's existing decision,
    and the temp file is cleaned up in a finally block (no .tmp litter)."""
    p = disposition_path(alert_path)
    tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(to_json(d))
            fh.flush()
        os.replace(tmp, p)
    finally:
        if tmp.exists():
            tmp.unlink()
    return p
