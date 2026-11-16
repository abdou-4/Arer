"""
export.py - Phase 6.3 + R4: the export layer of the alert queue.

Two separate operations (R4.1):

- the IOC/case export (`alerts export`) carries ONLY cases whose current,
  valid decision is an ANALYST-originated true_positive; the gate lives here
  in the service, not just in CLI help text, and cannot be bypassed by tool,
  imported, legacy_unverified or unreviewed decisions;
- the case-report export (`alerts export-queue`) flattens every readable
  record (what a SIEM wants to see for triage) under its own explicit name.

Safe by default (R4.3/R4.4):
- CSV cells are neutralized against spreadsheet formula injection (=, +, -,
  @, tab, CR - including after leading whitespace/control characters);
- v2 records are stored RAW and defanged EXACTLY ONCE on export; v1 records
  were stored already defanged, so only their sidecar note is defanged here
  (defanging twice is what damaged strings like "alert[[@]]..." before);
- `--raw` keeps everything as stored.

The flat schema is frozen by tests/test_export.py (EXPORT_KEYS / COLUMNS);
adding a field is a deliberate change like any other contract change.
"""
from __future__ import annotations

import csv
import io
import json
import re

from .alert import SCHEMA_V2, Alert
from .disposition import Disposition
from .util.defang import clean_deep

EXPORT_KEYS = [
    "schema", "alert_id", "generated_utc", "logic_hash", "config_hash",
    "level", "score", "sha256", "sha256_verified", "subject",
    "from", "from_domain", "message_id", "date",
    "source_file", "record_file",
    "by_category", "finding_ids", "overridden_by", "analyzer_errors",
    "analysis_complete",
    "disposition_status", "disposition_note", "disposition_set_utc",
]
COLUMNS = EXPORT_KEYS              # CSV: one column per key, same order


def export_row(a: Alert, d: Disposition | None, record_file: str) -> dict:
    """Flatten one alert (+ its disposition, None = new) into the export shape."""
    v = a.verdict
    return {
        "schema": a.schema_,
        "alert_id": a.alert_id,
        "generated_utc": a.generated_utc,
        "logic_hash": a.logic_hash,
        "config_hash": a.config_hash,
        "level": v.level.value,
        "score": v.score,
        "sha256": v.sha256,
        "sha256_verified": a.sha256_verified,
        "subject": v.subject,
        "from": a.scan.from_,
        "from_domain": a.scan.from_domain,
        "message_id": a.scan.message_id,
        "date": a.scan.date,
        "source_file": a.source_file,
        "record_file": record_file,
        "by_category": dict(sorted(v.by_category.items())),
        "finding_ids": [f.id for f in v.findings],
        "overridden_by": v.overridden_by or "",
        "analyzer_errors": list(v.analyzer_errors),
        "analysis_complete": a.analysis_complete,
        "disposition_status": d.status if d else "",
        "disposition_note": d.note if d else "",
        "disposition_set_utc": d.set_utc if d else "",
    }


# R4.3: spreadsheet formula injection. A cell that (after any leading
# whitespace/control characters a spreadsheet might ignore) starts with a
# formula trigger is neutralized with a leading apostrophe.
_FORMULA_START = re.compile(r"^[\s\x00-\x1f]+?[=+\-@\t\r]|^[=+\-@\t\r]")


def _csv_cell(v) -> str:
    if isinstance(v, dict):
        cell = ",".join(f"{k}={v[k]}" for k in v)          # csv.writer quotes it
    elif isinstance(v, list):
        cell = ",".join(str(x) for x in v)
    else:
        cell = v
    if isinstance(cell, str) and _FORMULA_START.match(cell):
        return "'" + cell                                  # spreadsheet treats it as text
    return cell


def to_jsonl(rows: list[dict]) -> str:
    return "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)


def to_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(COLUMNS)
    for r in rows:
        w.writerow([_csv_cell(r[c]) for c in COLUMNS])
    return buf.getvalue()


def render(rows: list[dict], fmt: str, defang: bool = True) -> str:
    """Defang exactly once (R4.4): v2 rows are stored raw and cleaned here;
    v1 rows were stored already defanged and pass through untouched EXCEPT
    the sidecar note, which was never defanged at rest."""
    if defang:
        fixed = []
        for r in rows:
            if r.get("schema") == SCHEMA_V2:
                cleaned = clean_deep(r)
                cleaned["schema"] = r.get("schema")   # machine-readable marker: never defanged
                fixed.append(cleaned)
            else:
                row = dict(r)
                note = row.get("disposition_note")
                if note:
                    row["disposition_note"] = clean_deep(note)
                fixed.append(row)
        rows = fixed
    return to_jsonl(rows) if fmt == "jsonl" else to_csv(rows)


# ---- R4.1: the analyst-confirmed export gate ------------------------------- #

def is_confirmed_phishing(a: Alert, d: Disposition | None) -> bool:
    """True only for a current, valid, analyst-originated true_positive
    decision (delegates to the disposition's own gate)."""
    return d is not None and d.is_analyst_confirmed_phishing()


def export_confirmed(reads, exclusion_counts: dict | None = None) -> list[dict]:
    """Flatten ONLY the analyst-confirmed cases (the default IOC export).

    reads: AlertRead items. Broken records are counted but never exported.
    Every excluded record increments a counter in exclusion_counts - counts
    only, never the excluded IOCs themselves."""
    from .alert import AlertRead                          # noqa: F401 - typing aid
    rows = []
    counts = exclusion_counts if exclusion_counts is not None else {}
    for r in reads:
        if r.alert is None:
            counts["unreadable"] = counts.get("unreadable", 0) + 1
            continue
        d = None
        try:
            from .disposition import read_disposition
            d = read_disposition(r.path, r.alert)
        except Exception:
            counts["unreadable"] = counts.get("unreadable", 0) + 1
            continue
        if is_confirmed_phishing(r.alert, d):
            rows.append(export_row(r.alert, d, r.path.name))
        elif d is None:
            counts["unreviewed"] = counts.get("unreviewed", 0) + 1
        elif d.effective_provenance != "analyst":
            counts["unverified_provenance"] = counts.get("unverified_provenance", 0) + 1
        elif d.status == "benign":
            counts["benign"] = counts.get("benign", 0) + 1
        else:                                             # acknowledged
            counts["acknowledged"] = counts.get("acknowledged", 0) + 1
    return rows
