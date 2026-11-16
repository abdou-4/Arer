"""
export.py - Phase 6.3: the aggregate view of the alert queue.

One flat line (JSONL) or row (CSV) per alert, dispositions merged in, for
SIEM / SOAR / spreadsheet consumption. The queue folder stays the source of
truth; the export is derived and carries `record_file` so every line can be
traced back to the exact record it came from.

Safe by default: every string is defanged on the way out (idempotent on
records that were already defanged at scan time), so an export can be pasted
into a ticket or shipped to a SIEM without leaking live IOCs. `--raw` keeps
everything as stored, for pipelines that want the real values.

The flat schema is frozen by tests/test_export.py (EXPORT_KEYS / COLUMNS);
adding a field is a deliberate change like any other contract change.
"""
from __future__ import annotations

import csv
import io
import json

from .alert import Alert
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


def _csv_cell(v) -> str:
    if isinstance(v, dict):
        return ",".join(f"{k}={v[k]}" for k in v)          # csv.writer quotes it
    if isinstance(v, list):
        return ",".join(str(x) for x in v)
    return v


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
    if defang:
        schemas = [r.get("schema") for r in rows]
        rows = [clean_deep(r) for r in rows]
        for r, s in zip(rows, schemas):
            if s:
                r["schema"] = s          # machine-readable marker: never defanged (see alert.to_json)
    return to_jsonl(rows) if fmt == "jsonl" else to_csv(rows)
