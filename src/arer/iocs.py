"""
iocs.py - R4.2: indicator-specific exports over confirmed cases ONLY.

Sources indicators from the STRUCTURED indicator block of v2 alert records
(`alert.indicators`) - never by string-splitting evidence prose. A confirmed
v1 record (which predates the structured block) contributes nothing; the
export summary reports how many confirmed cases were skipped for that reason
instead of inventing IOCs.

Eligibility is the R4.1 gate: only cases whose current, valid decision is an
analyst-originated true_positive contribute indicators. Full sender
addresses are NEVER exported (R4.5): the sender domain is the closest
identity that leaves the queue, and only when the case is confirmed.

Output formats:
- csv       typed columns: kind, value, case_sha256, campaign_id,
            first_seen, last_seen, source_file
- blocklist one normalized value per line, deterministic order, no prose,
            no duplicates (pass --kind to split files by type)
- misp      a documented MISP event/attribute structure; no invented
            threat-intelligence confidence scale (the comment carries the
            case reference instead)

All values are DEFANGED unless the caller passes raw=True - actionable live
indicators require the explicit opt-in, never the default.
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import NamedTuple

from .util.defang import defang, safe_text

IOC_KINDS = ("url", "domain", "sender_domain", "sha256")

MISP_TYPES = {"url": "url", "domain": "domain", "sender_domain": "domain", "sha256": "sha256"}


class IOC(NamedTuple):
    kind: str                 # one of IOC_KINDS
    value: str                # raw value; defanged only at serialization
    case_sha256: str
    campaign_id: str = ""
    first_seen: str = ""
    last_seen: str = ""
    source_file: str = ""


def _iso(ts: str) -> str:
    try:
        datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
        return ts
    except (ValueError, TypeError):
        return ""


def collect_iocs(confirmed: list[tuple[object, object]]) -> list[IOC]:
    """(alert, disposition) pairs that already passed the R4.1 gate ->
    deduplicated, deterministically ordered IOCs from the structured block."""
    out: dict[tuple[str, str], IOC] = {}
    skipped_no_block = 0
    for a, _d in confirmed:
        ind = getattr(a, "indicators", None) or {}
        urls = ind.get("urls") or []
        domains = ind.get("url_domains") or []
        sender = ind.get("sender_domain") or ""
        atts = ind.get("attachments") or []
        if not (urls or domains or sender or atts):
            skipped_no_block += 1
            continue
        first = _iso(a.generated_utc)
        for u in urls:
            out.setdefault(("url", u), IOC("url", u, a.verdict.sha256,
                                           getattr(a, "campaign_id", ""), first, first, a.source_file))
        for dm in domains:
            out.setdefault(("domain", dm), IOC("domain", dm, a.verdict.sha256,
                                               getattr(a, "campaign_id", ""), first, first, a.source_file))
        if sender:
            out.setdefault(("sender_domain", sender),
                           IOC("sender_domain", sender, a.verdict.sha256,
                               getattr(a, "campaign_id", ""), first, first, a.source_file))
        for att in atts:
            h = att.get("sha256") if isinstance(att, dict) else None
            if h:
                out.setdefault(("sha256", h), IOC("sha256", h, a.verdict.sha256,
                                                  getattr(a, "campaign_id", ""), first, first, a.source_file))
    iocs = sorted(out.values(), key=lambda i: (IOC_KINDS.index(i.kind), i.value))
    collect_iocs.last_skipped_no_block = skipped_no_block   # read by the CLI summary
    return iocs


def to_csv(iocs: list[IOC], *, raw: bool = False) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["kind", "value", "case_sha256", "campaign_id", "first_seen", "last_seen", "source_file"])
    for i in iocs:
        w.writerow([i.kind, i.value if raw else defang(i.value), i.case_sha256, i.campaign_id,
                    i.first_seen, i.last_seen, safe_text(i.source_file, 200)])
    return buf.getvalue()


def to_blocklist(iocs: list[IOC], *, kind: str | None = None, raw: bool = False) -> str:
    """One normalized indicator per line. No prose, no headers, no duplicates,
    deterministic order. (Defanged unless raw=True: an actionable blocklist
    needs the explicit --raw opt-in.)"""
    seen: set[str] = set()
    lines: list[str] = []
    for i in iocs:
        if kind and kind != "all" and i.kind != kind:
            continue
        v = i.value if raw else defang(i.value)
        if v not in seen:
            seen.add(v)
            lines.append(v)
    return "".join(ln + "\n" for ln in lines)


def to_misp(iocs: list[IOC], *, raw: bool = False) -> str:
    """A documented MISP event/attribute structure: one attribute per IOC,
    typed via MISP_TYPES, case reference in the comment. No confidence scale
    is invented. Timestamps are the IOC's first_seen, epoch seconds."""
    attributes = []
    for i in iocs:
        try:
            ts = int(datetime.strptime(i.first_seen, "%Y-%m-%dT%H:%M:%SZ"
                                       ).replace(tzinfo=timezone.utc).timestamp()) if i.first_seen else 0
        except ValueError:
            ts = 0
        attributes.append({
            "type": MISP_TYPES[i.kind],
            "category": "Network activity" if i.kind in ("url", "domain", "sender_domain") else "Payload delivery",
            "to_ids": True,
            "value": i.value if raw else defang(i.value),
            "comment": f"arer confirmed case {i.case_sha256[:12]}" +
                       (f" campaign {i.campaign_id}" if i.campaign_id else ""),
            "timestamp": ts,
        })
    event = {
        "Event": {
            "info": "arer confirmed phishing indicators",
            "distribution": "0",                       # your organisation only
            "threat_level_id": "4",                    # undefined - arer invents no scale
            "analysis": "1",                           # finished review (the analyst confirmed)
            "Attribute": attributes,
        }
    }
    return json.dumps(event, indent=2, ensure_ascii=False)
