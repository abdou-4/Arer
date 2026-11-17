"""
metrics.py - Phase 6.6: read-side metrics over the alert queue.

`arer alerts stats DIR` answers the analyst's operational questions from the
Phase 6 records alone - no new schema, nothing is written:

- how big is the queue and how much is still `new` (backlog)?
- of the decided records, how many were false alarms (benign share)?
- how fast do dispositions follow alerts (median time-to-disposition)?
- who sends the noise (top senders - already defanged in the records)?

Discipline carried over from the rest of Phase 6:
- pure function over (alert, disposition | None) pairs; the CLI does the
  reading loop and decides what happens to broken files, exactly like the
  campaigns view (6.4) - a broken record or corrupt sidecar is excluded from
  every number and named on stderr, because a metric over a silently
  incomplete queue would lie;
- time-to-disposition uses frozen file content only (generated_utc vs
  set_utc); the backlog age needs a clock, and `now` is injectable
  (the same pattern as build_alert and build_disposition).

Definitions (frozen here, documented in docs/metrics.md):
- decided     = benign + phishing. `acknowledged` is work queued, not a
                decision, so it does not count towards the false-alarm share.
- false alarms= benign records.
- TTD         = set_utc - generated_utc, in hours, over records that have a
                sidecar; reported as the median (robust against one outlier).
- backlog age = now - oldest record with no disposition.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from statistics import median
from typing import NamedTuple

from .alert import Alert
from .disposition import Disposition
from .util.defang import safe_text

_LEVEL_ORDER = ("MALICIOUS", "LIKELY_PHISHING", "SUSPICIOUS", "CLEAN", "INSUFFICIENT_DATA")

TOP_SENDERS_SHOWN = 5


class QueueStats(NamedTuple):
    """Every number the queue metrics report. `median_ttd_hours` is None when
    no record has a disposition yet; `oldest_new_age_hours` is None when the
    backlog is clear."""
    records: int
    campaigns: int                       # distinct mails (exact sha256)
    by_level: dict[str, int]
    by_status: dict[str, int]            # missing sidecar counts as "new"
    decided: int                         # benign + phishing
    false_alarms: int                    # benign
    top_senders: list[tuple[str, int]]   # defanged sender -> record count, best first
    median_ttd_hours: float | None
    oldest_new_age_hours: float | None


def _parse(ts: str) -> datetime | None:
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def queue_stats(pairs: list[tuple[Alert, Disposition | None]],
                *, now: datetime | None = None) -> QueueStats:
    """Compute the queue metrics. `pairs` are (alert record, sidecar or None);
    the caller excludes broken records/sidecars and counts them separately."""
    now = now or datetime.now(timezone.utc)
    by_level = Counter(a.verdict.level.value for a, _ in pairs)
    by_status = Counter(d.status if d else "new" for _, d in pairs)
    senders = Counter(safe_text(a.scan.from_, 60) for a, _ in pairs)
    senders.pop("", None)                                # a record with no sender says nothing
    ttds = []
    for a, d in pairs:
        if d is None:
            continue
        g, s = _parse(a.generated_utc), _parse(d.set_utc)
        if g and s:
            ttds.append(max((s - g).total_seconds(), 0.0) / 3600.0)   # clock skew is not a response time
    oldest_new = min((_parse(a.generated_utc) for a, d in pairs if d is None
                      and _parse(a.generated_utc) is not None), default=None)
    return QueueStats(
        records=len(pairs),
        campaigns=len({a.verdict.sha256 for a, _ in pairs}),
        by_level={k: by_level[k] for k in _LEVEL_ORDER if by_level[k]}
                 | {k: v for k, v in by_level.items() if k not in _LEVEL_ORDER},
        by_status={"new": by_status["new"], "acknowledged": by_status["acknowledged"],
                   "benign": by_status["benign"], "phishing": by_status["phishing"]},
        decided=by_status["benign"] + by_status["phishing"],
        false_alarms=by_status["benign"],
        top_senders=sorted(senders.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP_SENDERS_SHOWN],
        median_ttd_hours=round(median(ttds), 1) if ttds else None,
        oldest_new_age_hours=round((now - oldest_new).total_seconds() / 3600.0, 1) if oldest_new else None,
    )


def _fmt_hours(h: float) -> str:
    if h < 1:
        return f"{int(h * 60)}m"
    if h < 48:
        return f"{h:.1f}h"
    return f"{h / 24:.1f}d"


def render_queue_stats(s: QueueStats) -> str:
    """Plain-text report; same fixed label style as `history stats`."""
    lines = []
    lines.append(f"records        {s.records} valid")
    lines.append(f"campaigns      {s.campaigns} distinct mails (exact sha256)")
    verdict = ", ".join(f"{k} {v}" for k, v in s.by_level.items()) or "none"
    lines.append(f"by verdict     {verdict}")
    st = s.by_status
    lines.append(f"dispositions   {st['new']} new, {st['acknowledged']} acknowledged, "
                 f"{st['benign']} benign, {st['phishing']} phishing")
    if s.decided:
        share = round(100 * s.false_alarms / s.decided)
        lines.append(f"decided        {s.decided} of {s.records} "
                     f"(benign {s.false_alarms}, false-alarm share {share}%)")
    else:
        lines.append(f"decided        0 of {s.records}")
    lines.append("response time " + (f"median {s.median_ttd_hours}h from record to disposition"
                                      if s.median_ttd_hours is not None else "no dispositions yet"))
    lines.append("backlog       " + (f"oldest unresolved record is {_fmt_hours(s.oldest_new_age_hours)} old"
                                     if s.oldest_new_age_hours is not None else "queue is clear"))
    senders = ", ".join(f"{name} {n}" for name, n in s.top_senders) or "none recorded"
    lines.append(f"top senders   {senders}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# R7: analyst feedback metrics. Definitions (frozen here, docs/metrics.md):
#
# The denominators come from ANALYST decisions only (disposition.provenance
# == analyst): tool decisions, legacy v1 sidecars (legacy_unverified),
# imports and unreviewed records never enter a rate. Duplicate scans of the
# same mail are ONE case (verdict.sha256) - an event-level view is kept
# separate and never mixed into the case-level numbers.
#
# - reviewed case        a case (sha) with at least one analyst-provenance
#                        decision among its records;
# - case class           phishing if ANY analyst `phishing` record, else
#                        benign if ANY analyst `benign` record, else undecided
#                        (acknowledged-only cases are reviewed but carry no
#                        class and are excluded from rate denominators);
# - per-finding FP rate  benign cases containing the finding / classified
#                        cases containing the finding;
# - noisy-rule ranking   findings by that rate, with the reviewed count and
#                        the unresolved count; below MIN_SAMPLES the rate is
#                        flagged low-confidence, never presented as proof.
# --------------------------------------------------------------------------- #

MIN_SAMPLES = 5


@dataclass(frozen=True)
class FindingStat:
    finding_id: str
    reviewed: int          # cases with a class, containing the finding
    false_alarms: int      # of those, benign cases
    unresolved: int        # cases containing the finding with NO analyst decision yet
    low_confidence: bool   # reviewed < MIN_SAMPLES

    @property
    def fp_rate(self) -> float | None:
        return self.false_alarms / self.reviewed if self.reviewed else None


def _case_class(pairs: list[tuple[Alert, "Disposition | None"]], sha: str) -> str | None:
    classes = set()
    for a, d in pairs:
        if a.verdict.sha256 != sha or d is None:
            continue
        if d.effective_provenance != "analyst":
            continue
        if d.status == "phishing":
            classes.add("phishing")
        elif d.status == "benign":
            classes.add("benign")
    if "phishing" in classes:
        return "phishing"
    if "benign" in classes:
        return "benign"
    return None


def finding_metrics(pairs: list[tuple[Alert, "Disposition | None"]],
                    *, min_samples: int = MIN_SAMPLES) -> list[FindingStat]:
    """Per-finding feedback over CASES (deduplicated by verdict.sha256)."""
    seen: dict[str, set[str]] = {}
    klass: dict[str, str | None] = {}
    for a, d in pairs:
        sha = a.verdict.sha256
        if sha not in klass:
            klass[sha] = _case_class(pairs, sha)
        for f in a.verdict.findings:
            seen.setdefault(f.id, set()).add(sha)
    out = []
    for fid, shas in seen.items():
        reviewed = sum(1 for s in shas if klass[s])
        false_alarms = sum(1 for s in shas if klass[s] == "benign")
        unresolved = sum(1 for s in shas if klass[s] is None)
        out.append(FindingStat(fid, reviewed, false_alarms, unresolved, reviewed < min_samples))
    return sorted(out, key=lambda s: (-(s.fp_rate or 0.0), -s.reviewed, s.finding_id))


def weekly_alerts(pairs: list[tuple[Alert, "Disposition | None"]]) -> list[tuple[str, int, int]]:
    """Alert CASES per ISO week, oldest first: (week, cases, events). The
    event count is kept separate - five copies of one phishing run are one
    case and five events."""
    weeks: dict[str, set[str]] = defaultdict(set)
    events: dict[str, int] = defaultdict(int)
    for a, _d in pairs:
        try:
            dt = datetime.strptime(a.generated_utc, "%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, TypeError):
            continue
        week = f"{dt.isocalendar().year}-W{dt.isocalendar().week:02d}"
        weeks[week].add(a.verdict.sha256)
        events[week] += 1
    return [(w, len(weeks[w]), events[w]) for w in sorted(weeks)]


def render_finding_stats(stats: list[FindingStat], *, limit: int = 10) -> str:
    """The noisy-rule table: rate + counts, low-confidence rows flagged."""
    lines = [f"  {'finding':<34}{'FP rate':>9}{'false':>7}{'reviewed':>10}{'unresolved':>12}"]
    rows = [s for s in stats if s.reviewed or s.unresolved][:limit]
    if not rows:
        return "  no reviewed findings yet"
    for s in rows:
        rate = f"{100 * s.fp_rate:.0f}%" if s.fp_rate is not None else "-"
        flag = "  <- low-confidence" if s.low_confidence else ""
        lines.append(f"  {s.finding_id:<34}{rate:>9}{s.false_alarms:>7}{s.reviewed:>10}{s.unresolved:>12}{flag}")
    return "\n".join(lines)


def render_weekly(rows: list[tuple[str, int, int]], *, limit: int = 12) -> str:
    if not rows:
        return "  no alert records yet"
    lines = [f"  {'week':<10}{'cases':>7}{'events':>8}"]
    for week, cases, events in rows[-limit:]:
        lines.append(f"  {week:<10}{cases:>7}{events:>8}")
    return "\n".join(lines)
