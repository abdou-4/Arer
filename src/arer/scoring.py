"""
scoring.py - findings -> Verdict. Pure function: no I/O, easy to unit-test.

Steps
  1. Each finding id counts ONCE (5 IP-host URLs do not give 5x the points).
  2. Points = weight * confidence.
  3. Sum per category, cap each category (rules.yaml: caps).
  4. Add categories, clamp to 0-100.
  5. Score -> level using thresholds.
  6. Overrides can only RAISE the level (and lift the score to match).
  7. Partial email with no signals -> INSUFFICIENT_DATA instead of a false "CLEAN".
"""
from __future__ import annotations

from .config import Config
from .models import Email, Finding, Level, Verdict

_FLOOR = {Level.SUSPICIOUS: "suspicious", Level.LIKELY_PHISHING: "likely_phishing",
          Level.MALICIOUS: "malicious"}


def level_for(score: int, cfg: Config) -> Level:
    t = cfg.thresholds
    if score >= t.malicious:
        return Level.MALICIOUS
    if score >= t.likely_phishing:
        return Level.LIKELY_PHISHING
    if score >= t.suspicious:
        return Level.SUSPICIOUS
    return Level.CLEAN


def compute(findings: list[Finding], cfg: Config, email: Email | None = None,
            errors: list[str] | None = None) -> Verdict:
    # 1-2: one entry per finding id, best points wins
    best: dict[str, tuple[str, float]] = {}
    for f in findings:
        pts = f.weight * f.confidence
        if f.id not in best or pts > best[f.id][1]:
            best[f.id] = (f.category.value, pts)

    # 3: per-category sum, then cap
    raw: dict[str, float] = {}
    for cat, pts in best.values():
        raw[cat] = raw.get(cat, 0) + pts
    by_cat = {c: min(round(p), cfg.cap_for(c)) for c, p in raw.items()}

    # 4-5
    score = max(0, min(100, sum(by_cat.values())))
    level = level_for(score, cfg)

    # 6: overrides only ever raise
    overridden_by = None
    present = {f.id for f in findings}
    for o in cfg.overrides:
        if o.finding in present and o.min_level.rank > level.rank:
            level, overridden_by = o.min_level, o.finding
    if overridden_by and level in _FLOOR:
        score = max(score, getattr(cfg.thresholds, _FLOOR[level]))

    # 7
    if level == Level.CLEAN and email is not None and email.is_partial:
        level = Level.INSUFFICIENT_DATA

    ordered = sorted(findings, key=lambda f: (-f.weight * f.confidence, f.id))
    return Verdict(
        sha256=email.file.sha256 if email else "",
        subject=email.envelope.subject if email else "",
        score=score, level=level, by_category=by_cat, findings=ordered,
        overridden_by=overridden_by, analyzer_errors=errors or [],
    )
