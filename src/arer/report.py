"""
report.py - Verdict -> terminal text or JSON. Everything passes through defang/safe_text,
because the strings came from an attacker.
"""
from __future__ import annotations

import json

import click

from .models import Level, Verdict
from .util.defang import clean, clean_deep

_COLOR = {Level.CLEAN: "green", Level.SUSPICIOUS: "yellow",
          Level.LIKELY_PHISHING: "red", Level.MALICIOUS: "bright_red",
          Level.INSUFFICIENT_DATA: "cyan"}


def to_json(v: Verdict, defang: bool = True, indent: int = 2) -> str:
    data = v.model_dump(mode="json")
    return json.dumps(clean_deep(data) if defang else data, indent=indent, ensure_ascii=False)


def _bar(score: int, width: int = 30) -> str:
    n = round(width * score / 100)
    return "█" * n + "░" * (width - n)


def render_terminal(v: Verdict, cfg=None) -> str:
    color = _COLOR.get(v.level, "white")
    L: list[str] = []
    L.append(click.style("═" * 64, dim=True))
    L.append(f"Subject : {clean(v.subject, 100)}")
    L.append(f"SHA-256 : {v.sha256[:16]}…")
    L.append(f"Verdict : " + click.style(f" {v.level.value} ", fg=color, bold=True, reverse=True)
             + f"  {v.score}/100")
    L.append(click.style(_bar(v.score), fg=color))
    if v.overridden_by:
        L.append(click.style(f"Level forced by: {v.overridden_by}", fg="magenta"))

    if v.by_category:
        L.append("")
        for cat, pts in sorted(v.by_category.items(), key=lambda kv: -kv[1]):
            if pts == 0:
                continue
            cap = cfg.cap_for(cat) if cfg else "?"
            L.append(f"  {cat:<11}{pts:>3} / {cap}")

    L.append("")
    if v.findings:
        L.append("Findings")
        for f in v.findings:
            pts = round(f.weight * f.confidence)
            L.append(f"  {click.style(f'[+{pts}]', fg='yellow')} {f.id}")
            L.append(f"        {clean(f.summary, 160)}")
            for k, val in list(f.evidence.items())[:4]:
                L.append(click.style(f"        {k}: {clean(val, 100)}", dim=True))
    else:
        L.append("No findings.")

    if v.analyzer_errors:
        L.append("")
        L.append(click.style("Analyzer problems (result may be incomplete):", fg="red"))
        L += [f"  - {clean(e)}" for e in v.analyzer_errors]
    L.append(click.style("═" * 64, dim=True))
    return "\n".join(L)
