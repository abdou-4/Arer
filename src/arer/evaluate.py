"""
evaluate.py - measure the detector on labeled samples, so tuning is evidence, not guessing.

Labels come from folders: anything under a folder named phish/phishing/malicious is phishing,
under legit/ham/benign/clean is legitimate. An optional <root>/labels.csv (columns: filename,label)
overrides the folder for single files, for example a sample you found to be mislabeled.

Reports, at each severity level and across a score sweep:
  detection rate (phishing caught), false-alarm rate (legit flagged), precision,
  the phishing you MISSED, the legit mail you FLAGGED, and which findings fire on which class.

--only dev|test uses a stable 80/20 split (by file hash). Tune on dev, check on test now and
then, so your weights do not simply memorise your samples.
"""
from __future__ import annotations

import csv
import math
import statistics
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .config import Config
from .loader import LoadError, is_mail_candidate, load_any
from .models import Level, Verdict
from .pipeline import run_pipeline
from .util.defang import safe_text

PHISH_DIRS = {"phish", "phishing", "malicious"}
LEGIT_DIRS = {"legit", "ham", "benign", "clean"}
LEVELS = [Level.SUSPICIOUS, Level.LIKELY_PHISHING, Level.MALICIOUS]
SMALL_SAMPLE = 30


@dataclass
class Result:
    path: Path
    label: str                 # "phish" | "legit"
    verdict: Verdict
    source: str = ""           # folder it came from, e.g. "legit/modern" or "legit/archive"

    @property
    def split(self) -> str:
        sha = self.verdict.sha256
        return "test" if sha and int(sha[:8], 16) % 5 == 0 else "dev"


@dataclass
class Evaluation:
    results: list[Result]
    errors: list[str]
    unlabeled: int = 0
    duplicates: int = 0


def _label_of(path: Path, root: Path, overrides: dict[str, str]) -> str | None:
    if path.name in overrides:
        return overrides[path.name]
    for part in path.relative_to(root).parts[:-1]:
        low = part.lower()
        if low in PHISH_DIRS:
            return "phish"
        if low in LEGIT_DIRS:
            return "legit"
    return None


def _read_overrides(root: Path) -> dict[str, str]:
    f = root / "labels.csv"
    out: dict[str, str] = {}
    if f.is_file():
        with f.open(newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                lab = (row.get("label") or "").strip().lower()
                if row.get("filename") and lab in ("phish", "legit"):
                    out[row["filename"].strip()] = lab
    return out


def evaluate(root: Path, cfg: Config, only: str = "all", skip: set[str] | None = None,
             skip_dirs: set[str] | None = None) -> Evaluation:
    overrides = _read_overrides(root)
    skip_dirs = {d.lower() for d in (skip_dirs or set())}
    files = sorted(p for p in root.rglob("*") if is_mail_candidate(p)
                   and not ({x.lower() for x in p.relative_to(root).parts[:-1]} & skip_dirs))
    ev = Evaluation([], [])
    seen: set[str] = set()
    for p in files:
        label = _label_of(p, root, overrides)
        if label is None:
            ev.unlabeled += 1
            continue
        try:
            email = load_any(p, cfg)
        except LoadError as e:
            ev.errors.append(f"{safe_text(p.name)}: {safe_text(e, 120)}")
            continue
        verdict = run_pipeline(email, cfg, skip=skip or set())
        if verdict.sha256 and verdict.sha256 in seen:          # same email twice (eml + its parsed json)
            ev.duplicates += 1
            continue
        seen.add(verdict.sha256)
        r = Result(p, label, verdict, source="/".join(p.relative_to(root).parts[:-1]) or "(root)")
        if only == "all" or r.split == only:
            ev.results.append(r)
    return ev


# --------------------------------------------------------------------------- #
def _pct(n: int, d: int) -> str:
    return f"{100 * n / d:5.1f}%" if d else "  n/a "


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% range for a rate k/n. With few samples it is wide, which is the honest answer:
    0 false alarms in 10 emails is still compatible with about 28%."""
    if n == 0:
        return 0.0, 1.0
    p = k / n
    d = 1 + z * z / n
    centre = p + z * z / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, (centre - margin) / d), min(1.0, (centre + margin) / d)


def _rng(k: int, n: int) -> str:
    lo, hi = wilson(k, n)
    return f"[{100 * lo:.0f}-{100 * hi:.0f}%]"


def confusion(results: list[Result], flagged) -> dict[str, int]:
    tp = sum(1 for r in results if r.label == "phish" and flagged(r))
    fn = sum(1 for r in results if r.label == "phish" and not flagged(r))
    fp = sum(1 for r in results if r.label == "legit" and flagged(r))
    tn = sum(1 for r in results if r.label == "legit" and not flagged(r))
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn}


def render(ev: Evaluation, cfg: Config, details: bool = False) -> str:
    R = ev.results
    phish = [r for r in R if r.label == "phish"]
    legit = [r for r in R if r.label == "legit"]
    L: list[str] = []
    L.append(f"Samples: {len(phish)} phishing, {len(legit)} legitimate"
             + (f"   ({ev.duplicates} duplicates skipped)" if ev.duplicates else "")
             + (f"   ({ev.unlabeled} files outside phish/ or legit/ ignored)" if ev.unlabeled else ""))
    if min(len(phish), len(legit)) < SMALL_SAMPLE:
        L.append(f"WARNING: fewer than {SMALL_SAMPLE} samples in a class. Treat these numbers as a rough guide, not proof.")
    if not phish or not legit:
        L.append("Need at least one phishing and one legitimate sample for meaningful rates.")
    for e in ev.errors:
        L.append(f"  could not load: {e}")

    # ---- by severity level -------------------------------------------------- #
    L += ["", "Detection by level (flagged = this level or higher; [..] = 95% range given the sample size)",
          f"  {'level':<20}{'phishing caught':>29}{'legit flagged':>28}{'precision':>11}"]
    th = cfg.thresholds
    cutoff = {Level.SUSPICIOUS: th.suspicious, Level.LIKELY_PHISHING: th.likely_phishing, Level.MALICIOUS: th.malicious}
    for lvl in LEVELS:
        c = confusion(R, lambda r, lvl=lvl: r.verdict.level.rank >= lvl.rank)
        prec = _pct(c["tp"], c["tp"] + c["fp"]) if c["tp"] + c["fp"] else "  n/a "
        L.append(f"  {lvl.value + f' ({cutoff[lvl]})':<20}"
                 f"{c['tp']:>6}/{len(phish):<4}{_pct(c['tp'], len(phish)):>7} {_rng(c['tp'], len(phish)):<10}"
                 f"{c['fp']:>5}/{len(legit):<4}{_pct(c['fp'], len(legit)):>7} {_rng(c['fp'], len(legit)):<10}{prec:>11}")

    # ---- by source ---------------------------------------------------------- #
    sources = sorted({r.source for r in R})
    if len(sources) > 1:
        L += ["", f"By source (flagged = {Level.SUSPICIOUS.value} or higher)",
              f"  {'source':<26}{'n':>5}{'flagged':>12}{'median':>8}{'max':>6}"]
        for s in sources:
            rs = [r for r in R if r.source == s]
            n_flag = sum(1 for r in rs if r.verdict.level.rank >= Level.SUSPICIOUS.rank)
            sc = [r.verdict.score for r in rs]
            L.append(f"  {safe_text(s, 24):<26}{len(rs):>5}{f'{n_flag} ({100 * n_flag / len(rs):.0f}%)':>12}"
                     f"{int(statistics.median(sc)):>8}{max(sc):>6}")
        if sum(1 for s in sources if s.split('/')[0] in LEGIT_DIRS) > 1:
            L.append("  tip: judge false alarms on your modern mail. Old archives are for stress tests, not tuning.")

    # ---- misses and false alarms ------------------------------------------- #
    first = Level.SUSPICIOUS
    missed = [r for r in phish if r.verdict.level.rank < first.rank]
    false_alarms = [r for r in legit if r.verdict.level.rank >= first.rank]
    L += ["", f"Phishing MISSED (below {first.value}): {len(missed)}"]
    for r in sorted(missed, key=lambda r: r.verdict.score):
        top = ", ".join([f.id for f in r.verdict.findings if f.weight > 0][:3]) or "no findings"
        L.append(f"  score {r.verdict.score:>3}  {safe_text(r.path.name, 60)}   [{top}]")
    L += ["", f"Legit mail FLAGGED (false alarms): {len(false_alarms)}"]
    for r in sorted(false_alarms, key=lambda r: -r.verdict.score):
        top = ", ".join(f"{f.id}(+{round(f.weight * f.confidence)})" for f in [x for x in r.verdict.findings if x.weight > 0][:4])
        L.append(f"  score {r.verdict.score:>3}  {safe_text(r.path.name, 60)}   [{top}]")

    # ---- score distribution and sweep -------------------------------------- #
    def spread(rs):
        s = [r.verdict.score for r in rs]
        return f"min {min(s)}  median {int(statistics.median(s))}  max {max(s)}" if s else "n/a"
    L += ["", "Score by class", f"  phishing : {spread(phish)}", f"  legit    : {spread(legit)}"]
    if phish and legit:
        L += ["", "Score sweep (flag when score >= T)", "     T  phishing caught   legit flagged"]
        for t in range(5, 80, 5):
            c = confusion(R, lambda r, t=t: r.verdict.score >= t)
            L.append(f"  {t:>4}  {_pct(c['tp'], len(phish)):>14}   {_pct(c['fp'], len(legit)):>12}")

    # ---- which findings are useful ----------------------------------------- #
    on_p, on_l = Counter(), Counter()
    for r in phish:
        on_p.update({f.id for f in r.verdict.findings if f.weight > 0})
    for r in legit:
        on_l.update({f.id for f in r.verdict.findings if f.weight > 0})
    ids = sorted(set(on_p) | set(on_l), key=lambda i: (-(on_p[i] - on_l[i]), i))
    L += ["", "Findings: how often each fires", f"  {'finding':<34}{'on phishing':>12}{'on legit':>10}"]
    for i in ids:
        flag = "   <- noisy: fires on legit mail" if on_l[i] and on_l[i] >= on_p[i] else ""
        L.append(f"  {i:<34}{on_p[i]:>8}/{len(phish):<3}{on_l[i]:>6}/{len(legit):<3}{flag}")

    if details:
        L += ["", "Every sample"]
        for r in sorted(R, key=lambda r: (r.label, -r.verdict.score)):
            L.append(f"  {r.label:<6}{r.verdict.score:>4}  {r.verdict.level.value:<16} {safe_text(r.path.name, 60)}")
    return "\n".join(L)
