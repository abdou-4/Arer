"""
evaluate.py - measure the detector on labeled samples, so tuning is evidence, not guessing.

Labels come from folders: anything under a folder named phish/phishing/malicious is phishing,
under legit/ham/benign/clean is legitimate. An optional <root>/labels.csv supports exact relative
paths and unambiguous filename overrides. An optional <root>/manifest.csv records known campaign
groups and dataset provenance.

Reports, at each severity level and across a score sweep:
  detection rate (phishing caught), false-alarm rate (legit flagged), precision,
  the phishing you MISSED, the legit mail you FLAGGED, and which findings fire on which class.

--only dev|test uses a stable 80/20 split. Samples with the same manifest group_id stay together;
other samples retain the content-hash split. Tune on dev, check on test now and then.
"""
from __future__ import annotations

import hashlib
import csv
import math
import statistics
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from .config import Config
from .history.store import HistoryStore, logic_hash, rescore
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
    group_id: str = ""
    dataset: str = ""
    license: str = ""
    reference: str = ""
    collection_date: str = ""

    @property
    def split(self) -> str:
        # Campaign siblings share one split; ungrouped samples keep the old content-hash split.
        sha = (hashlib.sha256(self.group_id.encode("utf-8")).hexdigest()
               if self.group_id else self.verdict.sha256)
        return "test" if sha and int(sha[:8], 16) % 5 == 0 else "dev"


@dataclass
class Evaluation:
    results: list[Result]
    errors: list[str]
    unlabeled: int = 0
    duplicates: int = 0
    stale: int = 0              # history rows made by older analyzer logic or lists
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ManifestEntry:
    group_id: str = ""
    dataset: str = ""
    license: str = ""
    reference: str = ""
    collection_date: str = ""


def _safe_relative_path(raw: str, source: str, line: int) -> str:
    """Validate a POSIX-style path from a dataset CSV before matching it to a file."""
    value = raw.strip()
    parts = value.split("/")
    if (not value or "\\" in value or value.startswith("/")
            or any(part in ("", ".", "..") for part in parts)
            or (len(parts[0]) >= 2 and parts[0][1] == ":")):
        raise ValueError(f"{source} row {line}: path must be a safe root-relative path")
    return PurePosixPath(value).as_posix()


def _label_of(path: Path, root: Path, overrides: dict[str, str]) -> str | None:
    rel = path.relative_to(root).as_posix()
    if f"path:{rel}" in overrides:
        return overrides[f"path:{rel}"]
    if f"filename:{path.name}" in overrides:
        return overrides[f"filename:{path.name}"]
    for part in path.relative_to(root).parts[:-1]:
        low = part.lower()
        if low in PHISH_DIRS:
            return "phish"
        if low in LEGIT_DIRS:
            return "legit"
    return None


def _read_overrides(root: Path, files: list[Path] | None = None,
                    warnings: list[str] | None = None) -> dict[str, str]:
    """Read exact relative-path overrides and safe, unique legacy filename overrides."""
    f = root / "labels.csv"
    out: dict[str, str] = {}
    if not f.is_file():
        return out
    warnings = warnings if warnings is not None else []
    name_counts = Counter(p.name for p in (files or []))
    available_paths = {p.relative_to(root).as_posix() for p in (files or [])}
    with f.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        columns = set(reader.fieldnames or [])
        if "label" not in columns or not columns.intersection({"path", "filename"}):
            warnings.append("labels.csv needs a 'label' column and either 'path' or 'filename'")
            return out
        seen: set[str] = set()
        conflicted: set[str] = set()
        for line, row in enumerate(reader, start=2):
            lab = (row.get("label") or "").strip().lower()
            if lab not in ("phish", "legit"):
                warnings.append(f"labels.csv row {line}: invalid label; override ignored")
                continue
            raw_path = (row.get("path") or "").strip()
            raw_name = (row.get("filename") or "").strip()
            if raw_path:
                try:
                    rel = _safe_relative_path(raw_path, "labels.csv", line)
                except ValueError as exc:
                    warnings.append(str(exc) + "; override ignored")
                    continue
                if files is not None and rel not in available_paths:
                    warnings.append(f"labels.csv row {line}: path '{rel}' not found; override ignored")
                    continue
                key = f"path:{rel}"
            elif raw_name:
                if "/" in raw_name or "\\" in raw_name or raw_name in (".", ".."):
                    warnings.append(f"labels.csv row {line}: filename must be a basename; use the path column")
                    continue
                if files is not None and name_counts.get(raw_name, 0) > 1:
                    warnings.append(f"labels.csv row {line}: filename '{raw_name}' is ambiguous; use a relative path")
                    continue
                if files is not None and name_counts.get(raw_name, 0) == 0:
                    warnings.append(f"labels.csv row {line}: filename '{raw_name}' not found; override ignored")
                    continue
                key = f"filename:{raw_name}"
            else:
                warnings.append(f"labels.csv row {line}: missing path/filename; override ignored")
                continue
            if key in conflicted:
                continue
            if key in seen:
                out.pop(key, None)
                conflicted.add(key)
                warnings.append(f"labels.csv row {line}: duplicate target; all overrides for it are ignored")
                continue
            seen.add(key)
            out[key] = lab
    return out


def _read_manifest(root: Path, files: list[Path]) -> dict[str, ManifestEntry]:
    """Read optional campaign/provenance metadata; reject unsafe or unknown paths."""
    f = root / "manifest.csv"
    if not f.is_file():
        return {}
    available_paths = {p.relative_to(root).as_posix() for p in files}
    out: dict[str, ManifestEntry] = {}
    with f.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        if "path" not in (reader.fieldnames or []):
            raise ValueError("manifest.csv needs a 'path' column")
        for line, row in enumerate(reader, start=2):
            raw_path = (row.get("path") or "").strip()
            if not raw_path:
                raise ValueError(f"manifest.csv row {line}: missing path")
            rel = _safe_relative_path(raw_path, "manifest.csv", line)
            if rel not in available_paths:
                raise ValueError(f"manifest.csv row {line}: path '{rel}' does not match a mail sample under the dataset root")
            if rel in out:
                raise ValueError(f"manifest.csv row {line}: duplicate path '{rel}'")
            out[rel] = ManifestEntry(
                group_id=(row.get("group_id") or "").strip(),
                dataset=(row.get("dataset") or "").strip(),
                license=(row.get("license") or "").strip(),
                reference=(row.get("reference") or "").strip(),
                collection_date=(row.get("collection_date") or "").strip(),
            )
    return out


def evaluate_history(cfg: Config, only: str = "all", include_history: bool = False) -> Evaluation:
    """Re-score every LABELED scan in your history with today's rules.yaml. Instant, and needs no e-mail files."""
    ev = Evaluation([], [])
    store = HistoryStore.open(cfg.history.db_path, readonly=True)
    if store is None:
        ev.errors.append(f"no history database at {cfg.history.db_path} yet (use `arer label` or `arer history import`)")
        return ev
    try:
        current = logic_hash(cfg)
        for row in store.labeled():
            if row.logic_hash != current:
                ev.stale += 1
            v = rescore(store, row, cfg, drop_prefixes=() if include_history else ("history.",))
            r = Result(Path(row.name or row.sha256[:12]), row.label, v, source="history")
            if only == "all" or r.split == only:
                ev.results.append(r)
    finally:
        store.close()
    return ev


def evaluate(root: Path, cfg: Config, only: str = "all", skip: set[str] | None = None,
             skip_dirs: set[str] | None = None, include_history: bool = False) -> Evaluation:
    skip = set(skip or ())
    if not include_history:
        skip.add("history")        # your own history would leak campaign siblings into the test
    skip_dirs = {d.lower() for d in (skip_dirs or set())}
    all_files = sorted(p for p in root.rglob("*") if is_mail_candidate(p))
    ev = Evaluation([], [])
    try:
        overrides = _read_overrides(root, all_files, ev.warnings)
        manifest = _read_manifest(root, all_files)
    except (OSError, UnicodeError, csv.Error) as exc:
        raise ValueError(f"could not read dataset metadata: {safe_text(exc, 160)}") from exc
    files = [p for p in all_files
             if not ({x.lower() for x in p.relative_to(root).parts[:-1]} & skip_dirs)]
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
        verdict = run_pipeline(email, cfg, skip=skip)
        if verdict.sha256 and verdict.sha256 in seen:          # same email twice (eml + its parsed json)
            ev.duplicates += 1
            continue
        seen.add(verdict.sha256)
        rel = p.relative_to(root).as_posix()
        meta = manifest.get(rel, ManifestEntry())
        r = Result(
            p, label, verdict,
            source="/".join(p.relative_to(root).parts[:-1]) or "(root)",
            group_id=meta.group_id, dataset=meta.dataset, license=meta.license,
            reference=meta.reference, collection_date=meta.collection_date,
        )
        if only == "all" or r.split == only:
            ev.results.append(r)
    ungrouped = sum(1 for r in ev.results if not r.group_id)
    if manifest and ungrouped:
        ev.warnings.append(
            f"{ungrouped} evaluated sample(s) have no group_id and use the individual content-hash split"
        )
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
    if ev.stale:
        L.append(f"NOTE: {ev.stale} saved scans were made by older analyzer logic or word lists. Their stored findings are re-scored "
                 "with today's weights, but new rules did not run on them. Re-scan the original e-mails (arer history import) for exact results.")
    for warning in ev.warnings:
        L.append(f"WARNING: {safe_text(warning, 240)}")
    grouped = sum(1 for r in R if r.group_id)
    if grouped:
        L.append(f"Campaign grouping: {grouped}/{len(R)} evaluated samples have a manifest group_id")
    provenance = sorted({(r.dataset, r.license, r.reference, r.collection_date)
                         for r in R if any((r.dataset, r.license, r.reference, r.collection_date))})
    if provenance:
        L += ["", "Dataset provenance"]
        for dataset, license_name, reference, collection_date in provenance:
            details_text = "; ".join(
                f"{name}: {safe_text(value, 120)}"
                for name, value in (("license", license_name), ("reference", reference),
                                    ("collected", collection_date)) if value
            )
            L.append(f"  {safe_text(dataset or '(dataset unspecified)', 60)}"
                     + (f" — {details_text}" if details_text else ""))
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
