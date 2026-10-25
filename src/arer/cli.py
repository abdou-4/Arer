"""
arer - local phishing triage.

    arer parse data/samples -o output          .eml/.msg  ->  JSON files   (your old command)
    arer scan  data/samples                    .eml/.msg/.json -> verdict  (parse + analyze)
    arer scan  data/samples/mail.eml -q

Two commands, that's all. `scan` parses in memory, so you never run two steps.
Exit codes
    parse : 0 ok | 1 some files failed | 2 input missing
    scan  : 0 clean/suspicious | 2 likely phishing or malicious found | 1 a file failed
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

import click

from .config import ConfigError, load_config
from .evaluate import _label_of, evaluate, evaluate_history, render
from .history.indicators import extract_indicators
from .history.store import HistoryStore, logic_hash
from .loader import EMAIL_SUFFIXES, SCAN_SUFFIXES, LoadError, is_mail_candidate, load_any
from .models import Level
from .pipeline import run_pipeline
from .report import render_terminal, to_json
from .util.defang import safe_text

BAD = {Level.LIKELY_PHISHING, Level.MALICIOUS}


def collect(target: Path, recursive: bool, suffixes: set[str]) -> list[Path]:
    """A file -> itself. A folder -> matching files (symlinks and *.report.json skipped).
    For `scan`, files without an extension count too when they look like e-mail."""
    if target.is_file():
        return [target]
    pattern = "**/*" if recursive else "*"
    if suffixes == SCAN_SUFFIXES:
        return sorted(p for p in target.glob(pattern) if is_mail_candidate(p))
    return sorted(
        p for p in target.glob(pattern)
        if p.is_file() and not p.is_symlink()
        and p.suffix.lower() in suffixes and not p.name.endswith(".report.json")
    )


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Show debug logging.")
def main(verbose: bool):
    """arer: parse emails and detect phishing, fully local."""
    logging.basicConfig(level=logging.DEBUG if verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    # mail-parser warns about every calendar invite; that is noise unless you asked for -v
    logging.getLogger("mailparser").setLevel(logging.DEBUG if verbose else logging.ERROR)


# --------------------------------------------------------------------------- #
# arer parse   (same behaviour and options as your old CLI)
# --------------------------------------------------------------------------- #
@main.command()
@click.argument("input", type=click.Path(exists=True, path_type=Path))
@click.option("-o", "--output", type=click.Path(file_okay=False, path_type=Path),
              default=Path("output"), show_default=True, help="Folder for JSON files.")
@click.option("-r", "--recursive", is_flag=True, help="Search sub-folders too.")
@click.option("--trust", help="Trusted mail-server string, enables sender_ip detection.")
@click.option("--include-payload", is_flag=True, help="Embed attachment content (base64) in the JSON.")
@click.option("--extract-attachments", is_flag=True,
              help="Also write attachments to <output>/attachments/ (live malware on disk!).")
@click.option("--full", is_flag=True, help="Also embed mail-parser's own mail/mail_partial views.")
@click.option("--compact", is_flag=True, help="Single-line JSON.")
def parse(input, output, recursive, trust, include_payload, extract_attachments, full, compact):
    """Convert .eml/.msg file(s) into JSON."""
    from .mail_parser import SUPPORTED_SUFFIXES, parse_mail_file, to_json as parser_json

    files = collect(input, recursive, SUPPORTED_SUFFIXES)
    if not files:
        click.echo(f"no .eml/.msg files found in {input}", err=True)
        sys.exit(1)

    output.mkdir(parents=True, exist_ok=True)
    failures = 0
    for f in files:
        out_file = output / f"{f.name}.json"            # mail.eml -> mail.eml.json
        try:
            att_dir = output / "attachments" / f.name if extract_attachments else None
            data = parse_mail_file(f, trust=trust, include_attachment_payload=include_payload,
                                   include_library_views=full, attachments_dir=att_dir)
            out_file.write_text(parser_json(data, None if compact else 2), encoding="utf-8")
            click.echo(f"[ok]   {safe_text(f.name)} -> {out_file}")
        except Exception as exc:                        # noqa: BLE001 - one bad file never stops a batch
            failures += 1
            click.echo(f"[fail] {safe_text(f.name)}: {type(exc).__name__}: {safe_text(exc, 150)}", err=True)

    click.echo(f"done: {len(files) - failures}/{len(files)} parsed")
    sys.exit(1 if failures else 0)


def _save(cfg, email, verdict, name) -> int:
    store = HistoryStore.open(cfg.history.db_path, create=True)
    try:
        return store.save_scan(verdict.sha256, name, email, verdict, extract_indicators(email, cfg), logic_hash(cfg))
    finally:
        store.close()


# --------------------------------------------------------------------------- #
# arer scan
# --------------------------------------------------------------------------- #
@main.command()
@click.argument("input", nargs=-1, required=True, type=click.Path(exists=True, path_type=Path))
@click.option("-r", "--recursive", is_flag=True, help="Search sub-folders too.")
@click.option("--trust", help="Trusted mail-server string, enables sender_ip detection.")
@click.option("-q", "--quiet", is_flag=True, help="One line per email.")
@click.option("--json", "json_path", type=click.Path(dir_okay=False, path_type=Path),
              help="Save the report for ONE email to this file.")
@click.option("--out", "out_dir", type=click.Path(file_okay=False, path_type=Path),
              help="Save one <name>.report.json per email in this folder.")
@click.option("--raw", is_flag=True, help="Do not defang saved JSON (keeps real URLs/IPs).")
@click.option("--skip", multiple=True, help="Analyzer name to skip (repeatable).")
@click.option("--save/--no-save", default=None,
              help="Remember this scan in your history (default: config/history.yaml auto_save, normally off).")
@click.option("--config", "config_dir", type=click.Path(exists=True, file_okay=False),
              help="Config folder (default: ./config or $PHISHSCOPE_CONFIG).")
def scan(input, recursive, trust, quiet, json_path, out_dir, raw, skip, save, config_dir):
    """Analyze .eml/.msg/.json file(s) or folder(s) and print a verdict."""
    try:
        cfg = load_config(config_dir)
    except ConfigError as e:
        raise click.ClickException(str(e))

    paths: list[Path] = []
    for target in input:
        found = collect(target, recursive, SCAN_SUFFIXES)
        if not found:
            click.echo(click.style(f"✗ nothing to scan in {target} "
                                   f"(looking for {', '.join(sorted(SCAN_SUFFIXES))})", fg="red"), err=True)
        paths += found
    if not paths:
        sys.exit(1)
    if json_path and len(paths) > 1:
        raise click.UsageError("--json saves one report; use --out DIR for many emails")
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)

    worst, failed = 0, False
    for p in paths:
        try:
            email = load_any(p, cfg, trust=trust)
        except LoadError as e:
            click.echo(click.style(f"✗ {safe_text(e, 250)}", fg="red"), err=True)
            failed = True
            continue

        v = run_pipeline(email, cfg, skip=set(skip))
        if quiet:
            click.echo(f"{v.level.value:<18}{v.score:>3}  {safe_text(p.name)}")
        else:
            click.echo(render_terminal(v, cfg))

        if save if save is not None else cfg.history.auto_save:
            times = _save(cfg, email, v, p.name)
            if not quiet:
                click.echo(f"history: saved ({'first time' if times == 1 else f'seen {times} times'}). "
                           f"Label it with: arer label {v.sha256[:12]} phish|legit")

        report = to_json(v, defang=not raw)
        if json_path:
            json_path.write_text(report, encoding="utf-8")
        if out_dir:
            (out_dir / f"{p.name}.report.json").write_text(report, encoding="utf-8")
        if v.level in BAD:
            worst = 2

    sys.exit(worst or (1 if failed else 0))


# --------------------------------------------------------------------------- #
# arer eval   (measure detection and false alarms on labeled samples)
# --------------------------------------------------------------------------- #
@main.command("eval")
@click.argument("root", required=False, type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--from-history", is_flag=True,
              help="Re-score your LABELED saved scans with today's rules.yaml (instant, no e-mail files needed).")
@click.option("--with-history-signals", is_flag=True,
              help="Include history.* findings (off by default: they leak campaign siblings into a test).")
@click.option("--only", type=click.Choice(["all", "dev", "test"]), default="all", show_default=True,
              help="Use a stable 80/20 split: tune on dev, check on test.")
@click.option("--skip-dir", "skip_dirs", multiple=True, help="Ignore any folder with this name (e.g. archive).")
@click.option("--details", is_flag=True, help="List every sample with its score.")
@click.option("--skip", multiple=True, help="Analyzer name to turn off, to see what it contributes.")
@click.option("--config", "config_dir", type=click.Path(exists=True, file_okay=False),
              help="Config folder to test (copy config/ and change weights to compare).")
def eval_cmd(root, from_history, with_history_signals, only, skip_dirs, details, skip, config_dir):
    """Score every sample under ROOT/phish and ROOT/legit and report detection and false alarms."""
    try:
        cfg = load_config(config_dir)
    except ConfigError as e:
        raise click.ClickException(str(e))
    if from_history:
        ev = evaluate_history(cfg, only=only, include_history=with_history_signals)
    else:
        root = root or Path("data/samples")
        if not root.is_dir():
            raise click.ClickException(f"{root} does not exist (give a folder with phish/ and legit/, or use --from-history)")
        ev = evaluate(root, cfg, only=only, skip=set(skip), skip_dirs=set(skip_dirs), include_history=with_history_signals)
    if not ev.results:
        msg = "; ".join(ev.errors) or f"no labeled samples found under {root} (need phish/ and legit/ folders)"
        click.echo(click.style(msg, fg="red"), err=True)
        sys.exit(1)
    click.echo(render(ev, cfg, details=details))


# --------------------------------------------------------------------------- #
# arer label / arer history ...   (your private, labeled scan history)
# --------------------------------------------------------------------------- #
@main.command("label")
@click.argument("target")
@click.argument("label", type=click.Choice(["phish", "legit", "none"]))
@click.option("--note", help="Why (kept with the label).")
@click.option("--config", "config_dir", type=click.Path(exists=True, file_okay=False), help="Config folder.")
def label_cmd(target, label, note, config_dir):
    """Label an e-mail as phish or legit. TARGET is an e-mail file, or a saved scan's SHA-256 (6+ characters).

    Only labels you set teach arer: later mail from the same sender, links or attachments is judged by them."""
    try:
        cfg = load_config(config_dir)
    except ConfigError as e:
        raise click.ClickException(str(e))
    store = HistoryStore.open(cfg.history.db_path, create=True)
    try:
        p = Path(target)
        if p.is_file():
            try:
                email = load_any(p, cfg)
            except LoadError as e:
                raise click.ClickException(safe_text(e, 200))
            v = run_pipeline(email, cfg)
            store.save_scan(v.sha256, p.name, email, v, extract_indicators(email, cfg), logic_hash(cfg))
            sha = v.sha256
        else:
            sha = store.resolve(target)
            if not sha:
                raise click.ClickException("no unique saved scan matches that. Give an e-mail file, or 6+ characters of its SHA-256 (see: arer history list)")
        before = store.get(sha).label
        store.set_label(sha, None if label == "none" else label, note)
        row = store.get(sha)
    finally:
        store.close()
    click.echo(f"{sha[:12]}  {safe_text(row.name, 50)}  {row.level} {row.score}  label: {before or '-'} -> {row.label or '-'}")
    if row.label == "phish":
        click.echo("From now on, mail from this exact sender address (or its domain, unless that is Gmail or another protected domain), "
                   "or carrying these links or attachments, will be flagged.")


@main.group()
def history():
    """Your private scan history (data/history.db)."""


def _open_history(config_dir, create=False):
    try:
        cfg = load_config(config_dir)
    except ConfigError as e:
        raise click.ClickException(str(e))
    store = HistoryStore.open(cfg.history.db_path, create=create)
    if store is None and not create:
        raise click.ClickException(f"no history yet at {cfg.history.db_path}. Start with: arer scan FILE --save   or   arer label FILE phish")
    return cfg, store


@history.command("list")
@click.option("--label", type=click.Choice(["phish", "legit", "unlabeled"]))
@click.option("--limit", default=30, show_default=True)
@click.option("--config", "config_dir", type=click.Path(exists=True, file_okay=False))
def history_list(label, limit, config_dir):
    """Most recent saved scans."""
    cfg, store = _open_history(config_dir)
    try:
        rows = store.list(label, limit)
    finally:
        store.close()
    click.echo(f"{'sha256':<14}{'label':<10}{'verdict':<18}{'seen':>5}  {'sender domain':<26}file")
    for r in rows:
        click.echo(f"{r.sha256[:12]:<14}{r.label or '-':<10}{f'{r.level} {r.score}':<18}{r.times:>5}  "
                   f"{safe_text(r.from_domain, 24):<26}{safe_text(r.name, 40)}")


@history.command("stats")
@click.option("--config", "config_dir", type=click.Path(exists=True, file_okay=False))
def history_stats(config_dir):
    """Counts, labels and how many rows are stale."""
    cfg, store = _open_history(config_dir)
    try:
        s = store.stats(logic_hash(cfg))
    finally:
        store.close()
    db = cfg.history.db_path
    click.echo(f"history: {db}  ({db.stat().st_size / 1e3:.0f} KB)")
    click.echo(f"scans: {s['total']}   labeled phish: {s['phish']}   labeled legit: {s['legit']}   unlabeled: {s['unlabeled']}")
    click.echo(f"from {s['oldest'] or '-'}  to {s['newest'] or '-'}")
    need = cfg.history.min_scans
    click.echo(f"first-time-sender signal: {'active' if s['total'] >= need else f'silent until {need} scans are saved (cold start)'}")
    if s["stale"]:
        click.echo(click.style(f"{s['stale']} scans were made by older analyzer logic or word lists (stored findings may miss new rules).", fg="yellow"))


@history.command("import")
@click.argument("root", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--skip-dir", "skip_dirs", multiple=True, help="Ignore any folder with this name (e.g. archive).")
@click.option("--config", "config_dir", type=click.Path(exists=True, file_okay=False))
def history_import(root, skip_dirs, config_dir):
    """Save and label every sample under ROOT/phish and ROOT/legit (folder names are the labels)."""
    cfg, store = _open_history(config_dir, create=True)
    skip_dirs = {d.lower() for d in skip_dirs}
    n = skipped = failed = 0
    try:
        for p in sorted(x for x in root.rglob("*") if is_mail_candidate(x)):
            rel = {x.lower() for x in p.relative_to(root).parts[:-1]}
            if rel & skip_dirs:
                continue
            lab = _label_of(p, root, {})
            if lab is None:
                skipped += 1
                continue
            try:
                email = load_any(p, cfg)
            except LoadError as e:
                failed += 1
                click.echo(click.style(f"✗ {safe_text(e, 160)}", fg="red"), err=True)
                continue
            v = run_pipeline(email, cfg, skip={"history"})        # stored findings must not depend on the history itself
            store.save_scan(v.sha256, p.name, email, v, extract_indicators(email, cfg), logic_hash(cfg))
            store.set_label(v.sha256, lab)
            n += 1
    finally:
        store.close()
    click.echo(f"imported and labeled {n} e-mails ({skipped} outside phish/ or legit/, {failed} failed)")


@history.command("forget")
@click.argument("sha")
@click.option("--config", "config_dir", type=click.Path(exists=True, file_okay=False))
def history_forget(sha, config_dir):
    """Delete one saved scan completely (row, findings, indicators)."""
    cfg, store = _open_history(config_dir)
    try:
        full = store.resolve(sha)
        if not full:
            raise click.ClickException("no unique saved scan matches that")
        store.forget(full)
    finally:
        store.close()
    click.echo(f"forgot {full[:12]}")


# --------------------------------------------------------------------------- #
# arer feeds update | status   (the only part of arer that uses the network)
# --------------------------------------------------------------------------- #
@main.group()
def feeds():
    """Download and inspect the local phishing blocklists."""


@feeds.command("update")
@click.argument("names", nargs=-1)
@click.option("--config", "config_dir", type=click.Path(exists=True, file_okay=False), help="Config folder.")
def feeds_update(names, config_dir):
    """Download the enabled feeds (or only NAMES) and rebuild the index. Needs internet."""
    from .intel.updater import update_all
    try:
        cfg = load_config(config_dir)
    except ConfigError as e:
        raise click.ClickException(str(e))
    if not cfg.feeds.sources:
        raise click.ClickException("no feeds configured (config/feeds.yaml is missing or empty)")
    results = update_all(cfg, list(names) or None)
    if not results:
        raise click.ClickException("no enabled feeds. Enable one in config/feeds.yaml or name it: arer feeds update NAME")
    bad = False
    for r in results:
        if r.skipped:
            click.echo(f"[skip] {r.name:<30} {r.message}")
        elif r.ok:
            click.echo(f"[ok]   {r.name:<30} {r.entries:>9,} entries  {r.bytes / 1e6:6.1f} MB  ({r.seconds:.1f}s)")
        else:
            bad = True
            click.echo(click.style(f"[fail] {r.name:<30} {safe_text(r.message, 160)}", fg="red"), err=True)
    for r in results:
        note = cfg.feeds.sources.get(r.name).note if r.name in cfg.feeds.sources else ""
        if r.ok and not r.skipped and "NON-COMMERCIAL" in note.upper():
            click.echo(click.style(f"note: {r.name}: {note}", fg="yellow"))
    sys.exit(1 if bad else 0)


@feeds.command("status")
@click.option("--config", "config_dir", type=click.Path(exists=True, file_okay=False), help="Config folder.")
def feeds_status(config_dir):
    """Show which feeds are loaded and how old they are."""
    from datetime import datetime, timezone
    from .intel.store import DB_NAME, IntelStore
    try:
        cfg = load_config(config_dir)
    except ConfigError as e:
        raise click.ClickException(str(e))
    store = IntelStore.open(cfg.feeds.data_dir)
    have = {s.name: s for s in store.sources()} if store else {}
    db = cfg.feeds.data_dir / DB_NAME
    click.echo(f"index: {db}" + (f"  ({db.stat().st_size / 1e6:.1f} MB)" if db.is_file() else "  (not built yet)"))
    click.echo(f"{'feed':<30}{'enabled':<9}{'entries':>10}  {'age':<10} note")
    now = datetime.now(timezone.utc)
    for name, spec in cfg.feeds.sources.items():
        s = have.get(name)
        if s:
            age = (now - datetime.fromisoformat(s.fetched_at)).days
            stale = spec.enabled and age > cfg.feeds.max_age_days
            age_txt = click.style(f"{age}d STALE", fg="red") if stale else f"{age}d"
            click.echo(f"{name:<30}{'yes' if spec.enabled else 'no':<9}{s.entries:>10,}  {age_txt:<10} {safe_text(spec.note, 60)}")
        else:
            click.echo(f"{name:<30}{'yes' if spec.enabled else 'no':<9}{'-':>10}  {'never':<10} {safe_text(spec.note, 60)}")


if __name__ == "__main__":
    main()
