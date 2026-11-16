"""
arer - local phishing triage.

    arer parse data/samples -o output          .eml/.msg  ->  JSON files   (your old command)
    arer scan  data/samples                    .eml/.msg/.json -> verdict  (parse + analyze)
    arer scan  data/samples/mail.eml -q

Two commands, that's all. `scan` parses in memory, so you never run two steps.
Exit codes (frozen table, see docs/cli-contract.md and src/arer/exitcodes.py)
    parse : 0 ok | 1 some files failed | 2 input missing
    scan  : 0 CLEAN | 3 SUSPICIOUS | 4 LIKELY_PHISHING | 5 MALICIOUS
            6 INSUFFICIENT_DATA (no decision, not an alert)
            7 ANALYSIS_ERROR (analyzers failed, result incomplete)
            1 a file failed | 2 usage error
    Scripts must match exact codes (or the allowlist in arer.exitcodes),
    never "exit >= 3": code 6 is a no-decision and code 7 is not a verdict.
"""
from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

import click

from .config import ConfigError, load_config
from .exitcodes import (ALERT_EXITS, ANALYSIS_ERROR_EXIT, EXIT_CODES, EXIT_SEVERITY,
                        exit_code_for, is_alert_exit)
from .evaluate import _label_of, evaluate, evaluate_history, render
from .alert import build_alert, is_alert_level, read_alerts, to_json as alert_to_json
from .campaign import build_campaigns, campaign_level, campaign_status
from .disposition import STATUSES, build_disposition, read_disposition, write_disposition
from .export import export_row, render as render_export
from .metrics import queue_stats, render_queue_stats
from .history.indicators import extract_indicators
from .history.store import HistoryStore, logic_hash
from .loader import EMAIL_SUFFIXES, SCAN_SUFFIXES, LoadError, is_mail_candidate, load_any
from .models import Level
from .pipeline import run_pipeline
from .report import render_terminal, to_json
from .util.defang import safe_text
from .watcher import poll_once

# The exit-code contract lives in src/arer/exitcodes.py (R0 remediation):
# one frozen table, an explicit allowlist, and the batch severity order.
_EXIT_SEVERITY = EXIT_SEVERITY
__all__ = ["main", "exit_code_for"]   # exit_code_for is re-exported for callers/tests


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


@click.group(invoke_without_command=True)
@click.option("-v", "--verbose", is_flag=True, help="Show debug logging.")
@click.pass_context
def main(ctx: click.Context, verbose: bool):
    """arer: parse emails and detect phishing, fully local."""
    logging.basicConfig(level=logging.DEBUG if verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    # mail-parser logs every calendar invite and every undecodable header (some samples have corrupted ones): noise unless -v
    logging.getLogger("mailparser").setLevel(logging.DEBUG if verbose else logging.CRITICAL)

    if ctx.invoked_subcommand is None:                  # bare `arer`
        from .menu import run_menu, stdin_is_interactive   # imported here: menu.py imports this module
        if stdin_is_interactive():
            run_menu()
        else:                                           # pipes, scripts, CI: just show the help
            click.echo(ctx.get_help())


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
@click.option("--alerts", "alerts_dir", type=click.Path(file_okay=False, path_type=Path),
              help="Save one <name>.alert.json per alert-level email (schema arer.alert.v1, "
                   "see docs/alert-record.md) in this folder.")
@click.option("--raw", is_flag=True, help="Do not defang saved JSON (keeps real URLs/IPs).")
@click.option("--skip", multiple=True, help="Analyzer name to skip (repeatable).")
@click.option("--save/--no-save", default=None,
              help="Remember this scan in your history (default: config/history.yaml auto_save, normally off).")
@click.option("--config", "config_dir", type=click.Path(exists=True, file_okay=False),
              help="Config folder (default: ./config or $PHISHSCOPE_CONFIG).")
def scan(input, recursive, trust, quiet, json_path, out_dir, alerts_dir, raw, skip, save, config_dir):
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
    if alerts_dir:
        alerts_dir.mkdir(parents=True, exist_ok=True)

    codes, failed = [], False
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
        if alerts_dir and is_alert_level(v.level):
            alert = build_alert(v, email, p.name, cfg)
            (alerts_dir / f"{p.name}.alert.json").write_text(alert_to_json(alert, defang=not raw), encoding="utf-8")
        codes.append(EXIT_CODES[v.level])

    if failed:
        codes.append(1)
    sys.exit(max(codes, key=_EXIT_SEVERITY.get) if codes else 0)  # noqa: RUF015 - sys.exit wants the code, not the arg


# --------------------------------------------------------------------------- #
# arer alerts   (read back the records that `arer scan --alerts` wrote)
# --------------------------------------------------------------------------- #
@main.group()
def alerts():
    """Read alert records written by `arer scan --alerts DIR` (arer.alert.v1)."""


@alerts.command("list")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--level", type=click.Choice([lv.value for lv in Level]), help="Only show this verdict level.")
@click.option("--status", type=click.Choice([*STATUSES, "new"]),
              help="Only show alerts with this disposition ('new' = not handled yet).")
def alerts_list(directory, level, status):
    """Every alert record in DIRECTORY, newest first, with its disposition.
    Broken alert or disposition files are named too (exit 1)."""
    reads = read_alerts(directory)
    bad = 0
    rows = []
    for r in reads:
        if r.alert is None:
            bad += 1
            click.echo(click.style(f"✗ {r.error}", fg="red"), err=True)
            continue
        if level and r.alert.verdict.level.value != level:
            continue
        try:
            d = read_disposition(r.path)
        except Exception as e:                       # noqa: BLE001 - DispositionError names the file
            bad += 1
            click.echo(click.style(f"✗ {safe_text(e, 200)}", fg="red"), err=True)
            continue
        st = d.status if d else "new"
        if status and st != status:
            continue
        rows.append((r.alert, st))
    rows.sort(key=lambda row: (row[0].generated_utc, row[0].alert_id), reverse=True)
    if rows:
        click.echo(f"{'alert_id':<14}{'generated':<21}{'level':<18}{'score':>5}  {'status':<14}{'sha256':<14}{'from':<26}file")
        for a, st in rows:
            sender = safe_text(a.scan.from_, 60)
            click.echo(f"{a.alert_id[:12]:<14}{a.generated_utc:<21}{a.verdict.level.value:<18}{a.verdict.score:>5}  "
                       f"{st:<14}{a.verdict.sha256[:12]:<14}{sender:<26}{safe_text(a.source_file, 40)}")
    elif not bad:
        click.echo(f"no alert records in {directory}")
    if bad:
        click.echo(f"{len(rows)} valid, {bad} unreadable")
    sys.exit(1 if bad else 0)


@alerts.command("show")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.argument("alert_id")
def alerts_show(directory, alert_id):
    """Print the full record with id matching ALERT_ID (6+ characters is enough)."""
    matches = {r.alert.alert_id: r.path for r in read_alerts(directory)
               if r.alert and r.alert.alert_id.startswith(alert_id)}
    if len(matches) != 1:
        hint = "several match, give more characters" if len(matches) > 1 else "no alert record matches that"
        raise click.ClickException(hint + " (copy the alert_id from: arer alerts list DIRECTORY)")
    click.echo(matches.popitem()[1].read_text(encoding="utf-8"), nl=False)


@alerts.command("set")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.argument("alert_id")
@click.argument("status", type=click.Choice(STATUSES))
@click.option("--note", help="Why (the analyst's words, stored verbatim).")
def alerts_set(directory, alert_id, status, note):
    """Record the decision about one alert: acknowledged, benign or phishing.

    Writes <name>.disposition.json next to the alert record; the record itself
    is never modified. No disposition yet = `new` (see: arer alerts list --status new)."""
    matches = [r for r in read_alerts(directory)
               if r.alert and r.alert.alert_id.startswith(alert_id)]
    if len(matches) != 1:
        hint = "several match, give more characters" if len(matches) > 1 else "no alert record matches that"
        raise click.ClickException(hint + " (copy the alert_id from: arer alerts list DIRECTORY)")
    m = matches[0]
    d = build_disposition(m.alert.alert_id, status, mail_sha256=m.alert.verdict.sha256, note=note or "")
    out = write_disposition(d, m.path)
    click.echo(f"{m.alert.alert_id[:12]}  {safe_text(m.alert.source_file, 50)}  disposition: {status}"
               + (f"  ({safe_text(note, 120)})" if note else "") + f"\n  -> {safe_text(out.name, 80)}")


@alerts.command("export")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--format", "fmt", type=click.Choice(["jsonl", "csv"]), default="jsonl", show_default=True,
              help="jsonl = one flat JSON object per alert (SIEM-friendly); csv = one row per alert.")
@click.option("-o", "--out", "out_file", type=click.Path(dir_okay=False, path_type=Path),
              help="Write to this file instead of stdout.")
@click.option("--raw", is_flag=True, help="Do not defang the exported IOCs (export is safe-by-default).")
@click.option("--level", type=click.Choice([lv.value for lv in Level]), help="Only export this verdict level.")
@click.option("--status", type=click.Choice([*STATUSES, "new"]),
              help="Only export alerts with this disposition ('new' = not handled yet).")
def alerts_export(directory, fmt, out_file, raw, level, status):
    """Flatten alert records (+ their dispositions) for SIEM/SOAR/spreadsheets,
    one line (jsonl) or row (csv) per alert."""
    reads = read_alerts(directory)
    bad = 0
    rows = []
    for r in reads:
        if r.alert is None:
            bad += 1
            click.echo(click.style(f"✗ {r.error}", fg="red"), err=True)
            continue
        try:
            d = read_disposition(r.path)
        except Exception as e:                       # noqa: BLE001 - DispositionError names the file
            bad += 1
            click.echo(click.style(f"✗ {safe_text(e, 200)}", fg="red"), err=True)
            continue
        if level and r.alert.verdict.level.value != level:
            continue
        st = d.status if d else "new"
        if status and st != status:
            continue
        rows.append(export_row(r.alert, d, r.path.name))
    if not rows and not bad:
        click.echo(f"no alert records in {directory}")
    text = render_export(rows, fmt, defang=not raw)
    if out_file:
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(text, encoding="utf-8")
        click.echo(f"exported {len(rows)} alert(s) -> {out_file}")
    elif text:
        click.echo(text, nl=False)
    if bad:
        click.echo(f"{len(rows)} exported, {bad} unreadable", err=True)
    sys.exit(1 if bad else 0)


@alerts.command("campaigns")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--level", type=click.Choice([lv.value for lv in Level]),
              help="Only show groups whose most severe record has this level.")
@click.option("--status", type=click.Choice([*STATUSES, "new", "mixed"]),
              help="Only show groups with this combined disposition ('new' = no record handled yet, "
                   "'mixed' = members disagree).")
def alerts_campaigns(directory, level, status):
    """One row per distinct mail in DIRECTORY (records grouped by exact sha256):
    how many times it alerted, when it was first/last seen, and the combined
    disposition of its records.

    v1 groups by exact hash only - mails that merely look similar stay
    separate campaigns (no fuzzy clustering)."""
    reads = read_alerts(directory)
    bad = 0
    for r in reads:
        if r.alert is None:
            bad += 1
            click.echo(click.style(f"✗ {r.error}", fg="red"), err=True)
    rows = []
    for c in build_campaigns(reads):
        members = []                                 # (alert, disposition|None), readable members only
        for a, p in zip(c.alerts, c.paths):
            try:
                d = read_disposition(p)
            except Exception as e:                       # noqa: BLE001 - DispositionError names the file
                bad += 1
                click.echo(click.style(f"✗ {safe_text(e, 200)}", fg="red"), err=True)
                continue
            members.append((a, d))
        if not members:
            continue                                     # every member unreadable: nothing honest to show
        lvl = campaign_level([a for a, _ in members])
        if level and lvl.value != level:
            continue
        st = campaign_status([d.status if d else "new" for _, d in members])
        if status and st != status:
            continue
        rows.append((members, lvl, max(a.verdict.score for a, _ in members), st))
    if rows:
        click.echo(f"{'sha256':<14}{'seen':>5}  {'level':<18}{'score':>5}  "
                   f"{'first':<21}{'last':<21}{'from':<26}status")
        for members, lvl, score, st in rows:
            sender = safe_text(members[-1][0].scan.from_, 60)
            click.echo(f"{members[0][0].verdict.sha256[:12]:<14}{len(members):>5}  {lvl.value:<18}{score:>5}  "
                       f"{members[0][0].generated_utc:<21}{members[-1][0].generated_utc:<21}{sender:<26}{st}")
    elif not bad:
        click.echo(f"no alert records in {directory}")
    if bad:
        click.echo(f"{len(rows)} campaign(s), {bad} unreadable")
    sys.exit(1 if bad else 0)


@alerts.command("set-group")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.argument("sha256")
@click.argument("status", type=click.Choice(STATUSES))
@click.option("--note", help="Why (the analyst's words, stored verbatim).")
def alerts_set_group(directory, sha256, status, note):
    """Record one decision for every alert record of the same mail.

    SHA256 is 6 or more hex characters of the mail's hash (copy it from
    `alerts campaigns`). Writes/overwrites the per-alert disposition sidecars
    of the whole group; the alert records themselves are never modified."""
    sha256 = sha256.lower()
    campaigns = build_campaigns(read_alerts(directory))
    matches = [c for c in campaigns if c.mail_sha256.startswith(sha256)]
    if len(matches) != 1:
        hint = "several campaigns match, give more characters" if len(matches) > 1 else "no campaign matches that sha256"
        raise click.ClickException(hint + " (copy the sha256 from: arer alerts campaigns DIRECTORY)")
    c = matches[0]
    for a, p in zip(c.alerts, c.paths):
        write_disposition(build_disposition(a.alert_id, status, mail_sha256=c.mail_sha256, note=note or ""), p)
    click.echo(f"{c.mail_sha256[:12]}  {len(c.alerts)} alert(s) marked {status}"
               + (f"  ({safe_text(note, 120)})" if note else ""))


@alerts.command("stats")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path))
def alerts_stats(directory):
    """Metrics over the alert queue: backlog, false-alarm share, response
    time, top senders. Read-only; a broken record or corrupt sidecar is
    excluded from every number, named, and makes the command exit 1."""
    reads = read_alerts(directory)
    bad = 0
    pairs = []
    for r in reads:
        if r.alert is None:
            bad += 1
            click.echo(click.style(f"✗ {r.error}", fg="red"), err=True)
            continue
        try:
            d = read_disposition(r.path)
        except Exception as e:                       # noqa: BLE001 - DispositionError names the file
            bad += 1
            click.echo(click.style(f"✗ {safe_text(e, 200)} (excluded from the metrics)", fg="red"), err=True)
            continue
        pairs.append((r.alert, d))
    if not pairs and not bad:
        click.echo(f"no alert records in {directory}")
        return
    click.echo(render_queue_stats(queue_stats(pairs)))
    if bad:
        sys.exit(1)


# --------------------------------------------------------------------------- #
# arer watch   (mail drop folder -> fresh scan subprocess per mail)
# --------------------------------------------------------------------------- #
@main.command("watch")
@click.argument("drop", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--alerts", "alerts_dir", type=click.Path(file_okay=False, path_type=Path),
              help="Folder for alert records (same as scan --alerts; the subprocess writes them).")
@click.option("--every", "interval", type=float, default=5.0, show_default=True,
              help="Seconds between passes (continuous mode).")
@click.option("--timeout", "timeout", type=float, default=60.0, show_default=True,
              help="Seconds one mail may take before its scan is killed.")
@click.option("--skip", multiple=True, help="Analyzer name to turn off (same as scan).")
@click.option("--once", is_flag=True, help="One pass over the folder, then exit (cron-friendly).")
def watch_cmd(drop, alerts_dir, interval, timeout, skip, once):
    """Watch a mail drop folder: every mail file that appears is scanned by a
    fresh `arer scan` subprocess (killed if it hangs), then archived to
    handled/ or failed/ inside DROP - never overwritten, never deleted.

    With --once, one pass runs and the command exits (1 if any mail failed).
    Without it, the watcher loops until Ctrl-C."""
    def show(outcomes):
        for o in outcomes:
            line = f"{o.path.name}  {safe_text(o.detail, 120)}  -> {o.dest.relative_to(drop)}"
            click.echo(click.style(line, fg="red") if o.failed else line)
    if once:
        outcomes = poll_once(drop, alerts_dir=alerts_dir, timeout=timeout, skip=skip)
        show(outcomes)
        if any(o.failed for o in outcomes):
            sys.exit(1)
        return
    click.echo(f"watching {drop} every {interval:g}s (Ctrl-C to stop)")
    try:
        while True:
            show(poll_once(drop, alerts_dir=alerts_dir, timeout=timeout, skip=skip))
            time.sleep(interval)
    except KeyboardInterrupt:
        click.echo("\nstopped.")


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
              help="Use a stable 80/20 split; manifest group_id keeps known campaign samples together.")
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
        try:
            ev = evaluate(root, cfg, only=only, skip=set(skip), skip_dirs=set(skip_dirs), include_history=with_history_signals)
        except ValueError as e:
            raise click.ClickException(safe_text(e, 240))
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


# --------------------------------------------------------------------------- #
# arer menu   (the interactive front door; also what bare `arer` opens in a terminal)
# --------------------------------------------------------------------------- #
@main.command("menu")
def menu_cmd():
    """Open the interactive menu."""
    from .menu import run_menu                          # imported here: menu.py imports this module
    run_menu()


if __name__ == "__main__":
    main()
