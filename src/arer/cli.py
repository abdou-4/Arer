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

import json
import logging
import os
import sys
import time
from pathlib import Path

import click

from .config import ConfigError, load_config
from .exitcodes import (ALERT_EXITS, ANALYSIS_ERROR_EXIT, EXIT_CODES, EXIT_SEVERITY,
                        exit_code_for, is_alert_exit, is_analysis_incomplete, scan_exit_code)
from .evaluate import _label_of, evaluate, evaluate_history, render
from .alert import (AlertCollisionError, build_alert, is_alert_level, read_alerts,
                    to_json as alert_to_json, write_alert)
from .campaign import (build_campaigns, build_clusters, campaign_level, campaign_status,
                       strong_keys)
from .disposition import STATUSES, build_disposition, disposition_path, read_disposition, write_disposition
from .export import export_row, is_confirmed_phishing, render as render_export
from .iocs import collect_iocs, to_blocklist as iocs_to_blocklist, to_csv as iocs_to_csv, to_misp as iocs_to_misp
from .metrics import queue_stats, render_queue_stats
from .history.indicators import extract_indicators
from .history.store import (HistoryStore, MigrationRequired, STATUS_TO_DISPOSITION, logic_hash,
                            migrate as migrate_history, read_schema_version)
from .loader import EMAIL_SUFFIXES, SCAN_SUFFIXES, LoadError, is_mail_candidate, load_any
from .models import Level
from .pipeline import run_pipeline
from .report import render_terminal, to_json
from .util.defang import clean, safe_text
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
@click.option("--config", "config_dir", type=click.Path(exists=True, file_okay=False),
              help="Config folder (for the size limits).")
def parse(input, output, recursive, trust, include_payload, extract_attachments, full, compact, config_dir):
    """Convert .eml/.msg file(s) into JSON."""
    from .mail_parser import SUPPORTED_SUFFIXES, parse_mail_file, to_json as parser_json

    try:
        cfg = load_config(config_dir)
        max_bytes = cfg.limits.max_eml_mb * 1024 * 1024
    except ConfigError:
        max_bytes = None                                # unusable config must not block a parse
    files = collect(input, recursive, SUPPORTED_SUFFIXES)
    if not files:
        click.echo(f"no .eml/.msg files found in {input}", err=True)
        sys.exit(1)

    output.mkdir(parents=True, exist_ok=True)
    failures = 0
    for f in files:
        out_file = output / f"{f.name}.json"            # mail.eml -> mail.eml.json
        try:
            # R6.1: `parse` sits behind the SAME size boundary as `scan`
            if max_bytes is not None and f.stat().st_size > max_bytes:
                raise LoadError(f"{f.name} is {f.stat().st_size / 1e6:.1f} MB, "
                                f"limit is {cfg.limits.max_eml_mb} MB (max_eml_mb)")
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


def _mirror_decision(alerts_dir: Path, alert, status: str, note: str, config_dir=None) -> str:
    """Mirror one analyst disposition into the history database (R2).

    The sidecar stays the queue's local record; the decision event in
    history.db carries the provenance (analyst identity, timestamp,
    training eligibility). Best-effort: if the database is missing or still
    schema 1, the disposition still works and the caller prints a hint - a
    sidecar decision is NEVER lost because of the provenance layer.
    """
    import getpass
    try:
        cfg = load_config(config_dir)
    except ConfigError:
        return ""
    try:
        store = HistoryStore.open(cfg.history.db_path, create=True)
        if store is None:
            return ""
        try:
            if status == "phishing":
                eligible, reason = True, "analyst true_positive"
            elif status == "benign":
                eligible, reason = True, "analyst false_positive"
            else:
                eligible, reason = False, "workflow acknowledgement, never a training disposition"
            store.record_decision(
                alert.verdict.sha256, kind="disposition", value=STATUS_TO_DISPOSITION[status],
                provenance="analyst", analyst=getpass.getuser(),
                source_ref=f"alert:{alert.alert_id} (beside {alerts_dir})",
                note=note, training_eligible=eligible, eligibility_reason=reason)
            return ""
        finally:
            store.close()
    except MigrationRequired:
        return ("note: the decision is stored as a sidecar only - analyst provenance and "
                "training eligibility need schema 2:  arer history migrate")
    except Exception as e:                              # noqa: BLE001 - mirroring must never break triage
        return f"note: decision not mirrored to history ({safe_text(e, 120)})"


def _save(cfg, email, verdict, name) -> int:
    store = HistoryStore.open(cfg.history.db_path, create=True)
    try:
        return store.save_scan(verdict.sha256, name, email, verdict, extract_indicators(email, cfg), logic_hash(cfg))
    except ValueError:                          # R1.6: unverified claimed hash (parser-JSON input)
        return 0                                # caller prints the note; the scan itself is unaffected
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
              help="Folder for alert records (one `<alert_id>.alert.json` per alert-level email, "
                   "schema arer.alert.v1, see docs/alert-record.md).")
@click.option("--raw", is_flag=True,
              help="Do not defang the saved report JSON. Alert records (v2) always store the "
                   "raw representation; defanging happens on output (R4.4).")
@click.option("--store-sender", is_flag=True,
              help="Store the sender's plaintext address in alert records (v2 stores the "
                   "sender DOMAIN by default - R4.5 privacy default).")
@click.option("--jsonl", "jsonl_path", type=click.Path(dir_okay=False, path_type=Path),
              help="Write one versioned JSON record per scanned message to this file "
                   "(load failures become structured error lines).")
@click.option("--skip", multiple=True, help="Analyzer name to skip (repeatable).")
@click.option("--save/--no-save", default=None,
              help="Remember this scan in your history (default: config/history.yaml auto_save, normally off).")
@click.option("--config", "config_dir", type=click.Path(exists=True, file_okay=False),
              help="Config folder (default: ./config or $PHISHSCOPE_CONFIG).")
def scan(input, recursive, trust, quiet, json_path, out_dir, alerts_dir, raw, store_sender,
         jsonl_path, skip, save, config_dir):
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
    jsonl_fh = jsonl_path.open("w", encoding="utf-8") if jsonl_path else None

    def _jsonl_line(source: Path, *, ok: bool, v=None, error: str = "") -> None:
        """One versioned record per message (R3.3); operational failures are
        structured error lines, never silent."""
        if jsonl_fh is None:
            return
        line = {"schema": "arer.scan-jsonl.v1", "source_file": source.name, "ok": ok}
        if v is not None:
            line["exit_code"] = scan_exit_code(v)
            line["report"] = json.loads(to_json(v, defang=not raw))
        else:
            line["error"] = error
        jsonl_fh.write(json.dumps(line, ensure_ascii=False) + "\n")
        jsonl_fh.flush()

    codes, failed = [], False
    for p in paths:
        try:
            email = load_any(p, cfg, trust=trust)
        except LoadError as e:
            click.echo(click.style(f"✗ {safe_text(e, 250)}", fg="red"), err=True)
            _jsonl_line(p, ok=False, error=safe_text(e, 250))
            failed = True
            continue

        v = run_pipeline(email, cfg, skip=set(skip))
        code = scan_exit_code(v)
        if quiet:
            line = f"{v.level.value:<18}{v.score:>3}  {safe_text(p.name)}"
            if v.analyzer_errors:
                line += "  [analysis incomplete - analyzer problems, see the report]"
            click.echo(line)
        else:
            click.echo(render_terminal(v, cfg))

        if save if save is not None else cfg.history.auto_save:
            times = _save(cfg, email, v, p.name)
            if times == 0:
                click.echo(click.style("history: not saved - this scan has no verified SHA-256 "
                                       "(parser-JSON input). Rescan the original .eml/.msg to store it.", fg="yellow"))
            elif not quiet:
                click.echo(f"history: saved ({'first time' if times == 1 else f'seen {times} times'}). "
                           f"Label it with: arer label {v.sha256[:12]} phish|legit")

        report = to_json(v, defang=not raw)
        if json_path:
            json_path.write_text(report, encoding="utf-8")
        if out_dir:
            (out_dir / f"{p.name}.report.json").write_text(report, encoding="utf-8")
        if alerts_dir and (is_alert_level(v.level) or is_analysis_incomplete(v)):
            # R1.4: an analysis that failed part-way also lands in the queue, so
            # evasive or damaged mail is never silently dropped. The record
            # carries verdict.analyzer_errors, and (R4) it can never be exported
            # as a confirmed indicator because of errors alone.
            alert = build_alert(v, email, p.name, cfg, store_sender=store_sender)
            try:
                # R4.4: v2 records store the canonical (RAW) representation;
                # defanging happens exactly once at output/serialization.
                write_alert(alert, alerts_dir, defang=False)
            except AlertCollisionError as e:            # never overwrite another mail's record
                click.echo(click.style(f"✗ {safe_text(e, 200)}", fg="red"), err=True)
                failed = True
        _jsonl_line(p, ok=True, v=v)
        codes.append(code)

    if jsonl_fh is not None:
        jsonl_fh.close()
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
            d = read_disposition(r.path, r.alert)
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
            sender = clean(a.scan.from_ or a.scan.from_domain, 60)
            click.echo(f"{a.alert_id[:12]:<14}{a.generated_utc:<21}{a.verdict.level.value:<18}{a.verdict.score:>5}  "
                       f"{st:<14}{a.verdict.sha256[:12]:<14}{sender:<26}{clean(a.source_file, 40)}")
    elif not bad:
        click.echo(f"no alert records in {directory}")
    if bad:
        click.echo(f"{len(rows)} valid, {bad} unreadable")
    sys.exit(1 if bad else 0)


@alerts.command("show")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.argument("alert_id")
@click.option("--markdown", is_flag=True,
              help="Render a Markdown CASE summary (R7.3): verdict, reasons, indicators "
                   "(defanged), campaign, workflow and reproducibility hashes.")
@click.option("--raw", is_flag=True, help="Show live (un-defanged) indicators in the summary.")
def alerts_show(directory, alert_id, markdown, raw):
    """Print the full record with id matching ALERT_ID (6+ characters is enough)."""
    matches = [r for r in read_alerts(directory)
               if r.alert and r.alert.alert_id.startswith(alert_id)]
    if len(matches) != 1:
        hint = "several match, give more characters" if len(matches) > 1 else "no alert record matches that"
        raise click.ClickException(hint + " (copy the alert_id from: arer alerts list DIRECTORY)")
    r = matches[0]
    if not markdown:
        click.echo(r.path.read_text(encoding="utf-8"), nl=False)
        return
    from .casesummary import render_markdown
    from .campaign import build_clusters
    d = None
    try:
        d = read_disposition(r.path, r.alert)
    except Exception as e:                              # noqa: BLE001 - integrity errors are named
        click.echo(click.style(f"✗ {safe_text(e, 200)} (summary continues without a disposition)", fg="yellow"), err=True)
    campaign = None
    campaign_state = ""
    for c in build_clusters(read_alerts(directory)):
        if r.alert.verdict.sha256 in c.mail_sha256s and len(c.mail_sha256s) > 1:
            campaign = {"campaign_id": c.campaign_id, "mail_sha256s": c.mail_sha256s, "keys": c.keys}
            break
    try:
        cfg = load_config(None)
        store = HistoryStore.open(cfg.history.db_path, readonly=True)
        if store is not None:
            try:
                cur = store.current_decision(campaign["campaign_id"]) if campaign else None
                if cur and cur["kind"] == "campaign":
                    campaign_state = cur["value"]
            finally:
                store.close()
    except Exception:                                   # noqa: BLE001 - provenance is best-effort here
        pass
    click.echo(render_markdown(r.alert, d, record_file=r.path.name,
                               campaign=campaign, campaign_state=campaign_state, raw=raw), nl=False)


@alerts.command("set")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.argument("alert_id")
@click.argument("status", type=click.Choice(STATUSES))
@click.option("--note", help="Why (the analyst's words, stored verbatim).")
@click.option("--config", "config_dir", type=click.Path(exists=True, file_okay=False),
              help="Config folder (for the history database the decision is mirrored into).")
def alerts_set(directory, alert_id, status, note, config_dir):
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
    hint = _mirror_decision(directory, m.alert, status, note or "", config_dir)
    if hint:
        click.echo(click.style(hint, fg="yellow"))


@alerts.command("export")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--format", "fmt", type=click.Choice(["jsonl", "csv"]), default="jsonl", show_default=True,
              help="jsonl = one flat JSON object per alert (SIEM-friendly); csv = one row per alert.")
@click.option("-o", "--out", "out_file", type=click.Path(dir_okay=False, path_type=Path),
              help="Write to this file instead of stdout.")
@click.option("--raw", is_flag=True, help="Do not defang the exported IOCs (export is safe-by-default).")
@click.option("--level", type=click.Choice([lv.value for lv in Level]), help="Only export this verdict level.")
def alerts_export(directory, fmt, out_file, raw, level):
    """Export CONFIRMED phishing cases for IOC consumption (R4.1): only cases
    whose current decision is an ANALYST-originated `phishing` are included.
    Unreviewed, benign, acknowledged and legacy/import/tool-provenance
    records are counted in an exclusion summary - their indicators never
    leave the queue. For the full queue view (SIEM triage), use
    `alerts export-queue`."""
    reads = read_alerts(directory)
    bad = 0
    for r in reads:
        if r.alert is None:
            bad += 1
            click.echo(click.style(f"✗ {r.error}", fg="red"), err=True)
    counts: dict[str, int] = {}
    eligible = []
    for r in reads:
        if r.alert is None:
            continue
        try:
            d = read_disposition(r.path, r.alert)
        except Exception as e:                       # noqa: BLE001 - DispositionError names the file
            bad += 1
            click.echo(click.style(f"✗ {safe_text(e, 200)}", fg="red"), err=True)
            counts["unreadable"] = counts.get("unreadable", 0) + 1
            continue
        if not is_confirmed_phishing(r.alert, d):
            if d is None:
                counts["unreviewed"] = counts.get("unreviewed", 0) + 1
            elif d.effective_provenance != "analyst":
                counts["unverified_provenance"] = counts.get("unverified_provenance", 0) + 1
            elif d.status == "benign":
                counts["benign"] = counts.get("benign", 0) + 1
            else:
                counts["acknowledged"] = counts.get("acknowledged", 0) + 1
            continue
        if level and r.alert.verdict.level.value != level:
            continue
        eligible.append(export_row(r.alert, d, r.path.name))
    text = render_export(eligible, fmt, defang=not raw)
    if not eligible and not bad:
        click.echo(f"no confirmed phishing cases in {directory}")
    if out_file:
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(text, encoding="utf-8")
    elif text:
        click.echo(text, nl=False)
    excluded = ", ".join(f"{k} {v}" for k, v in sorted(counts.items()) if v) or "none"
    click.echo(f"confirmed: {len(eligible)} case(s) exported; excluded (no IOCs taken): {excluded}",
               err=True)
    if bad:
        click.echo(f"{bad} unreadable record(s)", err=True)
    sys.exit(1 if bad else 0)


@alerts.command("export-queue")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--format", "fmt", type=click.Choice(["jsonl", "csv"]), default="jsonl", show_default=True,
              help="jsonl = one flat JSON object per alert (SIEM-friendly); csv = one row per alert.")
@click.option("-o", "--out", "out_file", type=click.Path(dir_okay=False, path_type=Path),
              help="Write to this file instead of stdout.")
@click.option("--raw", is_flag=True, help="Do not defang the exported rows.")
@click.option("--level", type=click.Choice([lv.value for lv in Level]), help="Only export this verdict level.")
@click.option("--status", type=click.Choice([*STATUSES, "new"]),
              help="Only export alerts with this disposition ('new' = not handled yet).")
def alerts_export_queue(directory, fmt, out_file, raw, level, status):
    """The CASE-REPORT export (explicit name, R4.1): every readable alert
    record with its disposition, one line (jsonl) or row (csv) per alert -
    the SIEM/SOAR triage view. This is NOT the IOC export: use
    `alerts export` (analyst-confirmed only) or `alerts iocs` when
    indicators must leave the queue."""
    reads = read_alerts(directory)
    bad = 0
    rows = []
    for r in reads:
        if r.alert is None:
            bad += 1
            click.echo(click.style(f"✗ {r.error}", fg="red"), err=True)
            continue
        try:
            d = read_disposition(r.path, r.alert)
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


@alerts.command("iocs")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--format", "fmt", type=click.Choice(["csv", "blocklist", "misp"]), default="csv",
              show_default=True, help="Indicator-specific format (R4.2).")
@click.option("--kind", type=click.Choice(["all", "url", "domain", "sender_domain", "sha256"]),
              default="all", show_default=True, help="Only these indicators (blocklist/csv).")
@click.option("-o", "--out", "out_file", type=click.Path(dir_okay=False, path_type=Path),
              help="Write to this file instead of stdout.")
@click.option("--raw", is_flag=True,
              help="Export LIVE (un-defanged) indicators. Without it every value is defanged "
                   "- a blocklist of 'evil[.]com' lines is not actionable by accident.")
def alerts_iocs(directory, fmt, kind, out_file, raw):
    """Export the structured indicators of CONFIRMED phishing cases
    (analyst-originated decisions only): urls, url domains, sender domains
    and attachment hashes. Sender addresses never leave the queue (R4.5)."""
    reads = read_alerts(directory)
    bad = 0
    counts: dict[str, int] = {}
    confirmed = []
    for r in reads:
        if r.alert is None:
            bad += 1
            click.echo(click.style(f"✗ {r.error}", fg="red"), err=True)
            continue
        try:
            d = read_disposition(r.path, r.alert)
        except Exception as e:                       # noqa: BLE001 - DispositionError names the file
            bad += 1
            click.echo(click.style(f"✗ {safe_text(e, 200)}", fg="red"), err=True)
            continue
        if is_confirmed_phishing(r.alert, d):
            confirmed.append((r.alert, d))
        elif d is None:
            counts["unreviewed"] = counts.get("unreviewed", 0) + 1
        elif d.effective_provenance != "analyst":
            counts["unverified_provenance"] = counts.get("unverified_provenance", 0) + 1
        elif d.status == "benign":
            counts["benign"] = counts.get("benign", 0) + 1
        else:
            counts["acknowledged"] = counts.get("acknowledged", 0) + 1
    iocs = collect_iocs(confirmed)
    if fmt == "csv":
        text = iocs_to_csv(iocs, raw=raw)
    elif fmt == "blocklist":
        text = iocs_to_blocklist(iocs, kind=None if kind == "all" else kind, raw=raw)
    else:
        text = iocs_to_misp(iocs, raw=raw)
    if out_file:
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(text, encoding="utf-8")
    elif text:
        click.echo(text, nl=False)
    skipped = getattr(collect_iocs, "last_skipped_no_block", 0)
    excluded = ", ".join(f"{k} {v}" for k, v in sorted(counts.items()) if v) or "none"
    click.echo(f"confirmed cases: {len(confirmed)} ({skipped} skipped: no structured indicator block - "
               f"v1 record); indicators: {len(iocs)}; excluded (no IOCs taken): {excluded}", err=True)
    if bad:
        click.echo(f"{bad} unreadable record(s)", err=True)
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
                d = read_disposition(p, a)
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
            sender = clean(members[-1][0].scan.from_ or members[-1][0].scan.from_domain, 60)
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
@click.option("--config", "config_dir", type=click.Path(exists=True, file_okay=False),
              help="Config folder (for the history database the decision is mirrored into).")
def alerts_set_group(directory, sha256, status, note, config_dir):
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
        _mirror_decision(directory, a, status, note or "", config_dir)
    click.echo(f"{c.mail_sha256[:12]}  {len(c.alerts)} alert(s) marked {status}"
               + (f"  ({safe_text(note, 120)})" if note else ""))


@alerts.command("cases")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path))
def alerts_cases(directory):
    """The CASE queue (R2.5): one row per distinct mail (exact sha256,
    deduplicated across file names and sightings), ranked by verdict
    severity first and score second - the work order an analyst triages
    top-down. Read-only; broken records or sidecars are named, excluded
    from the ranking, and make the command exit 1."""
    reads = read_alerts(directory)
    bad = 0
    for r in reads:
        if r.alert is None:
            bad += 1
            click.echo(click.style(f"✗ {r.error}", fg="red"), err=True)
    rows = []
    for c in build_campaigns(reads):
        members = []
        for a, p in zip(c.alerts, c.paths):
            try:
                d = read_disposition(p, a)
            except Exception as e:                       # noqa: BLE001 - DispositionError names the file
                bad += 1
                click.echo(click.style(f"✗ {safe_text(e, 200)}", fg="red"), err=True)
                continue
            members.append((a, d))
        if not members:
            continue
        lvl = campaign_level([a for a, _ in members])
        score = max(a.verdict.score for a, _ in members)
        rows.append((-lvl.rank, -score, members[0][0].generated_utc, c.mail_sha256,
                     len(members), lvl, score,
                     min(m[0].generated_utc for m in members),
                     max(m[0].generated_utc for m in members),
                     campaign_status([d.status if d else "new" for _, d in members])))
    rows.sort(key=lambda r: (r[0], r[1], r[2], r[3]))    # severity desc, score desc, oldest, sha
    if rows:
        click.echo(f"{'sha256':<14}{'seen':>5}  {'level':<18}{'score':>5}  "
                   f"{'first':<21}{'last':<21}status")
        for _, _, _, sha, seen, lvl, score, first, last, st in rows:
            click.echo(f"{sha[:12]:<14}{seen:>5}  {lvl.value:<18}{score:>5}  "
                       f"{first:<21}{last:<21}{st}")
    elif not bad:
        click.echo(f"no alert records in {directory}")
    if bad:
        click.echo(f"{len(rows)} case(s), {bad} unreadable")
    sys.exit(1 if bad else 0)


@alerts.command("clusters")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--level", type=click.Choice([lv.value for lv in Level]),
              help="Only clusters whose most severe record has this level.")
@click.option("--csv", "csv_out", type=click.Path(dir_okay=False, path_type=Path),
              help="Also write a manifest-compatible 'sha256,group_id' mapping for evaluation.")
def alerts_clusters(directory, level, csv_out):
    """PROPOSED campaigns (R5): records grouped by STRONG shared artifacts -
    exact URL host+path, non-inline attachment hashes, normalized body
    fingerprints - never by sender or domain alone. Every member carries the
    key evidence that linked it. Membership is a proposal: confirm with
    `alerts confirm-campaign`."""
    reads = read_alerts(directory)
    bad = 0
    for r in reads:
        if r.alert is None:
            bad += 1
            click.echo(click.style(f"✗ {r.error}", fg="red"), err=True)
    rows = []
    for c in build_clusters(reads):
        lvl = campaign_level([a for a, _p in c.alerts])
        if level and lvl.value != level:
            continue
        rows.append((c, lvl))
    if rows:
        click.echo(f"{'campaign_id':<20}{'mails':>5}{'seen':>6}  {'level':<18}"
                   f"{'first':<21}{'last':<21}keys")
        for c, lvl in rows:
            strong = ", ".join(k.split(":", 1)[0] for k in c.keys if not k.startswith("sha:")) or "-"
            click.echo(f"{c.campaign_id:<20}{len(c.mail_sha256s):>5}{len(c.alerts):>6}  {lvl.value:<18}"
                       f"{c.alerts[0][0].generated_utc:<21}{c.alerts[-1][0].generated_utc:<21}{strong}")
    elif not bad:
        click.echo(f"no alert records in {directory}")
    if csv_out:
        import csv as _csv
        csv_out.parent.mkdir(parents=True, exist_ok=True)
        with csv_out.open("w", newline="", encoding="utf-8") as fh:
            w = _csv.writer(fh, lineterminator="\n")
            w.writerow(["sha256", "group_id"])
            for c, _lvl in rows:
                for sha in c.mail_sha256s:
                    w.writerow([sha, c.campaign_id])
        click.echo(f"manifest mapping: {len(rows)} campaign(s) -> {csv_out}")
    if bad:
        click.echo(f"{len(rows)} cluster(s), {bad} unreadable", err=True)
    sys.exit(1 if bad else 0)


@alerts.command("confirm-campaign")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.argument("campaign_id")
@click.option("--reject", is_flag=True, help="Record a REJECTION instead of a confirmation.")
@click.option("--note", help="Why (the analyst's words, stored verbatim).")
@click.option("--config", "config_dir", type=click.Path(exists=True, file_okay=False),
              help="Config folder (for the history database).")
def alerts_confirm_campaign(directory, campaign_id, reject, note, config_dir):
    """Record the analyst's verdict on a PROPOSED campaign (R5.2): confirmed
    or rejected, with who/when/why, append-only in history.db (auditable).
    Copy CAMPAIGN_ID from `alerts clusters`. The proposal itself is never
    auto-trusted; the confirmation is what downstream tooling may rely on."""
    import getpass
    clusters = build_clusters(read_alerts(directory))
    matches = [c for c in clusters if c.campaign_id.startswith(campaign_id.lower())]
    if len(matches) != 1:
        hint = "several match, give more characters" if len(matches) > 1 else "no campaign matches that id"
        raise click.ClickException(hint + " (copy the campaign_id from: arer alerts clusters DIRECTORY)")
    c = matches[0]
    try:
        cfg = load_config(config_dir)
    except ConfigError as e:
        raise click.ClickException(str(e))
    store = HistoryStore.open(cfg.history.db_path, create=True)
    if store is None:
        raise click.ClickException(f"no history database at {cfg.history.db_path}")
    try:
        value = "rejected" if reject else "confirmed"
        try:
            store.record_decision(
                c.campaign_id, kind="campaign", value=value, provenance="analyst",
                analyst=getpass.getuser(), source_ref=f"alerts clusters {directory}",
                note=note or "",
                training_eligible=False,
                eligibility_reason="campaign relationship, never a training label")
        except MigrationRequired as e:
            raise click.ClickException(safe_text(e, 240)) from e
    finally:
        store.close()
    action = "rejected" if reject else "confirmed"
    click.echo(f"{c.campaign_id}  {len(c.mail_sha256s)} mail(s)  {action}"
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
            d = read_disposition(r.path, r.alert)
        except Exception as e:                       # noqa: BLE001 - DispositionError names the file
            bad += 1
            click.echo(click.style(f"✗ {safe_text(e, 200)} (excluded from the metrics)", fg="red"), err=True)
            continue
        pairs.append((r.alert, d))
    if not pairs and not bad:
        click.echo(f"no alert records in {directory}")
        return
    click.echo(render_queue_stats(queue_stats(pairs)))
    # R7: analyst-feedback metrics - analyst-provenance decisions only
    from .metrics import finding_metrics, render_finding_stats, render_weekly, weekly_alerts
    click.echo("")
    click.echo("alerts per week (cases; duplicate scans are events, not cases)")
    click.echo(render_weekly(weekly_alerts(pairs)))
    click.echo("")
    click.echo("noisy rules (analyst decisions only; legacy/tool/import never count)")
    click.echo(render_finding_stats(finding_metrics(pairs)))
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
@click.option("--min-age", "min_age", type=float, default=0.0, show_default=True,
              help="Skip files modified within the last N seconds (leave them for the next "
                   "pass; protects against half-written transfers). 0 = off (producers "
                   "that rename atomically can keep it off).")
def watch_cmd(drop, alerts_dir, interval, timeout, skip, once, min_age):
    """Watch a mail drop folder: every mail file that appears is scanned by a
    fresh `arer scan` subprocess (killed if it hangs), then archived to
    handled/ or failed/ inside DROP - never overwritten, never deleted.

    With --once, one pass runs and the command exits (1 if any mail failed).
    Without it, the watcher loops until Ctrl-C."""
    def show(outcomes):
        for o in outcomes:
            line = f"{o.path.name}  {safe_text(o.detail, 120)}  -> {o.dest.relative_to(drop)}"
            click.echo(click.style(line, fg="red") if o.failed else line)
    lock = _acquire_watch_lock(drop)
    if lock is None:
        click.echo(click.style(f"another watcher is already running on {drop}", fg="red"), err=True)
        sys.exit(1)
    def _graceful(signum, frame):                       # SIGTERM: stop after the current pass
        raise KeyboardInterrupt
    import signal as _signal
    if not once:
        try:
            _signal.signal(_signal.SIGTERM, _graceful)
        except (ValueError, OSError):                   # not the main thread / unsupported
            pass
    try:
        if once:
            outcomes = poll_once(drop, alerts_dir=alerts_dir, timeout=timeout, skip=skip,
                                 min_age_s=min_age)
            show(outcomes)
            if any(o.failed for o in outcomes):
                sys.exit(1)
            return
        click.echo(f"watching {drop} every {interval:g}s (Ctrl-C to stop)")
        try:
            while True:
                show(poll_once(drop, alerts_dir=alerts_dir, timeout=timeout, skip=skip,
                               min_age_s=min_age))
                time.sleep(interval)
        except KeyboardInterrupt:
            click.echo("\nstopped.")
    finally:
        _release_watch_lock(lock)


def _watch_lock_path(drop: Path) -> Path:
    return drop / ".arer-watch.lock"


def _acquire_watch_lock(drop: Path):
    """Single-instance lock (R6.4): an O_EXCL lock file holding our pid. A
    STALE lock (the holder died) is taken over. Returns the lock path or
    None when another watcher is alive."""
    import signal as _sig
    lock = _watch_lock_path(drop)
    for _attempt in range(2):
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
            return lock
        except FileExistsError:
            try:
                pid = int(lock.read_text(encoding="utf-8").strip() or 0)
            except (OSError, ValueError):
                pid = 0
            alive = False
            if pid > 0:
                try:
                    os.kill(pid, 0)                     # a running holder (including this
                    alive = True                        # process) keeps its lock
                except ProcessLookupError:
                    alive = False
                except PermissionError:
                    alive = True
            if alive:
                return None
            try:
                lock.unlink()                           # stale lock: take over
            except OSError:
                return None
    return None


def _release_watch_lock(lock) -> None:
    try:
        if lock is not None:
            lock.unlink()
    except OSError:
        pass


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
    from .config import config_hash
    click.echo(click.style(f"config_hash: {config_hash(cfg)}   (same tuning must be used "
                           "for any comparison across runs)", fg="cyan"))


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
                raise click.ClickException(safe_text(e, 200)) from e
            v = run_pipeline(email, cfg)
            try:
                store.save_scan(v.sha256, p.name, email, v, extract_indicators(email, cfg), logic_hash(cfg))
            except ValueError as e:                     # R1.6: unverified claimed hash
                raise click.ClickException(safe_text(e, 240)) from e
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
    click.echo(f"history: {db}  ({db.stat().st_size / 1e3:.0f} KB)  schema {store.schema_version}")
    if store.schema_version == "1":
        click.echo(click.style("schema 1: analyst provenance and training eligibility are unavailable "
                               "until you run: arer history migrate", fg="yellow"))
    click.echo(f"scans: {s['total']}   labeled phish: {s['phish']}   labeled legit: {s['legit']}   unlabeled: {s['unlabeled']}")
    click.echo(f"from {s['oldest'] or '-'}  to {s['newest'] or '-'}")
    need = cfg.history.min_scans
    click.echo(f"first-time-sender signal: {'active' if s['total'] >= need else f'silent until {need} scans are saved (cold start)'}")
    if s["stale"]:
        click.echo(click.style(f"{s['stale']} scans were made by older analyzer logic or word lists (stored findings may miss new rules).", fg="yellow"))


@history.command("migrate")
@click.option("--dry-run", is_flag=True, help="Report what would happen; write nothing.")
@click.option("--no-backup", is_flag=True, help="Skip the verified backup copy (NOT recommended).")
@click.option("--config", "config_dir", type=click.Path(exists=True, file_okay=False))
def history_migrate(dry_run, no_backup, config_dir):
    """Migrate data/history.db from schema 1 to schema 2 (decisions,
    provenance, cases). Makes a verified backup copy first, runs in one
    transaction, preserves every scan/finding/indicator/label, and is
    idempotent. Your original file is never touched until the migration
    fully succeeds; keep the backup until you have verified the result."""
    try:
        cfg = load_config(config_dir)
    except ConfigError as e:
        raise click.ClickException(str(e))
    db = cfg.history.db_path
    version = read_schema_version(db)
    if not db.is_file():
        raise click.ClickException(f"no history database at {db} (nothing to migrate)")
    if version not in ("1", "2"):
        raise click.ClickException(f"{db} has unsupported schema '{version}' - refusing to touch it")
    try:
        report = migrate_history(db, dry_run=dry_run, backup=not no_backup)
    except Exception as e:                              # noqa: BLE001 - migration errors must be loud
        raise click.ClickException(f"migration aborted, the original database is unchanged: {safe_text(e, 200)}") from e
    if report.get("dry_run"):
        click.echo(f"DRY RUN - {report['message']}")
        return
    click.echo(report["message"])
    if report.get("backup"):
        click.echo(f"backup: {report['backup']}\n"
                   "keep it until you have verified the migrated database "
                   "(rollback = stop arer and copy the backup back over data/history.db)")
    if report.get("changed"):
        click.echo("next: arer history import-dispositions QUEUE_DIR   (import your existing alert sidecars)")


@history.command("import-dispositions")
@click.argument("queue", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--config", "config_dir", type=click.Path(exists=True, file_okay=False))
def history_import_dispositions(queue, config_dir):
    """Import validated disposition sidecars from QUEUE into history.db as
    `legacy_unverified` decision events (R2.4). A legacy sidecar is NEVER
    treated as an analyst-confirmed training label; review it (re-decide
    with `alerts set`) to make it eligible. Corrupt or mismatched sidecars
    are named and counted, never applied."""
    try:
        cfg = load_config(config_dir)
    except ConfigError as e:
        raise click.ClickException(str(e))
    store = HistoryStore.open(cfg.history.db_path, create=False)
    if store is None:
        raise click.ClickException(f"no history database at {cfg.history.db_path} (create one with a labeled scan)")
    counts = {"imported": 0, "duplicate": 0, "skipped_new": 0, "unreadable": 0}
    try:
        try:
            for r in read_alerts(queue):
                if r.alert is None:
                    counts["unreadable"] += 1
                    click.echo(click.style(f"✗ {r.error}", fg="red"), err=True)
                    continue
                try:
                    d = read_disposition(r.path, r.alert)
                except Exception as e:                       # noqa: BLE001 - integrity errors are named
                    counts["unreadable"] += 1
                    click.echo(click.style(f"✗ {safe_text(e, 200)}", fg="red"), err=True)
                    continue
                if d is None:
                    counts["skipped_new"] += 1
                    continue
                result = store.import_sidecar_decision(
                    r.alert.verdict.sha256, alert_id=r.alert.alert_id, status=d.status,
                    note=d.note, set_utc=d.set_utc, source_ref=r.path.name)
                counts[result] += 1
        except MigrationRequired as e:
            raise click.ClickException(safe_text(e, 240)) from e
    finally:
        store.close()
    click.echo(f"sidecars: {counts['imported']} imported, {counts['duplicate']} already imported "
               f"(duplicate), {counts['skipped_new']} without a decision, {counts['unreadable']} unreadable "
               "- all imported decisions carry provenance legacy_unverified")
    sys.exit(1 if counts["unreadable"] else 0)


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
            try:
                store.save_scan(v.sha256, p.name, email, v, extract_indicators(email, cfg), logic_hash(cfg))
            except ValueError as e:                     # R1.6: unverified claimed hash (parser-JSON sample)
                failed += 1
                click.echo(click.style(f"✗ {safe_text(p.name, 80)}: {safe_text(e, 160)}", fg="red"), err=True)
                continue
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
