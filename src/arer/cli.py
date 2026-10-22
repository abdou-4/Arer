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
from .evaluate import evaluate, render
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
@click.option("--config", "config_dir", type=click.Path(exists=True, file_okay=False),
              help="Config folder (default: ./config or $PHISHSCOPE_CONFIG).")
def scan(input, recursive, trust, quiet, json_path, out_dir, raw, skip, config_dir):
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
@click.argument("root", type=click.Path(exists=True, file_okay=False, path_type=Path), default=Path("data/samples"))
@click.option("--only", type=click.Choice(["all", "dev", "test"]), default="all", show_default=True,
              help="Use a stable 80/20 split: tune on dev, check on test.")
@click.option("--details", is_flag=True, help="List every sample with its score.")
@click.option("--skip", multiple=True, help="Analyzer name to turn off, to see what it contributes.")
@click.option("--config", "config_dir", type=click.Path(exists=True, file_okay=False),
              help="Config folder to test (copy config/ and change weights to compare).")
def eval_cmd(root, only, details, skip, config_dir):
    """Score every sample under ROOT/phish and ROOT/legit and report detection and false alarms."""
    try:
        cfg = load_config(config_dir)
    except ConfigError as e:
        raise click.ClickException(str(e))
    ev = evaluate(root, cfg, only=only, skip=set(skip))
    if not ev.results:
        click.echo(click.style(f"no labeled samples found under {root} (need phish/ and legit/ folders)", fg="red"), err=True)
        sys.exit(1)
    click.echo(render(ev, cfg, details=details))


if __name__ == "__main__":
    main()
