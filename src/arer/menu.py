"""
menu.py - the friendly, interactive front door:  just type  `arer`  and answer the questions.

How it works (so you can extend it):
  * Every menu entry is one small function that ASKS questions, builds the same arguments you would
    type yourself, and hands them to run_cli().  The menu never has its own logic for scanning,
    evaluating and so on: it always runs the real commands, and shows you the command it ran.
  * To add a menu entry (for example an AI feature later), write a function and put
    @register_action("Title", "one-line hint") above it. Numbers are assigned automatically.

Colours: none. Only plain text, bold and dim (grey), so it looks right on dark and light terminals.
Set NO_COLOR=1 to switch even that off.
"""
from __future__ import annotations

import os
import re
import shlex
import sys
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Callable

import click

from .cli import collect, main
from .evaluate import LEGIT_DIRS, PHISH_DIRS
from .loader import SCAN_SUFFIXES

# --------------------------------------------------------------------------- #
# LOGO SPACE
# Paste your shield here, one string per line. It is drawn to the left of the title.
# Keep it at most LOGO_WIDTH characters wide. Leave LOGO empty for now: the space is reserved.
# --------------------------------------------------------------------------- #
LOGO_WIDTH = 16
LOGO: list[str] = []

TITLE = [
    r"  __ _ _ __ ___ _ __ ",
    r" / _` | '__/ _ \ '__|",
    r"| (_| | | |  __/ |   ",
    r" \__,_|_|  \___|_|   ",
]
TAGLINE = "Local phishing email triage"
SUBLINE = "Scans run offline, on your computer."


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
def _style(text: str, **kw) -> str:
    return text if os.environ.get("NO_COLOR") else click.style(text, **kw)


def bold(text: str) -> str:
    return _style(text, bold=True)


def dim(text: str) -> str:
    return _style(text, dim=True)


def clean_path(raw: str) -> Path:
    """Accept what people really paste: quotes, drag-and-drop escapes, ~ for the home folder."""
    raw = raw.strip().strip("\"'")
    raw = raw.replace("\\ ", " ")
    return Path(raw).expanduser()


def _version() -> str:
    try:
        return version("arer")
    except PackageNotFoundError:
        return ""


def banner_lines() -> list[tuple[str, str]]:
    """[(text, kind)] where kind is 'title' or 'dim'. Logo space on the left, title on the right."""
    block = [(line, "title") for line in TITLE] + [("", "dim"), (TAGLINE + (f"  v{_version()}" if _version() else ""), "dim"),
                                                   (SUBLINE, "dim")]
    height = max(len(block), len(LOGO))
    top = (height - len(block)) // 2                      # centre the text next to a taller logo
    logo_top = (height - len(LOGO)) // 2
    out = []
    for i in range(height):
        logo = LOGO[i - logo_top] if 0 <= i - logo_top < len(LOGO) else ""
        text, kind = block[i - top] if 0 <= i - top < len(block) else ("", "dim")
        out.append((logo.ljust(LOGO_WIDTH) + text, kind))
    return out


def print_banner() -> None:
    click.echo()
    for text, kind in banner_lines():
        click.echo("  " + (bold(text) if kind == "title" else dim(text)))
    click.echo()


def run_cli(args: list[str]) -> int:
    """Run a normal arer command and show how to type it yourself next time."""
    click.echo(dim("\n  Running:  " + shlex.join(["arer", *args])) + "\n")
    code = 0
    try:
        main.main(args=args, prog_name="arer", standalone_mode=False)
    except SystemExit as e:                               # commands use exit codes: 2 = phishing found, 1 = a problem
        code = e.code if isinstance(e.code, int) else 1
    except click.ClickException as e:
        e.show()
        code = 1
    if code == 1:
        click.echo(dim("\n  (Some items could not be processed. See the messages above.)"))
    return code


def ask_path(question: str, want: str = "any", default: str | None = None) -> Path | None:
    """Ask for a file or folder until it exists. Type q to go back. Returns None if cancelled."""
    while True:
        raw = click.prompt(f"  {question} {dim('(q = back)')}", default=default or "", show_default=bool(default)).strip()
        if raw.lower() in ("q", "quit", "back"):
            return None
        if not raw:
            click.echo("  Please type or paste a path.")
            continue
        p = clean_path(raw)
        if not p.exists():
            click.echo(f"  I cannot find: {p}\n  Tip: drag the file or folder into this window to paste its path.")
        elif want == "file" and not p.is_file():
            click.echo("  That is a folder. Please give one email file.")
        elif want == "folder" and not p.is_dir():
            click.echo("  That is a file. Please give a folder.")
        else:
            return p


def ask_choice(question: str, options: list[tuple[str, str]]) -> str | None:
    """Numbered choice. Returns the chosen key, or None if cancelled."""
    click.echo(f"\n  {question}")
    for i, (_, label) in enumerate(options, 1):
        click.echo(f"    {i}  {label}")
    while True:
        raw = click.prompt(f"  Choose a number {dim('(q = back)')}", default="", show_default=False).strip().lower()
        if raw in ("q", "back", "0"):
            return None
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1][0]
        click.echo(f"  Please type a number from 1 to {len(options)}.")


# --------------------------------------------------------------------------- #
# the registry: one entry per menu item
# --------------------------------------------------------------------------- #
@dataclass
class Action:
    title: str
    hint: str
    run: Callable[[], None]


ACTIONS: list[Action] = []


def register_action(title: str, hint: str):
    def deco(fn: Callable[[], None]):
        ACTIONS.append(Action(title, hint, fn))
        return fn
    return deco


# --------------------------------------------------------------------------- #
# the menu entries
# --------------------------------------------------------------------------- #
@register_action("Scan emails", "Check one email, or a whole folder")
def scan_flow() -> None:
    path = ask_path("Email file or folder to scan")
    if path is None:
        return
    args = ["scan", str(path)]
    if path.is_dir():
        flat, deep = len(collect(path, False, SCAN_SUFFIXES)), len(collect(path, True, SCAN_SUFFIXES))
        count = flat
        if deep == 0:
            click.echo("  No emails (.eml, .msg or .json) found in that folder.")
            return
        if deep > flat:
            where = "No emails directly in this folder, but" if flat == 0 else f"{flat} emails here, and"
            if click.confirm(f"  {where} {deep} in total including sub-folders. Include sub-folders?", default=True):
                args.append("-r")
                count = deep
        click.echo(f"  Found {count} email(s).")
        if click.confirm("  Show one short line per email, instead of full reports?", default=count > 5):
            args.append("-q")
    if click.confirm("  Remember the result in your private history? (stores no email text)", default=False):
        args.append("--save")
    if click.confirm("  Also save a report file (JSON) for each email?", default=False):
        args += ["--out", click.prompt("  Folder for the reports", default="reports")]
    run_cli(args)


@register_action("Measure accuracy", "Test arer on labeled samples")
def eval_flow() -> None:
    kind = ask_choice("What should arer be tested on?", [
        ("folder", "A folder of labeled samples  (it needs sub-folders named phish and legit)"),
        ("history", "My saved scans that I have labeled"),
    ])
    if kind is None:
        return
    if kind == "history":
        run_cli(["eval", "--from-history"])
        return
    default = "data/samples" if Path("data/samples").is_dir() else None
    root = ask_path("Folder that contains phish/ and legit/", want="folder", default=default)
    if root is None:
        return
    names = {p.name.lower() for p in root.iterdir() if p.is_dir()}
    if not names & (PHISH_DIRS | LEGIT_DIRS):
        click.echo("  That folder has no sub-folders named phish or legit, so there is nothing to compare.")
        return
    args = ["eval", str(root)]
    if click.confirm("  List every sample with its score?", default=False):
        args.append("--details")
    run_cli(args)


@register_action("Label an email", "Teach arer: phishing or legitimate?")
def label_flow() -> None:
    raw = click.prompt(f"  Email file, or the ID from 'history list' {dim('(q = back)')}", default="", show_default=False).strip()
    if raw.lower() in ("", "q", "back"):
        return
    p = clean_path(raw)
    if p.is_file():
        target = str(p)
    elif re.fullmatch(r"[0-9a-fA-F]{6,64}", raw):
        target = raw
    else:
        click.echo("  That is neither an existing file nor a saved-scan ID (6 or more letters/digits).")
        return
    label = ask_choice("This email is:", [("phish", "Phishing"), ("legit", "Legitimate"), ("none", "Clear my label")])
    if label is None:
        return
    args = ["label", target, label]
    note = click.prompt("  A short note (optional, press Enter to skip)", default="", show_default=False).strip()
    if note:
        args += ["--note", note]
    run_cli(args)


@register_action("My history", "Saved scans, statistics, import")
def history_flow() -> None:
    what = ask_choice("History:", [("list", "Show recent saved scans"), ("stats", "Show statistics"),
                                    ("import", "Import a folder of labeled samples"), ("forget", "Delete one saved scan")])
    if what is None:
        return
    if what == "list":
        label = ask_choice("Which ones?", [("", "All"), ("phish", "Labeled phishing"), ("legit", "Labeled legitimate"),
                                            ("unlabeled", "Not labeled yet")])
        if label is None:
            return
        run_cli(["history", "list"] + (["--label", label] if label else []))
    elif what == "stats":
        run_cli(["history", "stats"])
    elif what == "import":
        root = ask_path("Folder that contains phish/ and legit/", want="folder")
        if root is not None:
            run_cli(["history", "import", str(root)])
    else:
        sha = click.prompt(f"  ID of the scan to delete {dim('(q = back)')}", default="", show_default=False).strip()
        if sha and sha.lower() not in ("q", "back"):
            run_cli(["history", "forget", sha])


@register_action("Blocklists", "Download or check phishing blocklists")
def feeds_flow() -> None:
    what = ask_choice("Blocklists:", [("status", "Show what is loaded and how old it is"),
                                       ("update", "Download the latest lists  (needs internet, about 70 MB)")])
    if what == "status":
        run_cli(["feeds", "status"])
    elif what == "update" and click.confirm("  This is the only step that uses the internet. Continue?", default=False):
        run_cli(["feeds", "update"])


@register_action("Convert emails to JSON", "Turn .eml / .msg into JSON files")
def parse_flow() -> None:
    path = ask_path("Email file or folder to convert")
    if path is None:
        return
    args = ["parse", str(path), "-o", click.prompt("  Folder for the JSON files", default="output")]
    if path.is_dir() and click.confirm("  Include sub-folders?", default=False):
        args.append("-r")
    run_cli(args)


@register_action("Help", "The commands behind this menu")
def help_flow() -> None:
    click.echo("""
  Everything in this menu is also a normal command. Type it yourself any time:

    arer scan PATH [-r] [-q]       check an email or folder  (-r sub-folders, -q one line each)
    arer eval [FOLDER]             measure accuracy on labeled samples
    arer label FILE phish|legit    teach arer from your own decision
    arer history list|stats|import|forget
    arer feeds status|update       local blocklists (update needs internet)
    arer parse PATH                convert emails to JSON
    arer --help                    every option

  Results:  CLEAN, SUSPICIOUS, LIKELY_PHISHING, MALICIOUS (or INSUFFICIENT_DATA).
  Nothing inside an email is ever opened or visited. Read USAGE.md for the full guide.""")


# --------------------------------------------------------------------------- #
# the menu itself
# --------------------------------------------------------------------------- #
def show_menu() -> None:
    print_banner()
    click.echo("  What would you like to do?\n")
    width = max(len(a.title) for a in ACTIONS) + 3
    for i, a in enumerate(ACTIONS, 1):
        click.echo(f"    {i}  {a.title.ljust(width)}{dim(a.hint)}")
    click.echo("    0  Quit\n")


def run_menu() -> None:
    try:
        while True:
            show_menu()
            choice = click.prompt("  Choose a number", default="", show_default=False).strip().lower()
            if choice in ("0", "q", "quit", "exit"):
                break
            if choice.isdigit() and 1 <= int(choice) <= len(ACTIONS):
                try:
                    ACTIONS[int(choice) - 1].run()
                    click.pause(dim("\n  Press any key to return to the menu..."))
                except click.Abort:
                    click.echo("\n  Cancelled.")
            else:
                click.echo(f"\n  Please type a number from 0 to {len(ACTIONS)}.")
    except (click.Abort, EOFError, KeyboardInterrupt):
        click.echo()
    click.echo("  Goodbye.")


def stdin_is_interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()
