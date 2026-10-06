"""Command line: parse a file or a whole folder of .eml/.msg into JSON files.

    uv run arer data/samples -o output
    uv run arer data/samples/mail.eml --trust mx.mycorp.com --extract-attachments
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .mail_parser import SUPPORTED_SUFFIXES, MailParserError, parse_mail_file, to_json


def collect(target: Path, recursive: bool) -> list[Path]:
    if target.is_file():
        return [target]
    pattern = "**/*" if recursive else "*"
    return sorted(p for p in target.glob(pattern) if p.suffix.lower() in SUPPORTED_SUFFIXES)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="arer", description="Parse .eml/.msg into JSON")
    ap.add_argument("input", type=Path, help="a .eml/.msg file or a folder containing them")
    ap.add_argument("-o", "--output", type=Path, default=Path("output"), help="folder for JSON files")
    ap.add_argument("-r", "--recursive", action="store_true", help="search sub-folders too")
    ap.add_argument("--trust", help="trusted mail-server string, enables sender_ip detection")
    ap.add_argument("--include-payload", action="store_true", help="embed attachment content (base64) in JSON")
    ap.add_argument("--extract-attachments", action="store_true", help="also write attachments to <output>/attachments/")
    ap.add_argument("--full", action="store_true", help="also embed mail-parser's own mail/mail_partial views")
    ap.add_argument("--compact", action="store_true", help="single-line JSON")
    args = ap.parse_args(argv)

    if not args.input.exists():
        print(f"error: {args.input} does not exist", file=sys.stderr)
        return 2

    files = collect(args.input, args.recursive)
    if not files:
        print(f"no .eml/.msg files found in {args.input}", file=sys.stderr)
        return 1

    args.output.mkdir(parents=True, exist_ok=True)
    failures = 0
    for f in files:
        out_file = args.output / f"{f.name}.json"  # mail.eml -> mail.eml.json (no eml/msg clash)
        try:
            att_dir = args.output / "attachments" / f.name if args.extract_attachments else None
            data = parse_mail_file(
                f,
                trust=args.trust,
                include_attachment_payload=args.include_payload,
                include_library_views=args.full,
                attachments_dir=att_dir,
            )
            out_file.write_text(to_json(data, None if args.compact else 2), encoding="utf-8")
            print(f"[ok]   {f.name} -> {out_file}")
        except (MailParserError, OSError, ValueError) as exc:
            failures += 1
            print(f"[fail] {f.name}: {type(exc).__name__}: {exc}", file=sys.stderr)

    print(f"done: {len(files) - failures}/{len(files)} parsed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
