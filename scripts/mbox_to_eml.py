#!/usr/bin/env python3
"""
mbox_to_eml.py - turn a Gmail Takeout (or any) .mbox file into one .eml file per message,
choosing a random sample of modern legitimate mail for data/samples/legit/.

    python scripts/mbox_to_eml.py "All mail Including Spam and Trash.mbox" \
        -o data/samples/legit --count 60 --prefix mine

How to get the mbox: https://takeout.google.com -> deselect all -> Mail -> choose labels (Inbox) -> export.

By default only messages labelled Inbox are used, and anything labelled Spam, Trash, Drafts or Sent is
skipped. Sent mail has no receiving-server authentication stamp, which would bias the test set.
Messages with no X-Gmail-Labels header (non-Gmail mbox) are kept.

PRIVACY: these are your real e-mails. Keep them out of git (add data/samples/legit/mine_* to .gitignore).
"""
from __future__ import annotations

import argparse
import hashlib
import mailbox
import random
import sys
from email.parser import BytesHeaderParser
from pathlib import Path

EXCLUDE = {"spam", "trash", "drafts", "draft", "sent"}


def labels_of(raw: bytes) -> set[str] | None:
    """Gmail labels as a lower-case set, or None when the header is absent."""
    h = BytesHeaderParser().parsebytes(raw)
    value = h.get("X-Gmail-Labels")
    if value is None:
        return None
    return {x.strip().strip('"').lower() for x in str(value).replace("\n", "").split(",") if x.strip()}


def pick(mbox_path: Path, label: str, count: int, seed: int, max_mb: float, require_auth: bool, have: set[str]):
    mb = mailbox.mbox(str(mbox_path))
    keys = list(mb.keys())
    random.Random(seed).shuffle(keys)                       # sample the whole mailbox, not just the newest
    chosen, scanned, skipped = [], 0, {"label": 0, "size": 0, "no_auth": 0, "dup": 0}
    for k in keys:
        if len(chosen) >= count:
            break
        scanned += 1
        raw = mb.get_bytes(k)
        if len(raw) > max_mb * 1024 * 1024:
            skipped["size"] += 1
            continue
        labels = labels_of(raw)
        if labels is not None and (label.lower() not in labels or labels & EXCLUDE):
            skipped["label"] += 1
            continue
        if require_auth and b"authentication-results" not in raw[:20000].lower():
            skipped["no_auth"] += 1
            continue
        digest = hashlib.sha256(raw).hexdigest()
        if digest in have:                                  # already exported by an earlier run
            skipped["dup"] += 1
            continue
        have.add(digest)
        chosen.append(raw)
    return chosen, scanned, skipped


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Sample an .mbox into .eml files")
    ap.add_argument("mbox", type=Path)
    ap.add_argument("-o", "--output", type=Path, default=Path("data/samples/legit"))
    ap.add_argument("--count", type=int, default=50, help="how many messages to extract (default 50)")
    ap.add_argument("--label", default="Inbox", help="Gmail label to require (default Inbox)")
    ap.add_argument("--prefix", default="mine", help="file name prefix (default mine)")
    ap.add_argument("--seed", type=int, default=1, help="random seed, so the sample is repeatable")
    ap.add_argument("--max-mb", type=float, default=5.0, help="skip messages larger than this")
    ap.add_argument("--allow-no-auth", action="store_true",
                    help="keep messages without an Authentication-Results header (normally skipped)")
    a = ap.parse_args(argv)

    if not a.mbox.is_file():
        print(f"error: {a.mbox} not found", file=sys.stderr)
        return 2
    a.output.mkdir(parents=True, exist_ok=True)
    old = sorted(a.output.glob(f"{a.prefix}_*.eml"))
    have = {hashlib.sha256(f.read_bytes()).hexdigest() for f in old}
    chosen, scanned, skipped = pick(a.mbox, a.label, a.count, a.seed, a.max_mb, not a.allow_no_auth, have)
    existing = len(old)
    for i, raw in enumerate(chosen, start=existing + 1):
        (a.output / f"{a.prefix}_{i:04d}.eml").write_bytes(raw)
    print(f"wrote {len(chosen)} messages to {a.output}  (looked at {scanned}; skipped: "
          f"{skipped['label']} wrong label, {skipped['no_auth']} no auth results, {skipped['size']} too large, "
          f"{skipped['dup']} already exported)")
    if len(chosen) < a.count:
        print(f"note: only {len(chosen)} of {a.count} requested matched. Try --label with another label or --allow-no-auth.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
