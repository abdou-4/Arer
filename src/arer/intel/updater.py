"""
intel/updater.py - download feeds and rebuild their part of the index.

This is the ONLY code in the project that uses the network, and only when you run
`arer feeds update`. Safety rules:
  * https only; redirects allowed only to the same host over https
  * hard download size cap, enforced while streaming
  * the feed is treated as text: every line is validated and normalised, nothing is executed
  * an update that shrinks a feed below min_keep_ratio of its previous size is REFUSED
    (an outage, an error page or a poisoned feed must not erase good data)
  * each feed is replaced in one SQLite transaction, so a crash never leaves half a feed
"""
from __future__ import annotations

import hashlib
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ..config import Config, FeedSource
from .store import (hash_key, domain_key, normalize_domain, normalize_hash, normalize_url, open_rw, url_key)

USER_AGENT = "arer-local-triage/0.1 (feed updater)"
TIMEOUT_S = 120
CHUNK = 1 << 16


class FeedError(Exception):
    """A feed could not be downloaded or was refused. The message is safe to show."""


class _SameHostHttps(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old, new = urllib.parse.urlsplit(req.full_url), urllib.parse.urlsplit(newurl)
        if new.scheme != "https" or new.hostname != old.hostname:
            raise FeedError(f"refused redirect to {new.scheme}://{new.hostname}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def default_fetch(url: str, max_bytes: int) -> bytes:
    if not url.lower().startswith("https://"):
        raise FeedError("feed url must be https")
    opener = urllib.request.build_opener(_SameHostHttps())
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with opener.open(req, timeout=TIMEOUT_S) as resp:
            if resp.status != 200:
                raise FeedError(f"HTTP {resp.status}")
            declared = resp.headers.get("Content-Length")
            if declared and declared.isdigit() and int(declared) > max_bytes:
                raise FeedError(f"download is {int(declared) / 1e6:.0f} MB, limit is {max_bytes / 1e6:.0f} MB")
            buf = bytearray()
            while chunk := resp.read(CHUNK):
                buf += chunk
                if len(buf) > max_bytes:
                    raise FeedError(f"download exceeded the {max_bytes / 1e6:.0f} MB limit")
            return bytes(buf)
    except urllib.error.HTTPError as e:
        raise FeedError(f"HTTP {e.code}") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise FeedError(f"network error: {type(e).__name__}") from e


def parse_feed(data: bytes, kind: str) -> set[bytes]:
    """Feed text -> set of index keys. Bad lines are skipped, never trusted."""
    keys: set[bytes] = set()
    norm, make = {"url": (normalize_url, url_key), "domain": (normalize_domain, domain_key),
                  "hash": (normalize_hash, hash_key)}[kind]
    for line in data.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or line[0] in "#;" or line.startswith("//"):
            continue
        if kind == "hash":
            line = line.split()[0]
        v = norm(line[:4200])
        if v:
            keys.add(make(v))
    return keys


@dataclass
class UpdateResult:
    name: str
    ok: bool
    message: str
    entries: int = 0
    bytes: int = 0
    seconds: float = 0.0
    skipped: bool = False


def update_source(name: str, spec: FeedSource, cfg: Config, conn,
                  fetch: Callable[[str, int], bytes] | None = None) -> UpdateResult:
    fetch = fetch or default_fetch
    t0 = time.time()
    max_bytes = cfg.feeds.max_download_mb * 1024 * 1024
    try:
        if spec.path:
            p = Path(spec.path)
            if not p.is_file():
                return UpdateResult(name, True, "no file yet (create it to use this list)", skipped=True)
            if p.stat().st_size > max_bytes:
                raise FeedError("local file too large")
            data = p.read_bytes()
        else:
            data = fetch(spec.url, max_bytes)
        keys = parse_feed(data, spec.kind)
        if not keys:
            raise FeedError("no valid entries found (wrong format or an error page?)")

        row = conn.execute("SELECT id, entries FROM sources WHERE name=?", (name,)).fetchone()
        if row and row[1] and len(keys) < row[1] * cfg.feeds.min_keep_ratio:
            raise FeedError(f"REFUSED: new list has {len(keys):,} entries, down from {row[1]:,}. Kept the old data.")

        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        digest = hashlib.sha256(data).hexdigest()
        with conn:                                               # one atomic transaction
            if row:
                sid = row[0]
                conn.execute("DELETE FROM ioc WHERE src=?", (sid,))
                conn.execute("UPDATE sources SET kind=?, entries=?, fetched_at=?, bytes=?, sha256=? WHERE id=?",
                             (spec.kind, len(keys), now, len(data), digest, sid))
            else:
                sid = conn.execute("INSERT INTO sources(name, kind, entries, fetched_at, bytes, sha256) VALUES(?,?,?,?,?,?)",
                                   (name, spec.kind, len(keys), now, len(data), digest)).lastrowid
            conn.executemany("INSERT OR IGNORE INTO ioc VALUES(?,?)", ((k, sid) for k in keys))
        return UpdateResult(name, True, "updated", len(keys), len(data), time.time() - t0)
    except FeedError as e:
        return UpdateResult(name, False, str(e), seconds=time.time() - t0)


def update_all(cfg: Config, names: list[str] | None = None,
               fetch: Callable[[str, int], bytes] | None = None) -> list[UpdateResult]:
    fetch = fetch or default_fetch
    conn = open_rw(cfg.feeds.data_dir)
    results = []
    try:
        for name, spec in cfg.feeds.sources.items():
            if names:
                if name not in names:
                    continue
            elif not spec.enabled:
                continue
            results.append(update_source(name, spec, cfg, conn, fetch))
        for n in names or []:
            if n not in cfg.feeds.sources:
                results.append(UpdateResult(n, False, "unknown feed name (see config/feeds.yaml)"))
        if any(r.ok and not r.skipped for r in results):
            conn.execute("VACUUM")                      # give back the space of replaced feeds
    finally:
        conn.close()
    return results
