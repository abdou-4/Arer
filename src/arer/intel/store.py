"""
intel/store.py - the blocklist index (data/feeds/intel.db).

Only 16-byte hashes of entries are stored, never the lists themselves: about 1.2 million
entries fit in roughly 31 MB, open in under a millisecond and answer a lookup in about
11 microseconds, with no RAM cost. The file is a disposable cache: delete it any time and
run `arer feeds update` to rebuild it. (Valuable data such as your own labels belongs in a
separate database, never here.)
"""
from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlsplit

DB_NAME = "intel.db"
SCHEMA = "1"
MAX_URL_LEN = 4096
_DOMAIN_OK = re.compile(r"^[a-z0-9_]([a-z0-9_\-.]*[a-z0-9_])?$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HOST_OK = re.compile(r"^[a-z0-9_.:\-]+$")           # letters, digits, dot, dash, underscore, colon (IPv6)


# --------------------------------------------------------------------------- #
# normalisation and keys
# --------------------------------------------------------------------------- #
def _h(prefix: str, value: str) -> bytes:
    return hashlib.sha256((prefix + value).encode("utf-8", "replace")).digest()[:16]


def url_key(norm: str) -> bytes:
    return _h("u:", norm)


def domain_key(domain: str) -> bytes:
    return _h("d:", domain)


def hash_key(sha256_hex: str) -> bytes:
    return _h("f:", sha256_hex.lower())


def normalize_url(raw: str) -> str | None:
    """
    host[:port]/path?query  - scheme dropped (http and https match each other), host lower-cased,
    default ports, fragment and user-info removed, path and query kept exactly (they are case-sensitive).
    The same function is used for feed entries and for URLs found in e-mail, so they line up.
    """
    raw = (raw or "").strip()
    if not raw or len(raw) > MAX_URL_LEN:
        return None
    if "://" not in raw:
        raw = "http://" + raw
    try:
        p = urlsplit(raw)
        host = (p.hostname or "").lower().rstrip(".")
        port = p.port
    except ValueError:
        return None
    scheme = p.scheme.lower()
    if not host or scheme not in ("http", "https", "ftp") or not _HOST_OK.match(host):
        return None
    default = {"http": 80, "https": 443, "ftp": 21}[scheme]
    hostport = host if port in (None, default) else f"{host}:{port}"
    return hostport + (p.path or "/") + (f"?{p.query}" if p.query else "")


def normalize_domain(raw: str) -> str | None:
    d = (raw or "").strip().lower().rstrip(".")
    if d.startswith("*."):
        d = d[2:]
    if not d or len(d) > 253 or "." not in d or not _DOMAIN_OK.match(d):
        return None
    return d


def normalize_hash(raw: str) -> str | None:
    h = (raw or "").strip().lower()
    return h if _HEX64.match(h) else None


def host_of(norm_url: str) -> str:
    """Hostname (no port) of a normalised URL."""
    return norm_url.split("/", 1)[0].split(":", 1)[0]


# --------------------------------------------------------------------------- #
# reading
# --------------------------------------------------------------------------- #
@dataclass
class SourceInfo:
    name: str
    kind: str
    entries: int
    fetched_at: str
    bytes: int
    sha256: str


class IntelStore:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self._lock = threading.Lock()

    @classmethod
    def open(cls, data_dir: Path) -> "IntelStore | None":
        """Open read-only. None if there is no usable database yet."""
        path = Path(data_dir) / DB_NAME
        if not path.is_file():
            return None
        try:
            conn = sqlite3.connect(f"file:{quote(str(path))}?mode=ro", uri=True, check_same_thread=False)
            row = conn.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
            if not row or row[0] != SCHEMA:
                conn.close()
                return None
            return cls(conn)
        except sqlite3.DatabaseError:
            return None

    def sources(self) -> list[SourceInfo]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT name, kind, entries, fetched_at, bytes, sha256 FROM sources ORDER BY name").fetchall()
        return [SourceInfo(*r) for r in rows]

    def lookup(self, keys: list[bytes]) -> dict[bytes, set[str]]:
        """key -> names of the feeds that list it."""
        found: dict[bytes, set[str]] = {}
        uniq = list(dict.fromkeys(keys))
        with self._lock:
            for i in range(0, len(uniq), 400):
                chunk = uniq[i:i + 400]
                q = ("SELECT i.h, s.name FROM ioc i JOIN sources s ON s.id = i.src WHERE i.h IN (%s)"
                     % ",".join("?" * len(chunk)))
                for h, name in self.conn.execute(q, chunk):
                    found.setdefault(bytes(h), set()).add(name)
        return found


# --------------------------------------------------------------------------- #
# writing (used by the updater only)
# --------------------------------------------------------------------------- #
def open_rw(data_dir: Path) -> sqlite3.Connection:
    d = Path(data_dir)
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    path = d / DB_NAME
    new = not path.exists()
    conn = sqlite3.connect(str(path))
    if new:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS sources(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, kind TEXT NOT NULL,
                                           entries INTEGER, fetched_at TEXT, bytes INTEGER, sha256 TEXT);
        CREATE TABLE IF NOT EXISTS ioc(h BLOB NOT NULL, src INTEGER NOT NULL, PRIMARY KEY(h, src)) WITHOUT ROWID;
    """)
    conn.execute("INSERT OR IGNORE INTO meta VALUES('schema', ?)", (SCHEMA,))
    conn.commit()
    return conn
