"""
history/store.py - the private history database (data/history.db).

Stores, per scanned e-mail: its SHA-256, timestamps, sender domain, verdict, the FINDINGS the analyzers produced
(id, confidence, short summary), content-free indicators (hashed sender address, domains, attachment hashes) and
YOUR label. Never bodies, subjects, recipients or attachments.

Why findings and not weights: weights live in rules.yaml, so changing a weight can re-score every saved e-mail
instantly. A row remembers which analyzer logic and lists produced it (logic_hash), so rows made by older logic are
flagged as stale rather than silently trusted.

Only labels you set teach the tool. It never learns from its own verdicts, so a wrong guess cannot reinforce itself.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from ..config import Config
from ..models import Category, Email, Finding, Level, Verdict
from ..scoring import compute

SCHEMA = "1"
LABELS = ("phish", "legit")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def logic_hash(cfg: Config) -> str:
    """Fingerprint of everything that decides which findings an e-mail produces (code + word lists)."""
    pkg = Path(__file__).resolve().parents[1]
    files = sorted((pkg / "analyzers").glob("*.py")) + sorted((pkg / "util").glob("*.py"))
    if cfg.config_dir:
        files += sorted((Path(cfg.config_dir) / "lists").glob("*.txt"))
    h = hashlib.sha256()
    for f in files:
        h.update(f.name.encode())
        h.update(f.read_bytes())
    return h.hexdigest()[:16]


@dataclass
class Row:
    sha256: str
    name: str
    first_seen: str
    last_seen: str
    times: int
    from_domain: str
    level: str
    score: int
    partial: bool
    logic_hash: str
    label: str | None
    label_at: str | None
    note: str | None


_COLS = "sha256,name,first_seen,last_seen,times,from_domain,level,score,partial,logic_hash,label,label_at,note"


def _row(r) -> Row:
    return Row(*r[:8], bool(r[8]), *r[9:])


class HistoryStore:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    # ---- opening ------------------------------------------------------------ #
    @classmethod
    def open(cls, path: Path, create: bool = False, readonly: bool = False) -> "HistoryStore | None":
        path = Path(path)
        if create:
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(path.parent, 0o700)
            except OSError:
                pass
            new = not path.exists()
            conn = sqlite3.connect(str(path))
            if new:
                try:
                    os.chmod(path, 0o600)
                except OSError:
                    pass
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE IF NOT EXISTS scans(
                    sha256 TEXT PRIMARY KEY, name TEXT, first_seen TEXT, last_seen TEXT, times INTEGER NOT NULL DEFAULT 1,
                    from_domain TEXT, level TEXT, score INTEGER, partial INTEGER NOT NULL DEFAULT 0, logic_hash TEXT,
                    label TEXT CHECK(label IN ('phish','legit')), label_at TEXT, note TEXT);
                CREATE TABLE IF NOT EXISTS findings(
                    sha256 TEXT NOT NULL, n INTEGER NOT NULL, id TEXT NOT NULL, category TEXT NOT NULL,
                    confidence REAL NOT NULL, source TEXT, summary TEXT, PRIMARY KEY(sha256, n));
                CREATE TABLE IF NOT EXISTS indicators(
                    sha256 TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(sha256, kind, value));
                CREATE INDEX IF NOT EXISTS ind_lookup ON indicators(kind, value);
            """)
            conn.execute("INSERT OR IGNORE INTO meta VALUES('schema', ?)", (SCHEMA,))
            conn.commit()
            return cls(conn)
        if not path.is_file():
            return None
        try:
            uri = f"file:{quote(str(path))}?mode={'ro' if readonly else 'rw'}"
            conn = sqlite3.connect(uri, uri=True)
            row = conn.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
            if not row or row[0] != SCHEMA:
                conn.close()
                return None
            return cls(conn)
        except sqlite3.DatabaseError:
            return None

    def close(self):
        self.conn.close()

    # ---- writing ------------------------------------------------------------ #
    def save_scan(self, sha: str, name: str, email: Email, verdict: Verdict, indicators, logic: str) -> int:
        """Insert or refresh a scan (keeps its label). Returns how many times it has now been seen."""
        if not sha:
            raise ValueError("this e-mail has no SHA-256, so it cannot be saved")
        now = now_iso()
        with self.conn:
            old = self.conn.execute("SELECT times FROM scans WHERE sha256=?", (sha,)).fetchone()
            fd = email.from_domain or ""
            if old:
                times = old[0] + 1
                self.conn.execute("UPDATE scans SET name=?, last_seen=?, times=?, from_domain=?, level=?, score=?, partial=?, "
                                  "logic_hash=? WHERE sha256=?",
                                  (name[:200], now, times, fd, verdict.level.value, verdict.score, int(email.is_partial), logic, sha))
                self.conn.execute("DELETE FROM findings WHERE sha256=?", (sha,))
                self.conn.execute("DELETE FROM indicators WHERE sha256=?", (sha,))
            else:
                times = 1
                self.conn.execute("INSERT INTO scans(sha256,name,first_seen,last_seen,times,from_domain,level,score,partial,logic_hash) "
                                  "VALUES(?,?,?,?,?,?,?,?,?,?)",
                                  (sha, name[:200], now, now, 1, fd, verdict.level.value, verdict.score, int(email.is_partial), logic))
            self.conn.executemany(
                "INSERT INTO findings VALUES(?,?,?,?,?,?,?)",
                [(sha, i, f.id, f.category.value, f.confidence, f.source, (f.summary or "")[:200])
                 for i, f in enumerate(verdict.findings)])
            self.conn.executemany("INSERT OR IGNORE INTO indicators VALUES(?,?,?)", [(sha, k, v) for k, v in indicators])
        return times

    def resolve(self, prefix: str) -> str | None:
        """A full SHA-256, or a unique prefix of at least 6 characters."""
        prefix = prefix.strip().lower()
        if len(prefix) < 6:
            return None
        rows = self.conn.execute("SELECT sha256 FROM scans WHERE sha256 LIKE ? LIMIT 2", (prefix + "%",)).fetchall()
        return rows[0][0] if len(rows) == 1 else None

    def set_label(self, sha: str, label: str | None, note: str | None = None) -> bool:
        if label not in (*LABELS, None):
            raise ValueError("label must be phish or legit")
        with self.conn:
            cur = self.conn.execute("UPDATE scans SET label=?, label_at=?, note=COALESCE(?, note) WHERE sha256=?",
                                    (label, now_iso() if label else None, note, sha))
        return cur.rowcount == 1

    def forget(self, sha: str) -> bool:
        with self.conn:
            for table in ("findings", "indicators"):
                self.conn.execute(f"DELETE FROM {table} WHERE sha256=?", (sha,))
            cur = self.conn.execute("DELETE FROM scans WHERE sha256=?", (sha,))
        return cur.rowcount == 1

    # ---- reading ------------------------------------------------------------ #
    def get(self, sha: str) -> Row | None:
        r = self.conn.execute(f"SELECT {_COLS} FROM scans WHERE sha256=?", (sha,)).fetchone()
        return _row(r) if r else None

    def list(self, label: str | None = None, limit: int = 30) -> list[Row]:
        q, args = f"SELECT {_COLS} FROM scans", []
        if label == "unlabeled":
            q += " WHERE label IS NULL"
        elif label:
            q += " WHERE label=?"; args.append(label)
        q += " ORDER BY last_seen DESC LIMIT ?"
        return [_row(r) for r in self.conn.execute(q, (*args, limit)).fetchall()]

    def total_scans(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]

    def stats(self, current_logic: str) -> dict:
        c = self.conn
        q = lambda s, *a: c.execute(s, a).fetchone()[0]
        return {"total": q("SELECT COUNT(*) FROM scans"), "phish": q("SELECT COUNT(*) FROM scans WHERE label='phish'"),
                "legit": q("SELECT COUNT(*) FROM scans WHERE label='legit'"),
                "unlabeled": q("SELECT COUNT(*) FROM scans WHERE label IS NULL"),
                "stale": q("SELECT COUNT(*) FROM scans WHERE logic_hash IS NOT ?", current_logic),
                "oldest": q("SELECT MIN(first_seen) FROM scans"), "newest": q("SELECT MAX(last_seen) FROM scans")}

    def seen(self, kind: str, value: str, exclude_sha: str = "") -> bool:
        return self.conn.execute("SELECT 1 FROM indicators WHERE kind=? AND value=? AND sha256!=? LIMIT 1",
                                 (kind, value, exclude_sha)).fetchone() is not None

    def seen_in_phish(self, kind: str, value: str, exclude_sha: str = "") -> bool:
        """True if an e-mail YOU labelled phishing had this indicator."""
        return self.conn.execute(
            "SELECT 1 FROM indicators i JOIN scans s ON s.sha256=i.sha256 "
            "WHERE i.kind=? AND i.value=? AND s.label='phish' AND i.sha256!=? LIMIT 1",
            (kind, value, exclude_sha)).fetchone() is not None

    def findings_of(self, sha: str) -> list[Finding]:
        rows = self.conn.execute("SELECT id, category, confidence, source, summary FROM findings WHERE sha256=? ORDER BY n",
                                 (sha,)).fetchall()
        return [Finding(id=i, category=Category(c), confidence=conf, source=s or "rule", summary=sm or "") for i, c, conf, s, sm in rows]

    def labeled(self) -> list[Row]:
        return [_row(r) for r in self.conn.execute(f"SELECT {_COLS} FROM scans WHERE label IS NOT NULL ORDER BY sha256").fetchall()]


def rescore(store: HistoryStore, row: Row, cfg: Config, drop_prefixes: tuple[str, ...] = ()) -> Verdict:
    """Re-run ONLY the scoring on a saved scan's findings, with today's rules.yaml. No e-mail needed."""
    findings = []
    for f in store.findings_of(row.sha256):
        if any(f.id.startswith(p) for p in drop_prefixes):
            continue
        f.weight = cfg.weight_for(f.id)
        findings.append(f)
    v = compute(findings, cfg)
    if v.level == Level.CLEAN and row.partial:
        v.level = Level.INSUFFICIENT_DATA
    v.sha256 = row.sha256
    return v
