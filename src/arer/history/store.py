"""
history/store.py - the private history database (data/history.db).

Stores, per scanned e-mail: its SHA-256, timestamps, sender domain, verdict, the FINDINGS the analyzers produced
(id, confidence, short summary), content-free indicators (hashed sender address, domains, attachment hashes) and
YOUR label. Never bodies, subjects, recipients or attachments.

Why findings and not weights: weights live in rules.yaml, so changing a weight can re-score every saved e-mail
instantly. A row remembers which analyzer logic and lists produced it (logic_hash), so rows made by older logic are
flagged as stale rather than silently trusted.

Only labels you set teach the tool. It never learns from its own verdicts, so a wrong guess cannot reinforce itself.

Schema 2 (R2 remediation) adds the provenance model without touching any v1
column or row:

- `cases`            one open case per SHA-256 (workflow state new/triaged/closed);
- `case_decisions`   APPEND-ONLY decision events with provenance (analyst /
                      import / tool / legacy_unverified), analyst identity,
                      source reference, note, timestamp and an explicit
                      training-eligibility flag + reason;
- `schema_migrations` which migration ran, when.

A schema-1 database keeps working read/write exactly as before; the decision
API refuses it with MigrationRequired until `arer history migrate` has run
(backup first, transactional, idempotent - see migrate()).
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

SCHEMA = "2"                       # version NEW databases are created with
KNOWN_SCHEMAS = ("1", "2")         # v1 databases stay fully readable/writable
LABELS = ("phish", "legit")

# R2 vocabulary (the roadmap's case model; sidecar statuses map onto it)
CASE_STATES = ("new", "triaged", "closed")
PROVENANCES = ("analyst", "import", "tool", "legacy_unverified")
# queue sidecar status -> case disposition value
STATUS_TO_DISPOSITION = {"phishing": "true_positive", "benign": "false_positive",
                         "acknowledged": "acknowledged"}


class MigrationRequired(RuntimeError):
    """The decision/provenance API needs schema 2; run `arer history migrate`."""


class UnsupportedSchema(RuntimeError):
    """The database's meta schema is not one this arer knows (KNOWN_SCHEMAS).
    It is NEVER opened, read or write: reading it would misread every row
    (a newer arer may have changed the layout) and create=True used to
    proceed with v1 SQL on top of foreign tables. The message names the
    found version and the versions this arer supports."""


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

_V2_DDL = """
CREATE TABLE IF NOT EXISTS schema_migrations(version TEXT PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cases(
    sha256 TEXT PRIMARY KEY, state TEXT NOT NULL DEFAULT 'new',
    first_seen TEXT, last_seen TEXT, campaign_id TEXT);
CREATE TABLE IF NOT EXISTS case_decisions(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_sha256 TEXT NOT NULL,
    kind TEXT NOT NULL,               -- disposition | label | campaign
    value TEXT NOT NULL,              -- true_positive / false_positive / acknowledged / phish / legit / campaign id
    provenance TEXT NOT NULL,         -- analyst | import | tool | legacy_unverified
    analyst TEXT,                     -- who, for analyst-originated decisions
    source_ref TEXT,                  -- record file / dataset id / command
    note TEXT,
    created_at TEXT NOT NULL,
    training_eligible INTEGER NOT NULL DEFAULT 0,
    eligibility_reason TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS idx_decisions_case ON case_decisions(case_sha256, id);
"""


def _unsupported_schema_error(path, version: str) -> UnsupportedSchema:
    known = ", ".join(f"'{v}'" for v in KNOWN_SCHEMAS)
    return UnsupportedSchema(
        f"history database {path} has schema '{version}', but this arer supports "
        f"schemas {known} - refusing to open it "
        "(made by a newer or foreign arer? convert it or restore a backup first)")


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
            existing = conn.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
            if existing is not None and existing[0] not in KNOWN_SCHEMAS:
                conn.close()
                raise _unsupported_schema_error(path, existing[0])
            if existing is None:
                # brand-new database: straight to schema 2 (v1 tables + provenance tables)
                conn.executescript(_V2_DDL)
                conn.execute("INSERT OR IGNORE INTO meta VALUES('schema', ?)", (SCHEMA,))
                conn.execute("INSERT OR IGNORE INTO schema_migrations VALUES('1', ?)", (now_iso(),))
                conn.execute("INSERT OR IGNORE INTO schema_migrations VALUES('2', ?)", (now_iso(),))
            elif existing[0] == "1":
                # a schema-1 database: keep it EXACTLY as it is (explicit migration only)
                pass
            elif existing[0] == SCHEMA:
                conn.executescript(_V2_DDL)      # make sure the v2 tables exist
            conn.commit()
            store = cls(conn)
            store.schema_version = existing[0] if existing else SCHEMA
            return store
        if not path.is_file():
            return None
        try:
            uri = f"file:{quote(str(path))}?mode={'ro' if readonly else 'rw'}"
            conn = sqlite3.connect(uri, uri=True)
            row = conn.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
            if row and row[0] not in KNOWN_SCHEMAS:
                conn.close()
                raise _unsupported_schema_error(path, row[0])
            if not row:
                conn.close()
                return None
            store = cls(conn)
            store.schema_version = row[0]
            return store
        except sqlite3.DatabaseError:
            return None

    def close(self):
        self.conn.close()

    # ---- writing ------------------------------------------------------------ #
    def save_scan(self, sha: str, name: str, email: Email, verdict: Verdict, indicators, logic: str) -> int:
        """Insert or refresh a scan (keeps its label). Returns how many times it has now been seen.

        R1.6: refuses UNVERIFIED identities. A parser-JSON input's claimed
        sha256 cannot be proven here; saving it would let a tampered hash
        merge cases and inherit YOUR labels. Rescan the original .eml to
        store it in history."""
        if not sha:
            raise ValueError("this e-mail has no SHA-256, so it cannot be saved")
        if not getattr(email, "file", None).sha256_verified:
            raise ValueError("this scan has no verified SHA-256 (parser-JSON input): the claimed source hash "
                             "cannot be proven, so it will not be saved to history or labeled. "
                             "Rescan the original .eml/.msg file instead")
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


    # ---- R2: provenance / decision model (schema 2 only) ---------------------- #
    def _need_v2(self) -> None:
        if getattr(self, "schema_version", KNOWN_SCHEMAS[0]) != "2":
            raise MigrationRequired(
                "this history database is still schema 1 - decisions and provenance "
                "need schema 2. Back it up and migrate first:  arer history migrate")

    def record_decision(self, case_sha256: str, *, kind: str, value: str, provenance: str,
                        analyst: str = "", source_ref: str = "", note: str = "",
                        created_at: str | None = None, training_eligible: bool = False,
                        eligibility_reason: str = "") -> int:
        """Append ONE decision event. Append-only: nothing is ever updated or
        deleted; the current decision of a case is its highest id."""
        if kind not in ("disposition", "label", "campaign"):
            raise ValueError(f"unknown decision kind '{kind}'")
        if provenance not in PROVENANCES:
            raise ValueError(f"unknown provenance '{provenance}' (use one of: {', '.join(PROVENANCES)})")
        self._need_v2()
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO case_decisions(case_sha256,kind,value,provenance,analyst,source_ref,note,"
                "created_at,training_eligible,eligibility_reason) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (case_sha256, kind, value, provenance, analyst, source_ref, note,
                 created_at or now_iso(), int(training_eligible), eligibility_reason))
            self.conn.execute(
                "INSERT INTO cases(sha256,state,first_seen,last_seen) VALUES(?,?,?,?) "
                "ON CONFLICT(sha256) DO NOTHING", (case_sha256, "new", created_at or now_iso(), created_at or now_iso()))
        return int(cur.lastrowid)

    def current_decision(self, case_sha256: str, kind: str | None = None) -> dict | None:
        """The latest accepted decision event of a case (optionally of one kind)."""
        self._need_v2()
        q = ("SELECT id,case_sha256,kind,value,provenance,analyst,source_ref,note,created_at,"
             "training_eligible,eligibility_reason FROM case_decisions WHERE case_sha256=?")
        args: list = [case_sha256]
        if kind:
            q += " AND kind=?"
            args.append(kind)
        row = self.conn.execute(q + " ORDER BY id DESC LIMIT 1", args).fetchone()
        if not row:
            return None
        keys = ("id", "case_sha256", "kind", "value", "provenance", "analyst", "source_ref",
                "note", "created_at", "training_eligible", "eligibility_reason")
        return dict(zip(keys, row))

    def decisions_of(self, case_sha256: str) -> list[dict]:
        """Every decision event of a case, oldest first (the audit trail)."""
        self._need_v2()
        rows = self.conn.execute(
            "SELECT id,case_sha256,kind,value,provenance,analyst,source_ref,note,created_at,"
            "training_eligible,eligibility_reason FROM case_decisions WHERE case_sha256=? ORDER BY id",
            (case_sha256,)).fetchall()
        keys = ("id", "case_sha256", "kind", "value", "provenance", "analyst", "source_ref",
                "note", "created_at", "training_eligible", "eligibility_reason")
        return [dict(zip(keys, r)) for r in rows]

    def training_decisions(self) -> list[dict]:
        """Decision events eligible to teach a model, with the reason recorded.

        The hard invariant (R2.2 / docs/ROADMAP.md): only ANALYST decisions
        (and verified imports) can be eligible. tool decisions, unreviewed
        verdicts, workflow acknowledgements and legacy_unverified rows are
        excluded - the flag is computed at write time and re-checked here, so
        a legacy row can never sneak in."""
        self._need_v2()
        rows = self.conn.execute(
            "SELECT id,case_sha256,kind,value,provenance,analyst,source_ref,note,created_at,"
            "training_eligible,eligibility_reason FROM case_decisions "
            "WHERE training_eligible=1 AND provenance IN ('analyst','import') ORDER BY id").fetchall()
        keys = ("id", "case_sha256", "kind", "value", "provenance", "analyst", "source_ref",
                "note", "created_at", "training_eligible", "eligibility_reason")
        return [dict(zip(keys, r)) for r in rows]

    def import_sidecar_decision(self, case_sha256: str, *, alert_id: str, status: str,
                                note: str, set_utc: str, source_ref: str) -> str:
        """Import one validated disposition sidecar as `legacy_unverified` (R2.4).

        Returns 'imported' or 'duplicate'. The original literal status and
        timestamp are preserved; the sidecar's mapped disposition is NEVER
        treated as an analyst-confirmed label."""
        self._need_v2()
        value = STATUS_TO_DISPOSITION[status]
        dup = self.conn.execute(
            "SELECT 1 FROM case_decisions WHERE case_sha256=? AND source_ref=? AND created_at=? "
            "AND value=? AND provenance='legacy_unverified' LIMIT 1",
            (case_sha256, source_ref, set_utc, value)).fetchone()
        if dup:
            return "duplicate"
        reason = {"true_positive": "legacy sidecar 'phishing' without recorded provenance - review before training",
                  "false_positive": "legacy sidecar 'benign' without recorded provenance - review before training",
                  "acknowledged": "workflow acknowledgement, never a training disposition"}.get(
                      value, "legacy sidecar without recorded provenance")
        self.record_decision(case_sha256, kind="disposition", value=value,
                             provenance="legacy_unverified", source_ref=source_ref,
                             note=note, created_at=set_utc, training_eligible=False,
                             eligibility_reason=reason)
        return "imported"


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


def _counts(conn: sqlite3.Connection) -> dict[str, int]:
    q = lambda s: conn.execute(s).fetchone()[0]           # noqa: E731
    return {"scans": q("SELECT COUNT(*) FROM scans"), "findings": q("SELECT COUNT(*) FROM findings"),
            "indicators": q("SELECT COUNT(*) FROM indicators"),
            "labels": q("SELECT COUNT(*) FROM scans WHERE label IS NOT NULL")}


def read_schema_version(path: Path) -> str | None:
    """The meta schema value of a history database file, or None."""
    path = Path(path)
    if not path.is_file():
        return None
    try:
        conn = sqlite3.connect(f"file:{quote(str(path))}?mode=ro", uri=True)
        try:
            row = conn.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
            return row[0] if row else None
        finally:
            conn.close()
    except sqlite3.DatabaseError:
        return None


def migrate(path: Path, *, dry_run: bool = False, backup: bool = True) -> dict:
    """Migrate a history database from schema 1 to schema 2 (R2.3).

    Safety contract:
    - a verified backup (SQLite backup API) is made FIRST and its row counts
      are checked against the source; the original file is untouched until
      the migration transaction has fully succeeded;
    - the migration runs in ONE transaction: any error rolls everything back
      and the original database is unchanged;
    - every scan row, finding, indicator, label, label_at and note is
      preserved; existing phish/legit labels become decision events with
      provenance `legacy_unverified` (never silently analyst-confirmed);
    - running it on a schema-2 database is a no-op (idempotent);
    - dry_run reports what WOULD happen and writes nothing.

    Never migrate the user's real database without their own backup strategy;
    this function still makes its own verified backup copy first.
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"no history database at {path}")
    version = read_schema_version(path)
    if version == "2":
        return {"changed": False, "message": "already schema 2 - nothing to do"}
    if version != "1":
        raise MigrationRequired(f"unsupported schema version '{version}' at {path}")

    src = sqlite3.connect(f"file:{quote(str(path))}?mode=ro", uri=True)
    before = _counts(src)
    if dry_run:
        src.close()
        return {"changed": False, "dry_run": True, "before": before,
                "message": (f"would back up {path} and migrate schema 1 -> 2: "
                            f"{before['scans']} scans ({before['labels']} labeled), "
                            f"{before['findings']} findings, {before['indicators']} indicators; "
                            f"{before['labels']} labeled rows would become legacy_unverified decision events")}

    backup_path = None
    if backup:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_path = path.with_name(f"{path.name}.pre-migration-{stamp}.db")
        dst = sqlite3.connect(str(backup_path))
        src.backup(dst)                                   # SQLite backup API: safe with WAL
        dst.commit()
        after_backup = _counts(dst)
        dst.close()
        if after_backup != before:
            src.close()
            backup_path.unlink(missing_ok=True)
            raise RuntimeError("backup verification failed - migration aborted, original untouched")

    conn = sqlite3.connect(str(path), isolation_level=None)  # explicit transaction control
    try:
        conn.execute("BEGIN IMMEDIATE")
        for stmt in _V2_DDL.split(";"):                    # executescript would COMMIT mid-migration
            if stmt.strip():
                conn.execute(stmt)
        now = now_iso()
        rows = conn.execute(f"SELECT sha256, first_seen, last_seen FROM scans").fetchall()
        conn.executemany("INSERT INTO cases(sha256,state,first_seen,last_seen) VALUES(?,?,?,?) "
                         "ON CONFLICT(sha256) DO NOTHING",
                         [(sha, "new", fs, ls) for sha, fs, ls in rows])
        labeled = conn.execute("SELECT sha256, label, label_at, note FROM scans WHERE label IS NOT NULL").fetchall()
        for sha, label, label_at, note in labeled:
            conn.execute(
                "INSERT INTO case_decisions(case_sha256,kind,value,provenance,analyst,source_ref,note,"
                "created_at,training_eligible,eligibility_reason) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (sha, "label", label, "legacy_unverified", "", "schema-1 scans.label", note or "",
                 label_at or now, 0, "legacy label migrated from schema 1 with no recorded provenance - "
                 "review before it may teach a model"))
        conn.execute("UPDATE meta SET value='2' WHERE key='schema'")
        conn.execute("INSERT OR REPLACE INTO schema_migrations VALUES('2', ?)", (now,))
        after = _counts(conn)
        if after != before:
            raise RuntimeError(f"post-migration check failed: {before} -> {after}")
        conn.execute("COMMIT")
    except BaseException:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        conn.close()
        src.close()
        raise                                             # original database untouched
    conn.close()
    src.close()
    return {"changed": True, "before": before, "after": after,
            "migrated_labels": len(labeled), "backup": str(backup_path) if backup_path else None,
            "message": f"migrated schema 1 -> 2 ({before['scans']} scans, {len(labeled)} labels preserved as legacy_unverified)"}


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
