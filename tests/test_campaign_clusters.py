"""R5: explainable campaign clustering over strong keys.

Frozen contract (remediation plan R5):
- same bytes -> same case/campaign (the exact sha256 key stays);
- different Message-ID/headers but the same strong URL host+path -> the mails
  join a cluster;
- different path on the SAME domain -> never grouped (host/domain alone is
  not a key);
- different sender, same strong artifact -> still grouped;
- same sender/domain but unrelated content and no strong shared key -> never
  grouped;
- a common inline logo / tracking pixel -> does NOT create a campaign (only
  non-inline attachment hashes are keys);
- campaign_id is durable (a member joining later keeps the id) and the
  evidence records WHICH key linked WHICH mail;
- the analyst confirm/reject action is recorded append-only in history.db
  with provenance and survives a reopen;
- `alerts clusters --csv` writes a manifest-compatible sha256,group_id
  mapping so campaign ids drive evaluation group splitting.
"""
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from arer.alert import Alert, ScanSubject, write_alert
from arer.campaign import build_clusters, cluster_id, url_key
from arer.cli import main
from arer.models import Level, Verdict


def mk_record(queue: Path, sha: str, gen: str, *, urls=(), url_domains=(), sender="",
              atts=(), body_fp="", aid=None):
    alert = Alert(alert_id=aid or sha[:8] + "0" * 24, generated_utc=gen, source_file=f"{sha[:6]}.eml",
                  logic_hash="h" * 16, scan=ScanSubject(from_="", from_domain=sender),
                  verdict=Verdict(sha256=sha, level=Level.MALICIOUS, score=80))
    alert.indicators = {"urls": list(urls), "url_domains": list(url_domains),
                        "sender_domain": sender, "attachments": list(atts)}
    alert.body_fingerprint = body_fp
    write_alert(alert, queue)
    return alert


# --------------------------- url key normalization ---------------------------- #


@pytest.mark.parametrize("a,b,same", [
    ("http://evil.example/a/b", "https://evil.example/a/b", True),      # scheme dropped
    ("http://evil.example/a/b?x=1", "http://evil.example/a/b", True),   # query dropped
    ("http://evil.example:443/a", "https://evil.example/a", True),      # default port dropped
    ("http://evil.example/a/b/", "http://evil.example/a/b", True),      # trailing slash
    ("http://evil.example/a%2Fb", "http://evil.example/a/b", True),     # percent-decoding once
    ("http://evil.example/a", "http://evil.example/b", False),          # different path
    ("http://other.example/a", "http://evil.example/a", False),         # different host
])
def test_url_key_normalization(a, b, same):
    ka, kb = url_key(a), url_key(b)
    assert bool(ka) and bool(kb)
    assert (ka == kb) == same


# --------------------------- the clustering scenarios ------------------------- #


def test_same_bytes_stay_one_case(tmp_path):
    q = tmp_path / "q"
    mk_record(q, "a" * 64, "2026-01-01T00:00:00Z")
    mk_record(q, "a" * 64, "2026-01-02T00:00:00Z", aid="a" * 8 + "1" * 24)
    clusters = build_clusters(_reads(q))
    assert len(clusters) == 1
    assert clusters[0].mail_sha256s == ["a" * 64]
    assert len(clusters[0].alerts) == 2                 # both sightings attached


def test_same_strong_url_different_headers_join(tmp_path):
    q = tmp_path / "q"
    mk_record(q, "a" * 64, "2026-01-01T00:00:00Z", urls=["http://phish.example/login"],
              sender="one.example", body_fp="AAA")
    mk_record(q, "b" * 64, "2026-01-02T00:00:00Z", urls=["http://phish.example/login"],
              sender="two.example", body_fp="BBB")
    clusters = build_clusters(_reads(q))
    assert len(clusters) == 1                           # merged by url host+path
    assert clusters[0].mail_sha256s == ["a" * 64, "b" * 64]
    evidence = {e["key"] for e in clusters[0].evidence}
    assert "url:phish.example/login" in evidence


def test_same_domain_different_path_never_groups(tmp_path):
    q = tmp_path / "q"
    mk_record(q, "a" * 64, "2026-01-01T00:00:00Z", urls=["http://cdn.example/x/one"],
              url_domains=["cdn.example"], sender="news.example")
    mk_record(q, "b" * 64, "2026-01-02T00:00:00Z", urls=["http://cdn.example/x/two"],
              url_domains=["cdn.example"], sender="news.example")
    clusters = build_clusters(_reads(q))
    assert len(clusters) == 2                           # domain alone is never a key
    assert {tuple(c.mail_sha256s) for c in clusters} == {("a" * 64,), ("b" * 64,)}


def test_shared_attachment_hash_groups_but_inline_does_not(tmp_path):
    q = tmp_path / "q"
    # non-inline shared artifact -> groups
    mk_record(q, "a" * 64, "2026-01-01T00:00:00Z",
              atts=[{"sha256": "c" * 64, "inline": False, "filename": "invoice.pdf", "size_bytes": 9}],
              sender="one.example")
    mk_record(q, "b" * 64, "2026-01-02T00:00:00Z",
              atts=[{"sha256": "c" * 64, "inline": False, "filename": "invoice.pdf", "size_bytes": 9}],
              sender="two.example")
    clusters = build_clusters(_reads(q))
    assert len(clusters) == 1 and len(clusters[0].mail_sha256s) == 2
    # inline shared logo/pixel -> never groups
    q2 = tmp_path / "q2"
    mk_record(q2, "d" * 64, "2026-01-01T00:00:00Z",
              atts=[{"sha256": "c" * 64, "inline": True, "filename": "logo.png", "size_bytes": 9}],
              sender="one.example")
    mk_record(q2, "e" * 64, "2026-01-02T00:00:00Z",
              atts=[{"sha256": "c" * 64, "inline": True, "filename": "logo.png", "size_bytes": 9}],
              sender="two.example")
    assert len(build_clusters(_reads(q2))) == 2


def test_same_sender_unrelated_content_never_groups(tmp_path):
    q = tmp_path / "q"
    mk_record(q, "a" * 64, "2026-01-01T00:00:00Z", sender="same.example",
              urls=["http://x1.example/a"], body_fp="AAA")
    mk_record(q, "b" * 64, "2026-01-02T00:00:00Z", sender="same.example",
              urls=["http://x2.example/b"], body_fp="BBB")
    assert len(build_clusters(_reads(q))) == 2


def test_body_fingerprint_is_a_strong_key(tmp_path):
    q = tmp_path / "q"
    mk_record(q, "a" * 64, "2026-01-01T00:00:00Z", body_fp="FP1", sender="one.example")
    mk_record(q, "b" * 64, "2026-01-02T00:00:00Z", body_fp="FP1", sender="two.example")
    clusters = build_clusters(_reads(q))
    assert len(clusters) == 1 and "body:FP1" in clusters[0].keys


def test_campaign_id_is_durable_when_a_member_joins_later(tmp_path):
    q = tmp_path / "q"
    mk_record(q, "a" * 64, "2026-01-01T00:00:00Z", urls=["http://phish.example/login"])
    first = build_clusters(_reads(q))[0]
    mk_record(q, "b" * 64, "2026-01-02T00:00:00Z", urls=["http://phish.example/login"])
    merged = build_clusters(_reads(q))[0]
    assert merged.mail_sha256s == ["a" * 64, "b" * 64]
    assert merged.campaign_id == first.campaign_id      # durable: not renumbered


def test_cluster_id_derives_from_the_canonical_key():
    keys = ["url:z.example/x", "url:a.example/y"]
    cid = cluster_id(keys)
    assert cid.startswith("cmp_") and len(cid) == 19
    assert cid == cluster_id(list(reversed(keys)))      # order-independent


# --------------------------- CLI + confirmation + manifest --------------------- #


def _reads(q: Path):
    from arer.alert import read_alerts
    return read_alerts(q)


def test_clusters_cli_shows_evidence_and_writes_manifest(tmp_path):
    q = tmp_path / "q"
    mk_record(q, "a" * 64, "2026-01-01T00:00:00Z", urls=["http://phish.example/login"])
    mk_record(q, "b" * 64, "2026-01-02T00:00:00Z", urls=["http://phish.example/login"])
    out = tmp_path / "manifest-mapping.csv"
    r = CliRunner().invoke(main, ["alerts", "clusters", str(q), "--csv", str(out)])
    assert r.exit_code == 0, r.output
    assert "url" in r.output                            # the key kind is shown
    rows = out.read_text(encoding="utf-8").splitlines()
    assert rows[0] == "sha256,group_id"
    assert len(rows) == 3                               # header + two mails, ONE group id
    assert rows[1].split(",")[1] == rows[2].split(",")[1]


def test_confirm_campaign_is_recorded_and_auditable(tmp_path):
    q = tmp_path / "q"
    mk_record(q, "a" * 64, "2026-01-01T00:00:00Z", urls=["http://phish.example/login"])
    mk_record(q, "b" * 64, "2026-01-02T00:00:00Z", urls=["http://phish.example/login"])
    cid = build_clusters(_reads(q))[0].campaign_id
    db = tmp_path / "history.db"
    cfg_dir = tmp_path / "cfg"
    import shutil
    shutil.copytree("config", cfg_dir)
    (cfg_dir / "history.yaml").write_text(f"db_path: {db}\n", encoding="utf-8")
    r = CliRunner().invoke(main, ["alerts", "confirm-campaign", str(q), cid[:12],
                                  "--note", "same run", "--config", str(cfg_dir)])
    assert r.exit_code == 0, r.output
    assert "confirmed" in r.output
    from arer.history.store import HistoryStore
    store = HistoryStore.open(db)
    try:
        events = store.decisions_of(cid)
        assert len(events) == 1
        assert events[0]["kind"] == "campaign" and events[0]["value"] == "confirmed"
        assert events[0]["provenance"] == "analyst" and events[0]["analyst"]
        assert events[0]["note"] == "same run"
        # append-only: a rejection adds a second event, nothing is overwritten
    finally:
        store.close()
    r = CliRunner().invoke(main, ["alerts", "confirm-campaign", str(q), cid[:12], "--reject",
                                  "--note", "actually separate", "--config", str(cfg_dir)])
    assert r.exit_code == 0 and "rejected" in r.output
    store = HistoryStore.open(db)
    try:
        events = store.decisions_of(cid)
        assert [e["value"] for e in events] == ["confirmed", "rejected"]   # the audit trail
    finally:
        store.close()


def test_confirm_campaign_requires_a_matching_cluster(tmp_path):
    q = tmp_path / "q"
    mk_record(q, "a" * 64, "2026-01-01T00:00:00Z")
    r = CliRunner().invoke(main, ["alerts", "confirm-campaign", str(q), "deadbeef"])
    assert r.exit_code == 1 and "no campaign matches" in r.output
