"""
campaign.py - Phase 6.4: the exact-hash campaign view over the alert queue.

The same mail (byte-identical, same verdict.sha256) often alerts many times:
one phishing run arrives as five copies and lands as five records in the
queue. This module groups the queue by EXACT sha256 so the analyst sees one
row per distinct mail - how many times it alerted, when it was first/last
seen, and the combined disposition - instead of five identical rows.

v1 groups by exact hash only. Mails that merely look similar stay separate
campaigns; fuzzy clustering is deliberately out of scope (a later phase, and
it would be a separate, additive view - never a change to what alert.py reads
or what disposition.py disposes).

This is a READ-SIDE helper only: it invents no schema and writes nothing.
Grouping membership depends on the alert record alone, so `alerts set-group`
can overwrite a corrupt sidecar - sidecars only feed the combined status.
"""
from __future__ import annotations

import hashlib
import re

from pathlib import Path
from typing import NamedTuple

from .alert import Alert, AlertRead
from .models import Level

# Combined status for a group whose members have per-alert dispositions:
# one single value (including "new" = no sidecar) when everyone agrees,
# "mixed" when members disagree. The CLI also accepts "mixed" as a filter.
MIXED_STATUS = "mixed"


class Campaign(NamedTuple):
    """Every valid alert record of one distinct mail (same sha256).

    alerts and paths are index-aligned and sorted oldest first, so
    alerts[0] is the first sighting and alerts[-1] the latest."""
    mail_sha256: str
    alerts: list[Alert]
    paths: list[Path]


def build_campaigns(reads: list[AlertRead]) -> list[Campaign]:
    """Group the valid records by verdict.sha256.

    Broken records (alert=None) simply never join a group - callers that
    display the view name them on stderr and exit 1, like every batch read.

    Campaigns come back sorted by most recent activity (newest member first),
    then sha256, so the queue is stable and the freshest run is on top.
    """
    grouped: dict[str, list[tuple[Alert, Path]]] = {}
    for r in reads:
        if r.alert is None:
            continue
        grouped.setdefault(r.alert.verdict.sha256, []).append((r.alert, r.path))
    campaigns = []
    for sha, members in grouped.items():
        members.sort(key=lambda m: (m[0].generated_utc, m[0].alert_id))
        campaigns.append(Campaign(mail_sha256=sha,
                                  alerts=[m[0] for m in members],
                                  paths=[m[1] for m in members]))
    campaigns.sort(key=lambda c: (c.alerts[-1].generated_utc, c.mail_sha256), reverse=True)
    return campaigns


def campaign_status(statuses: list[str]) -> str:
    """One status when all members agree, MIXED_STATUS when they do not."""
    distinct = set(statuses)
    return distinct.pop() if len(distinct) == 1 else MIXED_STATUS


def campaign_level(alerts: list[Alert]) -> Level:
    """The most severe verdict in the group (Level.rank: MALICIOUS is highest)."""
    return max(alerts, key=lambda a: a.verdict.level.rank).verdict.level


# --------------------------------------------------------------------------- #
# R5: explainable campaign clustering over STRONG keys.
#
# Exact-hash grouping (above) catches byte-identical mails only. Mass-mailed
# variants (per-recipient greetings, rotated headers) share STRONG artifacts,
# and that is what this layer groups on - never a sender or domain alone:
#
#   sha:<sha256>        the whole mail (still an exact-duplicate key)
#   url:<host><path>    exact URL host + path (scheme, query, fragment and
#                       default ports normalized away; percent-encoding
#                       decoded once). Host or registrable domain ALONE is
#                       never a key.
#   att:<sha256>        attachment hash - but ONLY for attachments that are
#                       not inline (a shared logo or tracking pixel must not
#                       create a campaign)
#   body:<fingerprint>  the record's normalized-body fingerprint (v2)
#
# Union-find over the shared keys; every link is explainable (the cluster
# records WHICH key joined WHICH mail). A domain-only match, a shared mail
# provider or a generic footer can never merge two mails.
#
# campaign_id is DURABLE and deterministic: derived from the cluster's
# canonical (lexicographically smallest) strong key, so a new member joining
# through another key keeps the same id. Auto-clustering is a PROPOSAL: an
# analyst confirms it with `alerts confirm-campaign` (recorded in
# history.db with provenance, auditable) - nothing is auto-confirmed.
# --------------------------------------------------------------------------- #

from urllib.parse import unquote, urlsplit

CLUSTER_ID_PREFIX = "cmp"


def url_key(url: str) -> str:
    """The normalized exact host+path key of one URL ("" when unusable).

    Robust to defanged storage forms ([.], [@], hxxp): campaign keys are
    computed from whatever representation the record carries."""
    url = url.replace("[.]", ".").replace("[@]", "@")
    url = re.sub(r"\b(h)xx(ps?)://", r"\1tt\2://", url, flags=re.I)
    url = url.replace("fxp://", "ftp://")
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    host = (parts.hostname or "").lower()
    if not host:
        return ""
    try:
        port = parts.port
    except ValueError:
        port = None
    if port in (80, 443):
        port = None
    path = unquote(parts.path or "/").rstrip("/") or "/"
    netloc = f"{host}:{port}" if port else host
    return f"url:{netloc}{path}"


def strong_keys(alert: Alert) -> list[tuple[str, str]]:
    """(key, evidence-value) pairs for one alert record. v1 records carry no
    structured block and contribute only their exact hash."""
    keys: list[tuple[str, str]] = [(f"sha:{alert.verdict.sha256}", alert.verdict.sha256)]
    ind = getattr(alert, "indicators", None) or {}
    for u in (ind.get("urls") or [])[:200]:
        k = url_key(u)
        if k:
            keys.append((k, u))
    for att in (ind.get("attachments") or [])[:100]:
        h = att.get("sha256") if isinstance(att, dict) else None
        if h and not att.get("inline"):
            keys.append((f"att:{h}", att.get("filename") or h))
    fp = getattr(alert, "body_fingerprint", "")
    if fp:
        keys.append((f"body:{fp}", fp))
    # deduplicate, keep order
    seen = set()
    out = []
    for k, ev in keys:
        if k not in seen:
            seen.add(k)
            out.append((k, ev))
    return out


class Cluster(NamedTuple):
    """One proposed campaign: members (oldest first), the strong keys that
    hold it together, and the evidence for every member (which key matched,
    on which value). campaign_id is durable and deterministic."""
    campaign_id: str
    mail_sha256s: list[str]              # distinct mails in the cluster
    alerts: list[Alert]                  # oldest first, index-aligned with paths
    paths: list[Path]
    keys: list[str]                      # the union of strong keys, sorted
    evidence: list[dict]                 # {key, value, alert_id, source_file, sha256}


def cluster_id(keys: list[str]) -> str:
    """Durable id: derived from the cluster's canonical (smallest) key, so a
    member joining later through another key cannot renumber the cluster."""
    canonical = min(keys)
    return f"{CLUSTER_ID_PREFIX}_{hashlib.sha256(canonical.encode('utf-8')).hexdigest()[:15]}"


def build_clusters(reads: list[AlertRead]) -> list[Cluster]:
    """Group the valid records into campaign clusters via shared strong keys.

    Broken records (alert=None) never join. Clusters come back sorted by
    most recent activity, then id. This is a PROPOSAL view: membership is
    evidence-backed but needs analyst confirmation before anything trusts it.
    """
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    key_members: dict[str, list[str]] = {}
    members: dict[str, list[tuple[Alert, Path]]] = {}
    member_keys: dict[str, list[tuple[str, str]]] = {}
    for r in reads:
        if r.alert is None:
            continue
        node = r.alert.verdict.sha256 or f"id:{r.alert.alert_id}"
        if node not in parent:
            parent[node] = node
        members.setdefault(node, []).append((r.alert, r.path))
        ks = strong_keys(r.alert)
        member_keys[node] = ks
        for k, _ev in ks:
            key_members.setdefault(k, [])
            if node not in key_members[k]:
                key_members[k].append(node)
    # a shared strong key merges the mails; sha:<sha> merges only the
    # byte-identical copies of one mail (they share the node anyway)
    for k, nodes in key_members.items():
        if k.startswith("sha:"):
            continue                        # one node per sha already
        for n in nodes[1:]:
            union(nodes[0], n)

    groups: dict[str, list[str]] = {}
    for node in parent:
        groups.setdefault(find(node), []).append(node)

    clusters = []
    for nodes in groups.values():
        nodes.sort(key=lambda n: (members[n][0][0].generated_utc, members[n][0][0].alert_id))
        keys = sorted({k for n in nodes for k, _ in member_keys[n]})
        sightings = [(a, p) for n in nodes for a, p in members[n]]
        evidence = []
        for n in nodes:
            for a, _p in members[n]:
                for k, ev in member_keys[n]:
                    if k != f"sha:{a.verdict.sha256}":
                        # every strong key this member contributes beyond its
                        # own exact hash (the shared-url/artifact/body evidence)
                        evidence.append({"key": k, "value": ev[:200], "alert_id": a.alert_id,
                                         "source_file": a.source_file, "sha256": a.verdict.sha256})
        clusters.append(Cluster(campaign_id=cluster_id(keys), mail_sha256s=sorted(nodes),
                                alerts=sightings, paths=[p for _a, p in sightings],
                                keys=keys, evidence=evidence))
    clusters.sort(key=lambda c: (c.alerts[-1][0].generated_utc, c.campaign_id), reverse=True)
    return clusters
