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
