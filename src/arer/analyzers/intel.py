"""
intel.py - checks links, the sender domain and attachment hashes against the local blocklist index.

Local lookups only, no network. Matching rules, each learned from testing against the real feed:
  * URLs match scheme-insensitively on host/path/query, so the http and https versions of a listed page both hit.
  * A listed ROOT page ("https://host/") is evidence about the whole domain, not one phishing page, so it only
    counts at domain strength (no forced MALICIOUS). On a protected site it is ignored: the live feed lists
    https://www.amazon.com/ today, and one mistaken entry must not condemn every mail that links to Amazon.
  * Domain matching also covers listed PARENT domains (login.evil.com is caught if evil.com is listed) ...
  * ... but never for protected domains (your legit list, mail platforms, free mail, URL shorteners): the feed lists
    bit.ly itself. For shared-hosting domains (github.io, pages.dev) only an exact listed subdomain counts, because
    the feed lists thousands of those and never the host itself.
Notices (weight 0) tell you when the data is missing or stale, so an old list never gives silent false comfort.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone

from ..intel.store import (IntelStore, domain_key, hash_key, host_of, normalize_url, url_key)
from ..models import Email
from ..util.domains import registrable
from ..util.urlcollect import extract_urls
from .base import Analyzer, register

_cache: dict = {}
_cache_lock = threading.Lock()


def open_cached(data_dir):
    """One open connection per database file version (re-opened after `arer feeds update`)."""
    from pathlib import Path
    from ..intel.store import DB_NAME
    p = Path(data_dir) / DB_NAME
    try:
        stamp = (str(p), p.stat().st_mtime_ns)
    except OSError:
        return None
    with _cache_lock:
        if stamp not in _cache:
            _cache.clear()
            _cache[stamp] = IntelStore.open(data_dir)
        return _cache[stamp]


def domain_candidates(host: str, is_hard, is_shared) -> list[str]:
    """Names to look up for a host. is_hard / is_shared take the registrable domain."""
    reg = registrable(host)
    if is_hard(reg):
        return []                                      # protected: a domain-level listing is never trusted
    if is_shared(reg):
        return [host] if host != reg else []           # only an exact listed subdomain counts
    if "." not in host:
        return [host]
    labels, n_reg = host.split("."), len(reg.split("."))
    return [".".join(labels[i:]) for i in range(0, max(1, len(labels) - n_reg + 1))]


@register
class Intel(Analyzer):
    name = "intel"

    def run(self, email: Email, cfg):
        fs = cfg.feeds
        wanted = [n for n, s in fs.sources.items() if s.enabled]
        if not wanted:
            return []
        store = open_cached(fs.data_dir)
        have = {s.name: s for s in store.sources()} if store else {}
        if not have:
            return [self.finding("intel.feeds_missing",
                                 "No blocklist data downloaded yet, so link, domain and hash blocklist checks are OFF. "
                                 "Run: arer feeds update", feeds=wanted)]
        out = []
        now = datetime.now(timezone.utc)
        ages = {}
        for n in wanted:
            s = have.get(n)
            if s is None:
                ages[n] = None
            else:
                try:
                    ages[n] = (now - datetime.fromisoformat(s.fetched_at)).days
                except ValueError:
                    ages[n] = None
        old = {n: a for n, a in ages.items() if a is None or a > fs.max_age_days}
        # local hash lists with no file yet are not "stale"
        old = {n: a for n, a in old.items() if not (a is None and fs.sources[n].path)}
        if old:
            worst = ", ".join(f"{n} ({'never downloaded' if a is None else f'{a} days old'})" for n, a in sorted(old.items()))
            out.append(self.finding("intel.feeds_stale",
                                    f"Blocklist data is out of date: {worst}. Run: arer feeds update", feeds=sorted(old)))

        L = cfg.lists
        hard = (L.get("legit_domains", frozenset()) | L.get("mail_platforms", frozenset())
                | L.get("free_mail", frozenset()) | L.get("shorteners", frozenset()))
        shared = L.get("shared_domains", frozenset())

        # ---- collect every key we need, then ask the database once ------------- #
        url_items = []                                  # (original url, url key, [domain keys], is_root, protected)
        for u in extract_urls(email, limit=200):
            norm = normalize_url(u)
            if not norm:
                continue
            host = host_of(norm)
            is_ip = host.replace(".", "").isdigit() or ":" in host
            dkeys = [] if is_ip else [domain_key(d) for d in domain_candidates(host, hard.__contains__, shared.__contains__)]
            is_root = norm.endswith("/") and norm.count("/") == 1          # "host/" with no path or query
            url_items.append((u, url_key(norm), dkeys, is_root, (not is_ip) and registrable(host) in hard))
        sender_keys, sender_dom = [], ""
        a = email.from_addr
        if a and a.domain and registrable(a.domain) not in L.get("free_mail", frozenset()):
            sender_dom = a.domain
            sender_keys = [domain_key(d) for d in domain_candidates(a.domain, hard.__contains__, shared.__contains__)]
        att_keys = [(att, hash_key(att.sha256)) for att in email.attachments if att.sha256]

        keys = [k for _, k, ds, _, _ in url_items for k in [k, *ds]] + sender_keys + [k for _, k in att_keys]
        allowed = set(wanted)                           # a feed you downloaded but disabled does not count
        hits = {k: v & allowed for k, v in (store.lookup(keys) if keys else {}).items() if v & allowed}

        exact, dom = [], []                             # exact = a specific listed page; dom = a listed domain / root page
        for u, k, ds, is_root, prot in url_items:
            srcs = set().union(*(hits[d] for d in ds if d in hits)) if ds else set()
            if k in hits:
                if not is_root:
                    exact.append((u, hits[k]))
                    continue
                if not prot:                            # a listed root page of an unprotected site = bad domain
                    srcs |= hits[k]
            if srcs:
                dom.append((u, srcs))
        if exact:
            srcs = sorted(set().union(*(s for _, s in exact)))
            out.append(self.finding("url.on_blocklist", f"Link is on a phishing blocklist ({', '.join(srcs)})",
                                    urls=[u for u, _ in exact][:5], count=len(exact), sources=srcs))
        if dom:
            srcs = sorted(set().union(*(s for _, s in dom)))
            out.append(self.finding("url.domain_on_blocklist",
                                    f"Link goes to a domain on a phishing blocklist ({', '.join(srcs)})", 0.9,
                                    urls=[u for u, _ in dom][:5], count=len(dom), sources=srcs))
        s_hits = set().union(*(hits[k] for k in sender_keys if k in hits)) if sender_keys else set()
        if s_hits:
            out.append(self.finding("sender.on_blocklist",
                                    f"Sender domain {sender_dom} is on a phishing blocklist ({', '.join(sorted(s_hits))})",
                                    domain=sender_dom, sources=sorted(s_hits)))
        bad = [(att, hits[k]) for att, k in att_keys if k in hits]
        if bad:
            out.append(self.finding("attachment.known_malicious_hash",
                                    "Attachment hash is on your known-bad list",
                                    attachments=[{"filename": att.filename[:100], "sha256": att.sha256} for att, _ in bad][:5],
                                    sources=sorted(set().union(*(s for _, s in bad)))))
        return out
