"""
history/indicators.py - what a scan remembers about an email, in a form that carries no content.

kinds: sender_addr (hashed), sender_domain, link_domain, attachment_sha256.
Domains of shared-hosting sites are stored in full (evil.github.io), others as their registrable
domain, so labelling one phishing page never taints the whole of github.io or google.com.
"""
from __future__ import annotations

import hashlib

from ..config import Config
from ..models import Email
from ..util.domains import registrable
from ..util.urlcollect import extract_urls
from urllib.parse import urlsplit

MAX_LINK_DOMAINS = 100


def addr_hash(address: str) -> str:
    return hashlib.sha256(address.strip().lower().encode("utf-8", "replace")).hexdigest()[:32]


def protected_sets(cfg: Config):
    L = cfg.lists
    hard = (L.get("legit_domains", frozenset()) | L.get("mail_platforms", frozenset())
            | L.get("free_mail", frozenset()) | L.get("shorteners", frozenset()))
    return hard, L.get("shared_domains", frozenset())


def domain_value(host: str, shared) -> str:
    host = host.lower().strip(".")
    reg = registrable(host)
    return host if reg in shared else reg


def extract_indicators(email: Email, cfg: Config) -> list[tuple[str, str]]:
    _, shared = protected_sets(cfg)
    out: list[tuple[str, str]] = []
    a = email.from_addr
    if a and a.address:
        out.append(("sender_addr", addr_hash(a.address)))
    if a and a.domain:
        out.append(("sender_domain", domain_value(a.domain, shared)))
    seen = set()
    for u in extract_urls(email, limit=200):
        try:
            host = (urlsplit(u).hostname or "").lower()
        except ValueError:
            continue
        if not host or host.replace(".", "").isdigit() or ":" in host:
            continue
        v = domain_value(host, shared)
        if v not in seen and len(seen) < MAX_LINK_DOMAINS:
            seen.add(v)
            out.append(("link_domain", v))
    for att in email.attachments:
        if att.sha256:
            out.append(("attachment_sha256", att.sha256.lower()))
    return list(dict.fromkeys(out))
