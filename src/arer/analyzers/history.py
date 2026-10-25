"""
history.py - what your own saved and labeled scans say about this e-mail.

  known_bad_hash         an attachment you labelled phishing before          -> forces MALICIOUS
  known_bad_sender       this sender (or its domain) was in phishing you labelled
  known_bad_link_domain  a link goes to a domain seen in phishing you labelled
  new_sender             first e-mail ever from this address (weak, and silent until enough history exists)

Only YOUR labels count. Protected domains (your legit list, free mail, mail platforms, shorteners) are never
condemned at domain level: labelling one scam from gmail.com must not taint all of Gmail, only that exact address.
No history file yet = this analyzer does nothing.
"""
from __future__ import annotations

from ..history.indicators import extract_indicators, protected_sets
from ..history.store import HistoryStore
from ..models import Email
from ..util.domains import registrable
from .base import Analyzer, register


@register
class History(Analyzer):
    name = "history"

    def run(self, email: Email, cfg):
        store = HistoryStore.open(cfg.history.db_path, readonly=True)
        if store is None:
            return []
        try:
            return self._check(email, cfg, store)
        finally:
            store.close()

    def _check(self, email, cfg, store):
        sha = email.file.sha256 or ""
        hard, _ = protected_sets(cfg)
        free = cfg.lists.get("free_mail", frozenset())
        ind = extract_indicators(email, cfg)
        of = lambda kind: [v for k, v in ind if k == kind]
        out = []

        bad_hash = [h for h in of("attachment_sha256") if store.seen_in_phish("attachment_sha256", h, sha)]
        if bad_hash:
            out.append(self.finding("history.known_bad_hash", "An attachment matches one you labelled as phishing",
                                    hashes=bad_hash[:5]))

        addr = (of("sender_addr") or [""])[0]
        sdom = (of("sender_domain") or [""])[0]
        if addr and store.seen_in_phish("sender_addr", addr, sha):
            out.append(self.finding("history.known_bad_sender", "This exact sender address sent phishing you labelled before",
                                    domain=sdom))
        elif sdom and registrable(sdom) not in hard and store.seen_in_phish("sender_domain", sdom, sha):
            out.append(self.finding("history.known_bad_sender",
                                    f"Sender domain {sdom} appeared in phishing you labelled before", 0.8, domain=sdom))

        bad_links = [d for d in of("link_domain") if registrable(d) not in hard and store.seen_in_phish("link_domain", d, sha)]
        if bad_links:
            out.append(self.finding("history.known_bad_link_domain",
                                    f"A link goes to a domain from phishing you labelled before: {', '.join(bad_links[:3])}",
                                    domains=bad_links[:5], count=len(bad_links)))

        # first-time sender: only meaningful once there is enough history to know who is "normal"
        if addr and store.total_scans() >= cfg.history.min_scans and not store.seen("sender_addr", addr, sha):
            domain_known = bool(sdom) and store.seen("sender_domain", sdom, sha) and registrable(sdom) not in free
            out.append(self.finding(
                "history.new_sender",
                "First e-mail ever from this sender" + (" (but the domain is known)" if domain_known else ""),
                0.4 if domain_known else 1.0, domain=sdom))
        return out
