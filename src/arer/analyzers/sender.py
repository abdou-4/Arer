"""
sender.py - is the From identity believable?

Checks: invalid address, Reply-To pointing elsewhere, display name faking an address or
brand, free-mail address claiming a brand, lookalike / punycode domains.
Needs no network. Domain knowledge comes from util/domains.py and config/lists/.
"""
from __future__ import annotations

import re

from ..models import Email
from ..util.domains import (decode_host, is_punycode, lookalike, mixed_script,
                            normalize_confusables, registrable, split_host)
from .base import Analyzer, register

ADDR_RE = re.compile(r"^[A-Za-z0-9._%+'\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$")
ANY_EMAIL = re.compile(r"[\w.+'\-]+@[\w\-]+(?:\.[\w\-]+)+")
# words that make "brand in display name" much more suspicious
OFFICIAL = {"support", "security", "billing", "helpdesk", "admin", "administrator", "verification", "official",
            "payment", "payments", "accounts", "customercare", "helpline", "hotline", "compliance", "fraud",
            "refund", "refunds"}
SENSITIVE = {"support", "security", "service", "services", "team", "account", "accounts", "alert",
             "alerts", "billing", "verification", "verify", "admin", "helpdesk", "help", "notification",
             "noreply", "customer", "care", "official", "payment", "payments", "login", "update"}


@register
class Sender(Analyzer):
    name = "sender"

    def run(self, email: Email, cfg):
        out = []
        a = email.from_addr
        addr = (a.address if a else "").strip()
        if not addr:
            out.append(self.finding("sender.invalid_format", "From address is missing or unreadable", address=""))
        elif not ADDR_RE.match(addr):
            domain = addr.rsplit("@", 1)[-1] if "@" in addr else ""
            unusual = bool(domain) and bool(re.fullmatch(r"[\w.\-\[\]:]+", domain))   # root@localhost, host_name.org
            # Full strength on purpose. Phase 4b softened "unusual" addresses because 2002-era, anonymised
            # SpamAssassin ham is full of user@localhost. That cost 3 real phishing detections and bought
            # nothing on modern mail (0/10 legit), so modern mail wins.
            out.append(self.finding(
                "sender.invalid_format",
                "From address is unusual (no dotted domain)" if unusual else "From address is malformed",
                address=addr[:100]))
        if a is None or not a.domain:
            return out

        brands = cfg.lists.get("brands", frozenset())
        legit = cfg.lists.get("legit_domains", frozenset())
        free = cfg.lists.get("free_mail", frozenset())
        tlds = cfg.lists.get("suspicious_tlds", frozenset())
        from_reg = registrable(a.domain)
        from_label = split_host(decode_host(a.domain))[1]

        # --- Reply-To goes somewhere else ---------------------------------- #
        rt = email.reply_to_domain
        rt_addr = email.envelope.reply_to[0].address.lower() if email.envelope.reply_to else ""
        # On a free-mail provider the domain says nothing about WHO owns the mailbox, so compare the whole address
        same_inbox_host_diff_box = bool(rt_addr) and from_reg in free and rt_addr != a.address.lower()
        if rt and (registrable(rt) != from_reg or same_inbox_host_diff_box):
            what = (f"Replies go to a different mailbox ({rt_addr}) than the sender ({a.address})"
                    if same_inbox_host_diff_box and registrable(rt) == from_reg
                    else f"Reply-To domain {rt} differs from From domain {a.domain}")
            out.append(self.finding(
                "sender.reply_to_mismatch", what,
                0.4 if email.is_bulk else 1.0, reply_to=rt_addr or rt, from_domain=a.domain, bulk_mail=email.is_bulk))

        # --- display name faking an address or a brand --------------------- #
        name = a.name or ""
        for fake in ANY_EMAIL.findall(name):
            fake_dom = fake.rsplit("@", 1)[-1].lower()
            if registrable(fake_dom) != from_reg:
                out.append(self.finding(
                    "sender.display_name_spoof",
                    f"Display name shows {fake} but the message comes from {a.domain}",
                    display_name=name[:100], shown_address=fake, from_domain=a.domain))
                break
        else:
            tokens = re.findall(r"[a-z0-9]+", name.lower())
            words, padded = set(tokens), f" {' '.join(tokens)} "
            hit = sorted(b for b in brands if f" {b} " in padded)      # also matches two-word brands ("geek squad")
            is_free = from_reg in free or a.domain in free      # gmail.com is "legit" but never speaks for a brand
            if not hit and is_free and words & OFFICIAL:
                out.append(self.finding(
                    "sender.freemail_brand", f"Free-mail address ({a.domain}) uses an official-sounding name: {name[:60]}",
                    0.6, display_name=name[:100], from_domain=a.domain))
            if hit and (is_free or from_reg not in legit) and not any(
                    normalize_confusables(b) in normalize_confusables(from_label) for b in hit):
                strong = bool(words & SENSITIVE) or any(len(b) >= 6 for b in hit)
                conf = 1.0 if strong else 0.5
                if is_free:
                    out.append(self.finding(
                        "sender.freemail_brand",
                        f"Free-mail address ({a.domain}) claims to be {', '.join(hit)}",
                        conf, display_name=name[:100], brands=hit, from_domain=a.domain))
                else:
                    out.append(self.finding(
                        "sender.display_name_spoof",
                        f"Display name claims {', '.join(hit)} but the domain is {a.domain}",
                        conf, display_name=name[:100], brands=hit, from_domain=a.domain))

        # --- lookalike / punycode ------------------------------------------ #
        shared = cfg.lists.get("shared_domains", frozenset())
        if from_reg in shared:
            out.append(self.finding(
                "sender.shared_domain",
                f"Sender uses {from_reg}, a shared domain where anyone can register a name",
                from_domain=a.domain, shared_domain=from_reg))
        look = None if from_reg in shared else lookalike(a.domain, brands, legit, tlds)
        if look:
            out.append(self.finding(
                "sender.lookalike_domain",
                f"{a.domain} imitates '{look.brand}' ({look.kind.replace('_', ' ')})",
                look.confidence, domain=a.domain, brand=look.brand, kind=look.kind))
        if is_punycode(a.domain):
            decoded = decode_host(a.domain)
            out.append(self.finding(
                "sender.punycode_domain", f"Internationalised domain {a.domain} (shown as {decoded})",
                1.0 if mixed_script(decoded) else 0.7, domain=a.domain, decoded=decoded,
                mixed_scripts=mixed_script(decoded)))
        return out
