"""
headers.py - technical oddities in the header block.

Bulk mail (List-Unsubscribe present) legitimately uses other domains for Message-ID and
Return-Path, so those mismatch findings get lower confidence for newsletters.
"""
from __future__ import annotations

from ..models import Email
from ..util.domains import has_public_suffix, registrable
from .base import Analyzer, register

MAX_HOPS = 8


@register
class Headers(Analyzer):
    name = "headers"

    def run(self, email: Email, cfg):
        out = []

        if email.hop_count == 0:
            out.append(self.finding("headers.missing_received", "No Received headers (route cannot be traced)"))
        elif email.hop_count > MAX_HOPS:
            out.append(self.finding("headers.high_hop_count",
                                    f"{email.hop_count} mail hops (more than {MAX_HOPS})", hops=email.hop_count))

        mailer = f"{email.envelope.x_mailer} {email.envelope.user_agent}".lower()
        bad = sorted(m for m in cfg.lists.get("bad_mailers", ()) if m in mailer)
        if bad:
            out.append(self.finding("headers.suspicious_mailer",
                                    f"Sent with a bulk-mailer tool: {', '.join(bad)}",
                                    x_mailer=email.envelope.x_mailer[:100], matched=bad))

        if not email.envelope.date:
            out.append(self.finding("headers.missing_date", "No (or unreadable) Date header"))

        if email.from_domain:
            from_reg = registrable(email.from_domain)
            platforms = cfg.lists.get("mail_platforms", frozenset())
            mid = email.message_id_domain
            if mid and registrable(mid) not in platforms:
                if not has_public_suffix(mid):
                    out.append(self.finding(
                        "headers.msgid_bare_host",
                        f"Message-ID uses a bare host name ({mid[:60]}), not a real domain",
                        0.8, message_id_domain=mid[:100], from_domain=email.from_domain))
                elif registrable(mid) != from_reg:
                    out.append(self.finding(
                        "headers.msgid_domain_mismatch",
                        f"Message-ID domain {mid} differs from From domain {email.from_domain}",
                        0.3 if email.is_bulk else 0.5, message_id_domain=mid, from_domain=email.from_domain))

            rp = email.return_path_domain
            if rp and registrable(rp) != from_reg and registrable(rp) not in platforms:
                out.append(self.finding(
                    "headers.returnpath_mismatch",
                    f"Return-Path domain {rp[:60]} differs from From domain {email.from_domain}",
                    0.2 if email.is_bulk else 0.4, return_path_domain=rp[:100], from_domain=email.from_domain))

        if email.defects.has_defects:
            cats = [str(c) for c in email.defects.categories][:5]
            out.append(self.finding("headers.parser_defects", "Message structure is malformed",
                                    0.5, categories=cats))
        return out
