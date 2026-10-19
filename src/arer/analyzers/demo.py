"""
demo.py - three tiny real checks so the pipeline works end to end today.
DELETE the matching checks once you write auth.py / sender.py / headers.py,
otherwise the same signal would be counted twice.
"""
from ..models import Email
from .base import Analyzer, register


@register
class Demo(Analyzer):
    name = "demo"

    def run(self, email: Email, cfg):
        out = []
        if "dkim=none" in email.auth_results.lower():
            out.append(self.finding("auth.dkim_none", "Message is not DKIM-signed",
                                    auth_results=email.auth_results[:200]))
        rt, fr = email.reply_to_domain, email.from_domain
        if rt and fr and rt != fr:
            out.append(self.finding("sender.reply_to_mismatch",
                                    f"Reply-To domain {rt} differs from From domain {fr}",
                                    reply_to=rt, from_domain=fr))
        if not email.envelope.date:
            out.append(self.finding("headers.missing_date", "No Date header"))
        return out
