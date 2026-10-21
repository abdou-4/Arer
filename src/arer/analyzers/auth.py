"""
auth.py - SPF / DKIM / DMARC, read from the Authentication-Results header.

We do NOT re-run SPF/DKIM: the original connecting IP is gone from a saved .eml and
DKIM keys rotate. Instead we read what the receiving mail server concluded.

TRUST: an attacker can write a fake "Authentication-Results: spf=pass; dkim=pass" into
the message. Only the stamp added by YOUR receiving server counts, which is the topmost
one, or the one whose server name is listed in rules.yaml -> auth.trusted_authserv_ids.
Lower (older) stamps are ignored.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..models import Email
from .base import Analyzer, register

_RESULT = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)
_DMARC_POLICY = re.compile(r"dmarc\s*=\s*[a-z]+\s*\(([^)]*)\)", re.I)
_POLICY = re.compile(r"\bp\s*=\s*([a-z]+)", re.I)
_COMMENT = re.compile(r"\([^)]*\)")


@dataclass
class AuthResult:
    authserv: str = ""
    spf: str | None = None
    dkim: str | None = None            # best result across signatures
    dmarc: str | None = None
    dmarc_policy: str | None = None
    raw: str = ""
    from_received_spf: bool = False
    seen: dict = field(default_factory=dict)


def parse_auth_results(header: str) -> AuthResult:
    text = " ".join(header.split())
    first = text.split(";", 1)[0].strip()
    authserv = first.split()[0] if first and "=" not in first.split()[0] else ""

    policy = None
    m = _DMARC_POLICY.search(text)
    if m and (pm := _POLICY.search(m.group(1))):
        policy = pm.group(1).lower()

    clean = _COMMENT.sub(" ", text)                       # forged text hides in comments
    found: dict[str, list[str]] = {}
    for kind, val in _RESULT.findall(clean):
        found.setdefault(kind.lower(), []).append(val.lower())

    dkim = None
    if "dkim" in found:
        vals = found["dkim"]
        dkim = "pass" if "pass" in vals else ("fail" if "fail" in vals else vals[0])
    return AuthResult(
        authserv=authserv.lower(), spf=(found.get("spf") or [None])[0], dkim=dkim,
        dmarc=(found.get("dmarc") or [None])[0], dmarc_policy=policy, raw=text[:300], seen=found,
    )


def pick_trusted(email: Email, trusted_ids: list[str]) -> AuthResult | None:
    headers = email.headers.security.get("authentication-results", [])
    parsed = [parse_auth_results(h) for h in headers]
    if trusted_ids:
        wanted = {t.lower() for t in trusted_ids}
        return next((p for p in parsed if p.authserv in wanted), None)
    return parsed[0] if parsed else None                  # topmost = added by our own server


def _spf_from_received_spf(value: str) -> AuthResult | None:
    words = value.split()
    if not words:
        return None
    word = words[0].lower().strip("();,")
    mapping = {"pass": "pass", "fail": "fail", "softfail": "softfail", "neutral": "neutral",
               "none": "none", "temperror": "temperror", "permerror": "permerror"}
    if word not in mapping:
        return None
    return AuthResult(spf=mapping[word], raw=value[:300], from_received_spf=True)


@register
class Auth(Analyzer):
    name = "auth"

    def run(self, email: Email, cfg):
        out = []
        res = pick_trusted(email, cfg.auth.trusted_authserv_ids)
        conf = 1.0

        if res is None and not cfg.auth.trusted_authserv_ids:
            # no Authentication-Results: fall back to Received-SPF (weaker: can't tell who wrote it)
            vals = email.headers.security.get("received-spf", [])
            res = _spf_from_received_spf(" ".join(vals[0].split())) if vals else None
            conf = 0.8

        if res is None:
            why = ("no Authentication-Results from a trusted server" if cfg.auth.trusted_authserv_ids
                   else "no Authentication-Results or Received-SPF header")
            return [self.finding("auth.results_missing", f"Cannot verify sender: {why}",
                                 trusted_servers=cfg.auth.trusted_authserv_ids)]

        ev = dict(authserv=res.authserv, spf=res.spf, dkim=res.dkim, dmarc=res.dmarc,
                  dmarc_policy=res.dmarc_policy, header=res.raw)

        if res.spf in ("fail", "hardfail"):
            out.append(self.finding("auth.spf_fail", "SPF failed: sender IP not authorised", conf, **ev))
        elif res.spf == "softfail":
            out.append(self.finding("auth.spf_softfail", "SPF softfail: sender IP probably not authorised", conf, **ev))

        if res.dkim == "fail":
            out.append(self.finding("auth.dkim_fail", "DKIM signature failed verification", conf, **ev))
        elif res.dkim == "none":
            out.append(self.finding("auth.dkim_none", "Message is not DKIM-signed", conf, **ev))

        if res.dmarc == "fail":
            out.append(self.finding("auth.dmarc_fail", "DMARC failed for the From domain", conf, **ev))
        elif res.dmarc in ("none", "bestguesspass"):
            out.append(self.finding("auth.dmarc_no_policy", "From domain publishes no DMARC policy", conf, **ev))
        elif res.dmarc_policy == "none" and res.dmarc != "pass":
            out.append(self.finding("auth.dmarc_no_policy", "DMARC policy is p=none (monitor only)", 0.7 * conf, **ev))
        return out
