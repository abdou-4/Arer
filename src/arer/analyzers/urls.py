"""
urls.py - STATIC link analysis. Never fetches, resolves or visits a URL.

Everything is judged from the URL text and the HTML around it. Local blocklists come
later (Phase 5). One finding per rule; the evidence lists the first few offending URLs.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote, urlsplit

from ..models import Email
from ..util.domains import (brand_in_subdomain, decode_host, is_punycode, lookalike,
                            mixed_script, registrable, split_host)
from ..util.html import parse_html
from ..util.urlcollect import extract_urls
from .base import Analyzer, register

MAX_URLS = 200
SHOWN_HOST = re.compile(r"^(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,24})(?:[/:?#].*)?$", re.I)
INT_HOST = re.compile(r"^(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}$", re.I)   # 2130706433, 0x7f.1, 0177.0.0.1
# strong words alone are suspicious; weak words are everywhere in legit URLs, so two are needed
STRONG_LOGIN = {"login", "signin", "logon", "verify", "verification", "webscr", "password", "passwd",
                "unlock", "suspended", "validate", "authenticate", "recover"}
WEAK_LOGIN = {"secure", "account", "update", "confirm", "banking", "wallet"}


def _is_ip(host: str) -> bool:
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return bool(INT_HOST.match(h))


@register
class Urls(Analyzer):
    name = "urls"

    def run(self, email: Email, cfg):
        L = cfg.lists
        legit, shorteners = L.get("legit_domains", frozenset()), L.get("shorteners", frozenset())
        tlds, shared = L.get("suspicious_tlds", frozenset()), L.get("shared_domains", frozenset())
        brands = L.get("brands", frozenset())
        from_reg = registrable(email.from_domain) if email.from_domain else ""
        bulk = email.is_bulk
        info = parse_html(email.body_html) if email.body_html else None

        urls = extract_urls(email, info, MAX_URLS)

        hits: dict[str, dict] = {}
        def hit(fid, conf, summary, url):
            h = hits.setdefault(fid, {"conf": 0.0, "summary": summary, "urls": [], "n": 0})
            h["n"] += 1
            if conf > h["conf"]:
                h["conf"], h["summary"] = conf, summary
            if len(h["urls"]) < 5 and url not in h["urls"]:
                h["urls"].append(url)

        # ---- link text says one thing, href goes elsewhere ---------------- #
        pairs = list(info.links) if info else []
        pairs += [(m.get("href", ""), m.get("displayed_text", "")) for m in email.indicators.href_text_mismatches
                  if isinstance(m, dict)]
        for href, text in pairs:
            m = SHOWN_HOST.match(text.strip()) if text and " " not in text.strip() else None
            try:
                target = (urlsplit(href).hostname or "").lower() if href.lower().startswith("http") else ""
            except ValueError:
                continue
            if m and target and registrable(m.group(1).lower()) != registrable(target):
                shown = m.group(1).lower()
                # a click-tracker usually carries the real destination inside its own URL: soften, don't ignore
                tracked = shown in unquote(unquote(href)).lower() or registrable(shown) in unquote(unquote(href)).lower()
                # The click goes to the sender's OWN domain (Discord: text dis.gd -> click.discord.com). That is only
                # deceptive when the text names a well-known site ("paypal.com" -> evil.example), so soften otherwise.
                shown_reg = registrable(shown)
                known_shown = shown_reg in legit or any(b in shown_reg.split(".")[0] for b in brands)
                own_target = bool(from_reg) and registrable(target) == from_reg and not known_shown
                conf = (0.4 if bulk else 1.0) * (0.3 if (tracked or own_target) else 1.0)
                hit("url.text_href_mismatch", conf,
                    f"Link text shows {shown} but goes to {target}"
                    + (" (looks like a click-tracker)" if tracked else " (the sender's own domain)" if own_target else ""),
                    f"{text[:80]} -> {href[:120]}")

        # ---- per-URL rules ------------------------------------------------ #
        for url in urls:
            try:
                p = urlsplit(url)
                host = (p.hostname or "").lower()
            except ValueError:
                continue
            if not host:
                continue
            if "@" in p.netloc:
                hit("url.userinfo_at", 1.0, "URL contains user@host (the real host is after the @)", url)
            if _is_ip(host):
                hit("url.ip_host", 1.0, f"Link points to a bare IP address ({host})", url)
                continue

            dhost = decode_host(host)
            reg = registrable(dhost)
            if reg == from_reg or reg in legit:
                continue                                         # the sender's own / known-good domains

            if is_punycode(host):
                hit("url.punycode", 1.0 if mixed_script(dhost) else 0.6,
                    f"Link uses an internationalised domain ({host})", url)
            sub, _, suffix = split_host(dhost)
            if suffix.split(".")[-1] in tlds:
                hit("url.suspicious_tld", 1.0, f"Link uses a commonly abused TLD (.{suffix.split('.')[-1]})", url)
            if host in shorteners or reg in shorteners:
                hit("url.shortener", 0.5 if bulk else 0.8, f"Link uses a URL shortener ({reg})", url)
            if reg in shared:
                hit("url.free_hosting", 0.7, f"Link is hosted on a free/shared domain ({reg})", url)
            if len([s for s in sub.split(".") if s]) >= 4:
                hit("url.many_subdomains", 0.5 if bulk else 1.0, f"Link has {len(sub.split('.'))} subdomain levels ({host[:60]})", url)
            look = lookalike(dhost, brands, legit, tlds)
            if look:
                hit("url.lookalike_domain", look.confidence,
                    f"Link domain {reg} imitates '{look.brand}' ({look.kind.replace('_', ' ')})", url)
            elif (b := brand_in_subdomain(dhost, brands, legit)):
                hit("url.lookalike_domain", 0.9, f"'{b}' is used as a subdomain of unrelated domain {reg}", url)
            if p.scheme == "http":
                hit("url.not_https", 0.25 if bulk else 0.5, "Link does not use HTTPS", url)
            tokens = set(re.split(r"[^a-z0-9]+", (p.path + " " + p.query).lower()))
            strong, weak = tokens & STRONG_LOGIN, tokens & WEAK_LOGIN
            if strong or len(weak) >= 2:
                hit("url.login_keywords", (0.6 if strong else 0.4) * (0.5 if bulk else 1.0),
                    f"Link path suggests a login/verification page ({', '.join(sorted(strong | weak))})", url)

        # ---- the email talks about a brand, but every link goes somewhere unrelated ---- #
        if info and brands:
            anchors = []                                   # (registrable domain, href) of clickable links
            for href, _ in info.links:
                if href.lower().startswith(("http://", "https://")):
                    try:
                        h = (urlsplit(href).hostname or "").lower()
                    except ValueError:
                        continue
                    if h and not _is_ip(h):
                        anchors.append((registrable(decode_host(h)), href))
            platforms = L.get("mail_platforms", frozenset())
            unrelated = [(r, u) for r, u in anchors if r != from_reg and r not in legit and r not in platforms]
            related = [r for r, _ in anchors if r == from_reg or r in legit]
            if unrelated and not related:
                name = email.from_addr.name if email.from_addr else ""
                head_words = re.findall(r"[a-z0-9]+", f"{email.envelope.subject} {name}".lower())
                body_words = re.findall(r"[a-z0-9]+", info.visible_text.lower())
                mentioned = sorted(b for b in brands if b in head_words or (len(b) >= 5 and body_words.count(b) >= 2))
                if mentioned:
                    doms = sorted({r for r, _ in unrelated})[:3]
                    hit("url.brand_mismatch", 0.4 if bulk else 0.8,
                        f"Message is about {', '.join(mentioned)}, but its links go only to unrelated domain(s): {', '.join(doms)}",
                        unrelated[0][1])

        return [self.finding(fid, h["summary"], h["conf"], urls=h["urls"], count=h["n"])
                for fid, h in sorted(hits.items())]
