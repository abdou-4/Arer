"""
body.py - what the message text and HTML are doing.

Word lists live in config/lists/ (urgency, credential, greetings) and include English,
French, Portuguese, Spanish and a little Arabic. Text is accent-folded before matching.
"""
from __future__ import annotations

import re
import unicodedata
from functools import lru_cache

from ..models import Email
from ..util.domains import registrable
from ..util.html import parse_html
from .base import Analyzer, register

ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")


_PUNCT = re.compile(r"[^\w\s]|_")
_SPACES = re.compile(r"\s+")


def fold(s: str) -> str:
    """lowercase, accents removed, punctuation -> space ("aujourd'hui" == "aujourd hui")."""
    s = unicodedata.normalize("NFKD", s.lower())
    s = "".join(c for c in s if not unicodedata.combining(c))
    return _SPACES.sub(" ", _PUNCT.sub(" ", s)).strip()


@lru_cache(maxsize=16)
def _matcher(phrases: frozenset[str]):
    if not phrases:
        return None
    alt = "|".join(re.escape(fold(p)) for p in sorted(phrases, key=len, reverse=True))
    return re.compile(rf"(?<!\w)(?:{alt})(?!\w)")


def matched(text: str, phrases: frozenset[str]) -> list[str]:
    m = _matcher(phrases)
    return sorted(set(m.findall(fold(text)))) if m else []


@register
class Body(Analyzer):
    name = "body"

    def run(self, email: Email, cfg):
        out = []
        info = parse_html(email.body_html) if email.body_html else None
        plain = email.body_text
        text = f"{plain}\n{info.visible_text if info else ''}"[:100_000]
        bulk = email.is_bulk
        L = cfg.lists

        urg = matched(text, L.get("urgency_words", frozenset()))
        if urg:
            out.append(self.finding("body.urgency_words", f"Pressure language: {', '.join(urg[:5])}",
                                    min(1.0, len(urg) / 3), phrases=urg[:10]))
        cred = matched(text, L.get("credential_words", frozenset()))
        if cred:
            out.append(self.finding("body.credential_words", f"Asks for credentials or payment data: {', '.join(cred[:5])}",
                                    min(1.0, len(cred) / 3), phrases=cred[:10]))

        head = text.strip()[:200]
        greet = matched(head, L.get("generic_greetings", frozenset()))
        if greet:
            out.append(self.finding("body.generic_greeting", f"Impersonal greeting: {greet[0]}", phrases=greet))

        if info:
            # login/card forms
            for form in info.forms:
                names = " ".join(n for _, n in form["fields"])
                sensitive = info.has_password_input or re.search(r"pass|pwd|pin|cvv|card|iban|ssn", names)
                if sensitive:
                    action = form["action"]
                    out.append(self.finding(
                        "body.password_form", "Email contains a form asking for a password or card data",
                        action=action[:150], fields=[f"{t}:{n}" for t, n in form["fields"]][:8],
                        external_action=bool(action.lower().startswith("http"))))
                    break
            else:
                if info.has_password_input:
                    out.append(self.finding("body.password_form", "Email contains a password input field"))

            # hidden text and zero-width salting
            if len(info.hidden_text) >= 100 or len(ZERO_WIDTH.findall(info.visible_text)) >= 3:
                out.append(self.finding(
                    "body.hidden_text", "Text hidden from the reader (invisible styling or zero-width characters)",
                    0.4 if bulk else 0.8, hidden_chars=len(info.hidden_text),
                    zero_width=len(ZERO_WIDTH.findall(info.visible_text)), sample=info.hidden_text[:120]))

            # image-only email
            if info.img_count >= 1 and len(info.visible_text) < 40 and len(plain.strip()) < 40:
                out.append(self.finding("body.image_only", "Message is just images, with almost no text",
                                        0.3 if bulk else 0.7, images=info.img_count))
        return out
