"""Context-aware Unicode obfuscation checks for visible message body text.

Sender names and link/domain surfaces are handled in their existing analyzers
so one attack does not produce duplicate sender/URL findings here.
"""
from __future__ import annotations

from ..models import Email
from ..util.html import parse_html
from ..util.unicode_text import (
    MAX_TEXT_CHARS,
    bidi_control_records,
    fold_for_matching,
    invisible_char_records,
    obfuscated_brand_matches,
)
from .base import Analyzer, register


def _trigger_words(cfg) -> set[str]:
    words: set[str] = set()
    for key in ("urgency_words", "credential_words", "lure_words", "brands"):
        for phrase in cfg.lists.get(key, frozenset()):
            words.update(fold_for_matching(phrase).split())
    return words


@register
class UnicodeTricks(Analyzer):
    name = "unicode"

    def run(self, email: Email, cfg):
        # Work only on bounded, visible text. The original Email and its body
        # fields are never rewritten or normalized in place.
        plain = email.body_text[:MAX_TEXT_CHARS]
        info = parse_html(email.body_html[:MAX_TEXT_CHARS]) if email.body_html else None
        visible_html = info.visible_text if info else ""
        text = f"{plain}\n{visible_html}"[:MAX_TEXT_CHARS]
        if not text:
            return []

        out = []
        trigger_words = _trigger_words(cfg)

        invisible = invisible_char_records(text, trigger_words)
        if invisible:
            only_soft_hyphen = all(str(item.get("codepoint", "")).startswith("U+00AD ") for item in invisible)
            confidence = 0.4 if only_soft_hyphen else 0.85
            out.append(self.finding(
                "body.invisible_chars",
                "Invisible formatting characters are inserted inside words",
                confidence,
                surface="visible message body",
                count=len(invisible),
                characters=invisible,
            ))

        bidi = bidi_control_records(text)
        if bidi:
            codes = {str(item.get("codepoint", "")).split(" ", 1)[0] for item in bidi}
            if codes & {"U+202D", "U+202E"}:       # explicit directional overrides are strongest
                bidi_confidence = 0.9
            elif codes & {"U+2066", "U+2067", "U+2068", "U+2069"}:  # isolates can be valid in RTL prose
                bidi_confidence = 0.55
            else:
                bidi_confidence = 0.7
            out.append(self.finding(
                "body.bidi_control",
                "Message body contains directional override, embedding or isolate controls",
                bidi_confidence,
                count=len(bidi),
                characters=bidi,
            ))

        # Phrase matching in Body already uses the same comparison skeleton.
        # This finding is reserved for brand lookalikes that are not otherwise
        # represented by an urgency/credential/lure finding.
        brands = cfg.lists.get("brands", frozenset())
        brand_hits = obfuscated_brand_matches(text, brands)
        if brand_hits:
            out.append(self.finding(
                "body.homoglyph_text",
                "A known brand name is written with visually confusable Unicode characters",
                0.8,
                matches=brand_hits,
            ))
        return out
