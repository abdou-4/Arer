"""Small, offline Unicode helpers for phishing-text analysis.

This module deliberately does NOT implement the complete Unicode TR39
confusables algorithm.  It provides a documented, conservative comparison key
for a focused set of Latin/Cyrillic/Greek lookalikes plus compatibility forms.
Original email text is never modified; callers use these derived values only
for comparison and retain the original text in their evidence.

All public text-processing helpers are bounded to MAX_TEXT_CHARS characters.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

MAX_TEXT_CHARS = 100_000

# Characters which are meaningful as formatting controls but invisible to a
# reader. ZWJ/ZWNJ are handled contextually below because they are legitimate
# in Persian, Arabic, Indic writing and emoji sequences.
BIDI_CONTROLS = frozenset(
    chr(cp) for cp in (
        0x202A, 0x202B, 0x202C, 0x202D, 0x202E,  # embeddings / overrides / PDF
        0x2066, 0x2067, 0x2068, 0x2069,          # isolates
    )
)
LRM_RLM = frozenset(("\u200e", "\u200f"))
SOFT_HYPHEN = "\u00ad"
ZWJ_ZWNJ = frozenset(("\u200c", "\u200d"))

# A deliberately limited table: add entries only when they have a clear visual
# Latin lookalike. Digits, Turkish dotless i, and broad transliteration rules
# are intentionally excluded.
_CONFUSABLES = str.maketrans({
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "у": "y", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ӏ": "l",
    # Greek
    "α": "a", "ε": "e", "ο": "o", "ρ": "p", "χ": "x", "υ": "y",
    "ι": "i", "κ": "k", "ν": "v", "τ": "t", "μ": "m", "ϲ": "c",
})

# Only these controls are candidates for an invisible-character finding.
# LRM/RLM are intentionally excluded. Other Cf characters are not blindly
# treated as attacks because many have script-specific uses.
_INVISIBLE_BASE = frozenset(("\u200b", "\u2060", "\ufeff"))

@dataclass(frozen=True)
class WordToken:
    original: str
    start: int
    end: int
    skeleton: str
    scripts: frozenset[str]
    obfuscated: bool


def _is_letter_or_number(ch: str) -> bool:
    return bool(ch) and unicodedata.category(ch)[0] in ("L", "N")


def _script_of(ch: str) -> str | None:
    """Best-effort script label from Unicode character names (stdlib only)."""
    if not ch or unicodedata.category(ch)[0] != "L":
        return None
    # NFKC handles full-width and mathematical alphabet forms before naming.
    normalized = unicodedata.normalize("NFKC", ch)
    if len(normalized) == 1:
        ch = normalized
    name = unicodedata.name(ch, "")
    if not name:
        return None
    if name.startswith(("CJK UNIFIED IDEOGRAPH", "CJK COMPATIBILITY IDEOGRAPH")):
        return "HAN"
    for prefix, script in (
        ("HIRAGANA", "HIRAGANA"), ("KATAKANA", "KATAKANA"),
        ("HANGUL", "HANGUL"), ("LATIN", "LATIN"),
        ("CYRILLIC", "CYRILLIC"), ("GREEK", "GREEK"),
        ("ARABIC", "ARABIC"), ("HEBREW", "HEBREW"),
        ("DEVANAGARI", "DEVANAGARI"), ("THAI", "THAI"),
        ("BENGALI", "BENGALI"), ("GURMUKHI", "GURMUKHI"),
        ("GUJARATI", "GUJARATI"), ("TAMIL", "TAMIL"),
        ("TELUGU", "TELUGU"), ("KANNADA", "KANNADA"),
        ("MALAYALAM", "MALAYALAM"), ("SINHALA", "SINHALA"),
        ("ARMENIAN", "ARMENIAN"), ("GEORGIAN", "GEORGIAN"),
        ("ETHIOPIC", "ETHIOPIC"), ("MYANMAR", "MYANMAR"),
        ("KHMER", "KHMER"), ("LAO", "LAO"), ("TIBETAN", "TIBETAN"),
    ):
        if name.startswith(prefix):
            return script
    # Useful fallback for scripts not explicitly listed above. This is a
    # heuristic, not a substitute for the Unicode Script property.
    return name.split(" ", 1)[0]


def _allowed_script_mix(scripts: frozenset[str]) -> bool:
    """Whether a token uses one of the common Japanese/Korean combinations."""
    if len(scripts) <= 1:
        return True
    if scripts <= {"HAN", "HIRAGANA", "KATAKANA"}:
        return True
    if scripts <= {"HAN", "HANGUL"}:
        return True
    if scripts <= {"LATIN", "HAN", "HIRAGANA", "KATAKANA"}:
        return True
    if scripts <= {"LATIN", "HAN", "HANGUL"}:
        return True
    return False


def comparison_skeleton(text: str) -> str:
    """Return Arer's conservative comparison key; never use it as display text."""
    value = unicodedata.normalize("NFKC", (text or "")[:MAX_TEXT_CHARS]).casefold()
    chars: list[str] = []
    for ch in value:
        # Remove invisible format controls and soft hyphens from the comparison
        # view so an inserted control cannot split a word for phrase matching.
        if unicodedata.category(ch) == "Cf" or ch == SOFT_HYPHEN:
            continue
        decomposed = unicodedata.normalize("NFKD", ch)
        for part in decomposed:
            if unicodedata.combining(part):
                continue
            chars.append(part.translate(_CONFUSABLES))
    return "".join(chars)


def fold_plain_for_matching(text: str) -> str:
    """Compatibility/diacritic fold without cross-script confusable mapping."""
    value = unicodedata.normalize("NFKC", (text or "")[:MAX_TEXT_CHARS]).casefold()
    chars: list[str] = []
    for ch in value:
        if unicodedata.category(ch) == "Cf" or ch == SOFT_HYPHEN:
            continue
        for part in unicodedata.normalize("NFKD", ch):
            if not unicodedata.combining(part):
                chars.append(part)
    out = [ch if ch.isalnum() or ch.isspace() else " " for ch in chars]
    return re.sub(r"\s+", " ", "".join(out)).strip()


def fold_for_matching(text: str) -> str:
    """Confusable-aware comparison key (intended for names and host labels)."""
    value = comparison_skeleton(text)
    out = [ch if ch.isalnum() or ch.isspace() else " " for ch in value]
    return re.sub(r"\s+", " ", "".join(out)).strip()


def fold_for_terms(text: str, phrases) -> str:
    """Fold prose, applying confusable mapping only to tokens matching terms.

    This prevents unrelated pure Cyrillic/Greek words from being globally
    transliterated during English keyword matching. A full-script spoof still
    matches when its skeleton equals an actual configured trigger token.
    """
    source = (text or "")[:MAX_TEXT_CHARS]
    target_words = {
        word for phrase in phrases
        for word in fold_plain_for_matching(phrase).split()
        if len(word) >= 3
    }
    tokens = word_tokens(source)
    if not tokens:
        return fold_plain_for_matching(source)
    parts: list[str] = []
    cursor = 0
    for token in tokens:
        parts.append(fold_plain_for_matching(source[cursor:token.start]))
        if token.obfuscated and token.skeleton in target_words:
            parts.append(token.skeleton)
        else:
            parts.append(fold_plain_for_matching(token.original))
        cursor = token.end
    parts.append(fold_plain_for_matching(source[cursor:]))
    return re.sub(r"\s+", " ", " ".join(part for part in parts if part)).strip()


def _char_is_word(ch: str) -> bool:
    cat = unicodedata.category(ch)
    return cat[0] in ("L", "N") or cat[0] == "M"


def _is_format_character(ch: str) -> bool:
    return unicodedata.category(ch) == "Cf" or ch == SOFT_HYPHEN


def _format_run_neighbors(text: str, index: int) -> tuple[str, str]:
    """Return the characters immediately outside a contiguous format run."""
    start = index
    while start > 0 and _is_format_character(text[start - 1]):
        start -= 1

    end = index + 1
    while end < len(text) and _is_format_character(text[end]):
        end += 1

    previous = text[start - 1] if start > 0 else ""
    following = text[end] if end < len(text) else ""
    return previous, following


def word_tokens(text: str, max_chars: int = MAX_TEXT_CHARS) -> list[WordToken]:
    """Extract words while retaining internal format characters for analysis.

    A format character is kept inside a token only when it sits between two
    letters/numbers. This joins e.g. ``Pay<ZWSP>Pal`` for comparison without
    treating separators or emoji ZWJ sequences as part of a word.
    """
    source = (text or "")[:max(0, min(max_chars, MAX_TEXT_CHARS))]
    tokens: list[WordToken] = []
    start: int | None = None
    chars: list[str] = []

    def flush(end: int) -> None:
        nonlocal start, chars
        if start is None or not chars:
            start, chars = None, []
            return
        original = "".join(chars)
        skeleton = fold_for_matching(original)
        scripts = frozenset(s for ch in original if (s := _script_of(ch)))
        obfuscated = _has_obfuscation(original)
        tokens.append(WordToken(original, start, end, skeleton, scripts, obfuscated))
        start, chars = None, []

    i = 0
    while i < len(source):
        ch = source[i]
        if _char_is_word(ch):
            if start is None:
                start = i
            chars.append(ch)
            i += 1
            continue

        if _is_format_character(ch):
            run_end = i + 1
            while run_end < len(source) and _is_format_character(source[run_end]):
                run_end += 1
            next_is_word = run_end < len(source) and _char_is_word(source[run_end])
            # Keep an entire consecutive format run only when it is internal
            # to a word. This also avoids treating emoji ZWJ sequences as words.
            if start is not None and next_is_word:
                chars.extend(source[i:run_end])
                i = run_end
                continue
            flush(i)
            i = run_end
            continue

        flush(i)
        i += 1

    flush(len(source))
    return tokens


def _is_confusable_char(ch: str) -> bool:
    """Check the confusables table after case-folding the original character."""
    return any(ord(part) in _CONFUSABLES for part in ch.casefold())


def _has_invisible_between_ascii_letters(token: str) -> bool:
    for index, ch in enumerate(token):
        if ch in LRM_RLM or not _is_format_character(ch):
            continue
        previous, following = _format_run_neighbors(token, index)
        if _ascii_letter(previous) and _ascii_letter(following):
            return True
    return False


def _has_obfuscation(token: str) -> bool:
    value = unicodedata.normalize("NFKC", token).casefold()
    if _has_invisible_between_ascii_letters(token):
        return True
    for ch in token:
        if ch in LRM_RLM or _is_format_character(ch):
            continue
        if _is_confusable_char(ch):
            return True
        normalized = unicodedata.normalize("NFKC", ch)
        if normalized != ch and normalized.isascii() and normalized.isalnum():
            return True
    # NFKC may change compatibility characters as a sequence.
    return bool(value and value != token.casefold() and value.isascii())


def _has_visual_confusable(token: str) -> bool:
    """Detect cross-script lookalikes and fullwidth spoofing characters.

    Mathematical alphanumeric characters are compatibility-normalized for
    phrase matching, but typographic styling alone is not treated as a
    homoglyph attack. Fullwidth ASCII forms remain covered because they can
    imitate ordinary Latin brand names.
    """
    for ch in token:
        if _is_confusable_char(ch):
            return True
        normalized = unicodedata.normalize("NFKC", ch)
        if (
            unicodedata.east_asian_width(ch) == "F"
            and normalized != ch
            and len(normalized) == 1
            and normalized.isascii()
            and normalized.isalnum()
        ):
            return True
    return False


def mixed_script_token(token: str) -> bool:
    scripts = frozenset(s for ch in (token or "") if (s := _script_of(ch)))
    return len(scripts) > 1 and not _allowed_script_mix(scripts)


def mixed_script_text(text: str) -> bool:
    """True when at least one individual word has a suspicious script mixture."""
    return any(mixed_script_token(token.original) for token in word_tokens(text))


def mixed_script_labels(host: str) -> list[str]:
    """Return domain labels containing suspicious mixed-script words."""
    bad: list[str] = []
    for label in (host or "").strip(".").split("."):
        if label and mixed_script_text(label):
            bad.append(label)
    return bad


def normalize_host_for_comparison(host: str) -> str:
    """Normalize each hostname label independently for shown-host comparisons."""
    return ".".join(comparison_skeleton(label) for label in (host or "").strip(".").split("."))


def codepoint_description(ch: str) -> str:
    return f"U+{ord(ch):04X} {unicodedata.name(ch, 'UNNAMED CHARACTER')}"


def codepoint_descriptions(text: str, limit: int = 12) -> list[str]:
    """Describe non-ASCII or formatting characters useful for analyst evidence."""
    out: list[str] = []
    seen: set[str] = set()
    for ch in (text or "")[:MAX_TEXT_CHARS]:
        if ord(ch) > 127 or ch in BIDI_CONTROLS:
            desc = codepoint_description(ch)
            if desc not in seen:
                out.append(desc)
                seen.add(desc)
                if len(out) >= limit:
                    break
    return out


def _ascii_letter(ch: str) -> bool:
    return len(ch) == 1 and ch.isascii() and ch.isalpha()


def invisible_char_records(text: str, trigger_words: set[str] | frozenset[str] = (),
                           limit: int = 12) -> list[dict[str, object]]:
    """Find suspicious invisible characters inserted inside ASCII words.

    ZWJ/ZWNJ are considered only between ASCII letters. Soft hyphens are
    reported only when removing them reconstructs a configured trigger word,
    avoiding noisy findings on ordinary German newsletter text.
    """
    source = (text or "")[:MAX_TEXT_CHARS]
    tokens = word_tokens(source)
    token_by_pos: dict[int, WordToken] = {}
    for token in tokens:
        for pos in range(token.start, token.end):
            token_by_pos[pos] = token

    records: list[dict[str, object]] = []
    for index, ch in enumerate(source):
        if ch in BIDI_CONTROLS or ch in LRM_RLM:
            continue
        if _is_format_character(ch):
            previous, following = _format_run_neighbors(source, index)
            ascii_letter_pair = _ascii_letter(previous) and _ascii_letter(following)
            if ch in ZWJ_ZWNJ:
                suspicious = ascii_letter_pair
            elif ch == SOFT_HYPHEN:
                token = token_by_pos.get(index)
                suspicious = bool(token and token.skeleton in trigger_words)
            else:
                suspicious = ascii_letter_pair
        elif ch in _INVISIBLE_BASE or (0xE0000 <= ord(ch) <= 0xE007F):
            previous, following = _format_run_neighbors(source, index)
            suspicious = _ascii_letter(previous) and _ascii_letter(following)
        else:
            suspicious = False
        if suspicious:
            token = token_by_pos.get(index)
            records.append({
                "codepoint": codepoint_description(ch),
                "index": index,
                "token": token.original if token else "",
                "context": source[max(0, index - 18):min(len(source), index + 19)],
            })
            if len(records) >= limit:
                break
    return records


def has_brand_obfuscation(token: str) -> bool:
    """Detect visual or embedded-invisible brand obfuscation, not styling alone."""
    return (
        _has_visual_confusable(token)
        or _has_invisible_between_ascii_letters(token)
    )




def bidi_control_records(text: str, limit: int = 12) -> list[dict[str, object]]:
    """Find suspicious directional controls while allowing a narrow RTL case.

    A balanced RLE (U+202B) / PDF (U+202C) pair that contains RTL characters
    and no LTR characters is a known legitimate formatting pattern in RTL
    prose. Suppress only that simple, balanced pair. Overrides, mixed-direction
    embeddings, nested controls, unmatched controls, and isolates remain visible
    to the analyzer.
    """
    source = (text or "")[:MAX_TEXT_CHARS]
    ignored: set[int] = set()
    embedding_openers = {"\u202a", "\u202b", "\u202d", "\u202e"}
    stack: list[tuple[str, int]] = []

    for index, ch in enumerate(source):
        if ch in embedding_openers:
            stack.append((ch, index))
        elif ch == "\u202c" and stack:
            opener, start = stack.pop()
            # Suppress only a top-level, balanced RLE/PDF pair. A nested pair
            # remains suspicious even when its own contents are RTL-only.
            if opener != "\u202b" or stack:
                continue
            segment = source[start + 1:index]
            directions = {unicodedata.bidirectional(char) for char in segment}
            has_rtl = bool(directions & {"R", "AL"})
            has_ltr = "L" in directions
            has_nested_controls = any(char in BIDI_CONTROLS for char in segment)
            if has_rtl and not has_ltr and not has_nested_controls:
                ignored.update((start, index))

    records: list[dict[str, object]] = []
    for index, ch in enumerate(source):
        if ch in BIDI_CONTROLS and index not in ignored:
            records.append({
                "codepoint": codepoint_description(ch),
                "index": index,
                "context": source[max(0, index - 18):min(len(source), index + 19)],
            })
            if len(records) >= limit:
                break
    return records


def obfuscated_term_tokens(text: str, terms: set[str] | frozenset[str],
                           min_length: int = 3, limit: int = 12) -> list[dict[str, object]]:
    """Return obfuscated words whose comparison skeleton matches known terms."""
    known = {fold_for_matching(term) for term in terms if term}
    known.discard("")
    out: list[dict[str, object]] = []
    for token in word_tokens(text):
        if len(token.skeleton) < min_length or token.skeleton not in known or not token.obfuscated:
            continue
        out.append({
            "original": token.original,
            "skeleton": token.skeleton,
            "start": token.start,
            "end": token.end,
            "scripts": sorted(token.scripts),
            "codepoints": codepoint_descriptions(token.original),
        })
        if len(out) >= limit:
            break
    return out


def obfuscated_brand_matches(text: str, brands: set[str] | frozenset[str]) -> list[dict[str, object]]:
    """Find visually confusable brand words (invisibles have their own finding)."""
    brand_words = {word for brand in brands for word in fold_for_matching(brand).split() if len(word) >= 3}
    known = {fold_for_matching(word) for word in brand_words}
    out: list[dict[str, object]] = []
    for token in word_tokens(text):
        if len(token.skeleton) < 3 or token.skeleton not in known or not _has_visual_confusable(token.original):
            continue
        out.append({
            "original": token.original,
            "skeleton": token.skeleton,
            "start": token.start,
            "end": token.end,
            "scripts": sorted(token.scripts),
            "codepoints": codepoint_descriptions(token.original),
        })
        if len(out) >= 12:
            break
    return out
