"""
util/domains.py - domain helpers shared by analyzers. Fully offline.

* registrable()  : "mail.shop.example.co.uk" -> "example.co.uk"
* lookalike()    : is this domain imitating a brand? (homoglyphs, typos, brand+words)
* is_punycode()/decode_host()/mixed_script() : international-domain tricks

tldextract is told NOT to download the public-suffix list (suffix_list_urls=()),
so it uses the snapshot bundled with the package. No network call, ever.
"""
from __future__ import annotations

import re
import unicodedata
from functools import lru_cache
from typing import NamedTuple

import tldextract
from rapidfuzz.distance import Levenshtein

_TLD = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


# --------------------------------------------------------------------------- #
# splitting
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=4096)
def split_host(host: str) -> tuple[str, str, str]:
    """(subdomain, label, suffix). Label is the registrable name without its suffix."""
    h = (host or "").strip().strip(".").lower()
    r = _TLD(h)
    sub, label, suffix = r.subdomain, r.domain, r.suffix
    if not suffix and "." in h:                  # unknown TLD: treat last label as the TLD
        parts = h.split(".")
        sub, label, suffix = ".".join(parts[:-2]), parts[-2], parts[-1]
    return sub, label, suffix


def registrable(host: str) -> str:
    """'example.co.uk' style name, or the host itself if it has no valid suffix (bare hostname)."""
    _, label, suffix = split_host(host)
    return f"{label}.{suffix}" if label and suffix else (host or "").strip().lower()


def has_public_suffix(host: str) -> bool:
    return bool(split_host(host)[2])


# --------------------------------------------------------------------------- #
# international-domain tricks
# --------------------------------------------------------------------------- #
def is_punycode(host: str) -> bool:
    return any(lab.startswith("xn--") for lab in (host or "").lower().split("."))


def decode_host(host: str) -> str:
    out = []
    for lab in (host or "").lower().split("."):
        if lab.startswith("xn--"):
            try:
                lab = lab.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                pass
        out.append(lab)
    return ".".join(out)


def mixed_script(text: str) -> bool:
    """True if letters come from more than one script (e.g. Latin + Cyrillic)."""
    scripts = set()
    for ch in text:
        if ch.isalpha():
            scripts.add(unicodedata.name(ch, "UNKNOWN").split(" ")[0])
    return len(scripts) > 1


_CONFUSABLE = str.maketrans({
    # Cyrillic / Greek letters that look Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
    "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ο": "o", "ν": "v", "α": "a", "ε": "e",
    "ι": "i", "κ": "k", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    # look-alike digits/symbols
    "0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s",
})


def normalize_confusables(s: str) -> str:
    s = unicodedata.normalize("NFKD", (s or "").lower())
    s = "".join(c for c in s if not unicodedata.combining(c))
    return s.translate(_CONFUSABLE).replace("rn", "m").replace("vv", "w")


# --------------------------------------------------------------------------- #
# brand lookalikes
# --------------------------------------------------------------------------- #
class Lookalike(NamedTuple):
    brand: str
    kind: str            # homoglyph | typosquat | brand_plus_words | contains_brand | brand_wrong_tld
    confidence: float
    label: str


def lookalike(host: str, brands, legit_domains, suspicious_tlds) -> Lookalike | None:
    """
    Does `host` imitate one of `brands`? None if clean or on the legit list.
    Best match wins. Brands are lowercase single words. The legit list prevents
    false alarms such as microsoftonline.com.
    """
    host = decode_host(host)
    if registrable(host) in legit_domains:
        return None
    _, label, suffix = split_host(host)
    if not label:
        return None

    tokens = [t for t in label.split("-") if t]
    nlabel = normalize_confusables(label)
    best: Lookalike | None = None

    def consider(brand, kind, conf):
        nonlocal best
        if best is None or conf > best.confidence:
            best = Lookalike(brand, kind, conf, label)

    for brand in sorted(brands):
        nb = normalize_confusables(brand)
        if label == brand:                               # paypal.top : right name, wrong TLD
            if suffix.split(".")[-1] in suspicious_tlds:
                consider(brand, "brand_wrong_tld", 0.6)
            continue
        for tok in tokens:
            ntok = normalize_confusables(tok)
            if tok == brand and len(tokens) > 1:
                consider(brand, "brand_plus_words", 0.9)              # paypal-secure.com
            elif ntok == nb and tok != brand:
                consider(brand, "homoglyph", 1.0)                     # paypa1.com, раypal.com
            elif len(brand) >= 5 and abs(len(ntok) - len(nb)) <= 1 and Levenshtein.distance(ntok, nb) == 1:
                consider(brand, "typosquat", 0.8)                     # paypall.com
        if len(brand) >= 6 and brand in label:
            consider(brand, "contains_brand", 0.6)                    # securepaypal.com
    return best


def brand_in_subdomain(host: str, brands, legit_domains) -> str | None:
    """paypal.com.secure-login.net / paypal.evil.com : brand used as a subdomain of someone else's domain."""
    host = decode_host(host)
    if registrable(host) in legit_domains:
        return None
    sub, _, _ = split_host(host)
    tokens = set(re.split(r"[.\-]", sub))
    return next((b for b in sorted(brands) if b in tokens), None)
