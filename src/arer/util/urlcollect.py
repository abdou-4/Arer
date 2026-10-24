"""util/urlcollect.py - the one place that decides which URLs of an e-mail get analysed."""
from __future__ import annotations

import re

from ..models import Email
from .html import HtmlInfo, parse_html

URL_IN_TEXT = re.compile(r"https?://[^\s<>\"'\)\]]+", re.I)


def extract_urls(email: Email, info: HtmlInfo | None = None, limit: int = 200) -> list[str]:
    """Clickable links, form targets and URLs written in the text. Raw-HTML URLs (xmlns, DTDs) are not links."""
    if info is None and email.body_html:
        info = parse_html(email.body_html)
    urls: list[str] = []

    def add(u: str):
        u = u.strip().rstrip(".,;:!?")
        if u.lower().startswith(("http://", "https://")) and u not in urls and len(urls) < limit:
            urls.append(u)

    if info:
        for href, _ in info.links:
            add(href)
        for form in info.forms:
            add(form["action"])
        for u in URL_IN_TEXT.findall(info.visible_text):
            add(u)
    for u in URL_IN_TEXT.findall(email.body_text):
        add(u)
    if not info and not email.body_text:                  # last resort for odd messages
        for u in email.indicators.urls:
            add(u)
    return urls
