"""
util/html.py - static HTML reader. Uses only the standard library.

Never renders, never fetches, never runs scripts. Extracts what analyzers need:
links (href + visible text), forms and input fields, visible text, hidden text, image count.
Hard limits stop a hostile HTML bomb from eating time or memory.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

MAX_TAGS = 20_000
MAX_LINKS = 500
MAX_TEXT = 100_000

_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param",
         "source", "track", "wbr"}
_HIDDEN = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|mso-hide\s*:\s*all"
    r"|font-size\s*:\s*0(?:px|pt|em|rem|%)?(?![\w.])|opacity\s*:\s*0(?:\.0+)?(?![\w.])"
    r"|max-height\s*:\s*0(?:px)?(?![\w.])", re.I)
_WHITE = re.compile(r"(?:^|;)\s*color\s*:\s*(?:#fff(?:fff)?|white|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))\s*(?:;|!|$)", re.I)
_WS = re.compile(r"\s+")

# tag names real e-mail HTML uses (HTML5 plus the legacy ones old mail clients still write)
_KNOWN = set("""a abbr acronym address area article aside audio b base basefont bdi bdo big blockquote body br button canvas
caption center cite code col colgroup data datalist dd del details dfn dialog dir div dl dt em embed fieldset figcaption
figure font footer form frame frameset h1 h2 h3 h4 h5 h6 head header hgroup hr html i iframe img input ins kbd label legend
li link main map mark marquee menu meta meter nav nobr noframes noscript object ol optgroup option output p param picture
pre progress q rp rt ruby s samp script section select small source span strike strong style sub summary sup table tbody
td template textarea tfoot th thead time title tr track tt u ul var video wbr xml xmp center
svg g path circle rect line polygon polyline ellipse defs use symbol clippath mask lineargradient radialgradient stop tspan text
image pattern filter fegaussianblur title desc style math mi mo mn blink layer ilayer spacer""".split())
# SVG icons and the like are normal in newsletters; only made-up names count
# tags that never carry message text but are used to pad a message with junk
_FILLER = {"textarea", "option", "basefont", "rt", "noframes", "xmp", "plaintext"}


@dataclass
class HtmlInfo:
    links: list[tuple[str, str]] = field(default_factory=list)       # (href, visible text)
    forms: list[dict] = field(default_factory=list)                  # {action, method, fields:[(type,name)]}
    visible_text: str = ""
    hidden_text: str = ""
    img_count: int = 0
    has_password_input: bool = False
    unknown_tags: int = 0               # distinct made-up tag names, e.g. <CZVVGQPYUH>
    doctypes: int = 0                   # a real message has one <!DOCTYPE>
    filler_tags: int = 0                # textarea/option/basefont/... used as padding
    hidden_elements: int = 0            # elements styled display:none and friends
    bg_images: int = 0                  # elements with a CSS background image


class _Reader(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.info = HtmlInfo()
        self.stack: list[tuple[str, bool]] = []          # (tag, hidden)
        self.skip = False                                # inside <script>/<style>
        self.tags = 0
        self.cur_a: list | None = None
        self.cur_form: dict | None = None
        self.vis: list[str] = []
        self.hid: list[str] = []
        self.vis_len = self.hid_len = 0
        self.unknown: set[str] = set()

    def handle_starttag(self, tag, attrs):
        self.tags += 1
        if self.tags > MAX_TAGS:
            return
        a = {k.lower(): (v or "") for k, v in attrs}
        parent_hidden = self.stack[-1][1] if self.stack else False
        style = a.get("style", "")
        hidden = parent_hidden or ("hidden" in a) or bool(_HIDDEN.search(style)) or bool(_WHITE.search(style))

        if tag not in _KNOWN and ":" not in tag and "-" not in tag and len(self.unknown) < 50:
            self.unknown.add(tag)                        # o:p, v:shape and custom-elements are normal; random names are not
        if tag in _FILLER:
            self.info.filler_tags += 1
        if _HIDDEN.search(style) or "hidden" in a:
            self.info.hidden_elements += 1
        if re.search(r"background(?:-image)?\s*:[^;]*url\(", style, re.I) or a.get("background"):
            self.info.bg_images += 1
        if tag == "img":
            self.info.img_count += 1
        elif tag == "a" and "href" in a and len(self.info.links) < MAX_LINKS:
            self.cur_a = [a["href"].strip(), []]
        elif tag == "form":
            self.cur_form = {"action": a.get("action", "").strip(), "method": a.get("method", "get").lower(), "fields": []}
            self.info.forms.append(self.cur_form)
        elif tag == "input":
            typ, name = a.get("type", "text").lower(), (a.get("name") or a.get("id") or "").lower()
            if typ == "password":
                self.info.has_password_input = True
            if self.cur_form is not None and len(self.cur_form["fields"]) < 100:
                self.cur_form["fields"].append((typ, name))

        if tag not in _VOID:
            self.stack.append((tag, hidden))
            if tag in ("script", "style"):
                self.skip = True

    def handle_endtag(self, tag):
        if tag == "a" and self.cur_a is not None:
            text = _WS.sub(" ", "".join(self.cur_a[1])).strip()
            self.info.links.append((self.cur_a[0], text[:300]))
            self.cur_a = None
        if tag == "form":
            self.cur_form = None
        for i in range(len(self.stack) - 1, -1, -1):     # lenient: pop to the matching open tag
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break
        self.skip = any(t in ("script", "style") for t, _ in self.stack)

    def handle_decl(self, decl):
        if decl.lower().startswith("doctype"):
            self.info.doctypes += 1

    def handle_data(self, data):
        if self.skip or self.tags > MAX_TAGS:
            return
        hidden = self.stack[-1][1] if self.stack else False
        if self.cur_a is not None and len("".join(self.cur_a[1])) < 400:
            self.cur_a[1].append(data)
        if hidden:
            if self.hid_len < MAX_TEXT:
                self.hid.append(data); self.hid_len += len(data)
        elif self.vis_len < MAX_TEXT:
            self.vis.append(data); self.vis_len += len(data)


def parse_html(html: str) -> HtmlInfo:
    r = _Reader()
    try:
        r.feed(html or "")
        r.close()
    except Exception:                                    # noqa: BLE001 - malformed HTML must never crash a scan
        pass
    r.info.unknown_tags = len(r.unknown)
    r.info.visible_text = _WS.sub(" ", "".join(r.vis)).strip()
    r.info.hidden_text = _WS.sub(" ", "".join(r.hid)).strip()
    return r.info
