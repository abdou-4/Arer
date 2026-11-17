"""
casesummary.py - R7.3: the Markdown case summary (`alerts show DIR ID --markdown`).

One durable, paste-ready document per case. Content contract:

- case id (sha256) and the alert event id;
- current verdict, score, per-category contributions and the analysis
  completeness status (R1.4);
- top reasons with their points and the supporting evidence;
- structured indicators, DEFANGED by default (no clickable live IOCs);
- campaign membership when the record belongs to a cluster, with the key
  evidence and the analyst confirmation state (from history.db, if any);
- workflow state and disposition, with provenance and analyst identity;
- logic/config hashes and engine/parser versions.

Safety rules (the content came from an attacker):
- every untrusted string (subject, sender/domain, filename, note, evidence,
  indicator values) is Markdown-escaped and length-limited; code-fence
  injection is impossible because untrusted text never contains a fence;
- NO links are ever emitted - live IOCs require an explicit --raw, and the
  summary defangs once (idempotent defang, R4.4);
- the summary shows the evidence that affected the result; it does NOT
  claim the rules prove intent.
"""
from __future__ import annotations

import re
from typing import Any

from .alert import Alert
from .disposition import Disposition
from .util.defang import defang, safe_text

_MD_UNSAFE = re.compile(r"([\\`*_{}\[\]()#+\-.!|<>])")


def _md(text: Any, max_len: int = 300) -> str:
    """Escape untrusted text for Markdown and keep it single-line."""
    s = safe_text(text, max_len)
    return _MD_UNSAFE.sub(r"\\\1", s)


def _md_ioc(value: Any, max_len: int = 300) -> str:
    """An IOC value for display: defanged ONCE, then Markdown-escaped."""
    return _md(defang(str(value)), max_len)


def render_markdown(alert: Alert, disposition: Disposition | None,
                    *, record_file: str = "", campaign: "dict | None" = None,
                    campaign_state: str = "", raw: bool = False) -> str:
    """The case summary. campaign is the cluster info dict from
    arer.campaign.build_clusters (None = unassigned); campaign_state is the
    latest analyst campaign decision value ('' = no decision yet)."""
    v = alert.verdict
    def ioc(value, max_len=300):                        # raw mode shows live values
        return str(value) if raw else _md_ioc(value, max_len)
    L: list[str] = []
    L.append("# Case summary")
    L.append("")
    L.append(f"- **Case (sha256):** `{v.sha256}`")
    L.append(f"- **Alert event:** `{alert.alert_id}`"
             + (f" (record `{_md(record_file, 120)}`)" if record_file else ""))
    L.append(f"- **Generated:** {_md(alert.generated_utc)}")
    L.append(f"- **Verdict:** **{v.level.value}**, score {v.score}/100"
             + (f", forced by `{_md(v.overridden_by)}`" if v.overridden_by else ""))
    if v.by_category:
        cats = ", ".join(f"{k} {pts}" for k, pts in sorted(v.by_category.items(), key=lambda kv: -kv[1]))
        L.append(f"- **Category contributions:** {cats}")
    L.append("- **Analysis:** " + ("complete" if alert.analysis_complete
                                   else f"INCOMPLETE - {len(alert.analysis_errors)} analyzer problem(s)"))
    if alert.analysis_errors:
        for e in alert.analysis_errors[:5]:
            L.append(f"  - {_md(e, 160)}")

    L.append("")
    L.append("## Top reasons")
    if alert.reasons:
        for r in alert.reasons:
            L.append(f"- `{r['finding']}` (+{r['points']} points: weight {r['weight']} x "
                     f"confidence {r['confidence']})")
    elif v.findings:
        for f in v.findings[:3]:
            pts = round(f.weight * f.confidence)
            L.append(f"- `{_md(f.id)}` (+{pts} points)")
    else:
        L.append("- none")
    L.append("")
    L.append("## Evidence")
    if v.findings:
        for f in v.findings[:6]:
            L.append(f"- **{_md(f.id)}** — {_md(f.summary, 200)}")
            for k, val in list(f.evidence.items())[:4]:
                L.append(f"  - {_md(k, 60)}: {ioc(val, 160)}")
    else:
        L.append("- none recorded")

    L.append("")
    L.append("## Indicators (defanged)")
    ind = alert.indicators or {}
    if ind.get("urls") or ind.get("url_domains") or ind.get("sender_domain") or ind.get("attachments"):
        for u in (ind.get("urls") or [])[:10]:
            L.append(f"- url: {ioc(u, 200)}")
        for dm in (ind.get("url_domains") or [])[:10]:
            L.append(f"- domain: {ioc(dm, 120)}")
        if ind.get("sender_domain"):
            L.append(f"- sender domain: {ioc(ind['sender_domain'], 120)}")
        for att in (ind.get("attachments") or [])[:10]:
            if isinstance(att, dict) and att.get("sha256"):
                flag = " (inline)" if att.get("inline") else ""
                L.append(f"- attachment sha256: `{att['sha256']}`{flag}"
                         + (f" — {_md(att.get('filename', ''), 80)}" if att.get("filename") else ""))
    else:
        L.append("- none recorded (v1 records carry no structured indicator block)")

    L.append("")
    L.append("## Campaign")
    if campaign:
        L.append(f"- **campaign_id:** `{campaign['campaign_id']}`")
        L.append(f"- **mails in cluster:** {len(campaign['mail_sha256s'])}")
        keys = ", ".join(f"`{_md(k, 60)}`" for k in campaign.get("keys", [])[:6]) or "-"
        L.append(f"- **linking keys:** {keys}")
        L.append(f"- **analyst state:** {_md(campaign_state or 'not reviewed yet')}")
    else:
        L.append("- no campaign relationship proposed for this mail")

    L.append("")
    L.append("## Workflow")
    if disposition:
        L.append(f"- **Disposition:** {_md(disposition.status)}"
                 f" (provenance {_md(disposition.effective_provenance)})"
                 + (f", analyst {_md(disposition.analyst, 80)}" if disposition.analyst else ""))
        L.append(f"- **Decided:** {_md(disposition.set_utc)}")
        if disposition.note:
            L.append(f"- **Note:** {_md(disposition.note, 300)}")
    else:
        L.append("- **Disposition:** new (no decision recorded)")
    L.append(f"- **sender domain:** {ioc(alert.scan.from_domain or '-', 120)}"
             + (" (plaintext address not stored - privacy default)" if not alert.scan.from_ else ""))
    if alert.scan.from_:
        L.append(f"- **sender:** {ioc(alert.scan.from_, 120)}")
    L.append(f"- **message-id:** {_md(alert.scan.message_id, 120)}")

    L.append("")
    L.append("## Reproducibility")
    L.append(f"- logic_hash `{_md(alert.logic_hash)}` — config_hash `{_md(alert.config_hash)}`")
    L.append(f"- engine {_md(alert.engine_version, 40)} — parser {_md(alert.parser_version, 40)}")
    L.append("- This summary lists the evidence that affected the result; it does not prove intent.")
    return "\n".join(L) + "\n"
