"""
pipeline.py - runs every analyzer safely, then scores the result.

Guarantees
  * One analyzer crashing never stops the scan (error is recorded in the verdict).
  * One analyzer running too long is abandoned after analyzer_timeout_s.
  * Analyzers cannot set their own weights: the pipeline stamps them from rules.yaml.
Limitation: Python threads cannot be killed, so a truly stuck analyzer lingers until
the process exits. Real kill-on-timeout needs a subprocess (a later hardening step).
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, wait

from .analyzers.base import Analyzer, get_analyzers
from .config import Config, get_config
from .models import Email, Finding, Verdict
from .scoring import compute

log = logging.getLogger("phishscope.pipeline")


def run_pipeline(email: Email, cfg: Config | None = None,
                 analyzers: list[Analyzer] | None = None,
                 skip: set[str] | None = None) -> Verdict:
    cfg = cfg or get_config()
    analyzers = analyzers if analyzers is not None else get_analyzers(skip)
    findings: list[Finding] = []
    errors: list[str] = []

    if analyzers:
        ex = ThreadPoolExecutor(max_workers=min(8, len(analyzers)))
        futures = {ex.submit(a.run, email, cfg): a for a in analyzers}
        done, pending = wait(futures, timeout=cfg.limits.analyzer_timeout_s)

        for fut in done:
            a = futures[fut]
            try:
                result = fut.result()
            except Exception as e:                       # noqa: BLE001 - isolation is the point
                log.exception("analyzer %s crashed", a.name)
                errors.append(f"{a.name}: crashed ({type(e).__name__})")
                continue
            for f in result or []:
                if not isinstance(f, Finding):
                    errors.append(f"{a.name}: returned a non-Finding object, ignored")
                    continue
                f.weight = cfg.weight_for(f.id)          # weights come from config only
                findings.append(f)

        for fut in pending:
            fut.cancel()
            errors.append(f"{futures[fut].name}: timed out after {cfg.limits.analyzer_timeout_s}s")
        ex.shutdown(wait=False, cancel_futures=True)

    return compute(findings, cfg, email, sorted(errors))
