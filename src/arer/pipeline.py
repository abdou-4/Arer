"""
pipeline.py - runs every analyzer safely, then scores the result.

Guarantees
  * One analyzer crashing never stops the scan (error is recorded in the verdict).
  * One analyzer running too long is abandoned after analyzer_timeout_s.
  * Analyzers cannot set their own weights: the pipeline stamps them from rules.yaml.
  * R1.5: in production the analyzer stage runs in a KILLABLE subprocess
    (src/arer/worker.py) - a hung analyzer can no longer keep `arer scan`
    alive; the worker (and its whole process group) is killed at the timeout.
    Callers that inject analyzers (tests, direct API) keep the in-process
    thread path.
  * R1.4: analyzer errors are visible in the verdict and, through
    arer.exitcodes.scan_exit_code, can never produce a false clean-success
    exit: errors + CLEAN/INSUFFICIENT_DATA exit 7 (ANALYSIS_ERROR).
"""
from __future__ import annotations

from .analyzers.base import Analyzer, get_analyzers
from .config import Config, get_config
from .models import Email, Verdict
from .scoring import compute
from .worker import analyze_with_threads, run_analyzers


def run_pipeline(email: Email, cfg: Config | None = None,
                 analyzers: list[Analyzer] | None = None,
                 skip: set[str] | None = None) -> Verdict:
    cfg = cfg or get_config()
    if analyzers is not None:
        # injected analyzer list: the caller owns execution (tests, direct API)
        findings, errors = analyze_with_threads(email, cfg, analyzers)
    else:
        findings, errors = run_analyzers(email, cfg, skip)
    return compute(findings, cfg, email, sorted(errors))
