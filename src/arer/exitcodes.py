"""
exitcodes.py - the ONE place where the `arer scan` exit-code contract lives.

R0 of the Phase 6 remediation froze this table in one module so that the CLI,
the watcher, the docs and the tests all read the same map instead of
re-deriving it from numeric comparisons.

The contract (docs/cli-contract.md):

    0  CLEAN              a verdict; the mail is clean
    1  operational error  a file could not be read / loaded (scan, parse)
    2  usage error        bad flags / missing argument (Click convention)
    3  SUSPICIOUS         a verdict; alert
    4  LIKELY_PHISHING    a verdict; alert
    5  MALICIOUS          a verdict; alert
    6  INSUFFICIENT_DATA  a verdict; a NO-DECISION, never an alert
    7  ANALYSIS_ERROR     NOT a verdict: analyzers failed, result incomplete
                          (fail-closed; introduced with the R1.4 change)
    8  RECORD_ERROR       NOT a verdict: an alert record could not be written
                          (collision, disk full, permissions). Introduced so a
                          failed queue write is never hidden behind a verdict code.

Rules that replace the old blanket advice:

- Scripts must use an EXPLICIT allowlist, never "exit >= 3": code 6 is a
  no-decision (not an alert) and code 7 is an analysis failure (not a
  verdict at all). VERDICT_EXITS / ALERT_EXITS below are that allowlist.
- Batch scans: worst outcome wins, ranked by EXIT_SEVERITY. A verdict
  outranks a load failure (1), which outranks an analysis error (7), which
  outranks INSUFFICIENT_DATA (6), which outranks clean (0).
"""
from __future__ import annotations

from .models import Level

ANALYSIS_ERROR_EXIT = 7
RECORD_ERROR_EXIT = 8

# verdict level -> exit code (frozen; changing it is a contract change)
EXIT_CODES: dict[Level, int] = {
    Level.CLEAN: 0,
    Level.SUSPICIOUS: 3,
    Level.LIKELY_PHISHING: 4,
    Level.MALICIOUS: 5,
    Level.INSUFFICIENT_DATA: 6,
}

# The allowlist of VALID verdict outcomes - the only codes a completed scan
# can produce. Everything else (1, 2, 7, negative/signal codes, unknown
# future codes) is NOT a successful scan result.
VERDICT_EXITS = frozenset(EXIT_CODES.values())          # {0, 3, 4, 5, 6}

# The subset a script treats as an alert worth a look. INSUFFICIENT_DATA (6)
# is deliberately absent: it is a no-decision, not an alert.
ALERT_EXITS = frozenset(code for lv, code in EXIT_CODES.items()
                        if lv in (Level.SUSPICIOUS, Level.LIKELY_PHISHING, Level.MALICIOUS))

# Operational codes: the scan itself did not complete honestly.
OPERATIONAL_EXITS = frozenset({1, 2, ANALYSIS_ERROR_EXIT, RECORD_ERROR_EXIT})

# "Worst wins" batch order (the pre-remediation order [0, 1, 6, 3, 4, 5] is
# preserved exactly; code 7 slots between a load failure and a no-decision).
# A verdict outranks a load failure (1), which outranks an analysis error (7),
# which outranks a no-decision (6), which outranks clean (0). A failed alert-
# record write (8) outranks EVERY verdict: a queue that silently lost a record
# must never be reported as a clean success (code 8 is never in VERDICT_EXITS,
# so the watcher archives such mail under failed/).
EXIT_SEVERITY = {code: rank for rank, code in enumerate(
    [0, 1, ANALYSIS_ERROR_EXIT, 6, 3, 4, 5, RECORD_ERROR_EXIT])}


def exit_code_for(level: Level) -> int:
    """Exit code for one scanned file whose analyzers all completed."""
    return EXIT_CODES[level]


def is_alert_exit(code: int) -> bool:
    """The explicit allowlist predicate scripts should use instead of `>= 3`."""
    return code in ALERT_EXITS


def scan_exit_code(verdict) -> int:
    """Exit code for one scanned file, including the R1.4 fail-closed rule.

    A run with analyzer errors must never be presented as a fully successful
    result: errors plus CLEAN or INSUFFICIENT_DATA exit 7 (ANALYSIS_ERROR).
    A run whose positive findings raised the verdict (SUSPICIOUS or above)
    keeps its verdict exit - the findings stand - and the errors stay visible
    in the report, the alert record and the export (verdict.analyzer_errors).
    """
    if verdict.analyzer_errors and verdict.level in (Level.CLEAN, Level.INSUFFICIENT_DATA):
        return ANALYSIS_ERROR_EXIT
    return EXIT_CODES[verdict.level]


def is_analysis_incomplete(verdict) -> bool:
    """True when analyzers failed and the result is not a positive verdict:
    exactly the runs that exit 7 and land in the queue flagged incomplete."""
    return scan_exit_code(verdict) == ANALYSIS_ERROR_EXIT
