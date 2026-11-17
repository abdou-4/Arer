"""R0: the exit-code contract, frozen in one module and one test file.

The remediation plan (R0) requires:
- every supported exit code has one unambiguous meaning, documented in one
  place (src/arer/exitcodes.py) and tested here;
- no documentation claims that code 6 is an alert, and no stale advice to
  use `exit >= 3` (code 6 is a no-decision; code 7 is an analysis failure,
  not a verdict);
- scripts use an explicit allowlist (VERDICT_EXITS / ALERT_EXITS /
  is_alert_exit), never a numeric range.
"""
import re
from pathlib import Path

from arer.exitcodes import (ALERT_EXITS, ANALYSIS_ERROR_EXIT, EXIT_CODES, EXIT_SEVERITY,
                            OPERATIONAL_EXITS, RECORD_ERROR_EXIT, VERDICT_EXITS, exit_code_for,
                            is_alert_exit)
from arer.models import Level

ROOT = Path(__file__).resolve().parents[1]


def test_exit_code_mapping_is_frozen():
    assert EXIT_CODES == {
        Level.CLEAN: 0,
        Level.SUSPICIOUS: 3,
        Level.LIKELY_PHISHING: 4,
        Level.MALICIOUS: 5,
        Level.INSUFFICIENT_DATA: 6,
    }
    assert exit_code_for(Level.CLEAN) == 0
    assert exit_code_for(Level.SUSPICIOUS) == 3
    assert exit_code_for(Level.LIKELY_PHISHING) == 4
    assert exit_code_for(Level.MALICIOUS) == 5
    assert exit_code_for(Level.INSUFFICIENT_DATA) == 6
    assert ANALYSIS_ERROR_EXIT == 7


def test_allowlists_are_explicit():
    # the allowlist of valid verdict outcomes: the only codes a completed
    # scan produces - and what the watcher treats as "handled"
    assert VERDICT_EXITS == {0, 3, 4, 5, 6}
    # alerts are an explicit subset: code 6 is a NO-DECISION, never an alert
    assert ALERT_EXITS == {3, 4, 5}
    assert is_alert_exit(3) and is_alert_exit(4) and is_alert_exit(5)
    assert not is_alert_exit(0)
    assert not is_alert_exit(6), "INSUFFICIENT_DATA must never count as an alert"
    assert not is_alert_exit(7), "ANALYSIS_ERROR is not a verdict, never an alert"
    assert not is_alert_exit(1) and not is_alert_exit(2)
    assert not is_alert_exit(-9), "signal kills are never verdicts"
    assert OPERATIONAL_EXITS == {1, 2, 7, RECORD_ERROR_EXIT}


def test_record_error_code_is_not_a_verdict():
    """Code 8 (RECORD_ERROR): an alert record could not be written. It is an
    operational failure, never a verdict - so it must stay OUT of the verdict
    and alert allowlists (the watcher archives code-8 mail under failed/)
    and it must outrank every verdict in the batch severity order, so a lost
    record is never hidden behind a MALICIOUS exit 5."""
    assert RECORD_ERROR_EXIT == 8
    assert 8 not in VERDICT_EXITS, "a failed record write is not a completed scan"
    assert 8 not in ALERT_EXITS
    assert not is_alert_exit(8)
    assert 8 in OPERATIONAL_EXITS
    assert EXIT_SEVERITY[RECORD_ERROR_EXIT] > EXIT_SEVERITY[5], \
        "a lost alert record must outrank any verdict, including MALICIOUS"
    assert 8 not in EXIT_CODES.values()


def test_batch_severity_order_is_unchanged_and_covers_all_codes():
    # worst-wins order preserved from the pre-remediation [0, 1, 6, 3, 4, 5];
    # code 7 slots between a load failure and a no-decision; code 8 (a failed
    # record write) outranks every verdict.
    order = sorted(EXIT_SEVERITY, key=EXIT_SEVERITY.get)
    assert order == [0, 1, 7, 6, 3, 4, 5, 8]
    for code in {0, 1, 2, 3, 4, 5, 6, 7, 8}:
        assert code in EXIT_SEVERITY or code == 2   # 2 never enters batch aggregation


def test_docs_no_longer_claim_ge3_means_alert():
    """The stale wording the remediation plan names must be gone everywhere."""
    stale_patterns = [
        r"`?exit >= 3`? as an alert",
        r"returns? 2 when anything",
        r"exit >= 3 means an alert",
    ]
    files = [ROOT / "README.md", ROOT / "USAGE.md", ROOT / "docs" / "cli-contract.md",
             ROOT / "src" / "arer" / "cli.py", ROOT / "src" / "arer" / "watcher.py"]
    for f in files:
        text = f.read_text(encoding="utf-8")
        for pat in stale_patterns:
            assert not re.search(pat, text), f"{f.name} still carries stale exit-code advice: {pat}"


def test_cli_contract_doc_has_the_full_frozen_table():
    text = (ROOT / "docs" / "cli-contract.md").read_text(encoding="utf-8")
    for line in ["| 0 |", "| 1 |", "| 2 |", "| 3 |", "| 4 |", "| 5 |",
                 "| 6 |", "| 7 |", "| 8 |", "INSUFFICIENT_DATA", "ANALYSIS_ERROR",
                 "RECORD_ERROR"]:
        assert line in text, f"docs/cli-contract.md is missing the frozen row/term: {line}"


def test_cli_docstring_describes_the_same_contract():
    import arer.cli as cli
    doc = cli.__doc__ or ""
    for term in ("INSUFFICIENT_DATA", "ANALYSIS_ERROR", "RECORD_ERROR", "SUSPICIOUS", "MALICIOUS"):
        assert term in doc
    assert "exit >= 3" not in doc.replace('never "exit >= 3"', "")
