"""R1.4 + R1.5: fail-closed scoring and the killable analyzer worker.

R1.4 - a failed analyzer can never produce a clean success:
- errors + CLEAN/INSUFFICIENT_DATA exit 7 (ANALYSIS_ERROR);
- errors never erase positive findings: an analyzer crash next to a real
  malicious finding keeps the verdict level and its exit code, and the
  errors stay visible in the verdict, the report, the alert record;
- incomplete analyses still land in the alert queue (never silently
  dropped) but only BECAUSE of the error - they are not verdicts.

R1.5 - the analyzer stage runs in a killable subprocess:
- detection parity: the worker path produces the SAME findings/score/level
  as the in-process path (frozen baseline keeps passing too);
- a hung worker is killed (process group) within the analyzer budget plus
  slack, the mail fails closed, and the pool respawns for the next mail;
- a worker that hard-exits mid-request is a failed mail, not a success.

Fault injection (tests only): ARER_FAULT_INJECT=<analyzer>[:die|:hang].
"""
import subprocess
import sys
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from arer.config import load_config
from arer.exitcodes import ANALYSIS_ERROR_EXIT, EXIT_CODES, scan_exit_code
from arer.loader import load_any
from arer.models import Level
from arer.pipeline import run_pipeline
from arer.worker import reset_pool

CLEAN_EML = ("From: Sam <sam@example.org>\r\nTo: me@example.org\r\nSubject: Lunch\r\n"
             "Date: Mon, 05 Jan 2026 09:00:00 +0000\r\nMessage-ID: <1@example.org>\r\n"
             "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
             "Hi, lunch on Friday?")

PHISH_EML = ("From: news@discord.com\r\nTo: v@example.com\r\nSubject: win\r\n"
             "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
             "<html><noframes><xml><CZVVGQPYUH><QWERTYUIOP><ASDFGHJKL><!DOCTYPE><!DOCTYPE>"
             "<!DOCTYPE><!DOCTYPE>" + "<textarea></textarea>" * 25 + "<option>" * 10
             + '<div style="display:none !important;">x</div>' * 22
             + '<a><div style="background: url(\'https://img.example.net/p.jpg\'); '
               'width:640px;height:1138px"></div></a>')


@pytest.fixture
def fault_env(monkeypatch):
    """Set a fault-injection env var and make sure the worker pool restarts,
    so the fresh worker inherits the env. Restores afterwards."""
    def set_fault(value):
        monkeypatch.setenv("ARER_FAULT_INJECT", value)
        reset_pool()
    yield set_fault
    monkeypatch.delenv("ARER_FAULT_INJECT", raising=False)
    reset_pool()


@pytest.fixture(scope="module")
def mails(tmp_path_factory):
    d = tmp_path_factory.mktemp("mails")
    (d / "clean.eml").write_text(CLEAN_EML, encoding="utf-8")
    (d / "phish.eml").write_text(PHISH_EML, encoding="utf-8")
    return d


# --------------------------- R1.4: the exit rule ------------------------------ #


def test_scan_exit_code_fails_closed_on_errors():
    class V:
        level = Level.CLEAN
        analyzer_errors = ["urls: crashed (RuntimeError)"]

    assert scan_exit_code(V) == ANALYSIS_ERROR_EXIT
    V.level = Level.INSUFFICIENT_DATA
    assert scan_exit_code(V) == ANALYSIS_ERROR_EXIT
    V.level = Level.MALICIOUS
    assert scan_exit_code(V) == EXIT_CODES[Level.MALICIOUS], "findings stand, errors are visible"
    V.analyzer_errors = []
    V.level = Level.CLEAN
    assert scan_exit_code(V) == 0


def test_faulty_clean_scan_exits_7_not_0(mails, fault_env):
    fault_env("urls")
    r = CliRunner().invoke(main_scan := __import__("arer.cli", fromlist=["main"]).main,
                           ["scan", str(mails / "clean.eml"), "-q"])
    assert r.exit_code == ANALYSIS_ERROR_EXIT, r.output
    assert "[analysis incomplete" in r.output        # visible even in quiet mode


def test_faulty_scan_is_visible_in_full_report(mails, fault_env):
    fault_env("urls")
    r = CliRunner().invoke(__import__("arer.cli", fromlist=["main"]).main,
                           ["scan", str(mails / "clean.eml")])
    assert "Analyzer problems" in r.output and "urls: crashed" in r.output


def test_errors_never_erase_a_positive_verdict(mails, fault_env):
    fault_env("urls")
    r = CliRunner().invoke(__import__("arer.cli", fromlist=["main"]).main,
                           ["scan", str(mails / "phish.eml"), "-q"])
    level = Level(r.output.split()[0])
    assert level.rank >= Level.SUSPICIOUS.rank
    assert r.exit_code == EXIT_CODES[level], "the verdict exit stands"
    assert "[analysis incomplete" in r.output


def test_worker_death_mid_request_fails_closed(mails, fault_env):
    fault_env("urls:die")
    r = CliRunner().invoke(__import__("arer.cli", fromlist=["main"]).main,
                           ["scan", str(mails / "clean.eml"), "-q"])
    assert r.exit_code == ANALYSIS_ERROR_EXIT, r.output


def test_hung_worker_is_killed_within_the_budget(mails, fault_env, tmp_path):
    """R1.5: a hung analyzer cannot outlive the budget. The worker's thread
    timeout reports the analyzer as failed (fail closed), and the worker
    self-terminates because the stuck thread can never be killed - the parent
    starts a clean worker for the next mail."""
    import shutil
    cfg_dir = tmp_path / "cfg"
    shutil.copytree("config", cfg_dir)
    rules = cfg_dir / "rules.yaml"
    rules.write_text(rules.read_text(encoding="utf-8").replace(
        "analyzer_timeout_s: 10", "analyzer_timeout_s: 1"), encoding="utf-8")
    fault_env("urls:hang")
    cfg = load_config(cfg_dir)
    assert cfg.limits.analyzer_timeout_s == 1
    t0 = time.time()
    v = run_pipeline(load_any(mails / "clean.eml", cfg), cfg)
    elapsed = time.time() - t0
    assert any("timed out after 1s" in e for e in v.analyzer_errors), v.analyzer_errors
    assert elapsed < 15, f"kill boundary took {elapsed:.1f}s"


def test_batch_mixed_outcomes_keep_verdict_severity(mails, fault_env):
    """One analysis-failed clean mail (7) and one SUSPICIOUS mail (3): the
    batch reports 3 - a verdict outranks an analysis error."""
    fault_env("urls")
    r = CliRunner().invoke(__import__("arer.cli", fromlist=["main"]).main,
                           ["scan", str(mails / "clean.eml"), str(mails / "phish.eml"), "-q"])
    assert r.exit_code == 3, r.output
    assert "[analysis incomplete" in r.output        # and the failure is still visible


def test_incomplete_analysis_lands_in_the_queue(mails, fault_env, tmp_path):
    """R1.4: a failed analysis is never silently dropped - it joins the
    analyst queue, carrying its analyzer errors."""
    fault_env("urls")
    q = tmp_path / "q"
    r = CliRunner().invoke(__import__("arer.cli", fromlist=["main"]).main,
                           ["scan", str(mails / "clean.eml"), "-q", "--alerts", str(q)])
    assert r.exit_code == ANALYSIS_ERROR_EXIT
    from arer.alert import read_alerts
    reads = read_alerts(q)
    assert len(reads) == 1 and reads[0].alert.verdict.analyzer_errors


# --------------------------- R1.5: the kill boundary -------------------------- #


def test_worker_parity_with_inprocess_path(mails):
    """The subprocess worker must produce the SAME verdict as the in-process
    analyzer path - moving execution behind a process boundary is not allowed
    to change detection."""
    cfg = load_config()
    email = load_any(mails / "phish.eml", cfg)
    from arer.analyzers.base import get_analyzers
    v_thread = run_pipeline(email, cfg, analyzers=get_analyzers(set()))
    v_worker = run_pipeline(email, cfg)
    assert v_thread.score == v_worker.score
    assert v_thread.level == v_worker.level
    assert [f.id for f in v_thread.findings] == [f.id for f in v_worker.findings]
    assert dict(v_thread.by_category) == dict(v_worker.by_category)


def test_cli_scan_survives_a_hung_worker_and_terminates(tmp_path):
    """Full-process check (the review's exact scenario): `arer scan` with a
    hung analyzer must TERMINATE with exit 7 - not print the verdict and
    hang until an external timeout kills it."""
    import os
    import shutil
    cfg_dir = tmp_path / "cfg"
    shutil.copytree("config", cfg_dir)
    rules = cfg_dir / "rules.yaml"
    rules.write_text(rules.read_text(encoding="utf-8").replace(
        "analyzer_timeout_s: 10", "analyzer_timeout_s: 1"), encoding="utf-8")
    mail = tmp_path / "clean.eml"
    mail.write_text(CLEAN_EML, encoding="utf-8")
    env = dict(os.environ, ARER_FAULT_INJECT="urls:hang")
    t0 = time.time()
    proc = subprocess.run([sys.executable, "-m", "arer", "scan", str(mail), "-q",
                           "--config", str(cfg_dir)],
                          capture_output=True, text=True, timeout=60, env=env)
    elapsed = time.time() - t0
    assert proc.returncode == ANALYSIS_ERROR_EXIT, proc.stdout + proc.stderr
    assert elapsed < 30, f"scan took {elapsed:.1f}s - the kill boundary did not fire"
    # no descendant worker lingers after the parent exited (the test process's
    # own pool worker, if any, is excluded - it belongs to THIS pytest process)
    from arer.worker import get_pool
    own = get_pool()._proc
    own_pid = own.pid if own else None
    lingering = subprocess.run(["pgrep", "-f", "arer.worker"], capture_output=True, text=True)
    pids = [int(x) for x in lingering.stdout.split()]
    assert all(p == own_pid for p in pids), f"lingering worker processes: {pids} (own: {own_pid})"


def test_pool_respawns_after_a_hang_for_the_next_mail(mails, fault_env):
    """Killability holds per mail: after a hung mail the pool starts a fresh
    worker and the NEXT mail still gets a real verdict."""
    fault_env("urls:hang")
    r1 = CliRunner().invoke(__import__("arer.cli", fromlist=["main"]).main,
                            ["scan", str(mails / "clean.eml"), "-q"])
    assert r1.exit_code == ANALYSIS_ERROR_EXIT
    fault_env("")                                    # clear the fault, keep the pool restarted
    r2 = CliRunner().invoke(__import__("arer.cli", fromlist=["main"]).main,
                            ["scan", str(mails / "clean.eml"), "-q"])
    assert r2.exit_code == 0, r2.output


def test_worker_serve_survives_a_malformed_line(mails):
    """A malformed request line must produce an error answer with id None and
    the worker must KEEP SERVING. Before the fix the except block referenced
    `req`, which was unbound when the FIRST line failed json.loads (the
    UnboundLocalError killed the worker) and echoed the PREVIOUS request's
    id on later lines."""
    import json as _json
    cfg = load_config()
    email = load_any(mails / "clean.eml", cfg)
    request = _json.dumps({"id": 42, "email": email.model_dump(mode="json"),
                           "config": cfg.model_dump(mode="json"), "skip": []})
    proc = subprocess.Popen([sys.executable, "-m", "arer.worker", "--serve"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    try:
        proc.stdin.write(b"{not json\n")             # malformed FIRST line
        proc.stdin.flush()
        first = proc.stdout.readline()
        proc.stdin.write(request.encode("utf-8") + b"\n")
        proc.stdin.flush()
        second = proc.stdout.readline()
    finally:
        proc.stdin.close()
        proc.kill()
        proc.wait(timeout=10)

    assert first, "no answer for the malformed line: the worker died"
    a1 = _json.loads(first)
    assert a1["id"] is None, f"a malformed line must answer id None, got {a1['id']!r}"
    assert a1["findings"] == [] and a1["errors"], a1
    assert "worker request failed" in a1["errors"][0]
    assert second, "the worker died after the malformed line - it must keep serving"
    a2 = _json.loads(second)
    assert a2["id"] == 42, f"the next request must be answered normally: {a2}"
    assert a2["errors"] == [] and a2["findings"], a2
