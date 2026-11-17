"""
worker.py - R1.5: analyzers run behind a KILLABLE process boundary.

The pre-remediation pipeline ran every analyzer in threads. Python threads
cannot be killed, so a truly stuck analyzer kept the whole `arer scan`
interpreter alive after the verdict had printed (reproduced in the review:
verdict printed, process hung until an external 90s timeout).

Design (remediation plan R1.5):

- Analyzer execution runs in a separate WORKER PROCESS (`python -m arer
  worker --serve`) in its own session (process group). The worker runs the
  exact same analyzer code with the same weights in the same thread pool, so
  detection results are identical to the pre-remediation engine.
- One worker serves a whole batch (scan of a folder, an eval run, the test
  process) with one JSON request per mail; after a hang or crash the parent
  kills the ENTIRE process group (SIGKILL), reports the mail as failed
  closed (R1.4), and a fresh worker is started for the next mail. Killability
  therefore holds PER MAIL: no hung analyzer can outlive its timeout.
- IPC is line-delimited JSON on stdin/stdout (one bounded request, one
  bounded answer). No pickle, no executable deserialization: the request is
  the Email model's own JSON plus the validated Config's JSON; the answer is
  a JSON list of findings and the list of analyzer errors.
- The worker's stderr is DISCARDED (DEVNULL): a chatty analyzer can never
  fill an unread 64 KB pipe and stall its own request until the timeout kill.
- Worker output is capped; an oversized or malformed answer is an analyzer
  error, never a silent success. Request sizes are capped on BOTH sides: the
  parent refuses to send a too-large request, and the worker answers a
  too-large line with an error instead of skipping it silently.

The pipeline keeps an in-process thread path for INJECTED analyzers (tests
and direct API users); production scans always go through the worker.

Fault injection for tests only (never a supported interface):
  ARER_FAULT_INJECT=<analyzer name>       that analyzer raises
  ARER_FAULT_INJECT=<name>:die            that analyzer hard-exits the worker
  ARER_FAULT_INJECT=<name>:hang           that analyzer sleeps (kill boundary)
"""
from __future__ import annotations

import atexit
import json
import os
import queue as _queue
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait

from .analyzers.base import Analyzer, get_analyzers
from .config import Config
from .models import Email, Finding

# Parent-side caps: a worker answer is at most this many bytes (findings are
# length-limited by the models already) and the parent waits at most the
# per-mail analyzer budget plus this much slack (startup/shutdown, kill, wait).
_MAX_WORKER_OUTPUT = 16 * 1024 * 1024
_MAX_REQUEST_BYTES = 64 * 1024 * 1024
_WORKER_SLACK_S = 5.0        # on top of the analyzer budget: covers IPC + kill + wait

_WORKER_CMD = (sys.executable, "-m", "arer.worker", "--serve")

# Sentinel queued by _pump when ONE answer line exceeds _MAX_WORKER_OUTPUT:
# the huge line is never queued (it would sit in memory whole), the parent
# fails the request closed instead.
_ANSWER_TOO_LARGE = object()


def analyze_with_threads(email: Email, cfg: Config, analyzers: list[Analyzer]
                         ) -> tuple[list[Finding], list[str]]:
    """The analyzer stage, in-process. Same behaviour as before the
    remediation; used by the worker AND by callers that inject analyzers."""
    findings: list[Finding] = []
    errors: list[str] = []

    if analyzers:
        fault = os.environ.get("ARER_FAULT_INJECT", "")
        ex = ThreadPoolExecutor(max_workers=min(8, len(analyzers)))
        futures = {ex.submit(_run_one, a, email, cfg, fault): a for a in analyzers}
        done, pending = wait(futures, timeout=cfg.limits.analyzer_timeout_s)

        for fut in done:
            a = futures[fut]
            try:
                result = fut.result()
            except Exception as e:                       # noqa: BLE001 - isolation is the point
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

    return findings, errors


def _run_one(a: Analyzer, email: Email, cfg: Config, fault: str):
    """Run one analyzer, honoring the TEST-ONLY fault injection hooks."""
    for spec in filter(None, fault.split(",")):
        name, _, mode = spec.partition(":")
        if name == a.name:
            if mode == "hang":
                time.sleep(600)
            elif mode == "die":
                os._exit(9)
            raise RuntimeError("fault injection")
    return a.run(email, cfg)


# --------------------------------------------------------------------------- #
# the worker process side
# --------------------------------------------------------------------------- #

def _serve() -> int:
    """`python -m arer worker --serve`: line-delimited JSON requests on stdin,
    one JSON answer line (with the echoed request id) per request on stdout.
    A crash kills only this process - the parent fails that mail closed and
    starts a fresh worker for the next one."""
    for raw in sys.stdin.buffer:
        req = None                                       # reset per iteration: a malformed
        if len(raw) > _MAX_REQUEST_BYTES:                # line must answer id None, not echo
            out = {"id": None, "findings": [],           # the PREVIOUS request's id, and the
                   "errors": ["worker request too large, not analyzed"]}
        else:
            try:                                         # UnboundLocalError that killed the
                req = json.loads(raw.decode("utf-8"))    # worker here is exactly the bug.
                email = Email.model_validate(req["email"])
                cfg = Config.model_validate(req["config"])
                analyzers = get_analyzers(set(req.get("skip") or ()))
                findings, errors = analyze_with_threads(email, cfg, analyzers)
                out = {"id": req.get("id"), "findings": [f.model_dump(mode="json") for f in findings],
                       "errors": errors}
            except Exception as e:                       # noqa: BLE001 - answer, then take the next mail
                out = {"id": req.get("id") if isinstance(req, dict) else None,
                       "findings": [],
                       "errors": [f"worker request failed: {type(e).__name__}: {str(e)[:200]}"]}
        try:
            sys.stdout.buffer.write(json.dumps(out).encode("utf-8") + b"\n")
            sys.stdout.buffer.flush()
        except Exception:                                # noqa: BLE001 - parent is gone
            return 3
        # R1.5: a timed-out analyzer is a thread we cannot kill - this worker
        # is polluted (the stuck thread leaks forever). Answer honestly, then
        # die so the parent starts a clean worker for the next mail.
        if any("timed out" in e for e in out["errors"]):
            os._exit(4)
    return 0


def _pump(proc, q) -> None:
    """Reader thread: move the worker's answer lines onto the queue until EOF.
    Reading is BOUNDED: iterating `for line in proc.stdout` buffers ONE WHOLE
    line (however big) before the len() check ever runs - the cap protected
    the queue, not the reader's memory. readline(_MAX_WORKER_OUTPUT + 1)
    never holds more than the cap plus one byte; a line that overflows the
    cap becomes the _ANSWER_TOO_LARGE sentinel (never the huge line itself)
    and its remainder is drained in bounded chunks until the newline (or
    EOF) so the stream stays in sync. The parent kills the worker on the
    sentinel anyway."""
    chunk_cap = _MAX_WORKER_OUTPUT + 1
    try:
        while True:
            chunk = proc.stdout.readline(chunk_cap)
            if not chunk:
                break                                  # EOF
            if len(chunk) > _MAX_WORKER_OUTPUT:
                q.put(_ANSWER_TOO_LARGE)
                while not chunk.endswith(b"\n"):       # the line continues past the cap:
                    chunk = proc.stdout.readline(chunk_cap)   # drain it, bounded
                    if not chunk:
                        break                          # EOF mid-line
                continue
            q.put(chunk)
    except Exception:                                 # noqa: BLE001 - reader dies with the pipe
        pass
    q.put(None)                                       # EOF marker


def worker_main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--serve":
        return _serve()
    sys.stderr.write("usage: python -m arer.worker --serve\n")
    return 2


# --------------------------------------------------------------------------- #
# the parent side: one killable worker per process, respawned on hang/crash
# --------------------------------------------------------------------------- #

class _WorkerDied(Exception):
    pass


class WorkerPool:
    """A reusable worker process. Every request is kill-bound: a mail that
    exceeds its budget gets its worker (and the whole process group) killed,
    its own result failed closed, and the next mail gets a fresh worker."""

    def __init__(self):
        self._proc: subprocess.Popen | None = None
        self._lines: _queue.Queue | None = None
        self._reader: threading.Thread | None = None
        self._counter = 0
        self._lock = threading.Lock()

    # ---- lifecycle -------------------------------------------------------- #
    def _start(self) -> None:
        popen_kwargs: dict = {}
        if os.name == "posix":
            popen_kwargs["start_new_session"] = True      # own group: killable as a tree
        try:
            self._proc = subprocess.Popen(
                list(_WORKER_CMD),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, **popen_kwargs)
            # stderr is deliberately DEVNULL: a PIPE nobody reads blocks a
            # chatty worker after ~64 KB until the timeout kill.
        except OSError as e:
            raise _WorkerDied(f"analyzer worker: could not start ({e})") from e
        q: _queue.Queue = _queue.Queue()
        self._lines = q

        self._reader = threading.Thread(target=_pump, args=(self._proc, q), daemon=True)
        self._reader.start()

    def kill(self) -> None:
        proc, self._proc, self._lines = self._proc, None, None
        if proc is None:
            return
        if os.name == "posix":
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)   # descendants too
            except (ProcessLookupError, PermissionError):
                pass
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        # R8: close the pipes so no handle lingers for the GC to complain about
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass

    # ---- one mail --------------------------------------------------------- #
    def run_analyzers(self, email: Email, cfg: Config, skip: set[str] | None
                      ) -> tuple[list[Finding], list[str]]:
        with self._lock:                                  # one mail at a time, like the old pool
            self._counter += 1
            rid = self._counter
            request = json.dumps({
                "id": rid,
                "email": email.model_dump(mode="json"),
                "config": cfg.model_dump(mode="json"),
                "skip": sorted(skip or ()),
            }).encode("utf-8")
            if len(request) > _MAX_REQUEST_BYTES:
                # fail FAST, before any worker is started or killed: a request
                # the worker must refuse anyway is an error for THIS mail only
                return [], ["analyzer worker: request too large, not analyzed"]
            timeout = float(cfg.limits.analyzer_timeout_s) + _WORKER_SLACK_S
            if self._proc is None:
                try:
                    self._start()
                except _WorkerDied as e:
                    return [], [str(e)]
            assert self._proc is not None and self._lines is not None
            try:
                self._proc.stdin.write(request + b"\n")
                self._proc.stdin.flush()
            except (BrokenPipeError, OSError):
                self.kill()                               # worker died between mails
                try:
                    self._start()
                    self._proc.stdin.write(request + b"\n")
                    self._proc.stdin.flush()
                except (_WorkerDied, OSError, BrokenPipeError) as e:
                    return [], [f"analyzer worker: could not start ({e})"]
            # wait for THE answer to THIS request; anything else = dead worker
            deadline_line = None
            try:
                while True:
                    try:
                        line = self._lines.get(timeout=timeout)
                    except _queue.Empty as e:
                        raise TimeoutError from e
                    if line is None:                      # EOF: worker crashed mid-request
                        raise _WorkerDied("analyzer worker: died mid-request (crash or OOM)")
                    if line is _ANSWER_TOO_LARGE:         # capped by the reader thread
                        raise _WorkerDied("analyzer worker: oversized answer, treated as an error")
                    try:
                        answer = json.loads(line.decode("utf-8"))
                    except Exception as e:                # noqa: BLE001 - malformed line fails closed
                        raise _WorkerDied(f"analyzer worker: malformed answer ({type(e).__name__})") from e
                    if answer.get("id") == rid:
                        deadline_line = answer
                        break
                    # an answer for a request we already abandoned: ignore it
            except TimeoutError:
                self.kill()
                return [], [f"analyzer worker: killed after hanging {timeout:g}s (R1.5 kill boundary)"]
            except _WorkerDied as e:
                self.kill()
                return [], [str(e)]
            if len(line) > _MAX_WORKER_OUTPUT:
                self.kill()
                return [], ["analyzer worker: oversized answer, treated as an error"]
            try:
                findings = [Finding.model_validate(f) for f in deadline_line["findings"]]
                errors = [str(e) for e in deadline_line["errors"]]
            except Exception as e:                        # noqa: BLE001 - bad shapes fail closed
                return [], [f"analyzer worker: unusable answer ({type(e).__name__})"]
            return findings, errors


_POOL: WorkerPool | None = None


def get_pool() -> WorkerPool:
    global _POOL
    if _POOL is None:
        _POOL = WorkerPool()
        atexit.register(_POOL.kill)
    return _POOL


def reset_pool() -> None:
    """Drop the cached worker (tests use this after changing fault-injection
    env vars, so the next mail gets a freshly started worker)."""
    global _POOL
    if _POOL is not None:
        _POOL.kill()
    _POOL = None


def run_analyzers(email: Email, cfg: Config, skip: set[str] | None = None
                  ) -> tuple[list[Finding], list[str]]:
    """Run the analyzer stage behind the kill boundary. Any worker crash,
    timeout, malformed or oversized answer becomes analyzer ERRORS - never a
    silent success - so scoring can fail closed (R1.4)."""
    try:
        return get_pool().run_analyzers(email, cfg, skip)
    except _WorkerDied as e:
        return [], [str(e)]


if __name__ == "__main__":
    sys.exit(worker_main())
