import time
from arer.analyzers.base import Analyzer
from arer.config import load_config
from arer.models import Email
from arer.pipeline import run_pipeline

cfg = load_config()

class Good(Analyzer):
    name = "good"
    def run(self, email, cfg): return [self.finding("auth.spf_fail", "x")]
class Boom(Analyzer):
    name = "boom"
    def run(self, email, cfg): raise RuntimeError("secret internals")
class Liar(Analyzer):
    name = "liar"
    def run(self, email, cfg):
        f = self.finding("auth.spf_fail", "x"); f.weight = 999; return [f, "junk"]
class Slow(Analyzer):
    name = "slow"
    def run(self, email, cfg): time.sleep(3); return []

def test_crash_is_isolated():
    v = run_pipeline(Email(), cfg, analyzers=[Good(), Boom()])
    assert v.score == 15 and any("boom: crashed" in e for e in v.analyzer_errors)
    assert "secret internals" not in str(v.analyzer_errors)

def test_weight_comes_from_config():
    v = run_pipeline(Email(), cfg, analyzers=[Liar()])
    assert v.findings[0].weight == 15 and any("non-Finding" in e for e in v.analyzer_errors)

def test_timeout():
    cfg2 = cfg.model_copy(deep=True); cfg2.limits.analyzer_timeout_s = 1
    v = run_pipeline(Email(), cfg2, analyzers=[Good(), Slow()])
    assert v.score == 15 and any("slow: timed out" in e for e in v.analyzer_errors)
