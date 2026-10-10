"""Stream -> Decider policy -> threshold escalation -> Bedrock (async)."""
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .bedrock_reporter import get_reporter
from .config import (CONTEXT_LINES_PER_IP, ESCALATE_CONFIDENCE, ESCALATE_COOLDOWN_SEC,
                     ESCALATE_LABELS)
from .decider_client import Verdict, get_client
from .sources import extract_ip


@dataclass
class Event:
    ts: float
    line: str
    ip: str | None
    verdict: Verdict
    action: str  # IGNORE | LOG | ESCALATED | HUMAN_REVIEW | COOLDOWN


@dataclass
class Report:
    ip: str
    trigger: str
    text: str
    seconds: float
    ts: float = field(default_factory=time.time)


class TriagePipeline:
    def __init__(self, client=None, reporter=None):
        self.client = client or get_client()
        self.reporter = reporter or get_reporter()
        self.context = defaultdict(lambda: deque(maxlen=CONTEXT_LINES_PER_IP))
        self.last_escalation: dict[str, float] = {}
        self.pool = ThreadPoolExecutor(max_workers=2)
        self.futures: list = []
        self.counts = defaultdict(int)
        self.latencies: list[float] = []

    def process(self, line: str) -> Event:
        v = self.client.classify(line)
        ip = extract_ip(line) or self._recent_incident_ip()
        self.counts[v.label] += 1
        self.latencies.append(v.latency_ms)
        if ip:
            self.context[ip].append(line)  # keep context for every line, even benign

        if v.label == "BENIGN":
            action = "IGNORE"
        elif v.label not in ESCALATE_LABELS:
            action = "LOG"
        elif v.confidence <= ESCALATE_CONFIDENCE:
            action = "HUMAN_REVIEW"  # high-severity but unsure -> a person decides
        elif ip and time.time() - self.last_escalation.get(ip, 0) < ESCALATE_COOLDOWN_SEC:
            action = "COOLDOWN"      # already investigating this IP
        else:
            action = "ESCALATED"
            self._escalate(ip or "unknown", line)
        return Event(time.time(), line, ip, v, action)

    def _recent_incident_ip(self):
        """Lines with no IP (e.g. pam/sudo) belong to the incident we're already tracking."""
        if not self.last_escalation:
            return None
        ip, t = max(self.last_escalation.items(), key=lambda kv: kv[1])
        return ip if time.time() - t < ESCALATE_COOLDOWN_SEC else None

    def _escalate(self, ip: str, trigger: str):
        self.last_escalation[ip] = time.time()
        ctx = list(self.context[ip])

        def job():
            t0 = time.time()
            try:
                text = self.reporter.report(ip, ctx, trigger)
            except Exception as e:  # noqa: BLE001
                text = f"Report generation failed: {e}"
            return Report(ip, trigger, text, time.time() - t0)

        self.futures.append(self.pool.submit(job))

    def collect_reports(self) -> list[Report]:
        done = [f for f in self.futures if f.done()]
        self.futures = [f for f in self.futures if not f.done()]
        return [f.result() for f in done]

    @property
    def avg_latency_ms(self) -> float:
        return sum(self.latencies) / len(self.latencies) if self.latencies else 0.0


if __name__ == "__main__":
    import sys
    from .sources import simulate
    pipe = TriagePipeline()
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    for i, line in enumerate(simulate(rate_per_sec=200)):
        if i >= n:
            break
        e = pipe.process(line)
        if e.action != "IGNORE":
            print(f"{e.verdict.label:19s} {e.verdict.confidence:.2f} {e.action:12s} {line[:90]}")
    time.sleep(3)
    for r in pipe.collect_reports():
        print("\n=== REPORT", r.ip, f"({r.seconds:.1f}s) ===\n", r.text)
    print(f"\navg classify latency: {pipe.avg_latency_ms:.2f} ms | counts: {dict(pipe.counts)}")
