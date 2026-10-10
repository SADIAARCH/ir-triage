"""Talks to a local `strands-decider serve` instance, with a rule-based fallback."""
import json
import re
import sys
import time
from dataclasses import dataclass, field

import requests

from .config import DECIDER_URL, LABELS, USE_HEURISTIC

INSTRUCTIONS = (
    "You are a security log triage policy. Classify this single log line. "
    "BENIGN = normal user or service activity. "
    "SUSPICIOUS_PROBE = scanning, enumeration, failed logins, odd user agents (nmap, nikto, sqlmap) "
    "with no sign of success. "
    "ACTIVE_EXPLOIT = an attempted exploit payload (SQL injection, path traversal, command injection, "
    "Log4Shell, shellcode, webshell upload). "
    "CRITICAL_INTRUSION = evidence the attacker succeeded (successful login after brute force, "
    "root shell, privilege escalation, data exfiltration)."
)


@dataclass
class Verdict:
    label: str
    confidence: float
    probs: dict = field(default_factory=dict)
    latency_ms: float = 0.0
    source: str = "decider"


class DeciderClient:
    def __init__(self, url: str = DECIDER_URL, timeout: float = 5.0):
        self.url = url.rstrip("/") + "/v1/systemone"
        self.timeout = timeout
        self.session = requests.Session()  # keep-alive = lower latency

    def raw(self, line: str) -> dict:
        payload = {
            "state": line,
            "questions": {
                "verdict": {
                    "type": "choice",
                    "instructions": INSTRUCTIONS,
                    "options": LABELS,
                }
            },
        }
        r = self.session.post(self.url, json=payload, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def classify(self, line: str) -> Verdict:
        t0 = time.perf_counter()
        data = self.raw(line)
        wall_ms = (time.perf_counter() - t0) * 1000
        return self._parse(data, wall_ms)

    @staticmethod
    def _parse(data: dict, wall_ms: float) -> Verdict:
        ans = data["answers"]["verdict"]
        probs = None
        for key in ("probs", "probabilities", "distribution", "options", "scores"):
            val = ans.get(key)
            if isinstance(val, dict):
                probs = {str(k): float(v) for k, v in val.items()}
                break
            if isinstance(val, list) and val and isinstance(val[0], dict):
                probs = {}
                for item in val:
                    name = item.get("label") or item.get("option") or item.get("name")
                    p = item.get("prob") or item.get("probability") or item.get("score")
                    probs[str(name)] = float(p)
                break
        if not probs:
            raise ValueError(f"Unrecognised Decider response shape: {json.dumps(ans)[:300]}")
        label = max(probs, key=probs.get)
        return Verdict(
            label=label,
            confidence=probs[label],
            probs=probs,
            latency_ms=float(data.get("latency_ms", wall_ms)),
            source="decider",
        )


# ---------------------------------------------------------------- fallback
_RULES = [
    ("CRITICAL_INTRUSION", 0.97, re.compile(
        r"Accepted (password|publickey) for root|session opened for user root|"
        r"sudo:.*COMMAND=/bin/(ba)?sh|/etc/shadow.* 200|exfil|reverse shell connected", re.I)),
    ("ACTIVE_EXPLOIT", 0.95, re.compile(
        r"union(\s|%20|\+)+select|'\s*or\s*'?1'?='?1|\.\./\.\./|%2e%2e%2f|"
        r"\$\{jndi:|;\s*(cat|wget|curl|nc)\s|cmd=|/bin/sh|<script>|\.php\?.*=(http|ftp)", re.I)),
    ("SUSPICIOUS_PROBE", 0.88, re.compile(
        r"nmap|nikto|sqlmap|masscan|Failed password|Invalid user|"
        r"/(wp-login|phpmyadmin|\.env|\.git|admin)\b.*\s(404|403)\s|authentication failure", re.I)),
]


class HeuristicClient:
    """Dev stand-in so you can build the whole pipeline without the model running."""

    def classify(self, line: str) -> Verdict:
        t0 = time.perf_counter()
        for label, conf, rx in _RULES:
            if rx.search(line):
                break
        else:
            label, conf = "BENIGN", 0.96
        probs = {l: (1 - conf) / 3 for l in LABELS}
        probs[label] = conf
        return Verdict(label, conf, probs, (time.perf_counter() - t0) * 1000, "heuristic")


def get_client():
    if USE_HEURISTIC:
        print("[triage] USE_HEURISTIC=1 -> rule engine (not the model)", file=sys.stderr)
        return HeuristicClient()
    client = DeciderClient()
    try:
        client.classify("GET /index.html 200")
        return client
    except Exception as e:  # noqa: BLE001
        print(f"[triage] Decider server not reachable ({e}); using heuristic fallback", file=sys.stderr)
        return HeuristicClient()


if __name__ == "__main__":
    # `python -m triage.decider_client` prints the RAW server response so you can
    # verify the response shape matches _parse() on your install.
    c = DeciderClient()
    line = '10.0.0.5 - - [10/Oct/2026:10:00:01] "GET /?id=1 UNION SELECT user,pass FROM users-- HTTP/1.1" 200 512'
    print(json.dumps(c.raw(line), indent=2))
