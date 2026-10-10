"""Escalation target: Amazon Bedrock (Converse API) writes the incident report."""
import time

from .config import AWS_REGION, BEDROCK_MODEL_ID, USE_MOCK_BEDROCK

SYSTEM = """You are a senior incident responder writing for a SOC team.
You receive log lines from ONE source IP that a fast triage model flagged.
Be precise, only claim what the logs support, and label guesses as hypotheses.
Output Markdown with exactly these sections:
## Summary
## Attack Timeline (table: time | evidence | meaning)
## Root Cause Analysis
## STRIDE Threat Model (table: category | applies? | evidence)
## MITRE ATT&CK Mapping
## Containment Playbook (numbered steps)
## Containment Script (one bash code block using ufw/iptables; comment every line)
## Confidence & Gaps"""


class BedrockReporter:
    def __init__(self):
        import boto3  # imported lazily so mock mode works without AWS creds
        self.client = boto3.client("bedrock-runtime", region_name=AWS_REGION)

    def report(self, ip: str, lines: list[str], trigger: str) -> str:
        prompt = (
            f"Source IP: {ip}\nTrigger line: {trigger}\n\nLog lines (oldest first):\n"
            + "\n".join(lines)
        )
        resp = self.client.converse(
            modelId=BEDROCK_MODEL_ID,
            system=[{"text": SYSTEM}],
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig={"maxTokens": 2000, "temperature": 0.2},
        )
        return resp["output"]["message"]["content"][0]["text"]


class MockReporter:
    def report(self, ip: str, lines: list[str], trigger: str) -> str:
        time.sleep(2)  # pretend to think
        return (
            f"## Summary\n(MOCK) {ip} escalated after: `{trigger[:90]}`\n\n"
            f"## Attack Timeline\n{len(lines)} related lines captured.\n\n"
            "## Containment Script\n```bash\nsudo ufw deny from " + ip + "\n```\n"
        )


def get_reporter():
    return MockReporter() if USE_MOCK_BEDROCK else BedrockReporter()
