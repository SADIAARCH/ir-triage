import os
from dotenv import load_dotenv

load_dotenv()

LABELS = ["BENIGN", "SUSPICIOUS_PROBE", "ACTIVE_EXPLOIT", "CRITICAL_INTRUSION"]

# Labels that are allowed to escalate to Bedrock (if confidence is high enough)
ESCALATE_LABELS = {"ACTIVE_EXPLOIT", "CRITICAL_INTRUSION"}

DECIDER_URL = os.getenv("DECIDER_URL", "http://localhost:8000")
USE_HEURISTIC = os.getenv("USE_HEURISTIC", "0") == "1"

AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
BEDROCK_MODEL_ID = os.getenv(
    "BEDROCK_MODEL_ID", "us.anthropic.claude-haiku-4-5-20251001-v1:0"
)
USE_MOCK_BEDROCK = os.getenv("USE_MOCK_BEDROCK", "0") == "1"

ESCALATE_CONFIDENCE = float(os.getenv("ESCALATE_CONFIDENCE", "0.90"))
ESCALATE_COOLDOWN_SEC = int(os.getenv("ESCALATE_COOLDOWN_SEC", "60"))
CONTEXT_LINES_PER_IP = 25
