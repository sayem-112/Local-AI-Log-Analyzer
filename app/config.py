"""All tunable numbers in one place. Override with environment variables."""
import os
from pathlib import Path


def _int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("LOGSEC_DATA", ROOT / "data"))
UPLOAD_DIR = DATA_DIR / "uploads"
DB_PATH = DATA_DIR / "jobs.sqlite3"

LLM_URL = os.environ.get("LLM_URL", "http://127.0.0.1:8081")
MODEL_NAME = os.environ.get("MODEL_NAME", "Qwen3.5-0.8B-Q4_K_M")

# ---- Token budget (per model call). Everything must fit in CTX_TOKENS. ----
CTX_TOKENS = _int("CTX_TOKENS", 2048)
REPLY_TOKENS = _int("REPLY_TOKENS", 300)    # max_tokens for the reply
MEMORY_TOKENS = _int("MEMORY_TOKENS", 260)  # cap for carried context from earlier parts
SAFETY_TOKENS = _int("SAFETY_TOKENS", 40)   # slack for tokenizer edge effects
# The log budget is what is left after the (measured) instructions + template.

# ---- Reliability ----
CALL_TIMEOUT_S = _int("CALL_TIMEOUT_S", 180)
MAX_ATTEMPTS = _int("MAX_ATTEMPTS", 3)
MAX_UPLOAD_BYTES = _int("MAX_UPLOAD_BYTES", 5 * 1024 * 1024)
ALLOWED_EXTENSIONS = {".log", ".txt"}
