import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
SAMPLE = ROOT / "Cultive8_Workspace_Agrigen_Server.log"


class FakeLLM:
    """Stands in for llama-server: ~1 token per 3 chars, so tests run without a model."""

    def count(self, text: str) -> int:
        return max(1, len(text) // 3)

    def count_messages(self, messages) -> int:
        return sum(self.count(m["content"]) + 4 for m in messages) + 3

    def model_name(self) -> str:
        return "fake"


@pytest.fixture
def llm():
    return FakeLLM()


@pytest.fixture
def sample():
    return str(SAMPLE)
