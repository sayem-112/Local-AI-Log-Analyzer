"""Thin client for llama-server: exact token counting and schema-constrained chat."""
from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

from . import config


class LLMError(Exception):
    """A failed call. `retryable` is False for errors a retry can't fix (e.g. prompt too long)."""

    def __init__(self, msg: str, retryable: bool = True):
        super().__init__(msg)
        self.retryable = retryable


@dataclass
class Reply:
    content: str
    finish_reason: str
    prompt_tokens: int
    cached_tokens: int
    gen_tokens: int
    ms: int


class LLM:
    def __init__(self, base_url: str = config.LLM_URL, timeout_s: int = config.CALL_TIMEOUT_S):
        self.http = httpx.Client(base_url=base_url, timeout=httpx.Timeout(timeout_s, connect=5))

    def healthy(self) -> bool:
        try:
            return self.http.get("/health", timeout=3).status_code == 200
        except httpx.HTTPError:
            return False

    def model_name(self) -> str:
        """The GGUF file the server actually loaded (so switching models shows up in the UI)."""
        try:
            path = self.http.get("/props", timeout=3).json().get("model_path", "")
            return path.replace("\\", "/").rsplit("/", 1)[-1].removesuffix(".gguf") or config.MODEL_NAME
        except (httpx.HTTPError, ValueError):
            return config.MODEL_NAME

    def count(self, text: str) -> int:
        r = self._post("/tokenize", {"content": text, "add_special": False})
        return len(r["tokens"])

    def count_messages(self, messages: list[dict]) -> int:
        """Exact prompt size: render the chat template, then tokenize the result."""
        prompt = self._post("/apply-template", {"messages": messages})["prompt"]
        return len(self._post("/tokenize", {"content": prompt, "add_special": True})["tokens"])

    def chat(self, messages: list[dict], schema: dict, max_tokens: int) -> Reply:
        t0 = time.monotonic()
        body = {
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0,
            "cache_prompt": True,
            "response_format": {"type": "json_schema", "json_schema": {"schema": schema}},
        }
        r = self._post("/v1/chat/completions", body)
        choice = r["choices"][0]
        t = r.get("timings", {})
        return Reply(
            content=choice["message"].get("content") or "",
            finish_reason=choice.get("finish_reason") or "",
            prompt_tokens=int(t.get("prompt_n", 0)) + int(t.get("cache_n", 0)),
            cached_tokens=int(t.get("cache_n", 0)),
            gen_tokens=int(t.get("predicted_n", 0)),
            ms=int((time.monotonic() - t0) * 1000),
        )

    def _post(self, path: str, body: dict) -> dict:
        try:
            r = self.http.post(path, json=body)
        except httpx.TimeoutException as e:
            raise LLMError(f"model call timed out: {path}") from e
        except httpx.HTTPError as e:
            raise LLMError(f"model server unreachable: {e}") from e
        if r.status_code >= 500:
            raise LLMError(f"model server error {r.status_code}: {r.text[:200]}")
        if r.status_code >= 400:
            raise LLMError(f"model rejected request {r.status_code}: {r.text[:200]}", retryable=False)
        return r.json()
