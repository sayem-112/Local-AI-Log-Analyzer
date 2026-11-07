"""The analysis steps, independent of storage: prepare -> analyze each part -> finalize.

jobs.py wraps these with persistence, retries and progress. Keeping them separate
means the same code runs from the web app, the CLI and the tests.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import config
from .chunker import Chunk, Rendered, chunk_text, has_content, plan_chunks, render_all
from .routine import routine_lines
from .ledger import EventFacts, Flag, Ledger, extract
from .llm import LLM, LLMError
from .logparse import Entry, index_entries, read_entry
from .prompts import CHUNK_SCHEMA, CHUNK_SYSTEM, chunk_user_message
from .validate import LineView, parse_json, verify_findings


@dataclass
class Prepared:
    path: str
    fmt: str
    entries: list[Entry]
    rendered: list[Rendered]
    chunks: list[Chunk]
    log_budget: int
    base_prompt_tokens: int


def prepare(path: str, llm: LLM) -> Prepared:
    fmt, entries = index_entries(path)
    if not entries:
        raise ValueError("the file has no log entries")
    # Measure the fixed part of every prompt (system + template + empty user frame).
    base = llm.count_messages(_messages("", 0, 0, ""))
    log_budget = config.CTX_TOKENS - base - config.MEMORY_TOKENS - config.REPLY_TOKENS - config.SAFETY_TOKENS
    if log_budget < 200:
        raise ValueError(f"token budget too small for log text ({log_budget})")
    rendered = render_all(path, fmt, entries, llm.count, max_entry_tokens=log_budget)
    if config.FOLD_ROUTINE:
        fold = routine_lines(path, entries)
        for r in rendered:
            r.routine = r.entry.start_line in fold
    return Prepared(path, fmt, entries, rendered, plan_chunks(rendered, log_budget), log_budget, base)


def chunk_events(prep: Prepared, chunk: Chunk) -> tuple[list[EventFacts], dict[int, LineView]]:
    """Facts and per-line views for the entries of one part (text is read back from disk)."""
    events, views = [], {}
    with open(prep.path, "rb") as f:
        for r in prep.rendered[chunk.entry_start:chunk.entry_end]:
            raw = read_entry(f, r.entry)
            facts = extract(r.entry.start_line, raw)
            views[r.entry.start_line] = LineView(raw, r.text, facts)
            if r.duplicate_of is None:  # a duplicate is the same event; don't count it twice
                events.append(facts)
    return events, views


def build_messages(prep: Prepared, chunk: Chunk, ledger: Ledger, llm: LLM) -> tuple[list[dict], str, int]:
    """Prompt for one part, trimmed so prompt + reply always fits the context window."""
    events, _ = chunk_events(prep, chunk)
    memory = ledger.memory_for(events, llm.count, config.MEMORY_TOKENS)
    text = chunk_text(prep.rendered, chunk)
    while True:
        messages = _messages(memory, chunk.first_line, chunk.last_line, text)
        n = llm.count_messages(messages)
        if n + config.REPLY_TOKENS <= config.CTX_TOKENS:
            return messages, memory, n
        if not memory:
            raise LLMError(f"part {chunk.index} is {n} tokens, over budget", retryable=False)
        memory = "\n".join(memory.splitlines()[:-1])  # drop the least suspicious card


def analyze_chunk(prep: Prepared, chunk: Chunk, ledger: Ledger, llm: LLM) -> dict:
    """One model call for one part. Returns a JSON-serializable result (saved by jobs.py)."""
    if not has_content(prep.rendered, chunk):  # only routine traffic: nothing for the model to read
        return {"accepted": [], "rejected": [], "salvaged": False, "finish_reason": "skipped", "memory": "",
                "prompt_tokens": 0, "cached_tokens": 0, "gen_tokens": 0, "ms": 0}
    messages, memory, prompt_tokens = build_messages(prep, chunk, ledger, llm)
    reply = llm.chat(messages, CHUNK_SCHEMA, config.REPLY_TOKENS)
    data, salvaged = parse_json(reply.content)
    if data is None:
        raise LLMError(f"unparseable reply ({reply.finish_reason}): {reply.content[:120]!r}")
    _, views = chunk_events(prep, chunk)
    part = prep.rendered[chunk.entry_start:chunk.entry_end]
    line_to_entry = {n: r.entry.start_line for r in part for n in range(r.entry.start_line, r.entry.end_line + 1)}
    dups = {r.entry.start_line: r.duplicate_of for r in part if r.duplicate_of}
    accepted, rejected = verify_findings(data.get("f", []), views, line_to_entry, dups)
    return {
        "accepted": accepted, "rejected": rejected, "salvaged": salvaged,
        "finish_reason": reply.finish_reason, "memory": memory,
        "prompt_tokens": prompt_tokens, "cached_tokens": reply.cached_tokens,
        "gen_tokens": reply.gen_tokens, "ms": reply.ms,
    }


def apply_chunk(prep: Prepared, chunk: Chunk, ledger: Ledger, result: dict | None) -> None:
    """Fold one finished part into the ledger. Replaying this rebuilds the ledger on resume."""
    events, _ = chunk_events(prep, chunk)
    for ev in events:
        ledger.observe(ev)
    for f in (result or {}).get("accepted", []):
        ledger.add_flag(f["id"], Flag(f["t"], f["s"], f["l"], f["r"], chunk.index, f.get("quote_ok", False)))


def _messages(memory: str, first: int, last: int, text: str) -> list[dict]:
    return [
        {"role": "system", "content": CHUNK_SYSTEM},
        {"role": "user", "content": chunk_user_message(memory, first, last, text)},
    ]
