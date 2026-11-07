"""Split compacted entries into parts that fit the model's token budget.

Rules:
- Never cut an entry: a part ends before the entry that would overflow it.
- One entry larger than the whole budget is clipped (marked with "…[clipped]").
- An entry identical to an earlier one is replaced by a short "duplicate of" note,
  so the model doesn't count one event twice and the tokens aren't wasted.
- Parts don't overlap; continuity comes from the code-owned ledger instead.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Callable

from .compact import Compactor
from .logparse import Entry, iter_entry_texts


@dataclass
class Chunk:
    index: int
    entry_start: int  # index into the entries list, inclusive
    entry_end: int    # exclusive
    first_line: int
    last_line: int
    tokens: int       # tokens of the rendered log block (lines + newlines)


@dataclass
class Rendered:
    entry: Entry
    text: str            # compact text sent to the model
    tokens: int
    duplicate_of: int | None = None  # first line of the identical earlier entry
    raw_hash: str = field(default="", repr=False)


def render_all(path: str, fmt: str, entries: list[Entry], count_tokens: Callable[[str], int],
               max_entry_tokens: int) -> list[Rendered]:
    """Compact every entry, mark exact duplicates, and count tokens with the model tokenizer."""
    compactor = Compactor(fmt).fit(t for _, t in iter_entry_texts(path, entries))
    seen: dict[str, int] = {}
    out: list[Rendered] = []
    for entry, raw in iter_entry_texts(path, entries):
        h = hashlib.sha1(raw.strip().encode("utf-8", "replace")).hexdigest()
        if h in seen:
            text = f"L{entry.start_line} exact duplicate of L{seen[h]} (same event logged twice)"
            out.append(Rendered(entry, text, count_tokens(text) + 1, seen[h], h))
            continue
        seen[h] = entry.start_line
        text = compactor.render(entry.start_line, entry.end_line, raw)
        n = count_tokens(text) + 1  # +1 for the newline that joins lines
        while n > max_entry_tokens and len(text) > 40:
            text = text[: int(len(text) * max_entry_tokens / n) - 12] + "…[clipped]"
            n = count_tokens(text) + 1
        out.append(Rendered(entry, text, n, None, h))
    return out


def plan_chunks(rendered: list[Rendered], budget: int) -> list[Chunk]:
    chunks: list[Chunk] = []
    start, used = 0, 0
    for i, r in enumerate(rendered):
        if used + r.tokens > budget and i > start:
            chunks.append(_make(len(chunks), rendered, start, i, used))
            start, used = i, 0
        used += r.tokens
    if start < len(rendered):
        chunks.append(_make(len(chunks), rendered, start, len(rendered), used))
    return chunks


def _make(idx: int, rendered: list[Rendered], start: int, end: int, used: int) -> Chunk:
    return Chunk(idx, start, end, rendered[start].entry.start_line, rendered[end - 1].entry.end_line, used)


def chunk_text(rendered: list[Rendered], chunk: Chunk) -> str:
    return "\n".join(r.text for r in rendered[chunk.entry_start:chunk.entry_end])
