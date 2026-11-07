"""Pre-grouping: find routine traffic the model doesn't need to read.

A line is routine only when every condition holds:
- an HTTP GET/HEAD from a browser user agent ("Mozilla/"),
- answered with 2xx/3xx and a normal-sized response,
- on a path the file requests at least ROUTINE_MIN_HITS times,
- with a query string of plain characters only (no quotes, %, <, ;, .., spaces).

Routine lines are not sent to the model. The ledger still counts them (they stay in
the facts and in evidence), and each slice shows one summary line saying how many
routine requests it folded, so the model knows they existed.
"""
from __future__ import annotations

import re
from collections import Counter

from .ledger import _COMBINED, LARGE_BYTES
from .logparse import Entry, iter_entry_texts, try_json

ROUTINE_MIN_HITS = 3
_SAFE_QUERY = re.compile(r"^[\w=&.,:/-]*$")


def _fields(text: str) -> tuple | None:
    obj = try_json(text)
    if obj is not None:
        ua = str(obj.get("user_agent") or obj.get("ua") or "")
        return (str(obj.get("method", "")), str(obj.get("path") or obj.get("url") or ""), obj.get("status"),
                obj.get("response_bytes") or 0, ua, str(obj.get("level", "INFO")).upper())
    m = _COMBINED.match(text)
    if m:
        ua = re.findall(r'"([^"]*)"', text)
        return (m["method"], m["path"], int(m["status"]), int(m["size"]) if m["size"].isdigit() else 0,
                ua[-1] if len(ua) >= 3 else "", "INFO")
    return None


def routine_lines(path: str, entries: list[Entry]) -> set[int]:
    rows = []
    for e, text in iter_entry_texts(path, entries):
        if e.start_line == e.end_line and (f := _fields(text)):
            rows.append((e.start_line, f))
    hits = Counter(f[1].split("?")[0] for _, f in rows)
    out = set()
    for line, (method, p, status, size, ua, level) in rows:
        base, _, query = p.partition("?")
        if (method in ("GET", "HEAD") and isinstance(status, int) and 200 <= status < 400
                and ua.startswith("Mozilla/") and level in ("INFO", "DEBUG")
                and (size or 0) < LARGE_BYTES and hits[base] >= ROUTINE_MIN_HITS
                and _SAFE_QUERY.match(query) and ".." not in p):
            out.add(line)
    return out
