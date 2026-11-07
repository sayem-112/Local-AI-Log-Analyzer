"""Read a log file into entries that keep their original line numbers.

An entry is one log event. Most formats use one line per event, but stack traces
and pretty-printed messages span several lines, so continuation lines are folded
into the entry above them. Only byte offsets are kept in memory; text is re-read
from disk when a chunk is built, so the job never holds extra copies of the log.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Iterator

# A line that starts a new event in plain-text logs: ISO/syslog/Apache-style
# timestamps, a bracketed level, or a leading IP address.
_TEXT_START = re.compile(
    r"^(\d{4}-\d{2}-\d{2}|\d{2}/\w{3}/\d{4}|\w{3} +\d{1,2} \d{2}:\d{2}|\[|\d{1,3}(\.\d{1,3}){3}\s|"
    r"(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|TRACE)\b)"
)
_CONTINUATION = re.compile(r"^(\s|at |Caused by|\.\.\.|Traceback|File \")")


@dataclass(frozen=True)
class Entry:
    start_line: int  # 1-based, inclusive
    end_line: int    # 1-based, inclusive
    offset: int      # byte offset of the first line in the file
    length: int      # byte length of all lines in the entry


def detect_format(path: str, sample: int = 50) -> str:
    """Return 'jsonl' when most non-empty lines are JSON objects, else 'text'."""
    seen = json_like = 0
    with open(path, "rb") as f:
        for raw in f:
            s = raw.strip()
            if not s:
                continue
            seen += 1
            if s.startswith(b"{"):
                json_like += 1
            if seen >= sample:
                break
    return "jsonl" if seen and json_like / seen >= 0.8 else "text"


def index_entries(path: str) -> tuple[str, list[Entry]]:
    """Single streaming pass that groups lines into entries. Returns (format, entries)."""
    fmt = detect_format(path)
    entries: list[Entry] = []
    has_text_starts = fmt == "text" and _has_start_pattern(path)

    cur_start = cur_end = cur_off = cur_len = None
    offset = 0
    with open(path, "rb") as f:
        for lineno, raw in enumerate(f, start=1):
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            starts_new = _is_entry_start(line, fmt, has_text_starts)
            if line.strip() == "":
                starts_new = False  # blank lines never start an entry
            if starts_new or cur_start is None:
                if cur_start is not None:
                    entries.append(Entry(cur_start, cur_end, cur_off, cur_len))
                if line.strip() == "":
                    offset += len(raw)
                    continue
                cur_start, cur_end, cur_off, cur_len = lineno, lineno, offset, len(raw)
            else:
                if line.strip():
                    cur_end = lineno
                cur_len += len(raw)
            offset += len(raw)
    if cur_start is not None:
        entries.append(Entry(cur_start, cur_end, cur_off, cur_len))
    return fmt, entries


def _has_start_pattern(path: str, sample: int = 50) -> bool:
    hits = seen = 0
    with open(path, "rb") as f:
        for raw in f:
            s = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if not s.strip():
                continue
            seen += 1
            hits += bool(_TEXT_START.match(s))
            if seen >= sample:
                break
    return seen > 0 and hits / seen >= 0.5


def _is_entry_start(line: str, fmt: str, has_text_starts: bool) -> bool:
    if fmt == "jsonl":
        return line.lstrip().startswith("{")
    if _CONTINUATION.match(line):
        return False
    return bool(_TEXT_START.match(line)) if has_text_starts else True


def read_entry(f, entry: Entry) -> str:
    """Read one entry's text from an open binary file handle."""
    f.seek(entry.offset)
    return f.read(entry.length).decode("utf-8", errors="replace").rstrip("\r\n")


def iter_entry_texts(path: str, entries: list[Entry]) -> Iterator[tuple[Entry, str]]:
    with open(path, "rb") as f:
        for e in entries:
            yield e, read_entry(f, e)


def try_json(text: str) -> dict | None:
    try:
        obj = json.loads(text)
    except (ValueError, TypeError):
        return None
    return obj if isinstance(obj, dict) else None
