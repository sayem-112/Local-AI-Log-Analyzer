"""Turn log entries into short, token-cheap lines for the model.

Raw JSON log lines cost ~110-130 tokens each, mostly on repeated keys, hostnames,
request IDs and long browser user-agent strings. The compactor learns from the
file itself which fields carry no information (constant, or a 1:1 alias of another
field) and renders the rest positionally. Nothing here is specific to one log file.

The original line number is always kept as the `L<n>` prefix, and the raw text stays
on disk, so evidence in the final report always points at the real line.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime
from typing import Iterable
from urllib.parse import unquote

from .ledger import _COMBINED
from .logparse import try_json

TIME_KEYS = ("time", "timestamp", "ts", "@timestamp", "datetime", "date")
IP_KEYS = ("client_ip", "ip", "remote_addr", "src_ip", "source_ip", "clientip", "remote_ip")
METHOD_KEYS = ("method", "http_method", "verb")
PATH_KEYS = ("path", "url", "uri", "request", "request_uri")
STATUS_KEYS = ("status", "status_code", "http_status_code", "response_code")
BYTES_KEYS = ("response_bytes", "bytes", "bytes_sent", "size", "body_bytes_sent")
DURATION_KEYS = ("duration_ms", "latency_ms", "elapsed_ms", "response_time_ms")
UA_KEYS = ("user_agent", "ua", "http_user_agent", "useragent")
LEVEL_KEYS = ("level", "severity", "loglevel")
SOURCE_KEYS = ("app", "service")
# Per-request correlation IDs: unique per line, useless to the model.
# Duplicates are detected in code before the model sees the chunk.
DROP_KEYS = {"request_id", "trace_id", "span_id", "correlation_id"}

MAX_VALUE_CHARS = 160
MAX_TEXT_CHARS = 400
SLOW_MS = 1000  # durations below this are normal latency and are dropped
LARGE_BYTES = 100_000  # response sizes below this are normal pages and are dropped
_BROWSER = re.compile(r"(Edg|OPR|Firefox|Chrome|Safari)/(\d+)")


class Compactor:
    def __init__(self, fmt: str):
        self.fmt = fmt
        self.redundant: set[str] = set()
        self.base_date: str | None = None

    def fit(self, texts: Iterable[str]) -> "Compactor":
        """Learn which fields are constant or aliases of another field."""
        if self.fmt != "jsonl":
            return self
        values: dict[str, set] = defaultdict(set)
        present: dict[str, int] = defaultdict(int)
        pairs: dict[tuple[str, str], dict] = defaultdict(dict)
        conflicts: set[tuple[str, str]] = set()
        n = 0
        rows = []
        for text in texts:
            obj = try_json(text)
            if obj is None:
                continue
            n += 1
            flat = {k: _scalar(v) for k, v in obj.items()}
            rows.append(flat)
            for k, v in flat.items():
                present[k] += 1
                if len(values[k]) <= 50:
                    values[k].add(v)
            if self.base_date is None:
                ts = _first(obj, TIME_KEYS)
                if isinstance(ts, str) and len(ts) >= 10:
                    self.base_date = ts[:10]
        if not n:
            return self

        common = [k for k, c in present.items() if c / n >= 0.95]
        protected = set(TIME_KEYS) | set(IP_KEYS) | set(PATH_KEYS) | set(STATUS_KEYS) | set(METHOD_KEYS)
        for k in common:
            if len(values[k]) == 1 and k not in protected:
                self.redundant.add(k)  # constant across the whole file
        # Low-cardinality fields that map 1:1 onto another field (e.g. host <-> app).
        small = [k for k in common if 1 < len(values[k]) <= 20 and k not in protected]
        for row in rows:
            for a in small:
                for b in small:
                    if a == b or (a, b) in conflicts or a not in row or b not in row:
                        continue
                    seen = pairs[(a, b)].setdefault(row[a], row[b])
                    if seen != row[b]:
                        conflicts.add((a, b))
        for a in small:
            for b in small:
                if a < b and (a, b) not in conflicts and (b, a) not in conflicts:
                    longer = max((a, b), key=lambda k: sum(len(str(v)) for v in values[k]))
                    self.redundant.add(longer)
        return self

    def render(self, start_line: int, end_line: int, text: str) -> str:
        label = f"L{start_line}" if start_line == end_line else f"L{start_line}-{end_line}"
        obj = try_json(text) if self.fmt == "jsonl" else None
        if obj is None and (m := _COMBINED.match(text)):
            return f"{label} {self._render_combined(m, text)}"
        if obj is None:
            flat = " ⏎ ".join(s.strip() for s in text.splitlines() if s.strip())
            flat = re.sub(r"\s+", " ", flat)
            return f"{label} {_clip(flat, MAX_TEXT_CHARS)}"
        return f"{label} {self._render_json(obj)}"

    def _render_json(self, obj: dict) -> str:
        used: set[str] = set(self.redundant) | DROP_KEYS
        parts: list[str] = []

        key, ts = _pick(obj, TIME_KEYS)
        if key:
            used.add(key)
            parts.append(self._time(str(ts)))
        src = []
        for k in SOURCE_KEYS:
            if k in obj and k not in used:
                src.append(str(obj[k]))
                used.add(k)
        if src:
            parts.append("|".join(src))
        key, lvl = _pick(obj, LEVEL_KEYS)
        if key:
            used.add(key)
            if str(lvl).upper() != "INFO":
                parts.append(str(lvl).upper())
        for keys in (IP_KEYS, METHOD_KEYS):
            key, v = _pick(obj, keys)
            if key:
                used.add(key)
                parts.append(str(v))
        key, path = _pick(obj, PATH_KEYS)
        if key:
            used.add(key)
            parts.append(_decode_path(str(path)))
        key, status = _pick(obj, STATUS_KEYS)
        if key:
            used.add(key)
            parts.append(str(status))
        key, size = _pick(obj, BYTES_KEYS)
        if key:
            used.add(key)
            if not isinstance(size, (int, float)) or size >= LARGE_BYTES:
                parts.append(f"bytes={_bytes(size)}")
        key, dur = _pick(obj, DURATION_KEYS)
        if key:
            used.add(key)
            if isinstance(dur, (int, float)) and dur >= SLOW_MS:
                parts.append(f"{dur}ms")
        key, ua = _pick(obj, UA_KEYS)
        if key:
            used.add(key)
            parts.append(f"ua={_short_ua(str(ua))}")
        for k, v in obj.items():
            if k in used:
                continue
            parts.append(f"{k}={_value(v)}")
        return " ".join(parts)

    def _render_combined(self, m: re.Match, text: str) -> str:
        """Apache/Nginx combined line -> same shape as JSON lines: time ip METHOD path status [user] [ua]."""
        parts = [m["time"].split(":", 1)[1].split(" ")[0] if ":" in m["time"] else m["time"], m["ip"],
                 m["method"], _decode_path(m["path"]), m["status"]]
        if m["size"].isdigit() and int(m["size"]) >= LARGE_BYTES:
            parts.append(f"bytes={_bytes(int(m['size']))}")
        if m["user"] != "-":
            parts.append(f"user={m['user']}")
        quoted = re.findall(r'"([^"]*)"', text)
        if len(quoted) >= 3:
            parts.append(f"ua={_short_ua(quoted[-1])}")
        return " ".join(parts)

    def _time(self, ts: str) -> str:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return _clip(ts, 40)
        t = dt.strftime("%H:%M:%S")
        if dt.microsecond:
            t += f".{dt.microsecond // 1000:03d}"
        date = dt.strftime("%Y-%m-%d")
        return t if date == self.base_date else f"{date}T{t}"


def build_compactor(texts: list[str], fmt: str | None = None) -> Compactor:
    if fmt is None:
        fmt = "jsonl" if texts and sum(t.lstrip().startswith("{") for t in texts) / len(texts) >= 0.8 else "text"
    return Compactor(fmt).fit(texts)


def _first(obj: dict, keys) -> object:
    return next((obj[k] for k in keys if k in obj), None)


def _pick(obj: dict, keys) -> tuple[str | None, object]:
    for k in keys:
        if k in obj:
            return k, obj[k]
    return None, None


def _scalar(v) -> object:
    return v if isinstance(v, (str, int, float, bool)) or v is None else json.dumps(v, sort_keys=True)


def _clip(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def _value(v) -> str:
    if isinstance(v, str):
        v = _clip(v, MAX_VALUE_CHARS)
        return json.dumps(v, ensure_ascii=False) if (" " in v or not v) else v
    if isinstance(v, (list, dict)):
        return _clip(json.dumps(v, separators=(",", ":"), ensure_ascii=False), MAX_VALUE_CHARS)
    return json.dumps(v)


def _decode_path(path: str) -> str:
    """URL-decode so payloads are readable; flag double encoding (an evasion signal)."""
    once = unquote(path)
    twice = unquote(once)
    if twice != once:
        return _clip(twice, MAX_VALUE_CHARS) + " [double-encoded]"
    return _clip(once, MAX_VALUE_CHARS)


def _bytes(v) -> str:
    if not isinstance(v, (int, float)):
        return f"size={v}"
    if v >= 1_000_000:
        return f"{v / 1_000_000:.1f}MB"
    if v >= 1000:
        return f"{v / 1000:.1f}kB"
    return f"{int(v)}B"


def _short_ua(ua: str) -> str:
    if len(ua) <= 40:
        return ua
    found = _BROWSER.findall(ua)
    if found:
        # Chrome UAs also say Safari/; prefer the most specific engine named.
        name, ver = next((m for m in found if m[0] != "Safari"), found[0])
        return f"{name}/{ver}"
    return _clip(ua.split(" ")[0], 40)
