"""Code-owned memory that links events across parts of the file.

The model is good at reading a line and saying "this is SQL injection". It is bad at
counting, remembering and keeping facts consistent over 15 calls. So code keeps the
counters (failed logins, denied requests, bursts, sessions) and the model's verified
flags, keyed by IP, username and session ID. Before each call, the cards of entities
that appear in the next part are rendered into the prompt.

Because the ledger is rebuilt by replaying the log and the saved per-part results,
it never needs its own snapshot: resume after a restart just replays.
"""
from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime

from .logparse import try_json

IP_KEYS = ("client_ip", "ip", "remote_addr", "src_ip", "source_ip", "clientip", "remote_ip")
USER_KEYS = ("username", "user", "user_name", "account", "login", "user_id")
SESSION_KEYS = ("session_id", "session", "sid")
STATUS_KEYS = ("status", "status_code", "http_status_code", "response_code")
PATH_KEYS = ("path", "url", "uri", "request", "request_uri")
TIME_KEYS = ("time", "timestamp", "ts", "@timestamp", "datetime")
BYTES_KEYS = ("response_bytes", "bytes", "bytes_sent", "body_bytes_sent")

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_TEXT_USER = re.compile(r"(?:user(?:name)?[=: ]+|for (?:invalid user )?)([\w.@-]+)", re.I)
_TEXT_STATUS = re.compile(r'"\s(\d{3})\s')
_TEXT_FAIL = re.compile(r"failed password|authentication failure|invalid user|login failed|invalid_password|bad password", re.I)
_TEXT_OK = re.compile(r"accepted password|login succeeded|auth(?:entication)? success", re.I)
_AUTH_PATH = re.compile(r"login|signin|sign-in|auth|session|token|oauth", re.I)
_ISO = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?")
_COMBINED = re.compile(
    r'^(?P<ip>[\d.:a-fA-F]+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)')
# Code guard for prompt injection. A model can't be trusted to report text that is
# trying to steer that same model (in testing, 0.8B and 2B both skipped it), so
# instruction-like text aimed at an AI is detected here, independent of the model.
_INJECTION = re.compile(
    r"\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|all|earlier|your)\b.{0,20}"
    r"\b(instructions?|prompts?|rules?|context)\b"
    r"|\byou are now\b|\bsystem prompt\b|\bnew instructions?\b"
    r"|\b(report|mark|classify|treat)\b.{0,40}\bas (safe|benign|clean|normal)\b"
    r"|\b(delete|remove|hide|suppress)\b.{0,30}\b(evidence|findings?|alerts?|failed login)", re.I)

BURST_WINDOW_S = 10
LARGE_BYTES = 1_000_000
MAX_LINES_PER_CARD = 2000


@dataclass
class EventFacts:
    line: int
    ip: str | None = None
    user: str | None = None
    session: str | None = None
    status: int | None = None
    path: str | None = None
    ts: float | None = None
    auth_fail: bool = False
    auth_ok: bool = False
    size: int | None = None
    injection: bool = False  # instruction-like text aimed at an AI (code guard)


def extract(line: int, raw: str) -> EventFacts:
    """Pull the fields the ledger counts. Works for JSON lines and common text formats."""
    f = EventFacts(line)
    obj = try_json(raw)
    if obj is not None:
        f.ip = _str(_first(obj, IP_KEYS))
        f.user = _str(_first(obj, USER_KEYS))
        f.session = _str(_first(obj, SESSION_KEYS))
        f.path = _str(_first(obj, PATH_KEYS))
        st = _first(obj, STATUS_KEYS)
        f.status = int(st) if isinstance(st, (int, str)) and str(st).isdigit() else None
        sz = _first(obj, BYTES_KEYS)
        f.size = sz if isinstance(sz, int) else None
        f.ts = _parse_ts(_str(_first(obj, TIME_KEYS)))
        auth_fields = " ".join(str(v) for k, v in obj.items() if any(w in k for w in ("auth", "login", "result")))
        _auth_outcome(f, str(obj.get("method", "")), auth_fields, str(obj.get("message", "")))
    elif m := _COMBINED.match(raw):
        # Apache/Nginx "combined" access log: ip - user [time] "METHOD path HTTP/x" status size "ref" "ua"
        f.ip = m["ip"]
        f.user = None if m["user"] == "-" else m["user"]
        f.path, f.status = m["path"], int(m["status"])
        f.size = int(m["size"]) if m["size"].isdigit() else None
        f.ts = _parse_clf_time(m["time"])
        q = _TEXT_USER.search(m["path"])  # e.g. /login?username=bob
        f.user = f.user or (q.group(1) if q else None)
        _auth_outcome(f, m["method"], "", raw)
    else:
        m = _IPV4.search(raw)
        f.ip = m.group(0) if m else None
        m = _TEXT_USER.search(raw)
        f.user = m.group(1) if m else None
        m = _TEXT_STATUS.search(raw)
        f.status = int(m.group(1)) if m else None
        m = _ISO.search(raw)
        f.ts = _parse_ts(m.group(0)) if m else None
        f.auth_fail = bool(_TEXT_FAIL.search(raw))
        f.auth_ok = bool(_TEXT_OK.search(raw))
    if obj is not None:
        f.injection = any(isinstance(v, str) and _INJECTION.search(v) for v in obj.values())
    else:
        f.injection = bool(_INJECTION.search(raw))
    return f


def _auth_outcome(f: EventFacts, method: str, auth_fields: str, message: str) -> None:
    """An explicit result wins; otherwise infer from a login path + status code.
    Form logins usually answer a good password with a redirect (302/303)."""
    is_auth_path = bool(f.path and _AUTH_PATH.search(f.path))
    if _TEXT_FAIL.search(auth_fields) or _TEXT_FAIL.search(message) or (is_auth_path and f.status in (401, 403)):
        f.auth_fail = True
    elif ("success" in auth_fields.lower() or _TEXT_OK.search(message)
          or (is_auth_path and method.upper() == "POST" and f.status is not None
              and (200 <= f.status < 300 or f.status in (302, 303)))):
        f.auth_ok = True


def _parse_clf_time(s: str) -> float | None:
    try:
        return datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except ValueError:
        return None


@dataclass
class Flag:
    type: str
    severity: str
    lines: list[int]
    reason: str
    part: int
    quote_ok: bool = False  # the model's quoted evidence was found on the cited line


@dataclass
class EntityCard:
    kind: str   # ip | user | session
    value: str
    first_line: int = 0
    last_line: int = 0
    events: int = 0
    fail_lines: list[int] = field(default_factory=list)
    success_after_fail: list[int] = field(default_factory=list)
    denied_lines: list[int] = field(default_factory=list)     # 403
    notfound_paths: dict[str, int] = field(default_factory=dict)  # 404 path -> line
    throttled_lines: list[int] = field(default_factory=list)  # 429
    large_lines: list[int] = field(default_factory=list)
    error_lines: list[int] = field(default_factory=list)      # 5xx caused by this actor (context only)
    max_burst: int = 0
    burst_line: int = 0
    users: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    sessions: set[str] = field(default_factory=set)
    flags: list[Flag] = field(default_factory=list)
    all_lines: list[int] = field(default_factory=list)  # capped; used to pick evidence later
    _window: deque = field(default_factory=deque, repr=False)

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.value}"

    def score(self) -> int:
        """How suspicious the counters alone look. Used to rank cards and pick candidates."""
        s = 10 * len(self.flags) + len(self.fail_lines) + 2 * len(self.success_after_fail)
        s += len(self.denied_lines) + len(self.notfound_paths) + len(self.throttled_lines)
        s += 3 * len(self.large_lines) if self.success_after_fail else 0
        s += self.max_burst // 5
        return s

    def notable(self, include_flags: bool = True) -> bool:
        return bool((include_flags and self.flags) or len(self.fail_lines) >= 2
                    or len(self.denied_lines) + len(self.notfound_paths) >= 3
                    or self.throttled_lines or self.max_burst >= 10)

    def render(self, include_flags: bool = True) -> str:
        """One short line for the prompt. Facts only; the model draws conclusions."""
        bits = []
        if self.fail_lines:
            who = f" for {','.join(sorted(self.users))}" if self.users and self.kind == "ip" else ""
            bits.append(f"{len(self.fail_lines)} failed logins{who} {_lines(self.fail_lines)}")
        if self.success_after_fail:
            bits.append(f"login success after failures {_lines(self.success_after_fail)}")
        if self.denied_lines:
            bits.append(f"{len(self.denied_lines)} denied(403) {_lines(self.denied_lines)}")
        if self.notfound_paths:
            paths = list(self.notfound_paths)[:4]
            bits.append(f"{len(self.notfound_paths)} distinct 404 paths ({' '.join(paths)})")
        if self.throttled_lines:
            bits.append(f"{len(self.throttled_lines)} rate-limited(429)")
        if self.max_burst >= 10:
            bits.append(f"{self.max_burst} requests within {BURST_WINDOW_S}s near L{self.burst_line}")
        if self.large_lines:
            bits.append(f"large responses {_lines(self.large_lines)}")
        if self.error_lines:  # context for the judge; never makes an actor notable on its own
            bits.append(f"{len(self.error_lines)} server errors(5xx) {_lines(self.error_lines)}")
        if self.kind == "session" and self.ips:
            bits.append(f"used by {','.join(sorted(self.ips))}")
        for fl in (self.flags[-3:] if include_flags else []):
            bits.append(f"flagged {fl.type}({fl.severity}) {_lines(fl.lines)}")
        return f"{self.value}: " + "; ".join(bits) if bits else f"{self.value}: seen {self.events}x"


class Ledger:
    def __init__(self) -> None:
        self.cards: dict[str, EntityCard] = {}

    def card(self, kind: str, value: str) -> EntityCard:
        k = f"{kind}:{value}"
        if k not in self.cards:
            self.cards[k] = EntityCard(kind, value)
        return self.cards[k]

    def observe(self, ev: EventFacts) -> None:
        for kind, value in (("ip", ev.ip), ("user", ev.user), ("session", ev.session)):
            if not value:
                continue
            c = self.card(kind, value)
            if not c.first_line:
                c.first_line = ev.line
            c.last_line = ev.line
            c.events += 1
            if len(c.all_lines) < MAX_LINES_PER_CARD:
                c.all_lines.append(ev.line)
            if ev.ip and kind != "ip":
                c.ips.add(ev.ip)
            if ev.user and kind != "user":
                c.users.add(ev.user)
            if ev.session and kind != "session":
                c.sessions.add(ev.session)
            if ev.auth_fail:
                c.fail_lines.append(ev.line)
            elif ev.auth_ok and c.fail_lines:
                c.success_after_fail.append(ev.line)
            if ev.status == 403:
                c.denied_lines.append(ev.line)
            elif ev.status == 404 and ev.path:
                c.notfound_paths.setdefault(ev.path.split("?")[0], ev.line)
            elif ev.status == 429:
                c.throttled_lines.append(ev.line)
            elif ev.status is not None and ev.status >= 500:
                c.error_lines.append(ev.line)
            if ev.size and ev.size >= LARGE_BYTES:
                c.large_lines.append(ev.line)
            if ev.injection and kind == ("ip" if ev.ip else "user" if ev.user else "session"):
                c.flags.append(Flag("prompt_injection", "M", [ev.line],
                                    "instruction-like text aimed at an AI inside a log field (code guard)",
                                    part=-1, quote_ok=True))
            if kind == "ip" and ev.ts is not None:
                w = c._window
                w.append(ev.ts)
                while w and ev.ts - w[0] > BURST_WINDOW_S:
                    w.popleft()
                if len(w) > c.max_burst:
                    c.max_burst, c.burst_line = len(w), ev.line

    def add_flag(self, entity_value: str, flag: Flag) -> None:
        """Attach a verified model flag to the matching entity (or an 'other' card)."""
        kind = next((k for k in ("ip", "session", "user") if f"{k}:{entity_value}" in self.cards), "other")
        self.card(kind, entity_value).flags.append(flag)

    def memory_for(self, events: list[EventFacts], count_tokens, budget: int) -> str:
        """Cards for entities that appear in the next part, most suspicious first, within budget.

        Only code-counted facts go into the prompt, never earlier model flags: a wrong
        flag carried forward would be repeated by the model in every later part.
        """
        keys = []
        for ev in events:
            for kind, value in (("ip", ev.ip), ("user", ev.user), ("session", ev.session)):
                k = f"{kind}:{value}"
                if value and k in self.cards and k not in keys:
                    keys.append(k)
        cards = [self.cards[k] for k in keys if self.cards[k].notable(include_flags=False)]
        shown_ips = {c.value for c in cards if c.kind == "ip"}
        # A user seen from one IP whose card is already shown adds nothing new.
        cards = [c for c in cards if not (c.kind == "user" and len(c.ips) == 1 and c.ips <= shown_ips)]
        cards.sort(key=lambda c: -c.score())
        lines, used = [], 0
        for c in cards:
            text = c.render(include_flags=False)
            n = count_tokens(text) + 1
            if used + n > budget:
                break
            lines.append(text)
            used += n
        return "\n".join(lines)

    def candidates(self) -> list[EntityCard]:
        return sorted((c for c in self.cards.values() if c.notable()), key=lambda c: -c.score())


def _lines(ls: list[int], keep: int = 2) -> str:
    if len(ls) <= keep * 2:
        return "(" + ",".join(f"L{n}" for n in ls) + ")"
    head = ",".join(f"L{n}" for n in ls[:keep])
    tail = ",".join(f"L{n}" for n in ls[-keep:])
    return f"({head}…{tail})"


def _first(obj: dict, keys):
    return next((obj[k] for k in keys if k in obj and obj[k] not in (None, "")), None)


def _str(v) -> str | None:
    return None if v is None else str(v)


def _parse_ts(s: str | None) -> float | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None
