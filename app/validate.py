"""Parse model replies defensively and check every finding against the real log lines.

Small models hallucinate line numbers and IDs. A finding is kept only when its cited
lines exist in the part that was analyzed and its IP/user actually appears on them.
Rejected findings are kept (with the reason) so the UI can show what was filtered.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

from .ledger import EventFacts
from .prompts import ATTACK_TYPES, SEVERITIES


def parse_json(content: str) -> tuple[dict | None, bool]:
    """Return (data, salvaged). Never raises. `salvaged` means the reply was broken or cut off."""
    text = content.strip()
    try:
        data = json.loads(text)
        return (data, False) if isinstance(data, dict) else (None, True)
    except ValueError:
        pass
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        try:
            data = json.loads(text[start:end + 1])
            if isinstance(data, dict):
                return data, True
        except ValueError:
            pass
    items = _complete_objects(text)
    if items:
        return {"f": items}, True
    return None, True


def _complete_objects(text: str) -> list[dict]:
    """Recover whole {...} items from a truncated array like {"f":[{...},{...},{"t":"sq"""
    i = text.find("[")
    if i == -1:
        return []
    out, depth, start, in_str, esc = [], 0, None, False, False
    for j in range(i + 1, len(text)):
        ch = text[j]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = j
            depth += 1
        elif ch == "}" and depth:
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    obj = json.loads(text[start:j + 1])
                    if isinstance(obj, dict):
                        out.append(obj)
                except ValueError:
                    pass
                start = None
    return out


@dataclass
class LineView:
    raw: str          # the original text on disk
    shown: str        # the compact text the model saw
    facts: EventFacts


def verify_findings(items: list, lines: dict[int, LineView], line_to_entry: dict[int, int],
                    duplicate_of: dict[int, int]) -> tuple[list[dict], list[dict]]:
    """Check one part's findings against its real lines. Returns (accepted, rejected).

    - cited lines must exist in this part (hallucinated line numbers are dropped)
    - the actor (IP, else user, else session) is taken from the cited lines by code;
      lines with no actor at all (server-side errors) can't be an attack by someone
    - login-based types must cite login events (brute_force -> a failed login,
      account_compromise -> a successful login)
    - one finding citing several actors is split into one finding per actor
    - the quoted evidence "e" is checked; a wrong quote only lowers confidence
    """
    accepted, rejected = [], []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        t, s = item.get("t"), item.get("s")
        reason = str(item.get("r") or "").strip()[:160]
        quote = str(item.get("e") or "").strip()
        if t not in ATTACK_TYPES or s not in SEVERITIES:
            rejected.append({**item, "why": "unknown type or severity"})
            continue
        cited: list[int] = []
        for n in item.get("l") or []:
            if not isinstance(n, int):
                continue
            n = line_to_entry.get(n, n)   # a line inside a multi-line entry -> entry start
            n = duplicate_of.get(n, n)    # a duplicate -> the original event
            if n in lines and n not in cited:
                cited.append(n)
        if not cited:
            rejected.append({**item, "why": "no cited line exists in this part"})
            continue
        if t == "brute_force":
            cited = [n for n in cited if lines[n].facts.auth_fail]
            if not cited:
                rejected.append({**item, "why": "brute_force cites no failed login"})
                continue
        if t == "account_compromise":
            if not any(lines[n].facts.auth_ok for n in cited):
                rejected.append({**item, "why": "account_compromise cites no successful login"})
                continue
        groups: dict[str, list[int]] = {}
        for n in cited:
            f = lines[n].facts
            actor = f.ip or f.user or f.session
            if actor:
                groups.setdefault(actor, []).append(n)
        if not groups:
            rejected.append({**item, "why": "cited lines have no client IP, user or session"})
            continue
        for actor, ns in groups.items():
            quote_ok = bool(quote) and any(_contains(lines[n].raw, quote) or _contains(lines[n].shown, quote)
                                           for n in ns)
            accepted.append({"t": t, "id": actor, "l": sorted(ns), "e": quote if quote_ok else "",
                             "s": s, "r": reason, "quote_ok": quote_ok})
    return accepted, rejected


def _contains(haystack: str, quote: str) -> bool:
    norm = lambda s: re.sub(r"\s+", " ", s).strip().lower().strip("\"'")  # noqa: E731
    q = norm(quote)
    return len(q) >= 3 and q in norm(haystack)


def verify_judge(data: dict | None) -> dict | None:
    if not isinstance(data, dict) or not isinstance(data.get("attack"), bool):
        return None
    if data.get("t") not in ATTACK_TYPES or data.get("s") not in SEVERITIES:
        return None
    chain = list(dict.fromkeys(c for c in data.get("chain") or [] if c in ATTACK_TYPES))
    return {
        "attack": data["attack"], "t": data["t"], "chain": chain or [data["t"]], "s": data["s"],
        "r": str(data.get("r") or "")[:240],
    }
