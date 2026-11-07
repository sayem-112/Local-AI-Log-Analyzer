"""Final stage: turn per-part flags + ledger facts into one merged report.

1. Group: cards that describe the same actor (an IP, the users it logged in as, the
   sessions it used) become one incident, so repeated findings merge into one.
2. Triage (code policy, documented in README): drop weak signals before spending a
   model call - a single unverified flag with no supporting facts, or "brute force"
   with fewer than 3 failed logins.
3. Judge: one model call per incident sees FACTS, FLAGS and EVIDENCE lines and decides
   attack or not, main type, chain, severity, reason and action.
4. Guard rails: if the judge call fails, a fallback built from the facts is used; if
   the judge dismisses an incident the facts strongly support, it is kept and marked
   for review instead of silently dropped.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from . import config
from .ledger import EntityCard, Flag, Ledger, extract
from .llm import LLM, LLMError
from .logparse import read_entry
from .prompts import DEFAULT_ACTIONS, JUDGE_SCHEMA, JUDGE_SYSTEM, SEVERITIES, judge_user_message
from .validate import parse_json, verify_judge

SEV_RANK = {"L": 0, "M": 1, "H": 2, "C": 3}
TYPE_LABELS = {
    "brute_force": "Brute force", "account_compromise": "Account compromise",
    "sql_injection": "SQL injection", "path_traversal": "Path traversal", "scanning": "Scanning",
    "rate_abuse": "Unusual request rate", "unauthorized_access": "Unauthorized access",
    "data_exfiltration": "Data exfiltration", "prompt_injection": "Prompt injection",
}
STAGE_ORDER = ["scanning", "rate_abuse", "prompt_injection", "sql_injection", "path_traversal",
               "brute_force", "account_compromise", "unauthorized_access", "data_exfiltration"]
JUDGE_REPLY_TOKENS = 160
MAX_REPORT_EVIDENCE = 40
SMALL_ACTOR_EVENTS = 40


@dataclass
class Incident:
    cards: list[EntityCard]
    sessions: list[EntityCard] = field(default_factory=list)

    @property
    def primary(self) -> EntityCard:
        ips = [c for c in self.cards if c.kind == "ip"]
        return max(ips or self.cards, key=lambda c: c.score())

    @property
    def flags(self) -> list[Flag]:
        seen, out = set(), []
        for c in self.cards:
            for f in c.flags:
                key = (f.type, tuple(f.lines))
                if key not in seen:
                    seen.add(key)
                    out.append(f)
        return out

    def max_fails(self) -> int:
        return max((len(c.fail_lines) for c in self.cards), default=0)

    def compromised(self) -> bool:
        return any(c.success_after_fail for c in self.cards) and self.max_fails() >= 3

    def facts_notable(self) -> bool:
        return any(c.notable(include_flags=False) for c in self.cards)

    def facts_strong(self) -> bool:
        """Facts that make 'not an attack' implausible, whatever the model says."""
        guard = any(f.part == -1 for f in self.flags)  # code guard hit (e.g. prompt injection text)
        return guard or self.compromised() or self.max_fails() >= 5 or any(
            len(c.throttled_lines) >= 3 or len(c.denied_lines) + len(c.notfound_paths) >= 5 for c in self.cards)

    def fact_chain(self) -> list[str]:
        """Attack steps the counters prove on their own."""
        steps = []
        if any(len(c.notfound_paths) + len(set(c.denied_lines)) >= 5 for c in self.cards if c.kind == "ip"):
            steps.append("scanning")
        if any(len(c.throttled_lines) >= 3 or c.max_burst >= 10 for c in self.cards):
            steps.append("rate_abuse")
        if self.max_fails() >= 3:
            steps.append("brute_force")
        if self.compromised():
            steps.append("account_compromise")
            if any(c.large_lines for c in self.cards + self.sessions):
                steps.append("data_exfiltration")
        return steps


def build_incidents(ledger: Ledger) -> list[Incident]:
    cands = {c.key: c for c in ledger.cards.values() if c.notable() and c.kind != "session"}
    parent = {k: k for k in cands}

    def find(k: str) -> str:
        while parent[k] != k:
            parent[k] = parent[parent[k]]
            k = parent[k]
        return k

    for c in cands.values():
        linked = [f"ip:{ip}" for ip in c.ips] if c.kind == "user" else [f"user:{u}" for u in c.users]
        for other in linked:
            if other in cands:
                parent[find(c.key)] = find(other)
    groups: dict[str, list[EntityCard]] = {}
    for k, c in cands.items():
        groups.setdefault(find(k), []).append(c)
    incidents = [Incident(cards) for cards in groups.values()]
    # Attach sessions used by a compromised actor: what it did after logging in is evidence.
    for inc in incidents:
        ips = {c.value for c in inc.cards if c.kind == "ip"}
        if inc.compromised() or inc.flags:
            inc.sessions = [s for s in ledger.cards.values() if s.kind == "session" and s.ips & ips]
    return incidents


def triage(inc: Incident) -> str | None:
    """Return a reason to dismiss without a model call, or None to judge it."""
    flags = inc.flags
    counted = {"rate_abuse", "brute_force", "account_compromise", "data_exfiltration"}
    if (not inc.facts_notable() and not any(f.quote_ok for f in flags) and len(flags) < 2
            and all(f.type in counted for f in flags)):
        # Counting-type claims need counters behind them. Payload-type flags (SQLi,
        # traversal, ...) go to the judge, which sees the actor's actual lines.
        return "single unverified model flag with no supporting facts"
    types = {f.type for f in flags}
    if types and types <= {"brute_force", "account_compromise"} and inc.max_fails() < 3:
        return f"only {inc.max_fails()} failed login(s); too few for brute force"
    return None


def evidence_lines(inc: Incident) -> list[int]:
    """Evidence in priority order (most telling first). Callers trim to their budget."""
    ordered: list[int] = []

    def add(ls):
        for n in ls:
            if n not in ordered:
                ordered.append(n)

    flags = sorted(inc.flags, key=lambda f: (not f.quote_ok, -SEV_RANK[f.severity]))
    for c in inc.cards:
        add(c.success_after_fail)
        add(c.large_lines)
        add(c.error_lines[:6])
    for s in inc.sessions:
        add(s.all_lines[:12])
    for f in flags:
        add(f.lines)
    for c in inc.cards:
        add(c.denied_lines)
        add(list(c.notfound_paths.values()))
        add(c.throttled_lines[:4])
        add(c.fail_lines[:3] + c.fail_lines[-3:])
    for c in inc.cards:
        add(c.fail_lines)
        add(c.throttled_lines)
    for c in inc.cards:  # an actor with little traffic: all of it is relevant context
        if c.events <= SMALL_ACTOR_EVENTS:
            add(c.all_lines)
    return ordered


def finalize(prep, ledger: Ledger, llm: LLM | None, failed_parts: list[dict] | None = None,
             on_progress=None) -> dict:
    by_line = {r.entry.start_line: r for r in prep.rendered}
    findings, dismissed = [], []
    incidents = sorted(build_incidents(ledger), key=lambda i: -i.primary.score())
    with open(prep.path, "rb") as fh:
        raw = lambda n: read_entry(fh, by_line[n].entry) if n in by_line else ""  # noqa: E731
        for i, inc in enumerate(incidents):
            if on_progress:
                on_progress(i, len(incidents))
            why = triage(inc)
            if why:
                dismissed.append({"id": inc.primary.value, "reason": why, "lines": evidence_lines(inc)[:6],
                                  "decided_by": "code"})
                continue
            verdict, decided_by, judge_ms = None, "fallback", 0
            if llm is not None:
                try:
                    verdict, judge_ms = _judge(inc, by_line, llm)
                    decided_by = "model" if verdict else "fallback"
                except LLMError:
                    verdict = None
            if verdict and not verdict["attack"]:
                if not inc.facts_strong():
                    dismissed.append({"id": inc.primary.value, "reason": verdict["r"] or "judged not an attack",
                                      "lines": evidence_lines(inc)[:6], "decided_by": "model"})
                    continue
                verdict, decided_by = None, "fallback (model dismissed, facts disagree)"
            findings.append(_finding(inc, verdict or _fallback(inc), decided_by, raw, judge_ms))
    findings.sort(key=lambda f: (-SEV_RANK[f["severity_code"]], f["first_line"]))
    for n, f in enumerate(findings, 1):
        f["id"] = f"F{n}"
    return {"findings": findings, "dismissed": dismissed, "failed_parts": failed_parts or []}


def _judge(inc: Incident, by_line: dict, llm: LLM) -> tuple[dict | None, int]:
    facts = "\n".join(c.render(include_flags=False) for c in inc.cards + inc.sessions)
    # Only flags whose quoted evidence checked out; unverified labels misled the judge in testing.
    verified = [f for f in inc.flags if f.quote_ok]
    flags = sorted(verified, key=lambda f: -SEV_RANK[f.severity])[:8]
    flag_text = "\n".join(f"{_lines(f.lines)} {f.type}: {f.reason}" for f in flags)
    lines = [n for n in evidence_lines(inc) if n in by_line]
    while True:
        shown = sorted(lines)
        evidence = "\n".join(by_line[n].text for n in shown)
        messages = [{"role": "system", "content": JUDGE_SYSTEM},
                    {"role": "user", "content": judge_user_message(facts, flag_text, evidence)}]
        n = llm.count_messages(messages)
        if n + JUDGE_REPLY_TOKENS <= config.CTX_TOKENS or len(lines) <= 1:
            break
        lines = lines[: max(1, int(len(lines) * 0.8))]  # drop lowest-priority evidence
    reply = llm.chat(messages, JUDGE_SCHEMA, JUDGE_REPLY_TOKENS)
    data, _ = parse_json(reply.content)
    return verify_judge(data), reply.ms


def _fallback(inc: Incident) -> dict:
    """Verdict built from facts and flags only, used when the judge call is unavailable."""
    flags = inc.flags
    chain = []
    if inc.max_fails() >= 3:
        chain.append("brute_force")
    if inc.compromised():
        chain.append("account_compromise")
    if any(c.large_lines for c in inc.cards) and inc.compromised():
        chain.append("data_exfiltration")
    counted = Counter(f.type for f in flags if f.quote_ok) or Counter(f.type for f in flags)
    for t, _ in counted.most_common(2):
        if t not in chain:
            chain.append(t)
    if not chain:
        if any(len(c.denied_lines) + len(c.notfound_paths) >= 3 for c in inc.cards):
            chain.append("scanning")
        if any(c.throttled_lines or c.max_burst >= 10 for c in inc.cards):
            chain.append("rate_abuse")
    chain = chain or ["unauthorized_access"]
    sev = max((f.severity for f in flags), key=lambda s: SEV_RANK[s], default="M")
    best = sorted(flags, key=lambda f: (not f.quote_ok, -SEV_RANK[f.severity]))
    facts = inc.primary.render(include_flags=False)
    reason = (best[0].reason + f" ({_lines(best[0].lines)}). " if best else "") + (
        facts if not facts.endswith("x") else "")
    return {"attack": True, "t": chain[-1] if inc.compromised() else chain[0], "chain": chain, "s": sev,
            "r": reason.strip()}


def _finding(inc: Incident, v: dict, decided_by: str, raw, judge_ms: int) -> dict:
    lines = sorted(evidence_lines(inc)[:MAX_REPORT_EVIDENCE])
    statuses = [extract(n, raw(n)).status for n in lines]
    sev = v["s"]
    # Severity policy applied by code (documented in README):
    # - a login after repeated failures is at least High; Critical if a very large
    #   response followed (data likely taken)
    # - otherwise, if every request in the evidence was rejected (4xx), it was a
    #   blocked attempt: at most Medium
    if inc.compromised():
        sev = max(sev, "H", key=lambda s: SEV_RANK[s])
        if any(c.large_lines for c in inc.cards + inc.sessions):
            sev = "C"
    elif any(s is not None and s >= 500 for s in statuses) and (
            {f.type for f in inc.flags} & {"sql_injection", "path_traversal"}):
        # an injection payload answered with a server error reached the backend: not blocked
        sev = max(sev, "H", key=lambda s: SEV_RANK[s])
    elif statuses and all(s is not None and s >= 400 for s in statuses):
        sev = min(sev, "M", key=lambda s: SEV_RANK[s])
    users = sorted({u for c in inc.cards for u in c.users} | {c.value for c in inc.cards if c.kind == "user"})
    ips = sorted({c.value for c in inc.cards if c.kind == "ip"} | {ip for c in inc.cards for ip in c.ips})
    sessions = sorted({s.value for s in inc.sessions} | {s for c in inc.cards for s in c.sessions})
    # Chain = steps the facts prove + model steps that are backed by something, in
    # kill-chain order. Counting-based steps need the counters; payload steps need a
    # verified flag of that type (in testing the judge added "rate_abuse" to SQLi chains).
    facts = set(inc.fact_chain())
    verified_types = {f.type for f in inc.flags if f.quote_ok}
    counted = {"rate_abuse", "brute_force", "account_compromise", "data_exfiltration"}
    backed = {t for t in set(v["chain"]) | {v["t"]}
              if t in facts or (t not in counted and t in verified_types) or t == "unauthorized_access"}
    steps = facts | backed or {v["t"]}
    chain = [t for t in STAGE_ORDER if t in steps]
    if v["t"] not in steps:  # main type must be one of the backed steps
        v = {**v, "t": chain[-1] if inc.compromised() else chain[0]}
    ids = {"ip": ", ".join(ips) or "the source", "user": ", ".join(users) or "the targeted accounts",
           "session": ("session " + ", ".join(sessions)) if sessions else "the attacker's sessions"}
    action = " ".join(DEFAULT_ACTIONS[t].format(**ids) for t in chain)
    return {
        "attack_type": TYPE_LABELS[v["t"]],
        "type_code": v["t"],
        "chain": [TYPE_LABELS[t] for t in chain],
        "severity": SEVERITIES[sev],
        "severity_code": sev,
        "ip": ips[0] if ips else None,
        "ips": ips, "users": users, "sessions": sessions,
        "evidence": [{"line": n, "text": raw(n)[:400]} for n in lines],
        "first_line": lines[0] if lines else 0,
        "last_line": lines[-1] if lines else 0,
        "reason": v["r"],
        "action": action,
        "facts": [c.render(include_flags=False) for c in inc.cards + inc.sessions],
        "model_flags": len(inc.flags),
        "decided_by": decided_by,
        "judge_ms": judge_ms,
    }


def _lines(ls: list[int]) -> str:
    return ",".join(f"L{n}" for n in ls[:6]) + ("…" if len(ls) > 6 else "")
