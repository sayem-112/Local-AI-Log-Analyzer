"""Spike benchmark: measures token cost per log line and model speed on the local llama-server.

Usage: python scripts/bench.py path/to/file.log [--server http://127.0.0.1:8081]
"""
import argparse
import json
import statistics
import sys
import time

import httpx


def wait_ready(client: httpx.Client, timeout: float = 120) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if client.get("/health").status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(1)
    sys.exit("server not ready")


def count(client: httpx.Client, text: str) -> int:
    return len(client.post("/tokenize", json={"content": text}).json()["tokens"])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--server", default="http://127.0.0.1:8081")
    args = ap.parse_args()

    client = httpx.Client(base_url=args.server, timeout=600)
    wait_ready(client)

    with open(args.log, encoding="utf-8") as f:
        lines = [ln.rstrip("\n") for ln in f if ln.strip()]

    sys.path.insert(0, ".")
    from app.compact import Compactor
    from app.logparse import index_entries, iter_entry_texts

    fmt, entries = index_entries(args.log)
    texts = [t for _, t in iter_entry_texts(args.log, entries)]
    comp = Compactor(fmt).fit(texts)
    print("dropped fields:", sorted(comp.redundant))
    compact = [comp.render(e.start_line, e.end_line, t) for e, t in zip(entries, texts)]

    raw_counts = [count(client, ln) for ln in lines]
    print(f"lines={len(lines)} raw_tokens_total={sum(raw_counts)} "
          f"per_line mean={statistics.mean(raw_counts):.0f} max={max(raw_counts)}")
    if compact:
        c_counts = [count(client, ln) for ln in compact]
        print(f"compact_tokens_total={sum(c_counts)} per_line mean={statistics.mean(c_counts):.0f} "
              f"max={max(c_counts)} ratio={sum(raw_counts)/sum(c_counts):.2f}x")
        print("sample:", compact[195])

    schema = {
        "type": "object",
        "properties": {"f": {"type": "array", "maxItems": 4, "items": {
            "type": "object",
            "properties": {"t": {"type": "string"}, "l": {"type": "array", "items": {"type": "integer"}}},
            "required": ["t", "l"]}}},
        "required": ["f"],
    }
    system = "You are a security log analyst. " * 40  # ~300 token fixed prefix to test cache reuse
    body_lines = "\n".join((compact or lines)[:20])
    for attempt in range(2):
        t0 = time.time()
        r = client.post("/v1/chat/completions", json={
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": f"Logs:\n{body_lines}\nList suspicious lines."}],
            "max_tokens": 200, "temperature": 0,
            "response_format": {"type": "json_schema", "json_schema": {"schema": schema}},
            "cache_prompt": True,
        }).json()
        t = r.get("timings", {})
        print(f"call{attempt+1}: wall={time.time()-t0:.1f}s prompt_n={t.get('prompt_n')} "
              f"cached={t.get('cache_n')} prompt_tps={t.get('prompt_per_second', 0):.1f} "
              f"gen_n={t.get('predicted_n')} gen_tps={t.get('predicted_per_second', 0):.1f}")
        print("   reply:", r["choices"][0]["message"]["content"][:300])
        body_lines = "\n".join((compact or lines)[20:40])  # new log, same prefix


if __name__ == "__main__":
    main()
