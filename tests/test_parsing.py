import json

from app.chunker import plan_chunks, render_all
from app.compact import Compactor
from app.logparse import index_entries, iter_entry_texts


def test_text_log_groups_stack_traces_and_keeps_line_numbers(tmp_path):
    p = tmp_path / "app.log"
    p.write_text(
        "2026-01-01 10:00:00 ERROR boom\n"
        "Traceback (most recent call last):\n"
        "  File \"x.py\", line 1\n"
        "\n"
        "2026-01-01 10:00:01 INFO ok\n", encoding="utf-8")
    fmt, entries = index_entries(str(p))
    assert fmt == "text"
    assert [(e.start_line, e.end_line) for e in entries] == [(1, 3), (5, 5)]
    texts = [t for _, t in iter_entry_texts(str(p), entries)]
    assert "Traceback" in texts[0] and texts[1].endswith("INFO ok")


def test_jsonl_with_bom_and_junk_lines_keeps_every_entry(tmp_path):
    rows = [json.dumps({"client_ip": "10.0.0.1", "status": 200}) for _ in range(9)]
    p = tmp_path / "mixed.log"
    p.write_bytes(b"\xef\xbb\xbf" + "\n".join(rows[:5] + ["junk line ###"] + rows[5:]).encode() + b"\n")
    fmt, entries = index_entries(str(p))
    assert fmt == "jsonl"
    assert [(e.start_line, e.end_line) for e in entries] == [(n, n) for n in range(1, 11)]
    texts = [t for _, t in iter_entry_texts(str(p), entries)]
    from app.logparse import try_json
    assert try_json(texts[0]) is not None  # BOM line still parses
    assert texts[5] == "junk line ###"     # junk is its own entry, not glued to the JSON above


def test_jsonl_sample_has_one_entry_per_line(sample):
    fmt, entries = index_entries(sample)
    assert fmt == "jsonl"
    assert len(entries) == 258
    assert entries[195].start_line == 196


def test_compactor_decodes_payloads_and_drops_redundant_fields(tmp_path):
    rows = [{"time": f"2026-01-01T00:00:0{i}Z", "app": "a" if i % 2 else "b", "host": "a.test" if i % 2 else "b.test",
             "client_ip": "10.0.0.1", "method": "GET", "path": "/x?q=%27%20OR%201%3D1--", "status": 400,
             "request_id": f"req-{i}",
             "user_agent": "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36"}
            for i in range(5)]
    texts = [json.dumps(r) for r in rows]
    c = Compactor("jsonl").fit(texts)
    assert "host" in c.redundant  # 1:1 alias of app
    out = c.render(7, 7, texts[0])
    assert out.startswith("L7 ")
    assert "' OR 1=1--" in out and "Chrome/130" in out
    assert "req-0" not in out and "b.test" not in out


def test_double_encoding_is_flagged():
    c = Compactor("jsonl")
    out = c.render(1, 1, json.dumps({"path": "/f?name=%252e%252e%252fetc%252fpasswd", "status": 403}))
    assert "../etc/passwd" in out and "[double-encoded]" in out


def test_chunks_fit_budget_cover_everything_and_mark_duplicates(sample, llm):
    fmt, entries = index_entries(sample)
    rendered = render_all(sample, fmt, entries, llm.count, max_entry_tokens=600)
    chunks = plan_chunks(rendered, budget=900)
    assert all(c.tokens <= 900 for c in chunks)
    assert chunks[0].entry_start == 0 and chunks[-1].entry_end == len(entries)
    assert all(a.entry_end == b.entry_start for a, b in zip(chunks, chunks[1:]))  # no gaps, no overlap
    dup = [r for r in rendered if r.duplicate_of]
    assert [(r.entry.start_line, r.duplicate_of) for r in dup] == [(223, 222)]
