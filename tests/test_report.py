"""The code-only path: no model at all. Shows what facts + guard catch on their own,
and that the report still forms (fallback) when every model call fails."""
from app.ledger import Ledger
from app.pipeline import apply_chunk, prepare
from app.report import finalize


def test_report_without_model_links_chain_across_whole_file(sample, llm):
    prep = prepare(sample, llm)
    assert len(prep.chunks) > 5
    ledger = Ledger()
    for ch in prep.chunks:
        apply_chunk(prep, ch, ledger, None)  # as if every model call failed
    rep = finalize(prep, ledger, None)
    by_ip = {f["ip"]: f for f in rep["findings"]}
    takeover = by_ip["203.0.113.44"]
    assert takeover["severity_code"] == "C"
    assert {5, 189, 196, 201} <= {e["line"] for e in takeover["evidence"]}
    assert "Account compromise" in takeover["chain"]
    assert by_ip["203.0.113.201"]["type_code"] == "prompt_injection"  # code guard
    assert "203.0.113.90" in by_ip and "203.0.113.155" in by_ip
    # normal errors and the single mistyped password are never reported
    assert "198.51.100.96" not in by_ip and "198.51.100.88" not in by_ip
    cited = {e["line"] for f in rep["findings"] for e in f["evidence"]}
    assert not cited & {11, 45, 84, 135, 136, 147, 207, 238, 239}
