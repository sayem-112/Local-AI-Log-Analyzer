"""Pre-grouping must never hide an attack line from the model."""
import json
from pathlib import Path

from app.logparse import index_entries
from app.routine import routine_lines

EVAL = Path(__file__).resolve().parent.parent / "eval"


def _attack_lines(expected: Path) -> set[int]:
    exp = json.loads(expected.read_text(encoding="utf-8"))
    return {n for e in exp["expected"] for n in e["must_lines"] + e["nice_lines"]}


def test_sample_folds_browser_traffic_but_no_attack_line(sample):
    _, entries = index_entries(sample)
    fold = routine_lines(sample, entries)
    assert len(fold) > 100  # most of the sample is ordinary browsing
    assert not fold & _attack_lines(EVAL / "sample_expected.json")
    assert not fold & {217, 223, 196, 198, 201}  # injection, duplicate, takeover, admin, export


def test_other_logs_fold_no_attack_line():
    for log, exp in [("apache_test.log", "apache_expected.json"), ("syslog_test.log", "syslog_expected.json")]:
        path = str(EVAL / log)
        _, entries = index_entries(path)
        assert not routine_lines(path, entries) & _attack_lines(EVAL / exp)
