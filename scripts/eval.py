"""Score a report against hand-labelled answers.

Usage: python scripts/eval.py report.json eval/sample_expected.json
Prints per-incident results and a one-line summary.
"""
import json
import sys


def main(report_path: str, expected_path: str) -> None:
    report = json.load(open(report_path, encoding="utf-8"))
    exp = json.load(open(expected_path, encoding="utf-8"))
    findings = report.get("findings", [])
    matched_ids = set()
    found = type_ok = sev_ok = 0
    must_hit = must_total = nice_hit = nice_total = 0

    for e in exp["expected"]:
        f = next((f for f in findings if e["actor"] in f.get("ips", []) or e["actor"] == f.get("ip")), None)
        lines = {ev["line"] for ev in f["evidence"]} if f else set()
        mh = len(lines & set(e["must_lines"]))
        nh = len(lines & set(e["nice_lines"]))
        must_hit += mh
        must_total += len(e["must_lines"])
        nice_hit += nh
        nice_total += len(e["nice_lines"])
        if not f:
            print(f"MISS  {e['name']:45} ({e['actor']})")
            continue
        matched_ids.add(f["id"])
        found += 1
        codes = {f["type_code"], *[k for k, v in _labels().items() if v in f.get("chain", [])]}
        t_ok = f["type_code"] in e["types"] and codes <= set(e["types"]) | {"unauthorized_access"}
        s_ok = f["severity_code"] in e["severity"]
        type_ok += t_ok
        sev_ok += s_ok
        print(f"FOUND {e['name']:45} type={f['type_code']}{'' if t_ok else ' (WRONG)'} "
              f"chain={f.get('chain')} sev={f['severity_code']}{'' if s_ok else ' (WRONG)'} "
              f"lines {mh}/{len(e['must_lines'])} must, {nh}/{len(e['nice_lines'])} nice")

    fps = [f for f in findings if f["id"] not in matched_ids]
    for f in fps:
        print(f"FALSE POSITIVE {f['id']} {f['type_code']} ip={f.get('ip')} lines={[x['line'] for x in f['evidence']][:8]}")
    benign_hits = sorted({ev["line"] for f in findings for ev in f["evidence"]} & set(exp["benign_lines"]))
    if benign_hits:
        print(f"benign lines cited as evidence: {benign_hits}")

    n = len(exp["expected"])
    print(f"\nSUMMARY found {found}/{n} | correct type {type_ok}/{n} | correct severity {sev_ok}/{n} | "
          f"must-lines {must_hit}/{must_total} | nice-lines {nice_hit}/{nice_total} | "
          f"false positives {len(fps)} | benign lines cited {len(benign_hits)}")


def _labels():
    sys.path.insert(0, ".")
    from app.report import TYPE_LABELS
    return TYPE_LABELS


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
