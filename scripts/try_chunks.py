"""Dev tool: run the model on selected parts only, to tune prompts fast.

Parts not selected are still folded into the ledger (facts only), so MEMORY is realistic.
Usage: python scripts/try_chunks.py file.log --only 0,1,4,10
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, ".")
from app.ledger import Ledger  # noqa: E402
from app.llm import LLM  # noqa: E402
from app.pipeline import analyze_chunk, apply_chunk, prepare  # noqa: E402
from app.report import finalize  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--only", default="")
    ap.add_argument("--show-prompt", action="store_true")
    ap.add_argument("--no-judge", action="store_true")
    ap.add_argument("--out", default="")
    ap.add_argument("--cache", default="", help="JSON file of part results to reuse/save (judge tuning)")
    args = ap.parse_args()
    only = {int(x) for x in args.only.split(",") if x.strip()}

    llm = LLM()
    prep = prepare(args.log, llm)
    print(f"parts={len(prep.chunks)} log_budget={prep.log_budget} fixed_prompt={prep.base_prompt_tokens}")
    ledger = Ledger()
    total = time.time()
    cache = json.load(open(args.cache, encoding="utf-8")) if args.cache and os.path.exists(args.cache) else {}
    for ch in prep.chunks:
        result = None
        if str(ch.index) in cache:
            result = cache[str(ch.index)]  # reuse saved part results to tune the judge quickly
        elif not only or ch.index in only:
            result = analyze_chunk(prep, ch, ledger, llm)
            cache[str(ch.index)] = result
            print(f"\n== part {ch.index} L{ch.first_line}-L{ch.last_line} prompt={result['prompt_tokens']} "
                  f"cached={result['cached_tokens']} gen={result['gen_tokens']} {result['ms']/1000:.1f}s "
                  f"finish={result['finish_reason']}")
            if args.show_prompt or result["memory"]:
                print("  MEMORY:", result["memory"].replace("\n", "\n          "))
            for f in result["accepted"]:
                print("  OK ", json.dumps(f))
            for f in result["rejected"]:
                print("  REJ", json.dumps(f))
        apply_chunk(prep, ch, ledger, result)
    if args.cache:
        json.dump(cache, open(args.cache, "w", encoding="utf-8"))
    print(f"\nparts done in {time.time()-total:.0f}s; judging...")
    report = finalize(prep, ledger, None if args.no_judge else llm)
    for f in report["findings"]:
        print(f"\n{f['id']} {f['severity']:8} {f['attack_type']:20} ip={f['ip']} users={f['users']} "
              f"[{f['decided_by']}]\n   chain={f['chain']}\n   lines={[e['line'] for e in f['evidence']]}"
              f"\n   reason={f['reason']}\n   action={f['action']}")
    for d in report["dismissed"]:
        print(f"\nDISMISSED {d['id']} by {d['decided_by']}: {d['reason']} {d['lines']}")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
    print(f"\ntotal {time.time()-total:.0f}s")


if __name__ == "__main__":
    main()
