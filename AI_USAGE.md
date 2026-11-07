# AI Usage

I set the technical direction, made the core design decisions, and verified the results against a scoring script. I used ChatGPT Codex to speed up implementation, and the app runs a local model for all log analysis.

## Tools

| Tool | What I used it for |
|---|---|
| ChatGPT Codex (OpenAI) | Implementation under my direction: writing code to my specifications, running benchmarks and evaluations I requested, and drafting documentation for my review. |
| Qwen3.5-2B and 0.8B, Q4_K_M, via llama.cpp | Runtime models. They perform all log analysis in the app, offline. No cloud AI is used at runtime. |

## How I directed the work

1. **Understanding before building.** I had Codex read the brief and all 258 lines of the sample log, then explain the requirements, the purpose of the task, and what a strong submission would look like. I checked its analysis against my own: the planted attacks, the decoys (database timeouts, deploy errors, one mistyped password, a duplicated line), and the prompt injection at line 217.

2. **Architecture review first.** I asked for the biggest risks and a priority order before writing code. That review set the plan: measure the model first, then splitting, memory, reliability, and finally the application.

3. **The core design decision.** I chose to keep cross-slice memory in code and let the model judge, because a small model can drop facts when it carries its own summary. I also set the speed strategy: short replies, a fixed prompt prefix the KV cache can reuse, compacted log lines, and prompt tuning on 0.8B with a handful of slices before full runs.

4. **Choosing the model by measurement.** I had the pipeline scored on 0.8B, then approved a 2B comparison on the same evaluation. I picked 2B because type accuracy improved from 2/5 to 4/5 at the same false-positive rate, while still fitting the RAM budget.

5. **Hardening before the deadline.** I ran validation against four questions: does it overfit to one log, can code-side pre-grouping reduce model calls, how does it handle bad uploads, and does it produce the same answer twice?

6. **Documentation.** I set the README structure and reviewed the final documentation to make sure the implementation, evaluation results, and limitations were accurately represented.

## Local model prompts

Both prompts live in `app/prompts.py`.

**Per-slice prompt.** The model gets MEMORY (code-counted facts about IPs and users from earlier slices) and one slice of compacted log lines between `<log>` tags, marked as untrusted data. A JSON schema, enforced by the llama.cpp grammar, shapes the reply:

```json
{"f":[{"l":[lines],"e":"quoted text","t":type,"s":"L|M|H|C","r":"reason"}]}
```

Design choices behind it:

- The system prompt stays identical across calls, so llama-server can reuse about 411 cached tokens per call.
- One-letter keys keep replies short; on two CPU threads, each generated token costs about five prompt tokens.
- The schema asks for lines and a quote before the label, so the model commits to evidence first.
- The reply has no IP field. Code takes the IP from the cited line.

**Judge prompt.** One call per suspect after the last slice. It reads code-counted FACTS, verified FLAGS and EVIDENCE lines, then returns attack or not, the attack chain, the main type, severity, and a reason. Response actions come from a code playbook.

## Prompt changes

Scores come from `scripts/eval.py` against hand-labelled answers.

| Version | Change | Reason and result |
|---|---|---|
| v1 | Rule list, reply includes an IP field (0.8B) | Baseline. The model over-used one label and a wrong flag carried forward through memory. |
| v2 | Quote evidence in the reply; one example; memory holds code facts and no model flags | Stopped wrong flags from spreading between slices. |
| v3 | Removed the IP field; code derives the actor; structural checks per type | Removed invented IPs as a class. Brute force linked across slices. |
| v4 | A mismatched quote lowers confidence instead of rejecting | Recovered real SQL injection findings. |
| v5 | Added the judge stage and triage | 0.8B: found 4/5, type 2/5, severity 4/5, 0 false positives. |
| v6 | Actions from a playbook | Consistent, specific response steps. |
| v7 | Switched to 2B with the same prompts | Type accuracy improved from 2/5 to 4/5. |
| v8 | Code guard for prompt injection | A model can't be trusted to report text aimed at itself. |
| v9 | Judge: a blocked attempt is still an attack; strong facts override a dismissal | Kept the scanner, the burst, and the injection in the report. |
| v10 | Each chain step needs a counter or a verified flag | Provided log: 5/5 found, correct type and severity; 9/9 required lines; 0 false positives. |
| v11 | Payload flags reach the judge; 5xx errors kept as context | Generated Apache log: 2/3 to 3/3. |
| v12 | A 5xx after a payload means it reached the server: High | Apache log 3/3 on each measure; provided log unchanged. |

**Experiment:** Leaving routine browser traffic out of prompts halved model calls on web logs but cost one detection on the Apache log. I kept it off by default (`FOLD_ROUTINE=1` turns it on).

## Token budget plan

The brief estimates the log at about 20,000 tokens. I measured it with the model's own tokenizer before designing anything: 39,638 tokens, 154 per line.

| Step | Tokens |
|---|---:|
| Raw log | 39,638 |
| After compaction (drop constant and alias fields and request IDs, decode URLs, shorten user agents, keep L<n> line numbers) | 13,344, 3x smaller |

Each call fits 2,048 tokens:

| Part | Tokens |
|---|---:|
| Fixed instructions and chat template | About 442, with 411 reused from cache |
| Memory | Up to 260 |
| Log slice | Up to about 1,006 |
| Reply | 300 reserved |
| Safety margin | 40 |

The app counts the full templated prompt (`/apply-template` then `/tokenize`) before each call and trims memory if the total would pass 2,048. The provided log needs 14 slices. llama-server runs with `--cache-ram 0` and `--ctx-checkpoints 8`, which keeps RAM at 2.0 GB of 4 GB while still reusing the prompt prefix.

## Mistakes found and fixed

**In AI-written code, found through tests, benchmarks, and evaluation runs:**

- An IP regex matched browser versions such as Chrome/130.0.0.0.
- ID matching treated 203.0.113.4 as a match for 203.0.113.44.
- Model flags placed in memory repeated a wrong label in later slices.
- llama-server's default 8 GB prompt cache let RAM grow to 3.8 GB.
- Triage dismissed a SQL injection whose next two requests returned HTTP 500.
- A UTF-8 BOM hid line 1, and junk lines inside a JSON log corrupted the entry above them.
- The system stats endpoint took about 550 ms per call; it now takes under 10 ms.

**From the local model, handled with checks in code:**

- Invented IPs and line numbers. Code now takes the actor from the cited line.
- Copied values from the prompt example into findings.
- Skipped the line telling an AI to report everything as safe. A code guard catches it.
- Called blocked attacks "not an attack". Strong facts now override a dismissal.
- Wrote the attacker's steps as the response action. Actions now come from a playbook.

## Verification

`scripts/eval.py` scores each report against hand-labelled answers.

- Three logs in different formats: the provided JSON log (5/5), a generated Apache log (3/3), and a generated Linux auth log (2/2). Zero false positives across all three.
- Six runs of the provided log produced identical findings, severities, and evidence lines.
- I killed the model server during a run; the job waited, retried, and finished with no lost slices.
- 13 unit tests run without a model, including one proving that pre-grouping hides no attack line in the three test logs.
- 14 edge-case uploads: wrong extensions, empty, binary, non-UTF-8, UTF-16, oversized, a path in the filename, CRLF, a 4 MB single line, and mixed JSON with junk.

## Decisions I made

- Code owns the memory; the model reads payloads and judges.
- Measure the real token count first, and design the budget from that.
- Choose the model by evaluation score: 2B over 0.8B.
- Severity and triage rules live in code, where a reviewer can read and change them.
- Pre-grouping stays off by default, because a measured speed gain cost a detection.
- Test generalization on two extra log formats before submitting.