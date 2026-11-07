"""Job storage (SQLite) and the single background worker that runs analyses.

Reliability rules:
- One job and one model call at a time (the 2048-token model has one slot; RAM stays flat).
- Every finished part is committed before the next starts, so a crash loses at most one call.
- Resume after restart: parts already done are replayed into the ledger from their saved
  results (no model calls); analysis continues from the first unfinished part.
- A part that keeps failing is retried with backoff, then split in half; if it still
  fails it is marked failed and the job continues. Code-counted facts still include its
  lines, and the report lists it under failed_parts.
"""
from __future__ import annotations

import json
import queue
import sqlite3
import threading
import time
import traceback
import uuid
from dataclasses import replace

from . import config
from .chunker import Chunk
from .ledger import Ledger
from .llm import LLM, LLMError
from .pipeline import analyze_chunk, apply_chunk, prepare
from .report import finalize

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY, filename TEXT, path TEXT, size INTEGER, lines INTEGER, fmt TEXT,
    status TEXT, stage TEXT, error TEXT, model TEXT,
    n_parts INTEGER DEFAULT 0, parts_done INTEGER DEFAULT 0, judge_done INTEGER DEFAULT 0, judge_total INTEGER DEFAULT 0,
    created_at REAL, started_at REAL, finished_at REAL, cancel INTEGER DEFAULT 0,
    budget TEXT, report TEXT
);
CREATE TABLE IF NOT EXISTS parts (
    job_id TEXT, idx INTEGER, first_line INTEGER, last_line INTEGER, log_tokens INTEGER,
    status TEXT, attempts INTEGER DEFAULT 0, error TEXT, result TEXT, ms INTEGER,
    PRIMARY KEY (job_id, idx)
);
"""


class Store:
    def __init__(self, path=config.DB_PATH):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.lock = threading.Lock()
        with self.lock:
            self.db.executescript(SCHEMA)

    def exec(self, sql: str, args=()) -> None:
        with self.lock:
            self.db.execute(sql, args)

    def one(self, sql: str, args=()) -> dict | None:
        with self.lock:
            row = self.db.execute(sql, args).fetchone()
        return dict(row) if row else None

    def all(self, sql: str, args=()) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.db.execute(sql, args).fetchall()]

    def create_job(self, filename: str, path: str, size: int, lines: int, fmt: str) -> str:
        job_id = uuid.uuid4().hex[:12]
        self.exec("INSERT INTO jobs (id, filename, path, size, lines, fmt, status, stage, model, created_at) "
                  "VALUES (?,?,?,?,?,?, 'ready', 'uploaded', ?, ?)",
                  (job_id, filename, path, size, lines, fmt, config.MODEL_NAME, time.time()))
        return job_id

    def update(self, job_id: str, **fields) -> None:
        cols = ", ".join(f"{k}=?" for k in fields)
        self.exec(f"UPDATE jobs SET {cols} WHERE id=?", (*fields.values(), job_id))

    def save_part(self, job_id: str, ch: Chunk, status: str, attempts: int, result=None, error=None, ms=0):
        """One transaction per finished part: this is what makes resume safe."""
        with self.lock:
            self.db.execute("BEGIN")
            self.db.execute(
                "UPDATE parts SET status=?, attempts=?, result=?, error=?, ms=? WHERE job_id=? AND idx=?",
                (status, attempts, json.dumps(result) if result is not None else None, error, ms, job_id, ch.index))
            done = self.db.execute("SELECT COUNT(*) FROM parts WHERE job_id=? AND status IN ('done','failed')",
                                   (job_id,)).fetchone()[0]
            self.db.execute("UPDATE jobs SET parts_done=? WHERE id=?", (done, job_id))
            self.db.execute("COMMIT")


class Runner:
    """Single worker thread. Jobs queue up; RAM use stays at one model + one job."""

    def __init__(self, store: Store, llm: LLM | None = None):
        self.store = store
        self.llm = llm or LLM()
        self.q: queue.Queue[str] = queue.Queue()
        self.current: str | None = None
        self.thread = threading.Thread(target=self._loop, daemon=True, name="analysis-worker")

    def start(self) -> None:
        # Resume jobs interrupted by a restart, oldest first.
        for row in self.store.all("SELECT id FROM jobs WHERE status IN ('queued','running') ORDER BY created_at"):
            self.store.update(row["id"], status="queued", stage="resuming")
            self.q.put(row["id"])
        self.thread.start()

    def submit(self, job_id: str) -> None:
        self.store.update(job_id, status="queued", stage="waiting", error=None, cancel=0)
        self.q.put(job_id)

    def _loop(self) -> None:
        while True:
            job_id = self.q.get()
            self.current = job_id
            try:
                self.run(job_id)
            except Exception as e:  # never let one job kill the worker
                traceback.print_exc()
                self.store.update(job_id, status="failed", stage="error", error=str(e)[:500], finished_at=time.time())
            finally:
                self.current = None

    def run(self, job_id: str) -> None:
        job = self.store.one("SELECT * FROM jobs WHERE id=?", (job_id,))
        if not job or job["status"] not in ("queued", "running"):
            return
        self.store.update(job_id, status="running", stage="waiting for model",
                          started_at=job["started_at"] or time.time())
        self._wait_for_model(job_id)
        self.store.update(job_id, model=self.llm.model_name())
        self.store.update(job_id, stage="splitting")
        prep = prepare(job["path"], self.llm)
        self._ensure_parts(job_id, prep)
        self.store.update(job_id, n_parts=len(prep.chunks), budget=json.dumps({
            "context": config.CTX_TOKENS, "fixed_prompt": prep.base_prompt_tokens,
            "memory_cap": config.MEMORY_TOKENS, "reply": config.REPLY_TOKENS,
            "safety": config.SAFETY_TOKENS, "log_per_part": prep.log_budget}))

        ledger = Ledger()
        saved = {p["idx"]: p for p in self.store.all("SELECT * FROM parts WHERE job_id=?", (job_id,))}
        failed = []
        for ch in prep.chunks:
            row = saved[ch.index]
            if row["status"] == "done":
                apply_chunk(prep, ch, ledger, json.loads(row["result"]))  # replay, no model call
                continue
            if self._cancelled(job_id):
                self.store.update(job_id, status="cancelled", stage="cancelled", finished_at=time.time())
                return
            self.store.update(job_id, stage=f"analyzing part {ch.index + 1}/{len(prep.chunks)}")
            result, attempts, error = self._run_part(job_id, prep, ch, ledger, row["attempts"])
            if result is not None:
                self.store.save_part(job_id, ch, "done", attempts, result, None, result.get("ms", 0))
            else:
                self.store.save_part(job_id, ch, "failed", attempts, None, error)
                failed.append({"part": ch.index, "lines": [ch.first_line, ch.last_line], "error": error})
            apply_chunk(prep, ch, ledger, result)  # facts are counted even if the model failed

        self.store.update(job_id, stage="writing report")

        def progress(i, n):
            self.store.update(job_id, judge_done=i, judge_total=n, stage=f"judging suspect {i + 1}/{n}")

        report = finalize(prep, ledger, self.llm, failed, progress)
        report["summary"] = self._summary(job_id, prep, report)
        self.store.update(job_id, status="done", stage="done", report=json.dumps(report), finished_at=time.time())

    # ---- helpers ----

    def _run_part(self, job_id: str, prep, ch: Chunk, ledger: Ledger, attempts: int):
        error = None
        for attempt in range(attempts, attempts + config.MAX_ATTEMPTS):
            try:
                return analyze_chunk(prep, ch, ledger, self.llm), attempt + 1, None
            except LLMError as e:
                error = str(e)
                if not e.retryable:
                    break
                self.store.update(job_id, stage=f"part {ch.index + 1}: retry {attempt + 1} after error")
                time.sleep(min(2 ** attempt, 20))
                self._wait_for_model(job_id, max_wait=60)
        # Last resort: smaller pieces produce shorter prompts and shorter replies.
        if ch.entry_end - ch.entry_start >= 2:
            try:
                return self._split_part(prep, ch, ledger), attempts + config.MAX_ATTEMPTS, None
            except LLMError as e:
                error = f"{error}; split also failed: {e}"
        return None, attempts + config.MAX_ATTEMPTS, error

    def _split_part(self, prep, ch: Chunk, ledger: Ledger) -> dict:
        mid = (ch.entry_start + ch.entry_end) // 2
        halves = [replace(ch, entry_end=mid, last_line=prep.rendered[mid - 1].entry.end_line),
                  replace(ch, entry_start=mid, first_line=prep.rendered[mid].entry.start_line)]
        merged = {"accepted": [], "rejected": [], "split": True, "ms": 0, "prompt_tokens": 0, "gen_tokens": 0,
                  "cached_tokens": 0, "memory": "", "salvaged": False, "finish_reason": "split"}
        for h in halves:
            r = analyze_chunk(prep, h, ledger, self.llm)
            for k in ("accepted", "rejected"):
                merged[k] += r[k]
            for k in ("ms", "prompt_tokens", "gen_tokens", "cached_tokens"):
                merged[k] += r[k]
        return merged

    def _ensure_parts(self, job_id: str, prep) -> None:
        existing = self.store.all("SELECT idx, first_line, last_line FROM parts WHERE job_id=? ORDER BY idx", (job_id,))
        plan = [(c.index, c.first_line, c.last_line) for c in prep.chunks]
        if existing and [(p["idx"], p["first_line"], p["last_line"]) for p in existing] == plan:
            return  # same plan as before the restart: keep saved results
        self.store.exec("DELETE FROM parts WHERE job_id=?", (job_id,))
        for c in prep.chunks:
            self.store.exec("INSERT INTO parts (job_id, idx, first_line, last_line, log_tokens, status) "
                            "VALUES (?,?,?,?,?, 'pending')", (job_id, c.index, c.first_line, c.last_line, c.tokens))

    def _wait_for_model(self, job_id: str, max_wait: int = 300) -> None:
        deadline = time.time() + max_wait
        while not self.llm.healthy():
            if time.time() > deadline:
                raise LLMError("model server is not responding")
            self.store.update(job_id, stage="waiting for model server")
            time.sleep(3)

    def _cancelled(self, job_id: str) -> bool:
        row = self.store.one("SELECT cancel FROM jobs WHERE id=?", (job_id,))
        return bool(row and row["cancel"])

    def _summary(self, job_id: str, prep, report: dict) -> dict:
        parts = self.store.all("SELECT * FROM parts WHERE job_id=?", (job_id,))
        results = [json.loads(p["result"]) for p in parts if p["result"]]
        return {
            "lines": prep.rendered[-1].entry.end_line if prep.rendered else 0,
            "entries": len(prep.entries), "parts": len(prep.chunks),
            "parts_failed": sum(p["status"] == "failed" for p in parts),
            "model_calls": len(results) + sum(1 for f in report["findings"] if f["decided_by"] == "model")
                           + sum(1 for d in report["dismissed"] if d["decided_by"] == "model"),
            "model_ms": sum(r.get("ms", 0) for r in results) + sum(f.get("judge_ms", 0) for f in report["findings"]),
            "prompt_tokens": sum(r.get("prompt_tokens", 0) for r in results),
            "cached_tokens": sum(r.get("cached_tokens", 0) for r in results),
            "gen_tokens": sum(r.get("gen_tokens", 0) for r in results),
            "flags_accepted": sum(len(r.get("accepted", [])) for r in results),
            "flags_rejected": sum(len(r.get("rejected", [])) for r in results),
            "findings": len(report["findings"]), "dismissed": len(report["dismissed"]),
            "model": self.llm.model_name(),
        }
