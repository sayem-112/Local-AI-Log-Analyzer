"""FastAPI app: upload, start, progress, report, and system stats.

Run: uvicorn app.main:app --port 8000   (llama-server must be running, see README)
"""
from __future__ import annotations

import json
import mimetypes
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

import psutil
from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import config
from .jobs import Runner, Store
from .logparse import index_entries

STATIC = config.ROOT / "static"
mimetypes.add_type("font/woff2", ".woff2")  # Windows' registry lacks it; serve fonts with the right type
store: Store
runner: Runner


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global store, runner
    config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    store = Store()
    runner = Runner(store)
    runner.start()  # resumes any job interrupted by a restart
    yield


app = FastAPI(title="traceLog", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC), name="static")  # bundled fonts: works offline


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.post("/api/jobs")
async def upload(file: UploadFile):
    name = Path(file.filename or "").name
    if Path(name).suffix.lower() not in config.ALLOWED_EXTENSIONS:
        raise HTTPException(400, "Only .log and .txt files are accepted.")
    tmp = config.UPLOAD_DIR / f"incoming-{os.getpid()}-{time.time_ns()}.part"
    size, head = 0, b""
    try:
        with open(tmp, "wb") as out:  # stream to disk in 64 KB pieces; never hold the file in RAM
            while chunk := await file.read(64 * 1024):
                size += len(chunk)
                if size > config.MAX_UPLOAD_BYTES:
                    raise HTTPException(413, f"File is larger than {config.MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")
                if len(head) < 8192:
                    head += chunk[: 8192 - len(head)]
                out.write(chunk)
        if size == 0 or not head.strip():
            raise HTTPException(400, "The file is empty.")
        if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
            raise HTTPException(400, "This file is UTF-16. Save it as UTF-8 and upload again.")
        if b"\x00" in head:
            raise HTTPException(400, "This looks like a binary file, not a text log.")
        sample = head.decode("utf-8", errors="replace")
        if sample.count("�") > len(sample) * 0.01 + 2:  # tolerate a cut multi-byte char at the edge
            raise HTTPException(400, "The file is not UTF-8 text.")
        fmt, entries = index_entries(str(tmp))
        if not entries:
            raise HTTPException(400, "No log entries found in the file.")
        job_id = store.create_job(name, "", size, entries[-1].end_line, fmt)
        final = config.UPLOAD_DIR / f"{job_id}.log"
        tmp.replace(final)
        store.update(job_id, path=str(final))
    finally:
        tmp.unlink(missing_ok=True)
    return _job_view(job_id)


@app.post("/api/jobs/{job_id}/start")
def start(job_id: str):
    job = _get(job_id)
    if job["status"] in ("queued", "running"):
        raise HTTPException(409, "This job is already running.")
    if job["status"] == "done":
        store.exec("DELETE FROM parts WHERE job_id=?", (job_id,))  # explicit re-run starts fresh
        store.update(job_id, report=None, parts_done=0, judge_done=0, judge_total=0)
    runner.submit(job_id)
    return _job_view(job_id)


@app.post("/api/jobs/{job_id}/cancel")
def cancel(job_id: str):
    _get(job_id)
    store.update(job_id, cancel=1)
    return _job_view(job_id)


@app.get("/api/jobs")
def list_jobs():
    rows = store.all("SELECT id, filename, status, created_at FROM jobs ORDER BY created_at DESC LIMIT 20")
    return rows


@app.get("/api/jobs/{job_id}")
def job(job_id: str):
    return _job_view(job_id)


@app.get("/api/jobs/{job_id}/report.json")
def report_download(job_id: str):
    job = _get(job_id)
    if not job["report"]:
        raise HTTPException(404, "The report is not ready yet.")
    return JSONResponse(json.loads(job["report"]),
                        headers={"Content-Disposition": f'attachment; filename="report-{job_id}.json"'})


@app.get("/api/system")
def system():
    backend = psutil.Process().memory_info().rss
    model_rss = _model_rss()
    return {
        "model_online": runner.llm.healthy(),
        "model": runner.llm.model_name(),
        "context_tokens": config.CTX_TOKENS,
        "rss_backend_mb": round(backend / 2**20),
        "rss_model_mb": round(model_rss / 2**20),
        "rss_total_mb": round((backend + model_rss) / 2**20),
        "ram_limit_mb": 4096,
        "busy_job": runner.current,
    }


_model_proc: psutil.Process | None = None


def _model_rss() -> int:
    """RSS of llama-server. Scanning every process takes ~0.5 s on Windows, so the
    process handle is cached and only looked up again if that process exits."""
    global _model_proc
    try:
        if _model_proc is not None and _model_proc.is_running():
            return _model_proc.memory_info().rss
    except psutil.Error:
        pass
    _model_proc = next((p for p in psutil.process_iter(["name"])
                        if (p.info["name"] or "").lower().startswith("llama-server")), None)
    try:
        return _model_proc.memory_info().rss if _model_proc else 0
    except psutil.Error:
        return 0


def _get(job_id: str) -> dict:
    job = store.one("SELECT * FROM jobs WHERE id=?", (job_id,))
    if not job:
        raise HTTPException(404, "Unknown job.")
    return job


def _job_view(job_id: str) -> dict:
    job = _get(job_id)
    parts = store.all("SELECT idx, first_line, last_line, log_tokens, status, attempts, error, ms, result "
                      "FROM parts WHERE job_id=? ORDER BY idx", (job_id,))
    view_parts = []
    for p in parts:
        r = json.loads(p.pop("result")) if p.get("result") else {}
        p.update(accepted=len(r.get("accepted", [])), rejected=len(r.get("rejected", [])),
                 prompt_tokens=r.get("prompt_tokens"), cached_tokens=r.get("cached_tokens"),
                 gen_tokens=r.get("gen_tokens"), memory=r.get("memory", ""), split=r.get("split", False),
                 rejected_items=r.get("rejected", []))
        view_parts.append(p)
    done_ms = [p["ms"] for p in view_parts if p["status"] == "done" and p["ms"]]
    remaining = sum(1 for p in view_parts if p["status"] == "pending")
    return {
        "id": job["id"], "filename": job["filename"], "size": job["size"], "lines": job["lines"], "fmt": job["fmt"],
        "status": job["status"], "stage": job["stage"], "error": job["error"], "model": job["model"],
        "n_parts": job["n_parts"], "parts_done": job["parts_done"],
        "judge_done": job["judge_done"], "judge_total": job["judge_total"],
        "eta_s": round(remaining * (sum(done_ms) / len(done_ms)) / 1000) if done_ms and remaining else None,
        "elapsed_s": round((job["finished_at"] or time.time()) - job["started_at"]) if job["started_at"] else None,
        "budget": json.loads(job["budget"]) if job["budget"] else None,
        "parts": view_parts,
        "report": json.loads(job["report"]) if job["report"] else None,
    }
