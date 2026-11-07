"""End-to-end smoke test of the running web app: upload -> start -> poll -> report.

Usage (app on :8000, model on :8081):
  python scripts/web_smoke.py Cultive8_Workspace_Agrigen_Server.log eval/apache_test.log
Saves each report to data/web_<job>.json for scripts/eval.py.
"""
import json
import sys
import time
from pathlib import Path

import httpx

c = httpx.Client(base_url="http://127.0.0.1:8000", timeout=30)
Path("data").mkdir(exist_ok=True)


def get(url: str) -> dict:
    for _ in range(5):  # uvicorn closes idle keep-alive connections; just retry
        try:
            return c.get(url).json()
        except httpx.TransportError:
            time.sleep(1)
    raise RuntimeError(f"app not reachable: {url}")


for arg in sys.argv[1:]:
    if arg.startswith("job:"):  # watch an existing job: job:<id>
        job = {"id": arg[4:]}
    else:
        with open(arg, "rb") as fh:
            job = c.post("/api/jobs", files={"file": (Path(arg).name, fh.read())}).json()
        c.post(f"/api/jobs/{job['id']}/start")
    print("watching", job["id"], arg, flush=True)
    while True:
        s = get(f"/api/jobs/{job['id']}")
        if s["status"] not in ("queued", "running"):
            break
        time.sleep(3)
    out = Path("data") / f"web_{job['id']}.json"
    out.write_text(json.dumps(s["report"] or {}), encoding="utf-8")
    print(s["status"], f"{s['elapsed_s']}s", (s["report"] or {}).get("summary"), "->", out, flush=True)
print(get("/api/system"))
