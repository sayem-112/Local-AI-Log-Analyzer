"""Edge-case uploads against the running app. Usage: python scripts/upload_cases.py"""
import json
import os

import httpx

c = httpx.Client(base_url="http://127.0.0.1:8000", timeout=60)
sample = open("Cultive8_Workspace_Agrigen_Server.log", "rb").read()
line = json.dumps({"time": "2026-01-01T00:00:00Z", "client_ip": "10.0.0.1", "path": "/", "status": 200})
cases = {
    "wrong extension (.exe)": ("evil.exe", b"MZ\x90"),
    "double extension (.log.exe)": ("x.log.exe", b"hello\n"),
    "uppercase extension (.LOG)": ("UPPER.LOG", b"2026-01-01 10:00:00 INFO ok\n"),
    "path in filename": ("../../etc/passwd.log", b"2026-01-01 10:00:00 INFO ok\n"),
    "empty": ("e.log", b""),
    "whitespace only": ("w.log", b" \n\t\n  \n"),
    "binary (NUL bytes)": ("b.log", b"\x00\x01\x02abc" * 50),
    "random high bytes, not UTF-8": ("r.log", os.urandom(4000).replace(b"\x00", b"\x01")),
    "UTF-16 with BOM": ("u16.log", "2026-01-01 10:00:00 INFO ok\n".encode("utf-16")),
    "UTF-8 BOM + JSON lines": ("bom.log", b"\xef\xbb\xbf" + sample),
    "CRLF line endings": ("crlf.log", sample.replace(b"\n", b"\r\n")),
    "one 4 MB line, no newline": ("long.log", b"x" * (4 * 1024 * 1024)),
    "over 5 MB": ("big.log", b"a\n" * (3 * 1024 * 1024)),
    "mixed JSON and junk lines": ("mixed.log", ("\n".join([line] * 40 + ["garbage ### not json"] * 5) + "\n").encode()),
}
for name, (fname, data) in cases.items():
    r = c.post("/api/jobs", files={"file": (fname, data)})
    body = r.json()
    detail = body.get("detail") or f"accepted: fmt={body.get('fmt')} lines={body.get('lines')} stored as {body.get('filename')!r}"
    print(f"{r.status_code}  {name:30} {detail}")
