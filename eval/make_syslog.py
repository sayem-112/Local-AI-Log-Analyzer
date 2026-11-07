"""Third test log: Linux auth/syslog (plain text, no JSON, no HTTP), with known answers.

A different domain from the two web logs: SSH brute force ending in a login and a
sudo read of /etc/shadow, a username-enumeration sweep, and decoys (cron, one typo).
Usage: python eval/make_syslog.py -> eval/syslog_test.log + eval/syslog_expected.json
"""
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(11)
OUT = Path(__file__).parent
t = datetime(2026, 10, 30, 9, 0, 0)
lines = []


def add(msg, gap=None):
    global t
    t += timedelta(seconds=gap if gap is not None else random.randint(20, 90))
    lines.append(f"{t.strftime('%b %d %H:%M:%S')} web01 {msg}")
    return len(lines)


def noise(n):
    for _ in range(n):
        add(random.choice([
            f"CRON[{random.randint(1000, 9999)}]: (root) CMD (/usr/local/bin/backup.sh)",
            f"systemd[1]: Started Session {random.randint(100, 999)} of user www-data.",
            "kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.0.2.250 DST=10.0.0.4 PROTO=UDP DPT=123",
            f"sshd[{random.randint(2000, 2999)}]: Accepted publickey for deploy from 10.0.0.21 port {random.randint(40000, 60000)} ssh2",
            f"nginx[812]: worker process {random.randint(800, 900)} exited on signal 0",
        ]))


brute, enum, typo = [], [], []
noise(5)
for i in range(10):
    brute.append(add(f"sshd[{2100 + i}]: Failed password for root from 198.51.100.66 port {51000 + i} ssh2"))
    noise(random.randint(3, 6))
    if i == 4:
        for u in ["admin", "test", "oracle", "postgres", "ubuntu", "git", "ftpuser"]:
            enum.append(add(f"sshd[{2400 + len(enum)}]: Invalid user {u} from 203.0.113.77 port {60000 + len(enum)}", gap=3))
    if i == 7:
        typo.append(add("sshd[2550]: Failed password for alice from 10.0.0.12 port 50111 ssh2"))
        typo.append(add("sshd[2551]: Accepted password for alice from 10.0.0.12 port 50112 ssh2", gap=12))
login = add("sshd[2199]: Accepted password for root from 198.51.100.66 port 51099 ssh2")
shadow = add("sudo: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/cat /etc/shadow", gap=40)
noise(6)

(OUT / "syslog_test.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
expected = {
    "_note": "Answers for eval/syslog_test.log (generated). Test fixture only.",
    "expected": [
        {"name": "SSH brute force -> root login", "actor": "198.51.100.66",
         "types": ["brute_force", "account_compromise", "unauthorized_access", "data_exfiltration"],
         "must_lines": [brute[0], brute[-1], login], "nice_lines": brute[1:-1], "severity": ["H", "C"]},
        {"name": "username enumeration sweep", "actor": "203.0.113.77",
         "types": ["brute_force", "scanning", "unauthorized_access"],
         "must_lines": enum[:2], "nice_lines": enum[2:], "severity": ["L", "M", "H"]},
    ],
    "benign_actors": ["10.0.0.12", "10.0.0.21", "192.0.2.250"],
    "benign_lines": typo,
}
(OUT / "syslog_expected.json").write_text(json.dumps(expected, indent=1), encoding="utf-8")
print(f"{len(lines)} lines; brute {brute[0]}..{brute[-1]} login {login} shadow {shadow}; enum {enum[0]}..{enum[-1]}")
