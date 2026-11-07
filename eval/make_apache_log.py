"""Generate a second, different test log (Apache combined format) with known answers.

Different format, IPs, paths, usernames and attack shapes from the sample, so a good
score here means the pipeline isn't tuned to one file. Deterministic (fixed seed).
Usage: python eval/make_apache_log.py  -> eval/apache_test.log + eval/apache_expected.json
"""
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(7)
OUT = Path(__file__).parent
start = datetime(2026, 10, 20, 14, 0, 0, tzinfo=timezone.utc)
BROWSERS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0.0.0 Safari/537.36 Edg/129.0",
]
PAGES = ["/", "/shop", "/shop/item/17", "/shop/item/42", "/cart", "/static/site.css", "/static/app.js",
         "/account", "/api/v2/stock?sku=17", "/blog/harvest-tips"]
lines, t = [], start


def add(ip, method, path, status, size, ua, user="-", gap=None):
    global t
    t += timedelta(seconds=gap if gap is not None else random.randint(15, 70))
    ts = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
    lines.append(f'{ip} - {user} [{ts}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"')
    return len(lines)


def normal(n):
    for _ in range(n):
        ip = f"192.0.2.{random.randint(20, 60)}"
        add(ip, "GET", random.choice(PAGES), random.choice([200] * 8 + [304, 404]), random.randint(300, 9000),
            random.choice(BROWSERS))


exp = {"stuff": [], "sqli": [], "scan": [], "mistype": [], "outage": []}
normal(6)
for i in range(12):  # credential attack, spread over the whole file
    exp["stuff"].append(add("198.51.100.23", "POST", "/account/login?username=ops.manager", 401, 512,
                            "Go-http-client/2.0"))
    normal(random.randint(4, 7))
    if i == 3:  # scanner burst early in the file
        for p in ["/.env", "/.aws/credentials", "/config.php.bak", "/admin.php", "/backup.zip", "/.DS_Store",
                  "/server-info", "/phpinfo.php"]:
            exp["scan"].append(add("203.0.113.66", "GET", p, random.choice([403, 404]), 210,
                                   "Mozilla/5.00 (Nikto/2.5.0)", gap=2))
    if i == 6:  # SQL injection probes, one returns a 500 (error-based, may have reached the DB)
        for p, st in [("/shop/item/17%20AND%201=1", 200), ("/shop/item/17'--", 500),
                      ("/api/v2/stock?sku=17%27%20UNION%20SELECT%20username,password%20FROM%20users--", 500)]:
            exp["sqli"].append(add("192.0.2.200", "GET", p, st, 1800, "sqlmap/1.8.4#stable", gap=5))
    if i == 8:  # a real user mistypes once (decoy)
        exp["mistype"].append(add("192.0.2.31", "POST", "/account/login?username=dana", 401, 512, BROWSERS[0]))
        exp["mistype"].append(add("192.0.2.31", "POST", "/account/login?username=dana", 302, 0, BROWSERS[0], gap=9))
    if i == 9:  # an outage: many users get 503 for a minute (decoy)
        for _ in range(5):
            exp["outage"].append(add(f"192.0.2.{random.randint(20, 60)}", "GET", "/shop", 503, 120,
                                     random.choice(BROWSERS), gap=8))
success = add("198.51.100.23", "POST", "/account/login?username=ops.manager", 302, 0, "Go-http-client/2.0")
normal(3)
dump = add("198.51.100.23", "GET", "/admin/customers/export?format=xlsx&all=true", 200, 7340032,
           "Go-http-client/2.0")
normal(5)

(OUT / "apache_test.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
expected = {
    "_note": "Answers for eval/apache_test.log (generated). Test fixture only.",
    "expected": [
        {"name": "credential attack -> login -> bulk export", "actor": "198.51.100.23",
         "types": ["brute_force", "account_compromise", "data_exfiltration"],
         "must_lines": [exp["stuff"][0], exp["stuff"][-1], success], "nice_lines": [dump], "severity": ["C"]},
        {"name": "SQL injection with server errors", "actor": "192.0.2.200", "types": ["sql_injection"],
         "must_lines": exp["sqli"][1:], "nice_lines": exp["sqli"][:1], "severity": ["H", "C"]},
        {"name": "scanner (Nikto)", "actor": "203.0.113.66", "types": ["scanning", "unauthorized_access", "path_traversal"],
         "must_lines": exp["scan"][:2], "nice_lines": exp["scan"][2:], "severity": ["L", "M"]},
    ],
    "benign_actors": ["192.0.2.31"],
    "benign_lines": exp["mistype"] + exp["outage"],
}
(OUT / "apache_expected.json").write_text(json.dumps(expected, indent=1), encoding="utf-8")
print(f"{len(lines)} lines; expected: { {e['actor']: e['must_lines'] for e in expected['expected']} }")
