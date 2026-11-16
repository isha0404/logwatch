"""Generate a realistic *fake* auth.log for demos and tests.

Never commit real server logs: they contain real IP addresses and usernames.
All attacker IPs here come from 203.0.113.0/24 and 198.51.100.0/24, ranges
reserved for documentation (RFC 5737), so they can't belong to anyone.

    python scripts/generate_sample_log.py > samples/auth.log
"""
import random
import sys
from datetime import datetime, timedelta

rng = random.Random(42)          # fixed seed -> the same file every time
HOST = "web01"
TEAM = {"alice": "10.0.0.21", "bob": "10.0.0.34", "deploy": "10.0.0.12"}
lines: list[tuple[datetime, str]] = []


def add(ts: datetime, msg: str) -> None:
    lines.append((ts, f"sshd[{rng.randint(1000, 65000)}]: {msg}"))


def accepted(ts, user, ip, method="publickey"):
    add(ts, f"Accepted {method} for {user} from {ip} port {rng.randint(40000, 65000)} ssh2")


def failed(ts, user, ip, invalid=False):
    who = f"invalid user {user}" if invalid else user
    add(ts, f"Failed password for {who} from {ip} port {rng.randint(40000, 65000)} ssh2")


start = datetime(2026, 11, 16, 0, 0, 0)

# Normal working-day logins
for day in range(2):
    base = start + timedelta(days=day)
    for user, ip in TEAM.items():
        for _ in range(rng.randint(2, 4)):
            accepted(base + timedelta(hours=rng.randint(8, 17), minutes=rng.randint(0, 59)), user, ip)
    # the odd typo from a real user - should NOT alert
    failed(base + timedelta(hours=10, minutes=5), "alice", TEAM["alice"])

# Background internet noise: scanners trying a password or two
for _ in range(25):
    ts = start + timedelta(minutes=rng.randint(0, 2 * 24 * 60))
    failed(ts, rng.choice(["root", "admin", "test", "oracle", "ubuntu"]), f"198.51.100.{rng.randint(1, 254)}", invalid=True)

# Attack 1: fast brute force against root (BRUTE_FORCE)
t = start + timedelta(hours=9, minutes=14, seconds=31)
for i in range(48):
    failed(t + timedelta(seconds=i * 1.2), "root", "203.0.113.7")

# Attack 2: password spraying - many usernames, one IP (BRUTE_FORCE, spraying)
t = start + timedelta(hours=13, minutes=2)
for i, user in enumerate(["admin", "test", "guest", "postgres", "git", "ftp", "user", "pi", "support", "backup", "web", "mysql"]):
    failed(t + timedelta(seconds=i * 3), user, "203.0.113.45", invalid=user not in TEAM)

# Attack 3: guessed password - failures then success (BRUTE_FORCE + POSSIBLE_COMPROMISE + NEW_SOURCE + ODD_HOURS)
t = start + timedelta(days=1, hours=2, minutes=47)
for i in range(14):
    failed(t + timedelta(seconds=i * 4), "bob", "203.0.113.99")
accepted(t + timedelta(seconds=14 * 4 + 3), "bob", "203.0.113.99", method="password")

# Odd-hours login from a known machine (ODD_HOURS only)
accepted(start + timedelta(days=1, hours=23, minutes=12), "deploy", TEAM["deploy"])

# Some junk the parser must ignore
lines.append((start + timedelta(hours=1), "CRON[2211]: pam_unix(cron:session): session opened for user root"))
lines.append((start + timedelta(hours=1, minutes=1), "sshd[3001]: Connection closed by 198.51.100.3 port 51234 [preauth]"))

for ts, msg in sorted(lines, key=lambda x: x[0]):
    sys.stdout.write(f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} {HOST} {msg}\n")
