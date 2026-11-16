"""Turn raw SSH log lines into structured LoginEvent objects.

Supports the two timestamp styles found in /var/log/auth.log (Debian/Ubuntu)
and /var/log/secure (RHEL/Fedora):

    Nov 16 09:14:31 web01 sshd[1234]: Failed password for root from 203.0.113.7 port 52344 ssh2
    2026-11-16T09:14:31.123456+00:00 web01 sshd[1234]: Accepted publickey for deploy from 10.0.0.12 port 22 ssh2

Timestamps are kept as the server's own wall-clock time (no timezone), because
that's what "odd hours" should be measured against.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator

FAILED = "failed"
ACCEPTED = "accepted"
INVALID_USER = "invalid_user"

# --- header: timestamp, host, sshd[pid] ------------------------------------
_SYSLOG_HEADER = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
_ISO_HEADER = re.compile(
    r"^(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+"
    r"(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)

# --- message bodies ---------------------------------------------------------
_IP = r"(?P<ip>[0-9A-Fa-f:.]+)"
_FAILED = re.compile(
    r"^Failed (?P<method>password|publickey) for (?P<invalid>invalid user )?(?P<user>\S+) from "
    + _IP + r" port (?P<port>\d+)"
)
_ACCEPTED = re.compile(
    r"^Accepted (?P<method>password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from "
    + _IP + r" port (?P<port>\d+)"
)
_INVALID = re.compile(r"^Invalid user (?P<user>\S*) from " + _IP + r"(?: port (?P<port>\d+))?")

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


@dataclass(frozen=True)
class LoginEvent:
    timestamp: datetime
    host: str
    outcome: str          # FAILED, ACCEPTED or INVALID_USER
    user: str
    ip: str
    port: int | None = None
    method: str | None = None


def parse_line(line: str, year: int | None = None) -> LoginEvent | None:
    """Parse one log line. Returns None for anything that isn't an SSH login event."""
    line = line.strip()
    if not line:
        return None

    header = _SYSLOG_HEADER.match(line)
    if header:
        month = _MONTHS.get(header["month"])
        if month is None:
            return None
        hh, mm, ss = (int(x) for x in header["time"].split(":"))
        try:
            ts = datetime(year or datetime.now().year, month, int(header["day"]), hh, mm, ss)
        except ValueError:          # e.g. "Feb 30"
            return None
    else:
        header = _ISO_HEADER.match(line)
        if not header:
            return None
        ts = datetime.fromisoformat(header["iso"])

    msg, host = header["msg"], header["host"]

    if m := _FAILED.match(msg):
        return LoginEvent(ts, host, FAILED, m["user"], m["ip"], int(m["port"]), m["method"])
    if m := _ACCEPTED.match(msg):
        return LoginEvent(ts, host, ACCEPTED, m["user"], m["ip"], int(m["port"]), m["method"])
    if m := _INVALID.match(msg):
        port = int(m["port"]) if m["port"] else None
        return LoginEvent(ts, host, INVALID_USER, m["user"] or "(blank)", m["ip"], port)
    return None


def parse_lines(lines: Iterable[str], year: int | None = None) -> Iterator[LoginEvent]:
    """Parse many lines, skipping junk and handling the Dec -> Jan year rollover
    that syslog's year-less timestamps cause."""
    year = year or datetime.now().year
    last_month = None
    for line in lines:
        event = parse_line(line, year)
        if event is None:
            continue
        # Syslog format only: if the month jumps backwards (Dec -> Jan) the year has rolled over.
        if _SYSLOG_HEADER.match(line.strip()):
            if last_month is not None and event.timestamp.month < last_month - 6:
                year += 1
                event = parse_line(line, year)
            last_month = event.timestamp.month
        yield event
