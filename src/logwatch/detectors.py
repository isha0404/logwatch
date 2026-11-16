"""Detection rules.

Each detector looks at one LoginEvent at a time and returns any alerts. Working
event-by-event means the same code serves both a one-off scan of a file and
live `--follow` mode.

Rules
-----
BRUTE_FORCE          many failed logins from one IP in a short window   (high)
POSSIBLE_COMPROMISE  a successful login from an IP that was just failing (critical)
ODD_HOURS            a successful login outside business hours           (medium)
NEW_SOURCE           a user logs in from a network they've never used    (medium)
"""
from __future__ import annotations

import ipaddress
import json
import os
from collections import defaultdict, deque
from datetime import timedelta

from .alerts import Alert
from .config import Config
from .parser import ACCEPTED, FAILED, INVALID_USER, LoginEvent


class BruteForceDetector:
    """Sliding window per IP. Alerts once per burst rather than once per line."""

    def __init__(self, threshold: int, window_seconds: int):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.failures: dict[str, deque] = defaultdict(deque)   # ip -> deque[(time, user)]
        # ip -> the open burst: its alert, start time, last failure time and usernames tried
        self.bursts: dict[str, dict] = {}

    @staticmethod
    def _describe(alert: Alert, ip: str, count: int, start, end, users: set[str]) -> None:
        span = int((end - start).total_seconds())
        names = sorted(users)
        target = names[0] if len(names) == 1 else f"{len(names)} different usernames"
        kind = "password guessing" if len(names) == 1 else "password spraying"
        alert.user = names[0] if len(names) == 1 else None
        alert.message = (f"{count} failed logins in {span}s from {ip} targeting {target} "
                         f"({kind}). Consider blocking this IP.")
        alert.details = {"failures": count, "duration_seconds": span, "users": names}

    def process(self, e: LoginEvent) -> list[Alert]:
        if e.outcome not in (FAILED, INVALID_USER):
            return []
        q = self.failures[e.ip]
        q.append((e.timestamp, e.user))
        while q and e.timestamp - q[0][0] > self.window:
            q.popleft()

        # Still inside a burst we've already reported: don't raise a new alert,
        # but keep the existing one up to date so the final count is accurate.
        burst = self.bursts.get(e.ip)
        if burst and e.timestamp - burst["last"] <= self.window:
            burst["count"] += 1
            burst["last"] = e.timestamp
            burst["users"].add(e.user)
            self._describe(burst["alert"], e.ip, burst["count"], burst["start"], e.timestamp, burst["users"])
            return []

        if len(q) >= self.threshold:
            users = {u for _, u in q}
            alert = Alert(rule="BRUTE_FORCE", severity="high", timestamp=e.timestamp, ip=e.ip, user=None, message="")
            self.bursts[e.ip] = {"alert": alert, "start": q[0][0], "last": e.timestamp, "count": len(q), "users": users}
            self._describe(alert, e.ip, len(q), q[0][0], e.timestamp, users)
            return [alert]
        return []


class CompromiseDetector:
    """A success straight after lots of failures from the same IP suggests the
    attacker guessed the password. This is the alert that matters most."""

    def __init__(self, min_failures: int, lookback_seconds: int):
        self.min_failures = min_failures
        self.lookback = timedelta(seconds=lookback_seconds)
        self.failures: dict[str, deque] = defaultdict(deque)

    def process(self, e: LoginEvent) -> list[Alert]:
        q = self.failures[e.ip]
        while q and e.timestamp - q[0] > self.lookback:
            q.popleft()
        if e.outcome in (FAILED, INVALID_USER):
            q.append(e.timestamp)
            return []
        if e.outcome == ACCEPTED and len(q) >= self.min_failures:
            n = len(q)
            q.clear()
            return [Alert(
                rule="POSSIBLE_COMPROMISE", severity="critical", timestamp=e.timestamp, ip=e.ip, user=e.user,
                message=(f"'{e.user}' logged in successfully from {e.ip} right after {n} failed attempts "
                         f"from the same address. The password may have been guessed."),
                details={"prior_failures": n, "method": e.method},
            )]
        return []


class OddHoursDetector:
    def __init__(self, start_hour: int, end_hour: int, weekend_is_odd: bool = False):
        self.start, self.end, self.weekend_is_odd = start_hour, end_hour, weekend_is_odd

    def process(self, e: LoginEvent) -> list[Alert]:
        if e.outcome != ACCEPTED:
            return []
        hour = e.timestamp.hour
        is_weekend = e.timestamp.weekday() >= 5
        outside = not (self.start <= hour < self.end) or (self.weekend_is_odd and is_weekend)
        if not outside:
            return []
        when = "at the weekend" if (self.weekend_is_odd and is_weekend and self.start <= hour < self.end) \
            else f"at {e.timestamp:%H:%M}, outside business hours ({self.start:02d}:00-{self.end:02d}:00)"
        return [Alert(
            rule="ODD_HOURS", severity="medium", timestamp=e.timestamp, ip=e.ip, user=e.user,
            message=f"'{e.user}' logged in from {e.ip} {when}. Check this was expected.",
        )]


def network_of(ip: str) -> str:
    """Group addresses into networks so a home router changing its last digits
    doesn't count as a 'new location'. /24 for IPv4, /64 for IPv6."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    prefix = 24 if addr.version == 4 else 64
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


class NewSourceDetector:
    """Remembers which networks each user normally logs in from. The very first
    login for a user just sets the baseline; later logins from an unseen network alert.

    Note: this is a privacy-friendly stand-in for geolocation - it needs no
    external GeoIP database."""

    def __init__(self, state_file: str | None = None):
        self.state_file = state_file
        self.known: dict[str, set[str]] = defaultdict(set)
        if state_file and os.path.exists(state_file):
            with open(state_file, encoding="utf-8") as f:
                for user, nets in json.load(f).items():
                    self.known[user] = set(nets)

    def process(self, e: LoginEvent) -> list[Alert]:
        if e.outcome != ACCEPTED:
            return []
        net = network_of(e.ip)
        seen = self.known[e.user]
        alerts = []
        if seen and net not in seen:
            alerts.append(Alert(
                rule="NEW_SOURCE", severity="medium", timestamp=e.timestamp, ip=e.ip, user=e.user,
                message=(f"'{e.user}' logged in from a network never seen before ({net}). "
                         f"Previously seen: {', '.join(sorted(seen))}."),
                details={"network": net, "known_networks": sorted(seen)},
            ))
        seen.add(net)
        return alerts

    def save(self) -> None:
        if not self.state_file:
            return
        tmp = self.state_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({u: sorted(n) for u, n in self.known.items()}, f, indent=2)
        os.replace(tmp, self.state_file)     # atomic, so a crash can't corrupt the state


class Engine:
    """Runs every enabled detector over a stream of events."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.allow = set(cfg.allow_ips)
        self.detectors = [
            BruteForceDetector(cfg.brute_force_threshold, cfg.brute_force_window_seconds),
            CompromiseDetector(cfg.compromise_min_failures, cfg.compromise_lookback_seconds),
            OddHoursDetector(cfg.business_start_hour, cfg.business_end_hour, cfg.weekend_is_odd),
        ]
        self.new_source = NewSourceDetector(cfg.state_file) if cfg.new_source_enabled else None
        if self.new_source:
            self.detectors.append(self.new_source)

    def process(self, e: LoginEvent) -> list[Alert]:
        if e.ip in self.allow:
            return []
        alerts: list[Alert] = []
        for d in self.detectors:
            alerts.extend(d.process(e))
        return alerts

    def run(self, events) -> list[Alert]:
        alerts: list[Alert] = []
        for e in events:
            alerts.extend(self.process(e))
        return alerts

    def save_state(self) -> None:
        if self.new_source:
            self.new_source.save()
