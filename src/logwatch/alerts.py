"""Alert objects and the ways LogWatch delivers them (terminal, JSON, email)."""
from __future__ import annotations

import json
import os
import smtplib
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from email.message import EmailMessage
from typing import Iterable, TextIO

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class Alert:
    rule: str
    severity: str              # low | medium | high | critical
    timestamp: datetime
    ip: str
    user: str | None
    message: str               # plain-English, readable by a non-specialist
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d


def sort_alerts(alerts: Iterable[Alert]) -> list[Alert]:
    """Most severe first, then oldest first."""
    return sorted(alerts, key=lambda a: (-SEVERITY_ORDER[a.severity], a.timestamp))


# --- terminal ---------------------------------------------------------------
_COLOURS = {"low": "\033[37m", "medium": "\033[33m", "high": "\033[31m", "critical": "\033[1;41;97m"}
_RESET = "\033[0m"


def format_alert(alert: Alert, colour: bool = False) -> str:
    label = f"[{alert.severity.upper():8}]"
    if colour:
        label = f"{_COLOURS[alert.severity]}{label}{_RESET}"
    return f"{label} {alert.timestamp:%Y-%m-%d %H:%M:%S}  {alert.rule:<22} {alert.message}"


def print_alerts(alerts: Iterable[Alert], stream: TextIO = sys.stdout) -> None:
    colour = stream.isatty()
    for a in alerts:
        print(format_alert(a, colour), file=stream)


def write_json(alerts: Iterable[Alert], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump([a.to_dict() for a in alerts], f, indent=2)


# --- email ------------------------------------------------------------------
def build_email_summary(alerts: list[Alert], source: str) -> tuple[str, str]:
    """Return (subject, body) for a plain-English digest email."""
    alerts = sort_alerts(alerts)
    worst = alerts[0].severity.upper() if alerts else "NONE"
    subject = f"[LogWatch] {len(alerts)} alert(s) on {source} - highest severity {worst}"

    lines = [
        f"LogWatch checked {source} and found {len(alerts)} thing(s) worth a look.",
        "",
    ]
    for a in alerts:
        lines.append(f"- {a.severity.upper()}: {a.message}")
        lines.append(f"  (rule {a.rule}, at {a.timestamp:%d %b %Y %H:%M:%S})")
    lines += [
        "",
        "What to do next:",
        "- CRITICAL: assume the account may be compromised. Change its password or keys and check what it did.",
        "- HIGH: consider blocking the IP address (e.g. with fail2ban or your firewall).",
        "- MEDIUM: check with the account owner that the login was really them.",
    ]
    return subject, "\n".join(lines)


class EmailNotifier:
    """Sends a digest email. All settings come from environment variables so that
    no credentials are ever stored in the code or config file:

        LOGWATCH_SMTP_HOST, LOGWATCH_SMTP_PORT (default 587),
        LOGWATCH_SMTP_USER, LOGWATCH_SMTP_PASSWORD,
        LOGWATCH_EMAIL_FROM, LOGWATCH_EMAIL_TO (comma-separated)
    """

    def __init__(self, env: dict | None = None):
        env = os.environ if env is None else env
        missing = [k for k in ("LOGWATCH_SMTP_HOST", "LOGWATCH_EMAIL_FROM", "LOGWATCH_EMAIL_TO") if not env.get(k)]
        if missing:
            raise ValueError("Email is not configured. Missing: " + ", ".join(missing))
        self.host = env["LOGWATCH_SMTP_HOST"]
        self.port = int(env.get("LOGWATCH_SMTP_PORT", "587"))
        self.user = env.get("LOGWATCH_SMTP_USER")
        self.password = env.get("LOGWATCH_SMTP_PASSWORD")
        self.sender = env["LOGWATCH_EMAIL_FROM"]
        self.recipients = [r.strip() for r in env["LOGWATCH_EMAIL_TO"].split(",") if r.strip()]

    def send(self, alerts: list[Alert], source: str) -> None:
        if not alerts:
            return
        subject, body = build_email_summary(alerts, source)
        msg = EmailMessage()
        msg["Subject"], msg["From"], msg["To"] = subject, self.sender, ", ".join(self.recipients)
        msg.set_content(body)
        with smtplib.SMTP(self.host, self.port, timeout=30) as smtp:
            smtp.starttls()                      # never send credentials in plain text
            if self.user and self.password:
                smtp.login(self.user, self.password)
            smtp.send_message(msg)
