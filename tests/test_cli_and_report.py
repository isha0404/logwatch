import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from unittest import mock

import pytest

from logwatch.alerts import Alert, EmailNotifier, build_email_summary
from logwatch.cli import main
from logwatch.config import load_config
from logwatch.report import build_html

SAMPLE = str(Path(__file__).parent.parent / "samples" / "auth.log")


def test_scan_sample_finds_every_planted_attack(tmp_path):
    out = tmp_path / "alerts.json"
    code = main(["scan", SAMPLE, "--year", "2026", "--json", str(out), "-q"])
    assert code == 1                                  # alerts found -> exit 1
    alerts = json.loads(out.read_text())
    rules = Counter(a["rule"] for a in alerts)
    assert rules == {"BRUTE_FORCE": 3, "POSSIBLE_COMPROMISE": 1, "ODD_HOURS": 2, "NEW_SOURCE": 1}
    assert {a["ip"] for a in alerts if a["rule"] == "BRUTE_FORCE"} == {"203.0.113.7", "203.0.113.45", "203.0.113.99"}
    # the genuine user's single typo must not cause an alert
    assert not any(a["ip"] == "10.0.0.21" for a in alerts)


def test_clean_log_exits_zero(tmp_path, capsys):
    log = tmp_path / "auth.log"
    log.write_text("Nov 16 10:00:00 web01 sshd[1]: Accepted publickey for alice from 10.0.0.21 port 1 ssh2\n")
    assert main(["scan", str(log)]) == 0
    assert "No alerts" in capsys.readouterr().out


def test_report_is_written_and_escapes_html(tmp_path):
    log = tmp_path / "auth.log"
    evil = "<script>alert(1)</script>"
    log.write_text("".join(
        f"Nov 16 10:00:{i:02d} web01 sshd[1]: Failed password for invalid user {evil} from 203.0.113.7 port 1 ssh2\n"
        for i in range(12)))
    report = tmp_path / "r.html"
    main(["scan", str(log), "--report", str(report), "-q"])
    html = report.read_text()
    assert "LogWatch report" in html and "203.0.113.7" in html
    assert evil not in html and "&lt;script&gt;" in html     # usernames come from attackers: never trust them


def test_report_handles_empty_log():
    assert "No alerts" in build_html([], [], "empty.log")


def test_missing_file_gives_friendly_error(capsys):
    assert main(["scan", "/no/such/file.log"]) == 2
    assert "logwatch:" in capsys.readouterr().err


def test_config_file_overrides_defaults(tmp_path):
    cfg_path = tmp_path / "c.toml"
    cfg_path.write_text("brute_force_threshold = 3\nbusiness_start_hour = 9\n")
    cfg = load_config(str(cfg_path))
    assert cfg.brute_force_threshold == 3 and cfg.business_start_hour == 9


def test_config_rejects_typos(tmp_path):
    cfg_path = tmp_path / "c.toml"
    cfg_path.write_text("brute_force_treshold = 3\n")
    with pytest.raises(ValueError, match="Unknown config"):
        load_config(str(cfg_path))


# --- email ------------------------------------------------------------------
ALERT = Alert("BRUTE_FORCE", "high", datetime(2026, 11, 16, 9, 0), "203.0.113.7", "root", "48 failed logins")
ENV = {"LOGWATCH_SMTP_HOST": "smtp.example.com", "LOGWATCH_SMTP_USER": "u", "LOGWATCH_SMTP_PASSWORD": "p",
       "LOGWATCH_EMAIL_FROM": "logwatch@example.com", "LOGWATCH_EMAIL_TO": "a@example.com, b@example.com"}


def test_email_summary_is_plain_english():
    subject, body = build_email_summary([ALERT], "auth.log")
    assert "1 alert" in subject and "HIGH" in subject
    assert "48 failed logins" in body and "What to do next" in body


def test_email_sent_over_tls_without_real_network():
    with mock.patch("smtplib.SMTP") as smtp_cls:
        EmailNotifier(ENV).send([ALERT], "auth.log")
    smtp = smtp_cls.return_value.__enter__.return_value
    smtp.starttls.assert_called_once()
    smtp.login.assert_called_once_with("u", "p")
    msg = smtp.send_message.call_args[0][0]
    assert msg["To"] == "a@example.com, b@example.com"


def test_email_requires_configuration():
    with pytest.raises(ValueError, match="LOGWATCH_SMTP_HOST"):
        EmailNotifier({})
