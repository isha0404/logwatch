from datetime import datetime

import pytest

from logwatch.parser import ACCEPTED, FAILED, INVALID_USER, parse_line, parse_lines


def test_failed_password():
    e = parse_line("Nov 16 09:14:31 web01 sshd[1234]: Failed password for root from 203.0.113.7 port 52344 ssh2", 2026)
    assert e.outcome == FAILED
    assert (e.user, e.ip, e.port, e.method, e.host) == ("root", "203.0.113.7", 52344, "password", "web01")
    assert e.timestamp == datetime(2026, 11, 16, 9, 14, 31)


def test_failed_password_for_invalid_user_extracts_real_username():
    e = parse_line("Nov 16 09:14:31 web01 sshd[1]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2", 2026)
    assert e.outcome == FAILED and e.user == "admin"


def test_accepted_publickey():
    e = parse_line("Nov  6 09:14:02 web01 sshd[9]: Accepted publickey for deploy from 10.0.0.12 port 50000 ssh2: RSA SHA256:abc", 2026)
    assert e.outcome == ACCEPTED and e.user == "deploy" and e.method == "publickey"
    assert e.timestamp.day == 6


def test_invalid_user_line():
    e = parse_line("Nov 16 09:00:00 web01 sshd[9]: Invalid user oracle from 198.51.100.4 port 4444", 2026)
    assert e.outcome == INVALID_USER and e.user == "oracle" and e.port == 4444


def test_iso_timestamp_format():
    e = parse_line("2026-11-16T09:14:31.123456+00:00 web01 sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2")
    assert e.timestamp == datetime(2026, 11, 16, 9, 14, 31)


def test_ipv6_address():
    e = parse_line("Nov 16 09:00:00 h sshd[1]: Failed password for root from 2001:db8::1 port 22 ssh2", 2026)
    assert e.ip == "2001:db8::1"


@pytest.mark.parametrize("line", [
    "",
    "   ",
    "Nov 16 09:00:00 web01 CRON[1]: pam_unix(cron:session): session opened for user root",
    "Nov 16 09:00:00 web01 sshd[1]: Connection closed by 1.2.3.4 port 5 [preauth]",
    "complete garbage \x00\xff",
    "Feb 30 09:00:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 5 ssh2",
])
def test_non_login_lines_are_ignored(line):
    assert parse_line(line, 2026) is None


def test_year_rolls_over_from_december_to_january():
    lines = [
        "Dec 31 23:59:58 h sshd[1]: Failed password for root from 1.2.3.4 port 5 ssh2",
        "Jan  1 00:00:01 h sshd[1]: Failed password for root from 1.2.3.4 port 5 ssh2",
    ]
    a, b = parse_lines(lines, year=2025)
    assert a.timestamp.year == 2025 and b.timestamp.year == 2026
    assert b.timestamp > a.timestamp
