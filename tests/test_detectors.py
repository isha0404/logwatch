from datetime import datetime, timedelta

from logwatch.config import Config
from logwatch.detectors import (BruteForceDetector, CompromiseDetector, Engine, NewSourceDetector,
                                OddHoursDetector, network_of)
from logwatch.parser import ACCEPTED, FAILED, LoginEvent

T0 = datetime(2026, 11, 16, 10, 0, 0)     # a Monday, mid-morning


def ev(outcome, seconds=0, user="root", ip="203.0.113.7", at=None):
    return LoginEvent(at or T0 + timedelta(seconds=seconds), "web01", outcome, user, ip, 22, "password")


def run(detector, events):
    out = []
    for e in events:
        out += detector.process(e)
    return out


# --- brute force ------------------------------------------------------------
def test_brute_force_fires_at_threshold():
    d = BruteForceDetector(threshold=5, window_seconds=60)
    assert run(d, [ev(FAILED, i) for i in range(4)]) == []
    alerts = d.process(ev(FAILED, 4))
    assert len(alerts) == 1 and alerts[0].rule == "BRUTE_FORCE"


def test_slow_failures_outside_window_do_not_fire():
    d = BruteForceDetector(threshold=5, window_seconds=60)
    assert run(d, [ev(FAILED, i * 30) for i in range(10)]) == []   # 2 per minute


def test_one_alert_per_burst_with_final_count():
    d = BruteForceDetector(threshold=5, window_seconds=60)
    alerts = run(d, [ev(FAILED, i) for i in range(40)])
    assert len(alerts) == 1
    assert alerts[0].details["failures"] == 40
    assert "40 failed logins" in alerts[0].message


def test_new_burst_after_quiet_period_alerts_again():
    d = BruteForceDetector(threshold=5, window_seconds=60)
    first = run(d, [ev(FAILED, i) for i in range(5)])
    second = run(d, [ev(FAILED, 600 + i) for i in range(5)])
    assert len(first) == 1 and len(second) == 1


def test_password_spraying_is_described():
    d = BruteForceDetector(threshold=5, window_seconds=60)
    alerts = run(d, [ev(FAILED, i, user=f"user{i}") for i in range(5)])
    assert "spraying" in alerts[0].message and alerts[0].user is None


def test_different_ips_are_counted_separately():
    d = BruteForceDetector(threshold=5, window_seconds=60)
    assert run(d, [ev(FAILED, i, ip=f"203.0.113.{i}") for i in range(20)]) == []


# --- possible compromise ----------------------------------------------------
def test_success_after_failures_is_critical():
    d = CompromiseDetector(min_failures=5, lookback_seconds=3600)
    alerts = run(d, [ev(FAILED, i) for i in range(6)] + [ev(ACCEPTED, 10)])
    assert len(alerts) == 1 and alerts[0].severity == "critical"
    assert alerts[0].details["prior_failures"] == 6


def test_one_typo_then_success_is_fine():
    d = CompromiseDetector(min_failures=5, lookback_seconds=3600)
    assert run(d, [ev(FAILED, 0), ev(ACCEPTED, 5)]) == []


def test_old_failures_are_forgotten():
    d = CompromiseDetector(min_failures=5, lookback_seconds=60)
    assert run(d, [ev(FAILED, i) for i in range(10)] + [ev(ACCEPTED, 3600)]) == []


# --- odd hours ------------------------------------------------------------
def test_login_at_3am_is_flagged():
    d = OddHoursDetector(7, 20)
    alerts = d.process(ev(ACCEPTED, at=datetime(2026, 11, 16, 3, 0)))
    assert len(alerts) == 1 and alerts[0].rule == "ODD_HOURS"


def test_login_during_business_hours_is_fine():
    assert OddHoursDetector(7, 20).process(ev(ACCEPTED, at=datetime(2026, 11, 16, 10, 0))) == []


def test_end_hour_is_exclusive():
    d = OddHoursDetector(7, 20)
    assert d.process(ev(ACCEPTED, at=datetime(2026, 11, 16, 19, 59))) == []
    assert len(d.process(ev(ACCEPTED, at=datetime(2026, 11, 16, 20, 0)))) == 1


def test_weekend_option():
    saturday = datetime(2026, 11, 21, 11, 0)
    assert OddHoursDetector(7, 20).process(ev(ACCEPTED, at=saturday)) == []
    assert len(OddHoursDetector(7, 20, weekend_is_odd=True).process(ev(ACCEPTED, at=saturday))) == 1


def test_failed_logins_never_trigger_odd_hours():
    assert OddHoursDetector(7, 20).process(ev(FAILED, at=datetime(2026, 11, 16, 3, 0))) == []


# --- new source -------------------------------------------------------------
def test_first_login_sets_baseline_second_network_alerts():
    d = NewSourceDetector()
    assert d.process(ev(ACCEPTED, 0, user="alice", ip="10.0.0.21")) == []
    assert d.process(ev(ACCEPTED, 1, user="alice", ip="10.0.0.99")) == []      # same /24
    alerts = d.process(ev(ACCEPTED, 2, user="alice", ip="198.51.100.5"))
    assert len(alerts) == 1 and alerts[0].rule == "NEW_SOURCE"


def test_known_sources_persist_between_runs(tmp_path):
    state = str(tmp_path / "state.json")
    d1 = NewSourceDetector(state)
    d1.process(ev(ACCEPTED, user="alice", ip="10.0.0.21"))
    d1.save()
    d2 = NewSourceDetector(state)
    assert d2.process(ev(ACCEPTED, user="alice", ip="10.0.0.21")) == []
    assert len(d2.process(ev(ACCEPTED, user="alice", ip="198.51.100.5"))) == 1


def test_network_grouping():
    assert network_of("10.0.0.21") == "10.0.0.0/24"
    assert network_of("2001:db8::1") == "2001:db8::/64"
    assert network_of("not-an-ip") == "not-an-ip"


# --- engine -----------------------------------------------------------------
def test_allow_list_suppresses_everything():
    engine = Engine(Config(brute_force_threshold=3, allow_ips=["203.0.113.7"]))
    assert engine.run([ev(FAILED, i) for i in range(50)]) == []
