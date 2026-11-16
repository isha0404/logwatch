"""Detection settings. Defaults are sensible for a small business server and can
be overridden with a TOML file (see logwatch.example.toml)."""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field, fields


@dataclass
class Config:
    # Brute force: this many failures from one IP within the window raises an alert
    brute_force_threshold: int = 10
    brute_force_window_seconds: int = 60

    # Possible compromise: a successful login from an IP with this many recent failures
    compromise_min_failures: int = 5
    compromise_lookback_seconds: int = 3600

    # Odd hours: successful logins outside [business_start, business_end) are flagged
    business_start_hour: int = 7
    business_end_hour: int = 20
    weekend_is_odd: bool = False

    # New source: flag a user logging in from a network (/24 for IPv4) they've never used
    new_source_enabled: bool = True
    state_file: str | None = None     # where known sources are remembered between runs

    # IPs or users that should never alert (e.g. your own monitoring)
    allow_ips: list[str] = field(default_factory=list)

    def validate(self) -> None:
        if self.brute_force_threshold < 2:
            raise ValueError("brute_force_threshold must be at least 2")
        if self.brute_force_window_seconds <= 0 or self.compromise_lookback_seconds <= 0:
            raise ValueError("time windows must be positive")
        for h in (self.business_start_hour, self.business_end_hour):
            if not 0 <= h <= 24:
                raise ValueError("business hours must be between 0 and 24")


def load_config(path: str | None = None) -> Config:
    cfg = Config()
    if path:
        with open(path, "rb") as f:
            data = tomllib.load(f)
        known = {f.name for f in fields(Config)}
        unknown = set(data) - known
        if unknown:
            raise ValueError(f"Unknown config option(s): {', '.join(sorted(unknown))}")
        for key, value in data.items():
            setattr(cfg, key, value)
    cfg.validate()
    return cfg
