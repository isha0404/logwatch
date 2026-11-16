"""Command line interface.

    logwatch scan /var/log/auth.log --report report.html
    logwatch follow /var/log/auth.log --email
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Iterator

from . import __version__
from .alerts import EmailNotifier, print_alerts, sort_alerts, write_json
from .config import load_config
from .detectors import Engine
from .parser import parse_line, parse_lines
from .report import write_report


def _read_lines(path: str) -> Iterator[str]:
    with open(path, encoding="utf-8", errors="replace") as f:
        yield from f


def cmd_scan(args) -> int:
    cfg = load_config(args.config)
    if args.state:
        cfg.state_file = args.state
    events = list(parse_lines(_read_lines(args.logfile), year=args.year))
    engine = Engine(cfg)
    alerts = sort_alerts(engine.run(events))
    engine.save_state()

    if not args.quiet:
        print(f"LogWatch {__version__}: parsed {len(events)} SSH login events from {args.logfile}")
        if alerts:
            print_alerts(alerts)
        else:
            print("No alerts. Nothing suspicious found.")

    if args.json:
        write_json(alerts, args.json)
    if args.report:
        write_report(events, alerts, args.logfile, args.report)
        if not args.quiet:
            print(f"Dashboard written to {args.report}")
    if args.email and alerts:
        EmailNotifier().send(alerts, args.logfile)
        if not args.quiet:
            print("Alert email sent.")
    return 1 if alerts else 0       # non-zero exit lets cron / CI react


def follow(path: str, poll: float = 1.0, from_start: bool = False) -> Iterator[str]:
    """Yield new lines as they're appended, like `tail -F`. Copes with log
    rotation (file replaced) and truncation."""
    f = open(path, encoding="utf-8", errors="replace")
    inode = os.fstat(f.fileno()).st_ino
    if not from_start:
        f.seek(0, os.SEEK_END)
    buffer = ""
    while True:
        chunk = f.readline()
        if chunk:
            buffer += chunk
            if buffer.endswith("\n"):
                yield buffer
                buffer = ""
            continue
        time.sleep(poll)
        try:
            st = os.stat(path)
        except FileNotFoundError:
            continue                      # mid-rotation; wait for the new file
        if st.st_ino != inode or st.st_size < f.tell():
            f.close()
            f = open(path, encoding="utf-8", errors="replace")
            inode = os.fstat(f.fileno()).st_ino
            buffer = ""


def cmd_follow(args) -> int:
    cfg = load_config(args.config)
    if args.state:
        cfg.state_file = args.state
    engine = Engine(cfg)
    notifier = EmailNotifier() if args.email else None
    print(f"LogWatch {__version__}: watching {args.logfile} (Ctrl+C to stop)")
    try:
        for line in follow(args.logfile, from_start=args.from_start):
            event = parse_line(line, args.year)
            if event is None:
                continue
            alerts = engine.process(event)
            if alerts:
                print_alerts(alerts)
                sys.stdout.flush()
                if notifier:
                    try:
                        notifier.send(alerts, args.logfile)
                    except Exception as exc:          # keep watching even if email fails
                        print(f"Could not send email: {exc}", file=sys.stderr)
                engine.save_state()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        engine.save_state()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="logwatch", description="Spot attacks on your server from its SSH login logs.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("logfile", help="path to auth.log / secure")
    common.add_argument("-c", "--config", help="TOML config file (see logwatch.example.toml)")
    common.add_argument("--state", help="JSON file to remember each user's known networks between runs")
    common.add_argument("--year", type=int, help="year for syslog timestamps, which don't include one (default: this year)")
    common.add_argument("--email", action="store_true", help="email alerts (configure with LOGWATCH_* env vars)")

    s = sub.add_parser("scan", parents=[common], help="analyse a log file once")
    s.add_argument("--report", metavar="HTML", help="write an HTML dashboard")
    s.add_argument("--json", metavar="FILE", help="write alerts as JSON")
    s.add_argument("-q", "--quiet", action="store_true", help="no terminal output (use the exit code)")
    s.set_defaults(func=cmd_scan)

    f = sub.add_parser("follow", parents=[common], help="watch a log file live and alert as things happen")
    f.add_argument("--from-start", action="store_true", help="process existing lines before following")
    f.set_defaults(func=cmd_follow)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (FileNotFoundError, PermissionError) as exc:
        print(f"logwatch: {exc}", file=sys.stderr)
        if isinstance(exc, PermissionError):
            print("Tip: auth.log is usually readable only by root or the 'adm' group.", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"logwatch: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
