"""Build a single-file HTML dashboard from parsed events and alerts.

pandas does the number crunching; the page itself is plain HTML + inline SVG,
so it opens in any browser with no internet connection and no JavaScript.
"""
from __future__ import annotations

from datetime import datetime
from html import escape

import pandas as pd

from .alerts import Alert, sort_alerts
from .parser import ACCEPTED, LoginEvent


def events_to_frame(events: list[LoginEvent]) -> pd.DataFrame:
    cols = ["timestamp", "host", "outcome", "user", "ip", "port", "method"]
    if not events:
        return pd.DataFrame(columns=cols)
    return pd.DataFrame([e.__dict__ for e in events], columns=cols)


def summarise(df: pd.DataFrame) -> dict:
    if df.empty:
        return {"total": 0, "failed": 0, "accepted": 0, "unique_ips": 0,
                "start": None, "end": None, "top_ips": pd.Series(dtype=int),
                "top_users": pd.Series(dtype=int), "per_hour": pd.DataFrame()}
    failed = df[df.outcome != ACCEPTED]
    per_hour = (df.assign(hour=df.timestamp.dt.floor("h"),
                          kind=df.outcome.where(df.outcome == ACCEPTED, "failed"))
                  .groupby(["hour", "kind"]).size().unstack(fill_value=0))
    for col in ("failed", ACCEPTED):
        if col not in per_hour:
            per_hour[col] = 0
    # include quiet hours too, so the x-axis is real time rather than "hours with activity"
    full_range = pd.date_range(per_hour.index.min(), per_hour.index.max(), freq="h")
    per_hour = per_hour.reindex(full_range, fill_value=0)
    return {
        "total": len(df),
        "failed": len(failed),
        "accepted": int((df.outcome == ACCEPTED).sum()),
        "unique_ips": df.ip.nunique(),
        "start": df.timestamp.min(),
        "end": df.timestamp.max(),
        "top_ips": failed.ip.value_counts().head(10),
        "top_users": failed.user.value_counts().head(10),
        "per_hour": per_hour[["failed", ACCEPTED]],
    }


def _bar_chart(per_hour: pd.DataFrame) -> str:
    if per_hour.empty:
        return "<p class='muted'>No login activity.</p>"
    w, h, pad = 760, 220, 28
    n = len(per_hour)
    peak = max(int((per_hour["failed"] + per_hour[ACCEPTED]).max()), 1)
    bw = (w - pad) / n
    bars = []
    for i, (hour, row) in enumerate(per_hour.iterrows()):
        x = pad + i * bw
        fh = (h - 30) * row["failed"] / peak
        ah = (h - 30) * row[ACCEPTED] / peak
        tip = f"{hour:%d %b %H:00} - {int(row['failed'])} failed, {int(row[ACCEPTED])} successful"
        bars.append(
            f"<g><title>{escape(tip)}</title>"
            f"<rect x='{x + 1:.1f}' y='{h - 20 - fh - ah:.1f}' width='{max(bw - 2, 1):.1f}' height='{ah:.1f}' class='ok'/>"
            f"<rect x='{x + 1:.1f}' y='{h - 20 - fh:.1f}' width='{max(bw - 2, 1):.1f}' height='{fh:.1f}' class='bad'/></g>"
        )
    first, last = per_hour.index[0], per_hour.index[-1]
    return (
        f"<svg viewBox='0 0 {w} {h}' role='img' aria-label='Logins per hour'>"
        f"<text x='0' y='12' class='axis'>{peak}</text>"
        f"<line x1='{pad}' x2='{w}' y1='{h - 20}' y2='{h - 20}' class='base'/>"
        + "".join(bars)
        + f"<text x='{pad}' y='{h - 4}' class='axis'>{first:%d %b %H:00}</text>"
        f"<text x='{w}' y='{h - 4}' class='axis' text-anchor='end'>{last:%d %b %H:00}</text></svg>"
    )


def _table(series: pd.Series, label: str) -> str:
    if series.empty:
        return "<p class='muted'>None.</p>"
    rows = "".join(f"<tr><td class='mono'>{escape(str(k))}</td><td class='num'>{v}</td></tr>"
                   for k, v in series.items())
    return f"<table><thead><tr><th>{label}</th><th class='num'>Failures</th></tr></thead><tbody>{rows}</tbody></table>"


def build_html(events: list[LoginEvent], alerts: list[Alert], source: str) -> str:
    s = summarise(events_to_frame(events))
    alerts = sort_alerts(alerts)
    period = f"{s['start']:%d %b %Y %H:%M} to {s['end']:%d %b %Y %H:%M}" if s["start"] is not None else "no events"

    alert_rows = "".join(
        f"<tr><td><span class='sev {a.severity}'>{a.severity}</span></td>"
        f"<td class='mono'>{a.timestamp:%d %b %H:%M:%S}</td><td class='mono'>{escape(a.rule)}</td>"
        f"<td>{escape(a.message)}</td></tr>" for a in alerts
    ) or "<tr><td colspan='4' class='muted'>No alerts. Nothing suspicious found.</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>LogWatch report - {escape(source)}</title>
<style>
:root {{ --bg:#0f1115; --panel:#171a21; --ink:#e6e8ec; --muted:#8b92a0; --line:#262a33; --bad:#e5484d; --ok:#3fb27f; }}
* {{ box-sizing: border-box; }}
body {{ margin:0; background:var(--bg); color:var(--ink); font:15px/1.5 system-ui, -apple-system, Segoe UI, sans-serif; }}
main {{ max-width:1000px; margin:0 auto; padding:32px 20px 64px; }}
h1 {{ font-size:24px; margin:0 0 4px; }} h2 {{ font-size:16px; margin:32px 0 12px; }}
.muted {{ color:var(--muted); }} .mono {{ font-family: ui-monospace, Menlo, Consolas, monospace; font-size:13px; }}
.kpis {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(160px,1fr)); gap:12px; margin-top:20px; }}
.kpi {{ background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:14px 16px; }}
.kpi b {{ display:block; font-size:26px; font-weight:600; }} .kpi span {{ color:var(--muted); font-size:13px; }}
.panel {{ background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:16px; overflow-x:auto; }}
.grid2 {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; }} @media (max-width:700px) {{ .grid2 {{ grid-template-columns:1fr; }} }}
table {{ width:100%; border-collapse:collapse; }} th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }}
th {{ color:var(--muted); font-weight:500; font-size:13px; }} .num {{ text-align:right; font-variant-numeric: tabular-nums; }}
.sev {{ font-size:12px; text-transform:uppercase; padding:2px 8px; border-radius:999px; font-weight:600; }}
.sev.critical {{ background:var(--bad); color:#fff; }} .sev.high {{ background:rgba(229,72,77,.18); color:#ff8a8e; }}
.sev.medium {{ background:rgba(232,166,74,.18); color:#f0b45e; }} .sev.low {{ background:#262a33; color:var(--muted); }}
svg {{ width:100%; height:auto; }} .bad {{ fill:var(--bad); }} .ok {{ fill:var(--ok); }} .base {{ stroke:var(--line); }}
.axis {{ fill:var(--muted); font-size:11px; }} .legend span {{ display:inline-flex; align-items:center; gap:6px; margin-right:16px; font-size:13px; color:var(--muted); }}
.legend i {{ width:10px; height:10px; border-radius:2px; display:inline-block; }}
</style></head><body><main>
<h1>LogWatch report</h1>
<div class="muted">{escape(source)} &middot; {period} &middot; generated {datetime.now():%d %b %Y %H:%M}</div>
<div class="kpis">
  <div class="kpi"><b>{len(alerts)}</b><span>alerts</span></div>
  <div class="kpi"><b>{s['failed']}</b><span>failed logins</span></div>
  <div class="kpi"><b>{s['accepted']}</b><span>successful logins</span></div>
  <div class="kpi"><b>{s['unique_ips']}</b><span>unique IP addresses</span></div>
</div>
<h2>Alerts</h2>
<div class="panel"><table><thead><tr><th>Severity</th><th>Time</th><th>Rule</th><th>What happened</th></tr></thead><tbody>{alert_rows}</tbody></table></div>
<h2>Logins per hour</h2>
<div class="panel"><div class="legend"><span><i style="background:var(--bad)"></i>failed</span><span><i style="background:var(--ok)"></i>successful</span></div>{_bar_chart(s['per_hour'])}</div>
<div class="grid2">
  <div><h2>Top attacking IPs</h2><div class="panel">{_table(s['top_ips'], 'IP address')}</div></div>
  <div><h2>Most targeted usernames</h2><div class="panel">{_table(s['top_users'], 'Username')}</div></div>
</div>
</main></body></html>"""


def write_report(events: list[LoginEvent], alerts: list[Alert], source: str, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_html(events, alerts, source))
