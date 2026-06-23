"""HTML coverage/alert dashboard.

A single server-rendered page: dark theme, inline CSS, no JavaScript. It reads
the in-memory alert store and the dynamic coverage report and renders them as
a restrained, minimalist analyst view (figures, a slim severity distribution
bar, hairline tactic/coverage rows, and a recent-alerts table).
"""

from __future__ import annotations

import html
import logging
from collections import Counter

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from core.models import Alert, CoverageReport
from api.routes_coverage import build_coverage_report

logger = logging.getLogger(__name__)

router = APIRouter(tags=["dashboard"])

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
# Restrained, slightly desaturated severity hues. Used only as small dots and
# thin bar segments -- never as large filled blocks -- so the page stays calm.
_SEVERITY_COLORS = {
    "CRITICAL": "#ff5d6c",
    "HIGH": "#ff9f45",
    "MEDIUM": "#ffd25e",
    "LOW": "#6fb1ff",
}


def _esc(value: object) -> str:
    return html.escape(str(value))


def _dot(color: str, size: int = 8) -> str:
    return (
        f'<span style="display:inline-block;width:{size}px;height:{size}px;'
        f'border-radius:50%;background:{color};vertical-align:middle"></span>'
    )


def _hero(alerts: list[Alert], report: CoverageReport) -> str:
    """The headline figures: alert volume and ATT&CK Cloud coverage."""
    figures = [
        (str(len(alerts)), "alerts detected"),
        (f"{report.coverage_percentage:g}<span class='pct'>%</span>", "att&ck cloud coverage"),
        (f"{report.techniques_covered}<span class='dim'>/{report.total_cloud_techniques}</span>",
         "iaas techniques covered"),
    ]
    cells = "".join(
        f'<div class="figure"><div class="fig-num">{num}</div>'
        f'<div class="fig-label">{label}</div></div>'
        for num, label in figures
    )
    return f'<section class="hero">{cells}</section>'


def _severity_bar(counts: Counter, total: int) -> str:
    """A single slim stacked bar showing the severity mix."""
    if total == 0:
        return '<div class="sevbar"><div class="sevbar-empty"></div></div>'
    segments = []
    for sev in _SEVERITY_ORDER:
        count = counts.get(sev, 0)
        if count:
            pct = count / total * 100
            segments.append(
                f'<span class="seg" style="flex:{pct};background:{_SEVERITY_COLORS[sev]}" '
                f'title="{sev}: {count}"></span>'
            )
    return f'<div class="sevbar">{"".join(segments)}</div>'


def _severity_legend(counts: Counter) -> str:
    items = []
    for sev in _SEVERITY_ORDER:
        items.append(
            f'<span class="legend-item">{_dot(_SEVERITY_COLORS[sev])}'
            f'<span class="legend-count">{counts.get(sev, 0)}</span>'
            f'<span class="legend-name">{sev.lower()}</span></span>'
        )
    return f'<div class="legend">{"".join(items)}</div>'


def _coverage_tactic_rows(report: CoverageReport) -> str:
    rows = []
    for tactic, stats in report.coverage_by_tactic.items():
        total = stats.get("total", 0)
        covered = stats.get("covered", 0)
        pct = int((covered / total) * 100) if total else 0
        rows.append(
            f'<div class="row">'
            f'<span class="row-label">{_esc(tactic)}</span>'
            f'<span class="track"><span class="fill cov" style="width:{pct}%"></span></span>'
            f'<span class="row-val">{covered}<span class="dim">/{total}</span></span>'
            f"</div>"
        )
    return "".join(rows) or '<div class="empty">No tactics.</div>'


def _tactic_alert_rows(alerts: list[Alert]) -> str:
    counts = Counter(a.tactic for a in alerts)
    if not counts:
        return '<div class="empty">No alerts yet.</div>'
    max_count = max(counts.values())
    rows = []
    for tactic, count in sorted(counts.items(), key=lambda kv: kv[1], reverse=True):
        width = int((count / max_count) * 100)
        rows.append(
            f'<div class="row">'
            f'<span class="row-label">{_esc(tactic)}</span>'
            f'<span class="track"><span class="fill" style="width:{width}%"></span></span>'
            f'<span class="row-val">{count}</span>'
            f"</div>"
        )
    return "".join(rows)


def _recent_alert_rows(alerts: list[Alert]) -> str:
    recent = sorted(alerts, key=lambda a: a.generated_at, reverse=True)[:20]
    if not recent:
        return ('<tr><td colspan="6" class="empty">'
                "No alerts yet &mdash; POST CloudTrail events to /ingest.</td></tr>")
    rows = []
    for a in recent:
        color = _SEVERITY_COLORS.get(a.severity, "#9a9aa2")
        sev = (
            f'<span class="sev">{_dot(color, 7)}'
            f'<span class="sev-text">{_esc(a.severity.title())}</span></span>'
        )
        actor = _esc(a.actor_arn or a.actor_type)
        rows.append(
            f"<tr>"
            f'<td class="mono dim">{_esc(a.event_time.strftime("%m-%d %H:%M:%S"))}</td>'
            f"<td>{sev}</td>"
            f'<td class="tech"><a href="{_esc(a.mitre_url)}" target="_blank" rel="noopener">'
            f'<span class="tid">{_esc(a.technique_id)}</span>'
            f'<span class="tname">{_esc(a.technique_name)}</span></a></td>'
            f'<td class="mono actor">{actor}</td>'
            f'<td class="mono">{_esc(a.source_ip)}</td>'
            f'<td class="mono dim">{_esc(a.aws_region)}</td>'
            f"</tr>"
        )
    return "".join(rows)


def render_dashboard(alerts: list[Alert], report: CoverageReport) -> str:
    counts = Counter(a.severity for a in alerts)
    total = len(alerts)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Cloud TTP Detection</title>
<style>
  :root {{
    --bg:#08080a; --panel:#0d0d10; --line:#1a1a1f; --line-soft:#141418;
    --fg:#ededee; --fg-dim:#8a8a92; --fg-faint:#5a5a62; --accent:#5bd6a6;
  }}
  * {{ box-sizing:border-box; }}
  html, body {{ margin:0; background:var(--bg); }}
  body {{
    color:var(--fg);
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Inter,Roboto,
                Helvetica,Arial,sans-serif;
    font-feature-settings:'tnum' 1; -webkit-font-smoothing:antialiased;
    line-height:1.5;
  }}
  .top-rule {{ height:1px; background:linear-gradient(90deg,
               transparent, var(--accent), transparent); opacity:.5; }}
  .shell {{ max-width:1080px; margin:0 auto; padding:0 40px; }}
  a {{ color:inherit; text-decoration:none; }}

  header {{ display:flex; align-items:baseline; justify-content:space-between;
            padding:42px 0 30px; }}
  .brand {{ font-size:14px; letter-spacing:.04em; }}
  .brand b {{ font-weight:600; }}
  .brand .sep {{ color:var(--fg-faint); margin:0 8px; }}
  .brand .sub {{ color:var(--fg-dim); font-weight:400; }}
  .meta {{ font-size:11px; letter-spacing:.16em; text-transform:uppercase;
           color:var(--fg-faint); }}

  .hero {{ display:flex; gap:64px; padding:18px 0 46px;
           border-bottom:1px solid var(--line); }}
  .figure {{ }}
  .fig-num {{ font-size:46px; font-weight:250; letter-spacing:-.02em;
              line-height:1; color:var(--fg); }}
  .fig-num .pct {{ font-size:24px; color:var(--fg-dim); margin-left:2px; }}
  .fig-num .dim {{ color:var(--fg-faint); font-weight:200; }}
  .fig-label {{ margin-top:12px; font-size:10.5px; letter-spacing:.16em;
                text-transform:uppercase; color:var(--fg-dim); }}

  .label {{ font-size:10.5px; letter-spacing:.18em; text-transform:uppercase;
            color:var(--fg-faint); margin:0 0 18px; }}

  section.block {{ padding:42px 0; border-bottom:1px solid var(--line); }}
  .sevbar {{ display:flex; gap:3px; height:6px; border-radius:999px;
             overflow:hidden; margin-bottom:18px; }}
  .sevbar .seg {{ height:100%; border-radius:999px; }}
  .sevbar-empty {{ flex:1; background:var(--line); border-radius:999px; }}
  .legend {{ display:flex; gap:30px; flex-wrap:wrap; }}
  .legend-item {{ display:inline-flex; align-items:center; gap:8px; }}
  .legend-count {{ font-size:15px; font-weight:400; }}
  .legend-name {{ font-size:11px; letter-spacing:.12em; text-transform:uppercase;
                  color:var(--fg-dim); }}

  .cols {{ display:grid; grid-template-columns:1fr 1fr; gap:64px; }}
  .row {{ display:flex; align-items:center; gap:16px; padding:9px 0; }}
  .row-label {{ flex:0 0 168px; font-size:13px; color:var(--fg); }}
  .track {{ flex:1; height:4px; background:var(--line); border-radius:999px;
            overflow:hidden; }}
  .fill {{ display:block; height:100%; border-radius:999px;
           background:var(--fg-dim); transition:width .4s ease; }}
  .fill.cov {{ background:var(--accent); }}
  .row-val {{ flex:0 0 auto; min-width:46px; text-align:right; font-size:12px;
              color:var(--fg-dim); font-variant-numeric:tabular-nums; }}
  .dim {{ color:var(--fg-faint); }}

  table {{ width:100%; border-collapse:collapse; }}
  th {{ text-align:left; font-size:10px; letter-spacing:.16em; font-weight:500;
        text-transform:uppercase; color:var(--fg-faint); padding:0 14px 14px 0; }}
  td {{ padding:13px 14px 13px 0; border-top:1px solid var(--line-soft);
        font-size:13px; vertical-align:middle; }}
  tbody tr {{ transition:background .15s ease; }}
  tbody tr:hover {{ background:rgba(255,255,255,.018); }}
  .mono {{ font-family:'SF Mono',ui-monospace,Consolas,'Courier New',monospace;
           font-size:12px; }}
  .actor {{ max-width:230px; overflow:hidden; text-overflow:ellipsis;
            white-space:nowrap; color:var(--fg-dim); }}
  .sev {{ display:inline-flex; align-items:center; gap:8px; }}
  .sev-text {{ font-size:12px; color:var(--fg-dim); }}
  .tech a {{ display:flex; flex-direction:column; gap:2px; }}
  .tech a:hover .tname {{ color:var(--fg); }}
  .tid {{ font-family:'SF Mono',ui-monospace,Consolas,monospace; font-size:11px;
          color:var(--accent); letter-spacing:.02em; }}
  .tname {{ font-size:12.5px; color:var(--fg-dim); }}
  .empty {{ color:var(--fg-faint); font-style:italic; padding:24px 0; }}

  footer {{ padding:34px 0 56px; color:var(--fg-faint); font-size:11px;
            letter-spacing:.04em; }}
  @media (max-width:820px) {{
    .shell {{ padding:0 22px; }}
    .hero {{ gap:36px; flex-wrap:wrap; }}
    .cols {{ grid-template-columns:1fr; gap:8px; }}
    .row-label {{ flex-basis:120px; }}
  }}
</style>
</head>
<body>
<div class="top-rule"></div>
<div class="shell">

  <header>
    <div class="brand"><b>ATT&amp;CK</b><span class="sep">/</span><span class="sub">Cloud TTP Detection</span></div>
    <div class="meta">CloudTrail &middot; in-memory</div>
  </header>

  {_hero(alerts, report)}

  <section class="block">
    <p class="label">Severity distribution</p>
    {_severity_bar(counts, total)}
    {_severity_legend(counts)}
  </section>

  <section class="block">
    <div class="cols">
      <div>
        <p class="label">Coverage by tactic</p>
        {_coverage_tactic_rows(report)}
      </div>
      <div>
        <p class="label">Alerts by tactic</p>
        {_tactic_alert_rows(alerts)}
      </div>
    </div>
  </section>

  <section class="block" style="border-bottom:none">
    <p class="label">Recent alerts &middot; latest 20</p>
    <table>
      <thead>
        <tr><th>Time</th><th>Severity</th><th>Technique</th>
            <th>Actor</th><th>Source IP</th><th>Region</th></tr>
      </thead>
      <tbody>{_recent_alert_rows(alerts)}</tbody>
    </table>
  </section>

  <footer>Rules as data &middot; enrichment from the official MITRE ATT&amp;CK STIX bundle</footer>

</div>
</body>
</html>"""


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    alerts = list(request.app.state.alert_store)
    report = build_coverage_report(
        request.app.state.enricher, request.app.state.engine.rules
    )
    return HTMLResponse(content=render_dashboard(alerts, report), status_code=200)
