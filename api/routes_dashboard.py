"""HTML coverage/alert dashboard.

A single server-rendered page: dark theme, inline CSS, no JavaScript. It reads
the in-memory alert store and the dynamic coverage report and renders them as
a restrained, minimalist analyst view (figures, a slim severity distribution
bar, hairline tactic/coverage rows, and a recent-alerts table).
"""

from __future__ import annotations

import html
import json
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


def _detail_row(a: Alert, idx: int) -> str:
    """Render the hidden detail <tr> for a single alert row."""
    color = _SEVERITY_COLORS.get(a.severity, "#9a9aa2")
    sev_html = (
        f'{_dot(color, 7)}'
        f'<span class="sev-text">{_esc(a.severity.title())}</span>'
    )

    raw_json = json.dumps(a.raw_event, indent=2, default=str)

    enr_html = ""
    if a.enrichment:
        e = a.enrichment
        tactic_names = _esc(", ".join(e.tactic_names) if e.tactic_names else "—")
        platforms = _esc(", ".join(e.platforms) if e.platforms else "—")
        data_sources = _esc(", ".join(e.data_sources) if e.data_sources else "—")
        desc = e.description or ""
        enr_desc = _esc((desc[:300] + "…") if len(desc) > 300 else desc)
        enr_html = (
            '<div class="dp-section">'
            '<div class="dp-slabel">MITRE Enrichment</div>'
            '<div class="dp-enr">'
            f'<div class="dp-field"><div class="dp-label">Tactic Names</div><div class="dp-value">{tactic_names}</div></div>'
            f'<div class="dp-field"><div class="dp-label">Platforms</div><div class="dp-value">{platforms}</div></div>'
            f'<div class="dp-field"><div class="dp-label">Data Sources</div><div class="dp-value">{data_sources}</div></div>'
            f'<div class="dp-field dp-enr-full"><div class="dp-label">STIX Description</div><div class="dp-value">{enr_desc}</div></div>'
            '</div>'
            '</div>'
        )

    panel = (
        '<div class="dp-inner">'
        f'<div class="dp-topbar"><button class="dp-fullbtn" onclick="openModal({idx});event.stopPropagation()">Full Details</button></div>'
        '<div class="dp-cols">'
        '<div>'
        f'<div class="dp-field"><div class="dp-label">Rule ID</div><div class="dp-value dp-mono">{_esc(a.rule_id)}</div></div>'
        f'<div class="dp-field"><div class="dp-label">Technique ID</div><div class="dp-value"><span class="tid">{_esc(a.technique_id)}</span></div></div>'
        f'<div class="dp-field"><div class="dp-label">Technique Name</div><div class="dp-value">{_esc(a.technique_name)}</div></div>'
        f'<div class="dp-field"><div class="dp-label">Tactic</div><div class="dp-value">{_esc(a.tactic)}</div></div>'
        f'<div class="dp-field"><div class="dp-label">Event Name</div><div class="dp-value dp-mono">{_esc(a.event_name)}</div></div>'
        f'<div class="dp-field"><div class="dp-label">Event Source</div><div class="dp-value dp-mono">{_esc(a.event_source)}</div></div>'
        f'<div class="dp-field"><div class="dp-label">Actor Type</div><div class="dp-value">{_esc(a.actor_type)}</div></div>'
        f'<div class="dp-field"><div class="dp-label">Actor ARN</div><div class="dp-value dp-mono dp-break">{_esc(a.actor_arn or "—")}</div></div>'
        '</div>'
        '<div>'
        f'<div class="dp-field"><div class="dp-label">Alert ID</div><div class="dp-value dp-mono dp-break">{_esc(a.alert_id)}</div></div>'
        f'<div class="dp-field"><div class="dp-label">Generated At</div><div class="dp-value dp-mono">{_esc(a.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC"))}</div></div>'
        f'<div class="dp-field"><div class="dp-label">Event Time</div><div class="dp-value dp-mono">{_esc(a.event_time.strftime("%Y-%m-%d %H:%M:%S UTC"))}</div></div>'
        f'<div class="dp-field"><div class="dp-label">Severity</div><div class="dp-value"><span class="sev">{sev_html}</span></div></div>'
        f'<div class="dp-field"><div class="dp-label">Region</div><div class="dp-value dp-mono">{_esc(a.aws_region)}</div></div>'
        f'<div class="dp-field"><div class="dp-label">Source IP</div><div class="dp-value dp-mono">{_esc(a.source_ip)}</div></div>'
        f'<div class="dp-field"><div class="dp-label">MITRE URL</div><div class="dp-value">'
        f'<a href="{_esc(a.mitre_url)}" target="_blank" rel="noopener" class="dp-link">{_esc(a.mitre_url)}</a></div></div>'
        '</div>'
        '</div>'
        '<div class="dp-section"><div class="dp-slabel">Description</div>'
        f'<div class="dp-desc">{_esc(a.description)}</div></div>'
        f'{enr_html}'
        '<div class="dp-section">'
        f'<button class="dp-rawbtn" id="rawbtn-{idx}" onclick="toggleRaw({idx});event.stopPropagation()">View Raw Event</button>'
        f'<div id="raw-{idx}" class="dp-raw" style="display:none"><pre>{_esc(raw_json)}</pre></div>'
        '</div>'
        '</div>'
    )

    return (
        f'<tr class="detail-row" id="detail-{idx}">'
        f'<td colspan="7" class="dp-cell">{panel}</td>'
        f'</tr>'
    )


def _recent_alert_rows_with_details(recent: list[Alert]) -> str:
    if not recent:
        return ('<tr><td colspan="7" class="empty">'
                "No alerts yet &mdash; POST CloudTrail events to /ingest.</td></tr>")
    rows = []
    for idx, a in enumerate(recent):
        color = _SEVERITY_COLORS.get(a.severity, "#9a9aa2")
        sev = (
            f'<span class="sev">{_dot(color, 7)}'
            f'<span class="sev-text">{_esc(a.severity.title())}</span></span>'
        )
        actor = _esc(a.actor_arn or a.actor_type)
        rows.append(
            f'<tr class="alert-row" onclick="toggleRow({idx})">'
            f'<td class="mono dim">{_esc(a.event_time.strftime("%m-%d %H:%M:%S"))}</td>'
            f'<td>{sev}</td>'
            f'<td class="tech"><a href="{_esc(a.mitre_url)}" target="_blank" rel="noopener"'
            f' onclick="event.stopPropagation()">'
            f'<span class="tid">{_esc(a.technique_id)}</span>'
            f'<span class="tname">{_esc(a.technique_name)}</span></a></td>'
            f'<td class="mono actor">{actor}</td>'
            f'<td class="mono">{_esc(a.source_ip)}</td>'
            f'<td class="mono dim">{_esc(a.aws_region)}</td>'
            f'<td class="td-chev"><span class="chev" id="chev-{idx}">&#9658;</span></td>'
            f'</tr>'
        )
        rows.append(_detail_row(a, idx))
    return "".join(rows)


def render_dashboard(alerts: list[Alert], report: CoverageReport) -> str:
    counts = Counter(a.severity for a in alerts)
    total = len(alerts)
    recent = sorted(alerts, key=lambda a: a.generated_at, reverse=True)[:20]

    # Embed full alert data for the modal — safe for inline <script> use
    alerts_json = json.dumps(
        [a.model_dump(mode="json") for a in recent], default=str
    ).replace("</", "<\\/")

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

  /* ── expandable alert rows ── */
  tbody tr.alert-row {{ cursor:pointer; }}
  tbody tr.alert-row:hover {{ background:rgba(255,255,255,.030); }}
  tbody tr.detail-row {{ display:none; transition:none; }}
  tbody tr.detail-row:hover {{ background:transparent; }}
  tbody tr.detail-row.open {{ display:table-row; animation:dpFadeIn .15s ease; }}
  @keyframes dpFadeIn {{ from {{opacity:0}} to {{opacity:1}} }}

  .td-chev {{ width:28px; text-align:right; padding-right:4px; }}
  .chev {{
    display:inline-block; color:var(--fg-faint); font-size:9px;
    transition:transform .2s ease; user-select:none;
  }}
  .chev.open {{ transform:rotate(90deg); }}

  /* detail panel cell */
  tr.detail-row td.dp-cell {{
    padding:0; border-top:none; background:#0f0f13;
  }}
  .dp-inner {{
    padding:22px 0 28px; position:relative;
  }}
  .dp-topbar {{ text-align:right; margin-bottom:18px; }}
  .dp-cols {{
    display:grid; grid-template-columns:1fr 1fr; gap:0 48px;
  }}
  .dp-field {{ margin-bottom:14px; }}
  .dp-label {{
    font-size:10px; letter-spacing:.16em; text-transform:uppercase;
    color:var(--fg-faint); margin-bottom:3px;
  }}
  .dp-value {{ font-size:13px; color:var(--fg); }}
  .dp-mono {{
    font-family:'SF Mono',ui-monospace,Consolas,'Courier New',monospace;
    font-size:12px;
  }}
  .dp-break {{ word-break:break-all; }}
  .dp-link {{ color:var(--accent); }}
  .dp-link:hover {{ text-decoration:underline; }}
  .dp-section {{ margin-top:22px; }}
  .dp-slabel {{
    font-size:10px; letter-spacing:.16em; text-transform:uppercase;
    color:var(--fg-faint); margin-bottom:10px;
  }}
  .dp-desc {{ font-size:13px; color:var(--fg-dim); }}
  .dp-enr {{
    display:grid; grid-template-columns:1fr 1fr; gap:12px 48px;
  }}
  .dp-enr-full {{ grid-column:1 / -1; }}
  .dp-rawbtn, .dp-fullbtn {{
    background:none; border:1px solid var(--line); color:var(--fg-dim);
    font-size:10px; letter-spacing:.12em; text-transform:uppercase;
    padding:5px 12px; cursor:pointer; border-radius:2px;
    font-family:inherit;
  }}
  .dp-rawbtn:hover, .dp-fullbtn:hover {{
    border-color:var(--accent); color:var(--accent);
  }}
  .dp-raw {{
    margin-top:10px; background:var(--bg); border-radius:2px;
    overflow-x:auto;
  }}
  .dp-raw pre {{
    margin:0; padding:14px 16px;
    font-family:'SF Mono',ui-monospace,Consolas,'Courier New',monospace;
    font-size:11px; color:var(--fg-dim); white-space:pre;
  }}

  /* ── modal ── */
  .modal-overlay {{
    display:none; position:fixed; inset:0;
    background:rgba(0,0,0,.78); z-index:900;
    align-items:center; justify-content:center;
  }}
  .modal-overlay.open {{ display:flex; }}
  .modal-box {{
    background:#111115; max-width:800px; width:90%; max-height:85vh;
    overflow-y:auto; border-radius:3px; padding:40px 44px;
    position:relative; border:1px solid var(--line);
  }}
  .modal-close {{
    position:absolute; top:14px; right:18px; background:none;
    border:none; color:var(--fg-faint); font-size:22px;
    cursor:pointer; line-height:1; font-family:inherit;
  }}
  .modal-close:hover {{ color:var(--fg); }}
  .modal-title {{
    font-size:10px; letter-spacing:.2em; text-transform:uppercase;
    color:var(--fg-faint); margin:0 0 28px;
  }}
  .modal-cols {{ display:grid; grid-template-columns:1fr 1fr; gap:0 48px; }}
  .modal-field {{ margin-bottom:16px; }}
  .modal-label {{
    font-size:10px; letter-spacing:.16em; text-transform:uppercase;
    color:var(--fg-faint); margin-bottom:4px;
  }}
  .modal-value {{ font-size:13.5px; color:var(--fg); }}
  .modal-mono {{
    font-family:'SF Mono',ui-monospace,Consolas,'Courier New',monospace;
    font-size:12.5px;
  }}
  .modal-break {{ word-break:break-all; }}
  .modal-link {{ color:var(--accent); }}
  .modal-link:hover {{ text-decoration:underline; }}
  .modal-section {{
    margin-top:24px; border-top:1px solid var(--line-soft);
    padding-top:24px;
  }}
  .modal-slabel {{
    font-size:10px; letter-spacing:.16em; text-transform:uppercase;
    color:var(--fg-faint); margin-bottom:12px;
  }}
  .modal-rawbtn {{
    background:none; border:1px solid var(--line); color:var(--fg-dim);
    font-size:10px; letter-spacing:.12em; text-transform:uppercase;
    padding:5px 12px; cursor:pointer; border-radius:2px; font-family:inherit;
  }}
  .modal-rawbtn:hover {{ border-color:var(--accent); color:var(--accent); }}
  .modal-raw {{
    margin-top:10px; background:var(--bg); border-radius:2px;
    overflow-x:auto;
  }}
  .modal-raw pre {{
    margin:0; padding:14px 16px;
    font-family:'SF Mono',ui-monospace,Consolas,'Courier New',monospace;
    font-size:11px; color:var(--fg-dim); white-space:pre;
  }}
  @media (max-width:820px) {{
    .dp-cols, .dp-enr, .modal-cols {{ grid-template-columns:1fr; gap:0; }}
    .dp-enr-full {{ grid-column:1; }}
    .modal-box {{ padding:28px 22px; }}
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
            <th>Actor</th><th>Source IP</th><th>Region</th><th></th></tr>
      </thead>
      <tbody>{_recent_alert_rows_with_details(recent)}</tbody>
    </table>
  </section>

  <footer>Rules as data &middot; enrichment from the official MITRE ATT&amp;CK STIX bundle</footer>

</div>

<!-- modal overlay -->
<div class="modal-overlay" id="modal-overlay" onclick="if(event.target===this)closeModal()">
  <div class="modal-box">
    <button class="modal-close" onclick="closeModal()">&#215;</button>
    <div id="modal-content"></div>
  </div>
</div>

<script>
const alerts = {alerts_json};

function esc(s) {{
  return String(s == null ? '—' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}}

function toggleRow(idx) {{
  const det = document.getElementById('detail-' + idx);
  const chev = document.getElementById('chev-' + idx);
  const isOpen = det.classList.contains('open');
  document.querySelectorAll('tr.detail-row.open').forEach(function(r) {{ r.classList.remove('open'); }});
  document.querySelectorAll('.chev.open').forEach(function(c) {{ c.classList.remove('open'); }});
  if (!isOpen) {{
    det.classList.add('open');
    chev.classList.add('open');
  }}
}}

function toggleRaw(idx) {{
  const el = document.getElementById('raw-' + idx);
  const btn = document.getElementById('rawbtn-' + idx);
  if (el.style.display === 'none') {{
    el.style.display = 'block';
    btn.textContent = 'Hide Raw Event';
  }} else {{
    el.style.display = 'none';
    btn.textContent = 'View Raw Event';
  }}
}}

function toggleModalRaw() {{
  const el = document.getElementById('modal-raw');
  const btn = document.getElementById('modal-rawbtn');
  if (el.style.display === 'none') {{
    el.style.display = 'block';
    btn.textContent = 'Hide Raw Event';
  }} else {{
    el.style.display = 'none';
    btn.textContent = 'View Raw Event';
  }}
}}

function openModal(idx) {{
  document.getElementById('modal-content').innerHTML = buildModalHTML(alerts[idx]);
  document.getElementById('modal-overlay').classList.add('open');
}}

function closeModal() {{
  document.getElementById('modal-overlay').classList.remove('open');
}}

document.addEventListener('keydown', function(e) {{
  if (e.key === 'Escape') closeModal();
}});

function buildModalHTML(a) {{
  var sevColors = {{CRITICAL:'#ff5d6c', HIGH:'#ff9f45', MEDIUM:'#ffd25e', LOW:'#6fb1ff'}};
  var c = sevColors[a.severity] || '#9a9aa2';
  var dot = '<span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:' + c + ';vertical-align:middle"></span>';

  var enrHTML = '';
  if (a.enrichment) {{
    var enr = a.enrichment;
    var tacticNames = esc((enr.tactic_names || []).join(', ') || '—');
    var platforms   = esc((enr.platforms   || []).join(', ') || '—');
    var dataSources = esc((enr.data_sources|| []).join(', ') || '—');
    var enrDesc     = enr.description || '';
    if (enrDesc.length > 300) enrDesc = enrDesc.substring(0, 300) + '…';
    enrHTML = (
      '<div class="modal-section">' +
      '<div class="modal-slabel">MITRE Enrichment</div>' +
      '<div class="modal-cols">' +
        '<div>' +
          '<div class="modal-field"><div class="modal-label">Tactic Names</div><div class="modal-value">' + tacticNames + '</div></div>' +
          '<div class="modal-field"><div class="modal-label">Platforms</div><div class="modal-value">' + platforms + '</div></div>' +
        '</div>' +
        '<div>' +
          '<div class="modal-field"><div class="modal-label">Data Sources</div><div class="modal-value">' + dataSources + '</div></div>' +
        '</div>' +
      '</div>' +
      '<div class="modal-field"><div class="modal-label">STIX Description</div><div class="modal-value">' + esc(enrDesc) + '</div></div>' +
      '</div>'
    );
  }}

  var rawJSON = JSON.stringify(a.raw_event || {{}}, null, 2);

  return (
    '<div class="modal-title">Alert Details</div>' +
    '<div class="modal-cols">' +
      '<div>' +
        '<div class="modal-field"><div class="modal-label">Rule ID</div><div class="modal-value modal-mono">' + esc(a.rule_id) + '</div></div>' +
        '<div class="modal-field"><div class="modal-label">Technique ID</div><div class="modal-value"><span class="tid">' + esc(a.technique_id) + '</span></div></div>' +
        '<div class="modal-field"><div class="modal-label">Technique Name</div><div class="modal-value">' + esc(a.technique_name) + '</div></div>' +
        '<div class="modal-field"><div class="modal-label">Tactic</div><div class="modal-value">' + esc(a.tactic) + '</div></div>' +
        '<div class="modal-field"><div class="modal-label">Event Name</div><div class="modal-value modal-mono">' + esc(a.event_name) + '</div></div>' +
        '<div class="modal-field"><div class="modal-label">Event Source</div><div class="modal-value modal-mono">' + esc(a.event_source) + '</div></div>' +
        '<div class="modal-field"><div class="modal-label">Actor Type</div><div class="modal-value">' + esc(a.actor_type) + '</div></div>' +
        '<div class="modal-field"><div class="modal-label">Actor ARN</div><div class="modal-value modal-mono modal-break">' + esc(a.actor_arn || '—') + '</div></div>' +
      '</div>' +
      '<div>' +
        '<div class="modal-field"><div class="modal-label">Alert ID</div><div class="modal-value modal-mono modal-break">' + esc(a.alert_id) + '</div></div>' +
        '<div class="modal-field"><div class="modal-label">Generated At</div><div class="modal-value modal-mono">' + esc(a.generated_at) + '</div></div>' +
        '<div class="modal-field"><div class="modal-label">Event Time</div><div class="modal-value modal-mono">' + esc(a.event_time) + '</div></div>' +
        '<div class="modal-field"><div class="modal-label">Severity</div><div class="modal-value">' + dot + ' <span class="sev-text">' + esc((a.severity || '').toLowerCase()) + '</span></div></div>' +
        '<div class="modal-field"><div class="modal-label">Region</div><div class="modal-value modal-mono">' + esc(a.aws_region) + '</div></div>' +
        '<div class="modal-field"><div class="modal-label">Source IP</div><div class="modal-value modal-mono">' + esc(a.source_ip) + '</div></div>' +
        '<div class="modal-field"><div class="modal-label">MITRE URL</div><div class="modal-value">' +
          '<a href="' + esc(a.mitre_url || '') + '" target="_blank" rel="noopener" class="modal-link">' + esc(a.mitre_url || '—') + '</a>' +
        '</div></div>' +
      '</div>' +
    '</div>' +
    '<div class="modal-section"><div class="modal-slabel">Description</div><div class="modal-value">' + esc(a.description) + '</div></div>' +
    enrHTML +
    '<div class="modal-section">' +
      '<button class="modal-rawbtn" id="modal-rawbtn" onclick="toggleModalRaw()">View Raw Event</button>' +
      '<div id="modal-raw" class="modal-raw" style="display:none"><pre>' + esc(rawJSON) + '</pre></div>' +
    '</div>'
  );
}}
</script>
</body>
</html>"""


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    alerts = list(request.app.state.alert_store)
    report = build_coverage_report(
        request.app.state.enricher, request.app.state.engine.rules
    )
    return HTMLResponse(content=render_dashboard(alerts, report), status_code=200)
