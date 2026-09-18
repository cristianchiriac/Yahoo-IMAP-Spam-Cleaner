"""JSON and self-contained HTML reporting, built from a single source of truth."""
from __future__ import annotations

import json
import time
from pathlib import Path

from .detection import Finding


def build_report_data(findings: list[Finding], scan_id: str, mode: str, folder: str,
                       skipped: int = 0, incomplete_retried: int = 0) -> dict:
    counts = {"processed": len(findings), "spam": 0, "clean": 0, "incomplete": 0}
    for f in findings:
        counts[f.verdict] = counts.get(f.verdict, 0) + 1
    return {
        "scan_id": scan_id,
        "mode": mode,
        "folder": folder,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": {**counts, "skipped": skipped, "incomplete_retried": incomplete_retried},
        "findings": [f.to_dict() for f in findings],
    }


def write_json_report(data: dict, path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Scan Report {scan_id}</title>
<style>
body {{ font-family: -apple-system, Segoe UI, sans-serif; margin: 2rem; background: #0f1115; color: #e6e6e6; }}
h1 {{ font-size: 1.4rem; }}
.summary {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }}
.tile {{ background: #1b1e26; border-radius: 8px; padding: 0.75rem 1.25rem; min-width: 100px; }}
.tile .n {{ font-size: 1.5rem; font-weight: bold; }}
.tile .l {{ font-size: 0.75rem; opacity: 0.7; text-transform: uppercase; }}
input[type=text] {{ width: 100%; padding: 0.5rem; margin-bottom: 1rem; border-radius: 6px; border: 1px solid #333; background: #1b1e26; color: #eee; }}
.card {{ background: #1b1e26; border-left: 4px solid #444; border-radius: 6px; padding: 0.75rem 1rem; margin-bottom: 0.6rem; }}
.card.spam {{ border-left-color: #e05252; }}
.card.clean {{ border-left-color: #4caf7d; }}
.card.incomplete {{ border-left-color: #d9a441; }}
.card summary {{ cursor: pointer; display: flex; gap: 0.75rem; align-items: baseline; flex-wrap: wrap; }}
.badge {{ font-size: 0.7rem; padding: 0.1rem 0.5rem; border-radius: 4px; background: #333; }}
.score {{ font-weight: bold; }}
.signals {{ margin-top: 0.5rem; font-size: 0.85rem; opacity: 0.9; }}
.signals li {{ margin-bottom: 0.2rem; }}
</style>
</head>
<body>
<h1>Scan Report &mdash; {folder} ({mode})</h1>
<div class="summary" id="summary"></div>
<input type="text" id="filter" placeholder="Filter by uid, sender, subject, rule, or verdict...">
<div id="cards"></div>
<script>
const REPORT = {data_json};
function renderSummary() {{
  const s = REPORT.summary;
  const el = document.getElementById('summary');
  el.innerHTML = Object.entries(s).map(([k,v]) => `<div class="tile"><div class="n">${{v}}</div><div class="l">${{k}}</div></div>`).join('');
}}
function renderCards(filterText) {{
  const container = document.getElementById('cards');
  const ft = (filterText || '').toLowerCase();
  const items = REPORT.findings.filter(f => {{
    if (!ft) return true;
    const hay = [f.uid, f.sender, f.subject, f.verdict, f.matched_hard_rule, ...(f.signals||[]).map(s=>s.name)].join(' ').toLowerCase();
    return hay.includes(ft);
  }});
  container.innerHTML = items.map(f => `
    <details class="card ${{f.verdict}}">
      <summary>
        <span class="badge">${{f.verdict.toUpperCase()}}</span>
        <span class="score">score ${{f.score}}</span>
        <span>UID ${{f.uid}}</span>
        <strong>${{(f.subject||'(no subject)').replace(/</g,'&lt;')}}</strong>
        <span>from ${{(f.sender||'').replace(/</g,'&lt;')}}</span>
      </summary>
      <div class="signals">
        ${{f.matched_hard_rule ? `<div>Hard match: <b>${{f.matched_hard_rule}}</b></div>` : ''}}
        <ul>
          ${{(f.signals||[]).map(s => `<li>${{s.name}} (+${{s.weight}}): ${{s.detail}}</li>`).join('')}}
        </ul>
      </div>
    </details>
  `).join('') || '<p>No findings match.</p>';
}}
document.getElementById('filter').addEventListener('input', e => renderCards(e.target.value));
renderSummary();
renderCards('');
</script>
</body>
</html>
"""


def build_html_report(data: dict) -> str:
    return _HTML_TEMPLATE.format(
        scan_id=data.get("scan_id", ""),
        folder=data.get("folder", ""),
        mode=data.get("mode", ""),
        data_json=json.dumps(data),
    )


def write_html_report(data: dict, path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(build_html_report(data), encoding="utf-8")
