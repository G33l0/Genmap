"""Export of scan comparisons as HTML or JSON.

The layout keeps two things visibly apart: the values Nmap reported in each
scan, and Genmap's reading of what a difference could mean.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from genmap import APP_NAME, __version__
from genmap.core.comparison import ComparisonResult, summarize
from genmap.reporting.engine import ReportError, _write_atomic
from genmap.reporting.html import STYLE

e = html.escape

SUMMARY_LABELS = [
    ("new_hosts", "New hosts"),
    ("missing_hosts", "Hosts not seen"),
    ("ports_opened", "Ports newly open"),
    ("ports_no_longer_open", "Ports no longer open"),
    ("service_changes", "Service or version changes"),
    ("os_changes", "OS guess changes"),
    ("script_changes", "Script output changes"),
]

EXTRA_STYLE = """
.change { border-left: 3px solid var(--accent); padding: 6px 12px; margin: 8px 0; }
.change.info { border-left-color: var(--border); color: var(--muted); }
.reading { color: var(--muted); font-style: italic; margin: 4px 0 0; }
.values td { width: 50%; }
"""


def comparison_to_dict(result: ComparisonResult) -> dict:
    return {
        "generator": f"{APP_NAME} {__version__}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "baseline": result.baseline_label,
        "newer": result.current_label,
        "summary": summarize(result),
        "notes": result.notes,
        "hosts": [
            {
                "address": host.address,
                "name": host.name,
                "status": host.status,
                "changes": [
                    {
                        "kind": change.kind.value,
                        "label": change.label,
                        "subject": change.subject,
                        "significant": change.significant,
                        "nmap_reported": {"baseline": change.before, "newer": change.after},
                        "genmap_reading": change.reading,
                    }
                    for change in host.changes
                ],
            }
            for host in result.hosts
        ],
    }


def render_comparison_html(result: ComparisonResult, *, include_unchanged: bool = False) -> str:
    summary = summarize(result)
    title = f"Scan comparison: {result.baseline_label} and {result.current_label}"
    generated = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    body = [f"<header><h1>{e(title)}</h1><div class='muted'>Generated {e(generated)} by {e(APP_NAME)} {e(__version__)}</div></header>"]
    body.append("<h2>Summary</h2><div class='metrics'>" + "".join(
        f"<div class='metric'><b>{summary[key]}</b>{e(label)}</div>" for key, label in SUMMARY_LABELS
    ) + "</div>")
    body.append(
        "<p class='small muted'>Each change shows what Nmap reported in the baseline and in the newer scan. "
        "The italic line under it is Genmap's reading of the difference, not something Nmap reported.</p>"
    )
    if result.notes:
        body.append("<h2>What was compared</h2><div class='warnings'><ul>" + "".join(f"<li>{e(n)}</li>" for n in result.notes) + "</ul></div>")
    hosts = [h for h in result.hosts if include_unchanged or h.status != "unchanged"]
    body.append(f"<h2>Hosts ({len(hosts)})</h2>")
    if not hosts:
        body.append("<p>No differences were found between the two scans.</p>")
    status_text = {
        "new": "New", "missing": "Not seen in the newer scan", "changed": "Changed",
        "unchanged": "No changes", "out_of_scope": "Outside the other scan's targets",
    }
    for host in hosts:
        body.append(f"<section class='host'><h3>{e(host.name)}</h3><p class='muted'>{e(status_text.get(host.status, host.status))}</p>")
        for change in host.changes:
            css = "change" if change.significant else "change info"
            body.append(
                f"<div class='{css}'><b>{e(change.label)}</b> {e(change.subject)}"
                "<table class='values'><tr><th>Baseline (Nmap)</th><th>Newer (Nmap)</th></tr>"
                f"<tr><td><pre>{e(change.before or '')}</pre></td><td><pre>{e(change.after or '')}</pre></td></tr></table>"
                f"<p class='reading'>Genmap's reading: {e(change.reading)}</p></div>"
            )
        body.append("</section>")
    body.append("<footer class='small muted'>Differences come from comparing two Nmap results. They show what Nmap observed at two times, not why it changed.</footer>")
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        f"<title>{e(title)}</title><style>{STYLE}{EXTRA_STYLE}</style></head><body><main>"
        + "".join(body) + "</main></body></html>"
    )


def export_comparison(result: ComparisonResult, fmt: str, path: Path, *, include_unchanged: bool = False) -> Path:
    try:
        if fmt == "json":
            _write_atomic(path, json.dumps(comparison_to_dict(result), indent=2))
        elif fmt == "html":
            _write_atomic(path, render_comparison_html(result, include_unchanged=include_unchanged))
        else:
            raise ReportError(f"Unknown comparison export format '{fmt}'.")
    except OSError as exc:
        raise ReportError(f"The comparison could not be written to {path}.", details=str(exc)) from exc
    return path
