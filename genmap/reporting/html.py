"""Self contained HTML reports.

Every value from Nmap is escaped because service banners and script output
come from the scanned systems and can contain markup. The page also carries
a Content Security Policy that forbids scripts and remote resources, so a
report stays inert even if it is opened from an untrusted location.
"""

from __future__ import annotations

import html
import json
from datetime import datetime
from typing import TYPE_CHECKING

from genmap import APP_NAME, __version__
from genmap.core.results import Host, ScriptResult

if TYPE_CHECKING:
    from genmap.reporting.engine import ReportOptions, ReportSource

e = html.escape

STYLE = """
:root { --text:#1b1f27; --muted:#5f6875; --border:#d6dae1; --alt:#f5f7fa; --accent:#2457c5; --ok:#1e7b3e; --warn:#a85f00; --bad:#b32a2a; }
* { box-sizing: border-box; }
body { font-family: "Segoe UI", system-ui, -apple-system, sans-serif; color: var(--text); margin: 0; background: #fff; line-height: 1.45; }
main { max-width: 1100px; margin: 0 auto; padding: 32px 28px 48px; }
header { border-bottom: 3px solid var(--accent); padding-bottom: 14px; margin-bottom: 20px; }
h1 { font-size: 24px; margin: 0 0 4px; } h2 { font-size: 19px; margin: 28px 0 10px; border-bottom: 1px solid var(--border); padding-bottom: 4px; }
h3 { font-size: 16px; margin: 0 0 6px; } h4 { font-size: 13px; margin: 14px 0 4px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
.muted { color: var(--muted); } .small { font-size: 12px; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { text-align: left; padding: 5px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { background: var(--alt); font-weight: 600; }
table.kv th { width: 190px; background: none; color: var(--muted); font-weight: 600; }
.metrics { display: flex; flex-wrap: wrap; gap: 12px; margin: 8px 0 4px; }
.metric { border: 1px solid var(--border); border-radius: 6px; padding: 10px 16px; min-width: 150px; }
.metric b { display: block; font-size: 22px; }
.host { border: 1px solid var(--border); border-radius: 8px; padding: 16px 18px; margin: 14px 0; page-break-inside: avoid; }
.state-open { color: var(--ok); font-weight: 600; } .state-closed { color: var(--bad); } .state-filtered { color: var(--warn); }
.guess { color: var(--muted); font-style: italic; }
pre { background: var(--alt); border: 1px solid var(--border); border-radius: 4px; padding: 8px 10px; white-space: pre-wrap; word-break: break-word; font: 12px Consolas, "Cascadia Mono", Menlo, monospace; margin: 4px 0 10px; }
.warnings { border: 1px solid var(--warn); background: #fff8ec; border-radius: 6px; padding: 10px 16px; }
details summary { cursor: pointer; color: var(--accent); }
footer { margin-top: 36px; border-top: 1px solid var(--border); padding-top: 10px; }
@media print { main { padding: 0; } .host { border-color: #999; } }
"""


def _kv(rows: list[tuple[str, str]]) -> str:
    return "<table class='kv'>" + "".join(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>" for k, v in rows if v) + "</table>"


def _scripts(scripts: list[ScriptResult]) -> str:
    out = []
    for script in scripts:
        body = script.output or (json.dumps(script.structured, indent=2) if script.structured else "")
        out.append(f"<div><b>{e(script.script_id)}</b><pre>{e(body)}</pre></div>")
    return "".join(out)


def _host(host: Host, options: "ReportOptions", visible_ports) -> str:
    parts = [f"<section class='host' id='host-{e(host.primary_address or 'unknown')}'>"]
    parts.append(f"<h3>{e(host.display_name)}</h3>")
    status = host.status.state + (f" ({host.status.reason})" if host.status.reason else "")
    identity = [("Status", status)]
    identity += [(a.address_type.upper(), a.address + (f"  {a.vendor}" if a.vendor else "")) for a in host.addresses]
    identity += [(f"Hostname ({h.hostname_type})" if h.hostname_type else "Hostname", h.name) for h in host.hostnames]
    if host.distance is not None:
        identity.append(("Network distance", f"{host.distance} hop{'s' if host.distance != 1 else ''}"))
    if host.uptime:
        identity.append(("Uptime (Nmap's estimate)", f"{host.uptime.seconds / 86400:.1f} days" + (f", last boot {host.uptime.last_boot}" if host.uptime.last_boot else "")))
    parts.append(_kv(identity))

    ports = visible_ports(host, options)
    hidden = len(host.ports) - len(ports)
    extra = ", ".join(f"{x.count} {x.state}" for x in host.extra_ports)
    parts.append("<h4>Ports</h4>")
    if ports:
        rows = []
        for port in ports:
            service = port.service
            name = service.name if service and service.name else ""
            if service and service.tunnel:
                name = f"{service.tunnel}/{name}"
            guess = service is not None and name and not service.is_probed
            name_html = f"<span class='guess' title='From the port table, not confirmed by probing'>{e(name)}?</span>" if guess else e(name)
            product = " ".join(p for p in ((service.product if service else None), (service.version if service else None)) if p)
            state_class = "state-" + port.state.split("|")[0]
            rows.append(
                f"<tr><td>{port.port_id}/{e(port.protocol)}</td><td class='{e(state_class)}'>{e(port.state)}</td>"
                f"<td>{e(port.reason or '')}</td><td>{name_html}</td><td>{e(product)}</td>"
                f"<td>{e(service.extra_info or '') if service else ''}</td><td class='small'>{e(' '.join(service.cpe)) if service else ''}</td></tr>"
            )
        parts.append("<table><tr><th>Port</th><th>State</th><th>Reason</th><th>Service</th><th>Product and version</th><th>Extra</th><th>CPE</th></tr>" + "".join(rows) + "</table>")
    else:
        parts.append("<p class='muted'>No ports to list.</p>")
    notes = []
    if hidden:
        notes.append(f"{hidden} closed or filtered port{'s' if hidden != 1 else ''} not listed")
    if extra:
        notes.append(f"not shown by Nmap: {extra}")
    if notes:
        parts.append(f"<p class='small muted'>{e('; '.join(notes))}.</p>")

    if options.include_script_output:
        port_scripts = [(p, p.scripts) for p in ports if p.scripts]
        if port_scripts:
            parts.append("<h4>Port script output</h4>")
            for port, scripts in port_scripts:
                parts.append(f"<p><b>{port.port_id}/{e(port.protocol)}</b></p>{_scripts(scripts)}")
        if host.host_scripts:
            parts.append("<h4>Host script output</h4>" + _scripts(host.host_scripts))

    if host.os and host.os.matches:
        rows = "".join(
            f"<tr><td>{e(str(m.accuracy) + '%' if m.accuracy is not None else '')}</td><td>{e(m.name)}</td>"
            f"<td class='small'>{e(', '.join(c for cls in m.classes for c in cls.cpe))}</td></tr>"
            for m in host.os.matches[:6]
        )
        parts.append("<h4>Operating system guesses</h4><p class='small muted'>Nmap's matches with its own accuracy ratings.</p>")
        parts.append(f"<table><tr><th>Accuracy</th><th>Match</th><th>CPE</th></tr>{rows}</table>")
    if host.traceroute and host.traceroute.hops:
        rows = "".join(
            f"<tr><td>{h.ttl}</td><td>{e(h.ip_address or '*')}</td><td>{e(h.hostname or '')}</td><td>{'' if h.rtt is None else f'{h.rtt:.2f} ms'}</td></tr>"
            for h in host.traceroute.hops
        )
        parts.append(f"<h4>Traceroute</h4><table><tr><th>TTL</th><th>Address</th><th>Name</th><th>RTT</th></tr>{rows}</table>")
    parts.append("</section>")
    return "".join(parts)


def render_html(source: "ReportSource", options: "ReportOptions") -> str:
    from genmap.reporting.engine import _all_warnings, _metadata, _summary, _visible_hosts, _visible_ports

    result = source.result
    title = options.title or source.title
    summary = _summary(result)
    generated = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    body = [f"<header><h1>{e(title)}</h1><div class='muted'>Generated {e(generated)} by {e(APP_NAME)} {e(__version__)} from Nmap's XML output</div></header>"]

    metrics = [
        (f"{summary['hosts_up']} / {summary['hosts_total']}", "Hosts up"),
        (str(summary["open_ports"]), "Open ports"),
        (str(len(summary["identified_services"])), "Identified services"),
    ]
    body.append("<h2>Summary</h2><div class='metrics'>" + "".join(f"<div class='metric'><b>{e(v)}</b>{e(k)}</div>" for v, k in metrics) + "</div>")
    if summary["identified_services"]:
        body.append(f"<p>Services identified by version detection: {e(', '.join(summary['identified_services']))}.</p>")
    if summary["port_table_service_names"]:
        body.append(
            "<p class='muted'>Names taken from Nmap's port table without confirmation: "
            + e(", ".join(summary["port_table_service_names"]))
            + ".</p>"
        )

    warnings = _all_warnings(source)
    if warnings:
        body.append("<h2>Warnings and errors</h2><div class='warnings'><ul>" + "".join(f"<li>{e(w)}</li>" for w in warnings) + "</ul></div>")

    body.append("<h2>Scan details</h2>" + _kv(_metadata(source)))
    if options.include_configuration and source.record is not None:
        body.append(
            "<details><summary>Scan configuration used by Genmap</summary><pre>"
            + e(json.dumps(source.record.configuration, indent=2))
            + "</pre></details>"
        )

    hosts = _visible_hosts(result, options)
    hidden_hosts = len(result.hosts) - len(hosts)
    body.append(f"<h2>Hosts ({len(hosts)})</h2>")
    if hidden_hosts:
        body.append(f"<p class='muted'>{hidden_hosts} host{'s' if hidden_hosts != 1 else ''} reported as down {'are' if hidden_hosts != 1 else 'is'} not listed.</p>")
    if not hosts:
        body.append("<p class='muted'>No hosts to list.</p>")
    for host in hosts:
        body.append(_host(host, options, _visible_ports))

    if options.include_script_output and (result.pre_scripts or result.post_scripts):
        body.append("<h2>Pre and post scan scripts</h2>")
        if result.pre_scripts:
            body.append("<h4>Before scanning</h4>" + _scripts(result.pre_scripts))
        if result.post_scripts:
            body.append("<h4>After scanning</h4>" + _scripts(result.post_scripts))

    body.append(
        "<footer class='small muted'>This report lists what Nmap reported for the scanned targets at the time of the scan. "
        "It does not rate risk or confirm vulnerabilities; script output and service versions should be verified before acting on them.</footer>"
    )
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<meta name='generator' content='{e(APP_NAME)} {e(__version__)}'>"
        f"<title>{e(title)}</title><style>{STYLE}</style></head><body><main>"
        + "".join(body)
        + "</main></body></html>"
    )
