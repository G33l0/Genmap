"""HTML rendering of host and port details for the results detail pane."""

from __future__ import annotations

import html
import json
from typing import Optional

from genmap.core.results import Host, Port, ScriptResult
from genmap.ui.theme.palettes import Palette


def _e(value: object) -> str:
    return html.escape(str(value)) if value is not None else ""


def _css(p: Palette) -> str:
    return f"""
    <style>
      body {{ color: {p.text}; }}
      h2 {{ font-size: 15pt; margin: 0 0 4px 0; }}
      h3 {{ font-size: 11pt; margin: 14px 0 4px 0; color: {p.text}; }}
      table {{ border-collapse: collapse; }}
      td, th {{ padding: 3px 12px 3px 0; vertical-align: top; text-align: left; }}
      th {{ color: {p.text_muted}; font-weight: 600; }}
      .muted {{ color: {p.text_muted}; }}
      .open {{ color: {p.success}; font-weight: 600; }}
      .closed {{ color: {p.danger}; }}
      .filtered {{ color: {p.warning}; }}
      pre {{ background: {p.surface_alt}; padding: 8px; font-family: Consolas, 'Cascadia Mono', Menlo, monospace; white-space: pre-wrap; }}
      .note {{ color: {p.text_muted}; font-size: 9pt; }}
    </style>
    """


def _rows(pairs: list[tuple[str, Optional[object]]]) -> str:
    out = []
    for key, value in pairs:
        if value in (None, "", []):
            continue
        out.append(f"<tr><th>{_e(key)}</th><td>{_e(value)}</td></tr>")
    return "<table>" + "".join(out) + "</table>" if out else ""


def _scripts(scripts: list[ScriptResult]) -> str:
    parts = []
    for script in scripts:
        body = script.output or (json.dumps(script.structured, indent=2) if script.structured else "")
        parts.append(f"<p><b>{_e(script.script_id)}</b></p><pre>{_e(body)}</pre>")
    return "".join(parts)


def host_html(host: Host, palette: Palette) -> str:
    parts = [_css(palette), f"<h2>{_e(host.display_name)}</h2>"]
    parts.append(f"<p class='muted'>Status: {_e(host.status.state)}" + (f" ({_e(host.status.reason)})" if host.status.reason else "") + "</p>")
    addresses = [(a.address_type.upper(), a.address + (f"  {a.vendor}" if a.vendor else "")) for a in host.addresses]
    names = [(f"Hostname ({h.hostname_type})" if h.hostname_type else "Hostname", h.name) for h in host.hostnames]
    parts.append("<h3>Identity</h3>" + _rows(addresses + names))
    open_ports = len(host.open_ports)
    extra = ", ".join(f"{e.count} {e.state}" for e in host.extra_ports)
    parts.append("<h3>Ports</h3>" + _rows([
        ("Listed", len(host.ports)),
        ("Open", open_ports),
        ("Not shown", extra or None),
    ]))
    if host.os and (host.os.matches or host.os.fingerprints):
        rows = []
        for match in host.os.matches[:8]:
            classes = "; ".join(
                " ".join(p for p in (c.vendor, c.os_family, c.os_generation, c.os_type) if p) for c in match.classes
            )
            rows.append(f"<tr><td>{_e(match.accuracy)}%</td><td>{_e(match.name)}</td><td class='muted'>{_e(classes)}</td></tr>")
        parts.append("<h3>OS detection</h3>")
        parts.append("<p class='note'>Nmap's guesses with its own accuracy ratings.</p>")
        if rows:
            parts.append("<table><tr><th>Accuracy</th><th>Match</th><th>Classes</th></tr>" + "".join(rows) + "</table>")
        else:
            parts.append("<p class='muted'>No exact match. Nmap produced a fingerprint instead.</p>")
        cpes = sorted({cpe for m in host.os.matches for c in m.classes for cpe in c.cpe})
        if cpes:
            parts.append(_rows([("CPE", ", ".join(cpes))]))
    info = []
    if host.uptime:
        days = host.uptime.seconds / 86400
        info.append(("Uptime guess", f"{days:.1f} days (last boot {host.uptime.last_boot})" if host.uptime.last_boot else f"{days:.1f} days"))
    if host.distance is not None:
        info.append(("Network distance", f"{host.distance} hop{'s' if host.distance != 1 else ''}"))
    if host.sequences:
        info.append(("TCP sequence", host.sequences.tcp_sequence_difficulty))
        info.append(("IP ID sequence", host.sequences.ip_id_sequence_class))
    if host.times and host.times.srtt is not None:
        info.append(("Smoothed RTT", f"{host.times.srtt / 1000:.2f} ms"))
    if info:
        parts.append("<h3>Other observations</h3>" + _rows(info))
    if host.traceroute and host.traceroute.hops:
        hops = "".join(
            f"<tr><td>{h.ttl}</td><td>{_e(h.ip_address or '*')}</td><td>{_e(h.hostname or '')}</td><td>{'' if h.rtt is None else f'{h.rtt:.2f} ms'}</td></tr>"
            for h in host.traceroute.hops
        )
        parts.append("<h3>Traceroute</h3><table><tr><th>TTL</th><th>Address</th><th>Name</th><th>RTT</th></tr>" + hops + "</table>")
    if host.host_scripts:
        parts.append("<h3>Host script results</h3>" + _scripts(host.host_scripts))
    return "".join(parts)


def port_html(host: Host, port: Port, palette: Palette) -> str:
    state_class = port.state.split("|")[0]
    parts = [_css(palette), f"<h2>{_e(port.label)} on {_e(host.display_name)}</h2>"]
    parts.append(f"<p>State: <span class='{_e(state_class)}'>{_e(port.state)}</span>" + (f" <span class='muted'>({_e(port.reason)}" + (f", TTL {port.reason_ttl}" if port.reason_ttl is not None else "") + ")</span>" if port.reason else "") + "</p>")
    service = port.service
    if service:
        method = service.method
        method_note = None
        if method == "table":
            method_note = "Name taken from Nmap's port table, not confirmed by probing."
        elif method == "probed":
            method_note = f"Identified by probing (confidence {service.confidence}/10)." if service.confidence is not None else "Identified by probing."
        parts.append("<h3>Service</h3>" + _rows([
            ("Name", service.name),
            ("Product", service.product),
            ("Version", service.version),
            ("Extra info", service.extra_info),
            ("Tunnel", service.tunnel),
            ("OS type", service.os_type),
            ("Device type", service.device_type),
            ("Hostname", service.hostname),
            ("CPE", ", ".join(service.cpe) or None),
        ]))
        if method_note:
            parts.append(f"<p class='note'>{_e(method_note)}</p>")
        if service.service_fingerprint:
            parts.append("<h3>Service fingerprint</h3><pre>" + _e(service.service_fingerprint) + "</pre>")
    if port.owner:
        parts.append(_rows([("Owner", port.owner)]))
    if port.scripts:
        parts.append("<h3>Script results</h3>" + _scripts(port.scripts))
    return "".join(parts)
