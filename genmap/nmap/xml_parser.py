"""Parsing of Nmap XML output into normalised result models.

defusedxml protects against entity expansion and external entity attacks
in case a result file was tampered with. The parser tolerates unknown
elements and attributes (they are preserved in ``extra`` dictionaries where
useful) and can salvage a truncated file left behind by a cancelled or
crashed scan.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from xml.etree.ElementTree import Element

from defusedxml import ElementTree as SafeElementTree
from defusedxml.common import DefusedXmlException

from genmap.core.results import (
    Address,
    ExtraPorts,
    Host,
    HostStatus,
    HostTimes,
    Hostname,
    OsClass,
    OsDetection,
    OsMatch,
    OsPortUsed,
    Port,
    RunStatistics,
    ScanInfo,
    ScanResult,
    ScriptResult,
    SequenceInfo,
    Service,
    Traceroute,
    TracerouteHop,
    Uptime,
)
from genmap.errors import XmlParseError

_SERVICE_KNOWN_ATTRS = {
    "name",
    "product",
    "version",
    "extrainfo",
    "method",
    "conf",
    "tunnel",
    "ostype",
    "devicetype",
    "hostname",
    "servicefp",
    "proto",
    "rpcnum",
    "lowver",
    "highver",
}


def _int(value: Optional[str]) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        try:
            return int(float(value))
        except ValueError:
            return None


def _float(value: Optional[str]) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _timestamp(value: Optional[str]) -> Optional[datetime]:
    number = _int(value)
    if number is None or number <= 0:
        return None
    try:
        return datetime.fromtimestamp(number, tz=timezone.utc).astimezone()
    except (OverflowError, OSError, ValueError):
        return None


def _script_structure(element: Element) -> dict[str, Any] | list[Any] | None:
    """Convert nested <table>/<elem> children into plain Python structures."""
    children = [child for child in element if child.tag in ("table", "elem")]
    if not children:
        return None
    keyed = all(child.get("key") is not None for child in children)
    if keyed:
        result: dict[str, Any] = {}
        for child in children:
            key = child.get("key", "")
            result[key] = _script_structure(child) if child.tag == "table" else (child.text or "")
        return result
    items: list[Any] = []
    for child in children:
        if child.tag == "table":
            items.append(_script_structure(child))
        else:
            items.append(child.text or "")
    return items


def _parse_script(element: Element) -> ScriptResult:
    return ScriptResult(
        script_id=element.get("id", "unknown"),
        output=(element.get("output") or "").strip("\n"),
        structured=_script_structure(element),
    )


def _parse_service(element: Optional[Element]) -> Optional[Service]:
    if element is None:
        return None
    extra = {k: v for k, v in element.attrib.items() if k not in _SERVICE_KNOWN_ATTRS}
    return Service(
        name=element.get("name"),
        product=element.get("product"),
        version=element.get("version"),
        extra_info=element.get("extrainfo"),
        method=element.get("method"),
        confidence=_int(element.get("conf")),
        tunnel=element.get("tunnel"),
        os_type=element.get("ostype"),
        device_type=element.get("devicetype"),
        hostname=element.get("hostname"),
        service_fingerprint=element.get("servicefp"),
        cpe=[cpe.text.strip() for cpe in element.findall("cpe") if cpe.text],
        extra=extra,
    )


def _parse_port(element: Element) -> Port:
    state = element.find("state")
    owner = element.find("owner")
    return Port(
        protocol=element.get("protocol", "tcp"),
        port_id=_int(element.get("portid")) or 0,
        state=state.get("state", "unknown") if state is not None else "unknown",
        reason=state.get("reason") if state is not None else None,
        reason_ttl=_int(state.get("reason_ttl")) if state is not None else None,
        reason_ip=state.get("reason_ip") if state is not None else None,
        service=_parse_service(element.find("service")),
        scripts=[_parse_script(s) for s in element.findall("script")],
        owner=owner.get("name") if owner is not None else None,
    )


def _parse_os(element: Optional[Element]) -> Optional[OsDetection]:
    if element is None:
        return None
    detection = OsDetection()
    for used in element.findall("portused"):
        detection.ports_used.append(
            OsPortUsed(
                state=used.get("state", ""),
                protocol=used.get("proto", ""),
                port_id=_int(used.get("portid")) or 0,
            )
        )
    for match in element.findall("osmatch"):
        classes = [
            OsClass(
                os_type=cls.get("type"),
                vendor=cls.get("vendor"),
                os_family=cls.get("osfamily"),
                os_generation=cls.get("osgen"),
                accuracy=_int(cls.get("accuracy")),
                cpe=[c.text.strip() for c in cls.findall("cpe") if c.text],
            )
            for cls in match.findall("osclass")
        ]
        detection.matches.append(
            OsMatch(
                name=match.get("name", "Unknown"),
                accuracy=_int(match.get("accuracy")),
                line=_int(match.get("line")),
                classes=classes,
            )
        )
    for fingerprint in element.findall("osfingerprint"):
        text = fingerprint.get("fingerprint")
        if text:
            detection.fingerprints.append(text)
    return detection


def _parse_trace(element: Optional[Element]) -> Optional[Traceroute]:
    if element is None:
        return None
    trace = Traceroute(port=_int(element.get("port")), protocol=element.get("proto"))
    for hop in element.findall("hop"):
        trace.hops.append(
            TracerouteHop(
                ttl=_int(hop.get("ttl")) or 0,
                ip_address=hop.get("ipaddr"),
                rtt=_float(hop.get("rtt")),
                hostname=hop.get("host"),
            )
        )
    return trace


def _parse_host(element: Element) -> Host:
    status = element.find("status")
    host = Host(
        status=HostStatus(
            state=status.get("state", "unknown") if status is not None else "unknown",
            reason=status.get("reason") if status is not None else None,
            reason_ttl=_int(status.get("reason_ttl")) if status is not None else None,
        ),
        start_time=_timestamp(element.get("starttime")),
        end_time=_timestamp(element.get("endtime")),
        comment=element.get("comment"),
    )
    for address in element.findall("address"):
        host.addresses.append(
            Address(
                address=address.get("addr", ""),
                address_type=address.get("addrtype", "ipv4"),
                vendor=address.get("vendor"),
            )
        )
    hostnames = element.find("hostnames")
    if hostnames is not None:
        for hostname in hostnames.findall("hostname"):
            name = hostname.get("name")
            if name:
                host.hostnames.append(Hostname(name=name, hostname_type=hostname.get("type")))

    ports = element.find("ports")
    if ports is not None:
        for extra in ports.findall("extraports"):
            reasons = {
                r.get("reason", "unknown"): _int(r.get("count")) or 0
                for r in extra.findall("extrareasons")
            }
            host.extra_ports.append(
                ExtraPorts(state=extra.get("state", "unknown"), count=_int(extra.get("count")) or 0, reasons=reasons)
            )
        for port in ports.findall("port"):
            host.ports.append(_parse_port(port))
    host.ports.sort(key=lambda p: (p.protocol, p.port_id))

    host.os = _parse_os(element.find("os"))

    uptime = element.find("uptime")
    if uptime is not None and _int(uptime.get("seconds")) is not None:
        host.uptime = Uptime(seconds=_int(uptime.get("seconds")) or 0, last_boot=uptime.get("lastboot"))

    distance = element.find("distance")
    if distance is not None:
        host.distance = _int(distance.get("value"))

    tcp_seq = element.find("tcpsequence")
    ipid = element.find("ipidsequence")
    tcpts = element.find("tcptssequence")
    if any(e is not None for e in (tcp_seq, ipid, tcpts)):
        host.sequences = SequenceInfo(
            tcp_sequence_index=_int(tcp_seq.get("index")) if tcp_seq is not None else None,
            tcp_sequence_difficulty=tcp_seq.get("difficulty") if tcp_seq is not None else None,
            ip_id_sequence_class=ipid.get("class") if ipid is not None else None,
            tcp_timestamp_class=tcpts.get("class") if tcpts is not None else None,
        )

    hostscript = element.find("hostscript")
    if hostscript is not None:
        host.host_scripts = [_parse_script(s) for s in hostscript.findall("script")]

    host.traceroute = _parse_trace(element.find("trace"))

    times = element.find("times")
    if times is not None:
        host.times = HostTimes(
            srtt=_int(times.get("srtt")),
            rtt_variance=_int(times.get("rttvar")),
            timeout=_int(times.get("to")),
        )

    known = {
        "status", "address", "hostnames", "ports", "os", "uptime", "distance", "tcpsequence",
        "ipidsequence", "tcptssequence", "hostscript", "trace", "times", "smurf",
    }
    for child in element:
        if child.tag not in known:
            host.extra.setdefault(child.tag, []).append(dict(child.attrib))
    return host


def parse_nmap_xml_string(text: str) -> ScanResult:
    """Parse XML text. Raises XmlParseError when the document is unusable."""
    try:
        root = SafeElementTree.fromstring(text)
    except DefusedXmlException as exc:
        raise XmlParseError(
            "The Nmap XML contains constructs that are not allowed for safety reasons.",
            details=str(exc),
        ) from exc
    except Exception as exc:  # ParseError and friends
        raise XmlParseError(
            "The Nmap XML output is not well formed.",
            remedy="The scan may have been interrupted before Nmap finished writing its output.",
            details=str(exc),
        ) from exc
    return _parse_root(root)


def _parse_root(root: Element) -> ScanResult:
    if root.tag != "nmaprun":
        raise XmlParseError(
            "The file is XML but not Nmap output.",
            details=f"Root element is <{root.tag}>, expected <nmaprun>.",
        )
    result = ScanResult(
        scanner=root.get("scanner", "nmap"),
        nmap_version=root.get("version"),
        xml_output_version=root.get("xmloutputversion"),
        command_line=root.get("args"),
        started_at=_timestamp(root.get("start")),
    )
    for info in root.findall("scaninfo"):
        result.scan_infos.append(
            ScanInfo(
                scan_type=info.get("type", ""),
                protocol=info.get("protocol", ""),
                number_of_services=_int(info.get("numservices")),
                services=info.get("services"),
                scan_flags=info.get("scanflags"),
            )
        )
    verbose = root.find("verbose")
    debugging = root.find("debugging")
    result.verbosity = _int(verbose.get("level")) if verbose is not None else None
    result.debugging = _int(debugging.get("level")) if debugging is not None else None

    for pre in root.findall("prescript"):
        result.pre_scripts.extend(_parse_script(s) for s in pre.findall("script"))
    for post in root.findall("postscript"):
        result.post_scripts.extend(_parse_script(s) for s in post.findall("script"))

    for host in root.findall("host"):
        result.hosts.append(_parse_host(host))

    for output in root.findall("output"):
        if output.text and output.text.strip():
            result.warnings.append(output.text.strip())

    stats = root.find("runstats")
    if stats is not None:
        finished = stats.find("finished")
        hosts = stats.find("hosts")
        result.statistics = RunStatistics(
            hosts_up=_int(hosts.get("up")) or 0 if hosts is not None else 0,
            hosts_down=_int(hosts.get("down")) or 0 if hosts is not None else 0,
            hosts_total=_int(hosts.get("total")) or 0 if hosts is not None else 0,
            elapsed_seconds=_float(finished.get("elapsed")) if finished is not None else None,
            summary=finished.get("summary") if finished is not None else None,
            exit_status=finished.get("exit") if finished is not None else None,
            error_message=finished.get("errormsg") if finished is not None else None,
            finished_at=_timestamp(finished.get("time")) if finished is not None else None,
        )
    else:
        result.truncated = True
        up = sum(1 for h in result.hosts if h.is_up)
        result.statistics = RunStatistics(hosts_up=up, hosts_total=len(result.hosts))
    return result


_HOST_CLOSE = re.compile(rb"</host>\s*")


def salvage_truncated_xml(data: bytes) -> Optional[bytes]:
    """Try to close an XML document Nmap did not finish writing.

    Nmap flushes complete <host> elements as it goes, so cutting after the
    last one and closing <nmaprun> recovers everything that was finished.
    """
    if b"<nmaprun" not in data:
        return None
    if b"</nmaprun>" in data:
        return data
    matches = list(_HOST_CLOSE.finditer(data))
    if matches:
        cut = matches[-1].end()
        return data[:cut] + b"\n</nmaprun>\n"
    # No hosts finished; keep the header if the <nmaprun> tag itself is complete.
    header_end = data.find(b">", data.find(b"<nmaprun"))
    if header_end == -1:
        return None
    tail = data[header_end + 1 :]
    # Drop any partially written element after the header.
    partial = tail.rfind(b"<")
    if partial != -1 and tail.rfind(b">") < partial:
        tail = tail[:partial]
    # Keep only complete top level children by removing anything after the last '>'.
    last_close = tail.rfind(b">")
    tail = tail[: last_close + 1] if last_close != -1 else b""
    return data[: header_end + 1] + tail + b"\n</nmaprun>\n"


def parse_nmap_xml_file(path: Path) -> ScanResult:
    """Parse a file, salvaging truncated output when necessary."""
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise XmlParseError(f"Could not read {path.name}.", details=str(exc)) from exc
    if not data.strip():
        raise XmlParseError(
            "Nmap did not write any XML output.",
            remedy="Check the scan output for the error Nmap reported before it stopped.",
        )
    try:
        return parse_nmap_xml_string(data.decode("utf-8", errors="replace"))
    except XmlParseError as first_error:
        salvaged = salvage_truncated_xml(data)
        if salvaged is None or salvaged == data:
            raise first_error
        try:
            result = parse_nmap_xml_string(salvaged.decode("utf-8", errors="replace"))
        except XmlParseError:
            raise first_error
        result.truncated = True
        result.warnings.append(
            "The XML output was incomplete; results were recovered from the hosts Nmap finished."
        )
        return result
