import csv
import io
import json

import pytest

from genmap.core.results import Address, Host, HostStatus, Port, ScanResult, ScriptResult, Service
from genmap.core.scan_config import ScanConfiguration
from genmap.engine.run_store import RunStatus, RunStore, summarize_result
from genmap.nmap.xml_parser import parse_nmap_xml_file
from genmap.reporting import ReportOptions, ReportSource, generate_report, result_to_csv
from genmap.reporting.engine import ReportError


@pytest.fixture
def source(fixtures, tmp_path):
    xml = fixtures / "lan_inventory.xml"
    result = parse_nmap_xml_file(xml)
    store = RunStore(tmp_path / "scans")
    config = ScanConfiguration()
    config.targets.targets = ["192.168.56.0/29"]
    record = store.create(config, profile_name="Network inventory")
    record.status = RunStatus.COMPLETED
    record.exit_code = 0
    record.summary = summarize_result(result)
    return ReportSource(result=result, xml_path=xml, record=record)


def test_html_report_contents(source, tmp_path):
    path = generate_report(source, "html", tmp_path / "r.html", ReportOptions())
    text = path.read_text()
    assert text.startswith("<!doctype html>")
    assert "default-src 'none'" in text
    assert "<script" not in text.lower()
    for expected in ("Nmap scan of 192.168.56.0/29", "files.lab.internal", "OpenSSH", "ssh-hostkey", "MikroTik RouterOS 6.36", "Network inventory", "121.30 seconds"):
        assert expected in text
    assert "1 host reported as down is not listed" in text
    assert "does not rate risk" in text


def test_options_filter_content(source, tmp_path):
    lean = generate_report(source, "html", tmp_path / "lean.html", ReportOptions(include_script_output=False, include_configuration=False)).read_text()
    assert "ssh-hostkey" not in lean and "Scan configuration used by Genmap" not in lean
    full = generate_report(source, "html", tmp_path / "full.html", ReportOptions(include_closed_ports=True, include_down_hosts=True)).read_text()
    assert "192.168.56.2" in full and "state-closed" in full


def test_json_report(source, tmp_path):
    data = json.loads(generate_report(source, "json", tmp_path / "r.json").read_text())
    assert data["summary"]["hosts_up"] == 3 and data["summary"]["open_ports"] == 6
    assert data["summary"]["complete"] is True
    assert len(data["hosts"]) == 3
    assert data["configuration"]["targets"]["targets"] == ["192.168.56.0/29"]
    assert data["scan"]["Profile"] == "Network inventory"
    ports = [p["port_id"] for p in data["hosts"][1]["ports"]]
    assert 53 not in ports  # closed ports are excluded by default


def test_csv_report(source, tmp_path):
    rows = list(csv.DictReader(io.StringIO(generate_report(source, "csv", tmp_path / "r.csv").read_text())))
    assert {r["host"] for r in rows} == {"192.168.56.1", "192.168.56.5", "192.168.56.6"}
    assert all(r["state"] not in ("closed", "filtered") for r in rows)
    snmp = next(r for r in rows if r["port"] == "161")
    assert snmp["service_method"] == "table"
    everything = list(csv.DictReader(io.StringIO(result_to_csv(source.result))))
    assert len(everything) == 11


def test_xml_report_is_an_exact_copy(source, tmp_path, fixtures):
    path = generate_report(source, "xml", tmp_path / "copy.xml")
    assert path.read_bytes() == (fixtures / "lan_inventory.xml").read_bytes()
    missing = ReportSource(result=source.result, xml_path=None)
    with pytest.raises(ReportError):
        generate_report(missing, "xml", tmp_path / "x.xml")


def test_hostile_values_are_escaped(tmp_path):
    hostile = ScanResult(hosts=[Host(
        status=HostStatus(state="up"),
        addresses=[Address(address="10.0.0.9")],
        ports=[Port(
            protocol="tcp", port_id=80, state="open",
            service=Service(name="http", method="probed", product="<script>alert(1)</script>", extra_info="\"><img src=x onerror=alert(2)>"),
            scripts=[ScriptResult(script_id="http-title", output="</pre><iframe src=//evil></iframe>")],
        )],
    )])
    text = generate_report(ReportSource(hostile), "html", tmp_path / "h.html").read_text()
    assert "<script>alert(1)" not in text and "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert "<img src=x" not in text and "<iframe" not in text


def test_truncated_scan_is_flagged(fixtures, tmp_path):
    result = parse_nmap_xml_file(fixtures / "truncated_scan.xml")
    text = generate_report(ReportSource(result), "html", tmp_path / "t.html").read_text()
    assert "did not finish writing its output" in text
    data = json.loads(generate_report(ReportSource(result), "json", tmp_path / "t.json").read_text())
    assert data["summary"]["complete"] is False


def test_unwritable_destination(source, tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    with pytest.raises(ReportError):
        generate_report(source, "html", blocker / "sub" / "r.html")
    with pytest.raises(ReportError):
        generate_report(source, "pdf", tmp_path / "r.pdf")
