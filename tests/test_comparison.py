import pytest

from genmap.core.comparison import ChangeKind, ScanSide, compare_scans, covered_ports, mask_volatile, side_from, summarize
from genmap.core.results import Address, Host, HostStatus, Port, ScanInfo, ScanResult, ScriptResult, Service
from genmap.core.targets import address_in_scope
from genmap.nmap.xml_parser import parse_nmap_xml_file

LAB = {"targets": {"targets": ["192.168.56.0/29"]}}
LATER = {"targets": {"targets": ["192.168.56.0/29", "10.9.9.9"]}}


@pytest.fixture
def scans(fixtures):
    return parse_nmap_xml_file(fixtures / "lan_inventory.xml"), parse_nmap_xml_file(fixtures / "lan_inventory_later.xml")


def kinds(result, address):
    host = next(h for h in result.hosts if h.address == address)
    return {(c.kind, c.subject) for c in host.changes}


def test_identical_scans_have_no_changes(scans):
    baseline, _ = scans
    result = compare_scans(side_from(baseline, "a", LAB), side_from(baseline, "b", LAB))
    assert not result.has_changes and result.notes == []
    assert all(h.status == "unchanged" for h in result.hosts)


def test_realistic_changes_are_found(scans):
    baseline, later = scans
    result = compare_scans(side_from(baseline, "baseline", LAB), side_from(later, "later", LATER))
    assert summarize(result) == {
        "new_hosts": 1, "missing_hosts": 1, "changed_hosts": 2, "unchanged_hosts": 0, "out_of_scope_hosts": 1,
        "ports_opened": 1, "ports_no_longer_open": 1, "service_changes": 2, "os_changes": 0, "script_changes": 2,
    }
    assert kinds(result, "192.168.56.1") == {
        (ChangeKind.VERSION_CHANGED, "80/tcp"), (ChangeKind.PORT_OPENED, "443/tcp"), (ChangeKind.PORT_STATE, "161/udp"),
    }
    files = kinds(result, "192.168.56.5")
    assert (ChangeKind.VERSION_CHANGED, "22/tcp") in files
    assert (ChangeKind.PORT_NO_LONGER_OPEN, "445/tcp") in files
    assert (ChangeKind.SCRIPT_CHANGED, "nbstat") in files
    closed = next(c for c in result.changes() if c.subject == "445/tcp")
    assert closed.after.startswith("closed (among 3 ports")


def test_scope_prevents_false_new_and_missing_hosts(scans):
    baseline, later = scans
    result = compare_scans(side_from(baseline, "baseline", LAB), side_from(later, "later", LATER))
    outsider = next(h for h in result.hosts if h.address == "10.9.9.9")
    assert outsider.status == "out_of_scope" and not outsider.significant_changes
    narrowed = compare_scans(side_from(baseline, "baseline", LAB), side_from(later, "later", {"targets": {"targets": ["192.168.56.5"]}}))
    router = next(h for h in narrowed.hosts if h.address == "192.168.56.1")
    assert router.status in ("changed", "unchanged")  # present in both, compared normally
    no_router_scan = side_from(later, "later", {"targets": {"targets": ["192.168.56.4/30"]}})
    no_router_scan.result = later.model_copy(deep=True)
    no_router_scan.result.hosts = [h for h in later.hosts if h.primary_address != "192.168.56.1"]
    result = compare_scans(side_from(baseline, "baseline", LAB), no_router_scan)
    router = next(h for h in result.hosts if h.address == "192.168.56.1")
    assert router.status == "out_of_scope"  # not missing: the later scan never targeted it


def test_unknown_scope_is_stated_not_assumed(scans):
    baseline, later = scans
    result = compare_scans(ScanSide(baseline, "baseline"), ScanSide(later, "later"))
    new = next(h for h in result.hosts if h.address == "192.168.56.7")
    assert new.status == "new" and "could not be checked" in new.changes[0].reading
    assert any("target list of at least one scan is unknown" in n for n in result.notes)


def test_ports_outside_either_scan_are_informational(scans):
    baseline, later = scans
    result = compare_scans(side_from(baseline, "a", LAB), side_from(later, "b", LATER))
    change = next(c for c in result.changes(include_informational=True) if c.subject == "8080/tcp")
    assert change.kind == ChangeKind.PORT_NOT_COVERED and not change.significant
    assert any("probed different TCP ports" in n for n in result.notes)


def test_covered_ports_from_scaninfo(scans):
    baseline, later = scans
    assert covered_ports(baseline) == {"tcp": {22, 80, 443, 445, 3389}, "udp": {53, 161}}
    assert 8080 in covered_ports(later)["tcp"]
    assert covered_ports(ScanResult()) == {}


def _host(address, ports, scripts=(), host_scripts=(), extra=()):
    return Host(
        status=HostStatus(state="up"),
        addresses=[Address(address=address)],
        ports=list(ports),
        host_scripts=list(host_scripts),
        extra_ports=list(extra),
    )


def _result(*hosts, services="22,80"):
    return ScanResult(scan_infos=[ScanInfo(scan_type="syn", protocol="tcp", services=services)], hosts=list(hosts))


def test_table_names_are_not_compared_with_probed_names():
    before = _host("10.0.0.1", [Port(protocol="tcp", port_id=80, state="open", service=Service(name="http", method="table"))])
    after = _host("10.0.0.1", [Port(protocol="tcp", port_id=80, state="open", service=Service(name="http-proxy", product="Squid", method="probed"))])
    result = compare_scans(ScanSide(_result(before), "a", ["10.0.0.1"]), ScanSide(_result(after), "b", ["10.0.0.1"]))
    change = result.changes(include_informational=True)[0]
    assert change.kind == ChangeKind.SERVICE_UNCONFIRMED and not result.has_changes


def test_timestamps_in_script_output_are_ignored():
    def with_time(stamp):
        return _host("10.0.0.1", [], host_scripts=[ScriptResult(script_id="smb2-time", output=f"\n  date: {stamp}\n  start_date: N/A")])

    a = _result(with_time("2025-03-11T09:15:10"))
    b = _result(with_time("2025-03-18T11:02:44"))
    result = compare_scans(ScanSide(a, "a", ["10.0.0.1"]), ScanSide(b, "b", ["10.0.0.1"]))
    assert not result.has_changes
    assert mask_volatile("Server time: Tue, 18 Mar 2025 09:15:10 GMT; took 3.2s") == mask_volatile("Server time: Wed, 19 Mar 2025 10:00:00 GMT; took 12s")
    assert mask_volatile("SSH-2.0-OpenSSH_9.6") != mask_volatile("SSH-2.0-OpenSSH_8.9")


def test_scripts_not_compared_when_one_scan_ran_none():
    with_script = _host("10.0.0.1", [], host_scripts=[ScriptResult(script_id="nbstat", output="NetBIOS name: A")])
    without = _host("10.0.0.1", [])
    result = compare_scans(ScanSide(_result(with_script), "a", ["10.0.0.1"]), ScanSide(_result(without), "b", ["10.0.0.1"]))
    assert not result.has_changes
    assert any("Only one of the scans produced NSE output" in n for n in result.notes)


def test_ping_scans_do_not_report_ports():
    a = ScanResult(hosts=[_host("10.0.0.1", [Port(protocol="tcp", port_id=22, state="open")])])
    b = ScanResult(hosts=[_host("10.0.0.1", [])])
    result = compare_scans(ScanSide(a, "a", ["10.0.0.1"]), ScanSide(b, "b", ["10.0.0.1"]))
    assert not result.has_changes
    assert any("did not scan ports" in n for n in result.notes)


def test_mac_change_is_reported():
    a = _host("10.0.0.1", [])
    a.addresses.append(Address(address="00:11:22:33:44:55", address_type="mac", vendor="Dell"))
    b = _host("10.0.0.1", [])
    b.addresses.append(Address(address="66:77:88:99:AA:BB", address_type="mac", vendor="HP"))
    result = compare_scans(ScanSide(_result(a), "a", ["10.0.0.1"]), ScanSide(_result(b), "b", ["10.0.0.1"]))
    assert [c.kind for c in result.changes()] == [ChangeKind.MAC_CHANGED]


def test_file_based_targets_mean_unknown_scope():
    side = side_from(ScanResult(), "x", {"targets": {"targets": [], "target_file": "hosts.txt"}})
    assert side.targets is None


@pytest.mark.parametrize(
    "address, targets, exclusions, names, expected",
    [
        ("10.0.0.5", ["10.0.0.0/24"], [], [], True),
        ("10.0.1.5", ["10.0.0.0/24"], [], [], False),
        ("10.0.0.5", ["10.0.0.0/24"], ["10.0.0.5"], [], False),
        ("10.0.3.7", ["10.0.0-3.1-10"], [], [], True),
        ("10.0.4.7", ["10.0.0-3.1-10"], [], [], False),
        ("10.0.0.5", ["files.lab"], [], [], None),
        ("10.0.0.5", ["files.lab"], [], ["FILES.lab."], True),
        ("2001:db8::5", ["2001:db8::/64"], [], [], True),
        ("10.0.0.5", ["2001:db8::/64", "10.0.0.5"], [], [], True),
    ],
)
def test_address_in_scope(address, targets, exclusions, names, expected):
    assert address_in_scope(address, targets, exclusions, names) is expected


def test_comparison_export_escapes_scanned_content(tmp_path):
    import json

    from genmap.core.comparison import Change, ComparisonResult, HostComparison
    from genmap.reporting.comparison import export_comparison, render_comparison_html

    hostile = "<img src=x onerror=alert(1)>"
    change = Change(ChangeKind.SCRIPT_CHANGED, "10.0.0.1", "http-title on 80/tcp", hostile, "<script>x</script>", "reading")
    result = ComparisonResult("a<b", "c", [HostComparison("10.0.0.1", "10.0.0.1", "changed", [change])], ["note <i>"])
    page = render_comparison_html(result)
    assert "<img src=x" not in page and "<script>x" not in page and "note <i>" not in page
    assert "default-src 'none'" in page
    path = export_comparison(result, "json", tmp_path / "c.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["hosts"][0]["changes"][0]["nmap_reported"]["baseline"] == hostile
    assert data["hosts"][0]["changes"][0]["genmap_reading"] == "reading"
