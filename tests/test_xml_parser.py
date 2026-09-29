import pytest

from genmap.errors import XmlParseError
from genmap.nmap.xml_parser import parse_nmap_xml_file, parse_nmap_xml_string, salvage_truncated_xml


def test_real_localhost_scan(fixtures):
    result = parse_nmap_xml_file(fixtures / "localhost_syn_version_os.xml")
    assert result.nmap_version == "7.94SVN"
    assert result.statistics.exit_status == "success"
    assert not result.truncated
    host = result.hosts[0]
    assert host.primary_address == "127.0.0.1"
    assert host.primary_hostname == "localhost"
    port = host.open_ports[0]
    assert port.label == "8765/tcp"
    assert port.service.name == "http"
    assert port.service.product == "SimpleHTTPServer"
    assert {s.script_id for s in port.scripts} == {"http-server-header", "http-methods", "http-title"}
    assert host.best_os_match.name.startswith("Linux")
    assert host.sequences.tcp_sequence_difficulty == "Good luck!"


def test_multi_host_inventory(fixtures):
    result = parse_nmap_xml_file(fixtures / "lan_inventory.xml")
    assert len(result.hosts) == 4
    assert len(result.hosts_up) == 3
    assert result.total_open_ports == 6
    assert result.statistics.hosts_total == 8
    assert result.statistics.elapsed_seconds == pytest.approx(121.30)
    assert [(i.scan_type, i.protocol) for i in result.scan_infos] == [("syn", "tcp"), ("udp", "udp")]
    assert result.pre_scripts[0].script_id == "broadcast-dhcp-discover"
    assert result.post_scripts[0].script_id == "ssh-hostkey"

    router = result.hosts[0]
    assert router.mac_address.vendor == "MikroTik"
    assert router.distance == 1
    assert router.uptime.seconds == 1296412
    assert router.traceroute.hops[0].hostname == "gw.lab.internal"
    assert router.os.matches[0].accuracy == 100
    assert router.os.matches[0].classes[0].cpe == ["cpe:/o:mikrotik:routeros:6"]
    assert router.extra_ports[0].count == 3 and router.extra_ports[0].reasons == {"reset": 3}
    snmp = next(p for p in router.ports if p.port_id == 161)
    assert snmp.protocol == "udp" and snmp.state == "open|filtered"
    assert snmp.service.method == "table"
    assert router.host_scripts[0].structured == {"enterprise": "mikrotik", "engineIDFormat": "unknown"}

    files = result.hosts[1]
    ssh = files.ports[0]
    assert ssh.service.version == "8.9p1 Ubuntu 3ubuntu0.10"
    assert ssh.service.cpe == ["cpe:/a:openbsd:openssh:8.9p1", "cpe:/o:linux:linux_kernel"]
    keys = ssh.scripts[0].structured
    assert isinstance(keys, list) and keys[1]["type"] == "ssh-ed25519"
    assert files.host_scripts[0].structured == {"3:1:1": ["Message signing enabled but not required"]}
    assert "<unknown>" in files.host_scripts[1].output

    workstation = result.hosts[2]
    rdp = workstation.ports[1]
    assert rdp.port_id == 3389 and rdp.service.tunnel == "ssl"
    assert workstation.os is not None and workstation.os.matches == []

    assert result.hosts[3].status.state == "down"


def test_unknown_fields_are_preserved_not_fatal(fixtures):
    result = parse_nmap_xml_file(fixtures / "lan_inventory.xml")
    assert result.hosts[1].extra["futurefield"] == [{"flavour": "unknown-to-genmap"}]
    ds = next(p for p in result.hosts[2].ports if p.port_id == 445)
    assert ds.service.extra == {"newattribute": "kept"}


def test_ping_sweep_and_list_scan(fixtures):
    sweep = parse_nmap_xml_file(fixtures / "ping_sweep_loopback.xml")
    assert len(sweep.hosts) == 4
    assert all(host.ports == [] for host in sweep.hosts)
    listing = parse_nmap_xml_file(fixtures / "list_scan.xml")
    assert [h.primary_address for h in listing.hosts] == ["127.0.0.1", "10.9.9.9"]


def test_truncated_file_is_salvaged(fixtures):
    result = parse_nmap_xml_file(fixtures / "truncated_scan.xml")
    assert result.truncated
    assert [h.primary_address for h in result.hosts] == ["192.168.56.1", "192.168.56.5"]
    assert any("incomplete" in w for w in result.warnings)


def test_salvage_without_hosts_keeps_header():
    data = b'<?xml version="1.0"?><nmaprun scanner="nmap" version="7.95"><scaninfo type="syn" protocol="tcp"/><host><status state="u'
    salvaged = salvage_truncated_xml(data)
    result = parse_nmap_xml_string(salvaged.decode())
    assert result.truncated and result.hosts == [] and result.scan_infos[0].scan_type == "syn"


def test_entity_expansion_is_refused(fixtures):
    with pytest.raises(XmlParseError) as info:
        parse_nmap_xml_file(fixtures / "billion_laughs.xml")
    assert "not allowed" in info.value.message


def test_external_entities_are_refused():
    text = '<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///etc/passwd">]><nmaprun args="&x;"/>'
    with pytest.raises(XmlParseError):
        parse_nmap_xml_string(text)


def test_non_nmap_xml(fixtures):
    with pytest.raises(XmlParseError) as info:
        parse_nmap_xml_file(fixtures / "not_nmap.xml")
    assert "not Nmap output" in info.value.message


def test_empty_and_missing_files(tmp_path):
    empty = tmp_path / "empty.xml"
    empty.write_text("")
    with pytest.raises(XmlParseError):
        parse_nmap_xml_file(empty)
    with pytest.raises(XmlParseError):
        parse_nmap_xml_file(tmp_path / "missing.xml")


def test_garbage_is_reported_as_parse_error():
    with pytest.raises(XmlParseError):
        parse_nmap_xml_string("this is not xml")


def test_error_exit_status():
    text = (
        '<nmaprun scanner="nmap" version="7.95"><runstats>'
        '<finished time="1" elapsed="0.1" exit="error" errormsg="Failed to open device eth9"/>'
        '<hosts up="0" down="0" total="0"/></runstats></nmaprun>'
    )
    result = parse_nmap_xml_string(text)
    assert result.statistics.exit_status == "error"
    assert result.statistics.error_message == "Failed to open device eth9"
