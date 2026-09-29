from genmap.core.results import Address, Host, Hostname, HostStatus, Port, ScanResult, Service
from genmap.engine.run_store import summarize_result
from genmap.nmap.xml_parser import parse_nmap_xml_file


def test_host_display_prefers_ipv4_and_user_hostnames():
    host = Host(
        status=HostStatus(state="up"),
        addresses=[Address(address="aa:bb:cc:dd:ee:ff", address_type="mac"), Address(address="fe80::1", address_type="ipv6"), Address(address="10.0.0.5")],
        hostnames=[Hostname(name="ptr.example", hostname_type="PTR"), Hostname(name="given.example", hostname_type="user")],
    )
    assert host.primary_address == "10.0.0.5"
    assert host.primary_hostname == "given.example"
    assert host.display_name == "10.0.0.5 (given.example)"
    assert host.mac_address.address == "aa:bb:cc:dd:ee:ff"


def test_service_display_name():
    assert Service(name="http", product="nginx", version="1.24").display_name() == "nginx 1.24"
    assert Service(name="http").display_name() == "http"


def test_result_summary(fixtures):
    result = parse_nmap_xml_file(fixtures / "lan_inventory.xml")
    assert result.distinct_services == {"http", "domain", "ssh", "netbios-ssn", "ms-wbt-server", "microsoft-ds"}
    summary = summarize_result(result)
    assert (summary.hosts_total, summary.hosts_up, summary.open_ports) == (4, 3, 6)
    assert result.summary_line() == "3 hosts up, 6 open ports"


def test_normalized_result_serializes(fixtures):
    result = parse_nmap_xml_file(fixtures / "lan_inventory.xml")
    again = ScanResult.model_validate_json(result.model_dump_json())
    assert again == result


def test_open_ports_only_counts_open():
    host = Host(ports=[Port(protocol="tcp", port_id=1, state="open"), Port(protocol="udp", port_id=2, state="open|filtered")])
    assert [p.port_id for p in host.open_ports] == [1]


def test_port_table_guesses_are_not_identified_services():
    from genmap.core.results import ScanResult

    result = ScanResult(hosts=[Host(
        status=HostStatus(state="up"),
        ports=[
            Port(protocol="tcp", port_id=22, state="open", service=Service(name="ssh", method="probed", confidence=10)),
            Port(protocol="tcp", port_id=8080, state="open", service=Service(name="http-proxy", method="table", confidence=3)),
        ],
    )])
    assert result.distinct_services == {"ssh", "http-proxy"}
    assert result.identified_services == {"ssh"}
    assert summarize_result(result).services == 1
