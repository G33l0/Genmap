import pytest

from genmap.core.ports import merge_port_specifications, parse_port_specification, validate_port_specification
from genmap.errors import PortSpecificationError


def test_simple_list_and_ranges():
    parsed = parse_port_specification("22,80,443,8000-8100")
    assert parsed.explicit_port_count == 3 + 101
    assert not parsed.uses_service_names


def test_open_ended_ranges():
    parsed = parse_port_specification("-100,60000-")
    assert [(r.start, r.end) for r in parsed.ranges] == [(1, 100), (60000, 65535)]


def test_protocol_prefixes_apply_until_changed():
    parsed = parse_port_specification("T:22,80,U:53,161,S:9")
    protocols = [(r.start, r.protocol) for r in parsed.ranges]
    assert protocols == [(22, "tcp"), (80, "tcp"), (53, "udp"), (161, "udp"), (9, "sctp")]
    assert parsed.protocols == {"tcp", "udp", "sctp"}


def test_service_names_and_wildcards():
    parsed = parse_port_specification("http*,ssh,U:snmp")
    assert [p.pattern for p in parsed.service_patterns] == ["http*", "ssh", "snmp"]
    assert parsed.service_patterns[-1].protocol == "udp"


def test_normalized_output_preserves_order():
    assert parse_port_specification("http,U:53,T:22-25,ssh").normalized() == "http,U:53,T:22-25,ssh"


def test_protocol_scan_upper_bound():
    parse_port_specification("1,6,17", protocol_scan=True)
    with pytest.raises(PortSpecificationError):
        parse_port_specification("300", protocol_scan=True)


@pytest.mark.parametrize(
    "spec",
    ["", "80,,443", "70000", "100-50", "22, 80", "T:", "80;ls", "1-2-3", "abc$"],
)
def test_invalid_specifications(spec):
    with pytest.raises(PortSpecificationError):
        parse_port_specification(spec)


def test_validate_returns_trimmed():
    assert validate_port_specification("  22,80 ") == "22,80"


def test_merge():
    assert merge_port_specifications(["22,80", "80,443"]) == "22,80,443"
