import pytest

from genmap.core.targets import TargetKind, estimate_host_count, parse_target, parse_targets, split_target_text
from genmap.errors import TargetError


@pytest.mark.parametrize(
    "text, kind, hosts",
    [
        ("192.168.1.10", TargetKind.IPV4, 1),
        ("2001:db8::1", TargetKind.IPV6, 1),
        ("fe80::1%eth0", None, None),
        ("10.0.0.0/24", TargetKind.IPV4_NETWORK, 256),
        ("10.0.0.5/24", TargetKind.IPV4_NETWORK, 256),
        ("2001:db8::/120", TargetKind.IPV6_NETWORK, 256),
        ("scanme.nmap.org", TargetKind.HOSTNAME, 1),
        ("localhost", TargetKind.HOSTNAME, 1),
        ("files.lab.internal.", TargetKind.HOSTNAME, 1),
        ("example.com/30", TargetKind.HOSTNAME_NETWORK, 4),
        ("10.0.0-3.1-254", TargetKind.IPV4_OCTET_RANGE, 4 * 254),
        ("192.168.1.*", TargetKind.IPV4_OCTET_RANGE, 256),
        ("192.168.1.1,5,9", TargetKind.IPV4_OCTET_RANGE, 3),
    ],
)
def test_parse_valid_targets(text, kind, hosts):
    if kind is None:
        # Scoped IPv6 addresses are valid for Nmap but contain a %, which the
        # Python ipaddress module also accepts from 3.9 onwards.
        target = parse_target(text)
        assert target.kind == TargetKind.IPV6
        return
    target = parse_target(text)
    assert target.kind == kind
    assert target.estimated_hosts == hosts


@pytest.mark.parametrize(
    "text",
    [
        "",
        "   ",
        "256.1.1.1",
        "1.2.3",
        "10.0.0.0/33",
        "10.0.0.0/abc",
        "-sV",
        "host;rm -rf /",
        "$(whoami)",
        "a b",
        "10.0.0.300-400",
        "10.0.0.20-10",
        "2001:db8:::1",
        "bad_-host-.com",
        "10.0.0-3.1/24",
    ],
)
def test_parse_invalid_targets(text):
    with pytest.raises(TargetError):
        parse_target(text)


def test_error_messages_are_readable():
    with pytest.raises(TargetError) as info:
        parse_target("-oN")
    assert "dash" in info.value.message


def test_split_and_deduplicate():
    assert split_target_text("a.com, b.com\n10.0.0.1  10.0.0.2") == ["a.com", "b.com", "10.0.0.1", "10.0.0.2"]
    targets = parse_targets("10.0.0.1, 10.0.0.1 10.0.0.2")
    assert [t.raw for t in targets] == ["10.0.0.1", "10.0.0.2"]


def test_estimate_host_count():
    assert estimate_host_count(parse_targets("10.0.0.0/30 10.0.1.1")) == 5
    assert estimate_host_count([]) == 0
