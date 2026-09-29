from pathlib import Path

import pytest

from genmap.core.scan_config import (
    ArpPingMode,
    DnsResolutionMode,
    PortSelectionMode,
    ScanConfiguration,
    ScanMode,
    ScriptArgument,
    SctpScanTechnique,
    TcpScanTechnique,
)
from genmap.errors import ArgumentError
from genmap.nmap.command_builder import build_command_plan, build_targets, build_user_arguments, format_command

NMAP = Path("/usr/bin/nmap")


def args_of(config: ScanConfiguration) -> list[str]:
    return build_user_arguments(config)[0]


def base() -> ScanConfiguration:
    config = ScanConfiguration()
    config.targets.targets = ["192.168.1.0/24"]
    config.output.verbosity = 0
    return config


def test_default_configuration_adds_no_scan_flag():
    assert args_of(base()) == []


@pytest.mark.parametrize(
    "technique, flag",
    [
        (TcpScanTechnique.SYN, "-sS"),
        (TcpScanTechnique.CONNECT, "-sT"),
        (TcpScanTechnique.ACK, "-sA"),
        (TcpScanTechnique.WINDOW, "-sW"),
        (TcpScanTechnique.MAIMON, "-sM"),
        (TcpScanTechnique.FIN, "-sF"),
        (TcpScanTechnique.NULL, "-sN"),
        (TcpScanTechnique.XMAS, "-sX"),
    ],
)
def test_tcp_techniques(technique, flag):
    config = base()
    config.techniques.tcp = technique
    assert args_of(config) == [flag]


def test_special_techniques_carry_their_values():
    config = base()
    config.techniques.tcp = TcpScanTechnique.IDLE
    config.techniques.idle_zombie = "10.0.0.9:80"
    assert args_of(config) == ["-sI", "10.0.0.9:80"]
    config.techniques.tcp = TcpScanTechnique.CUSTOM_FLAGS
    config.techniques.custom_tcp_flags = "SYNFIN"
    assert args_of(config) == ["--scanflags", "SYNFIN"]
    config.techniques.tcp = TcpScanTechnique.FTP_BOUNCE
    config.techniques.ftp_bounce_relay = "anonymous:x@ftp.example.com"
    assert args_of(config) == ["-b", "anonymous:x@ftp.example.com"]


def test_combined_protocols():
    config = base()
    config.techniques.tcp = TcpScanTechnique.SYN
    config.techniques.udp = True
    config.techniques.sctp = SctpScanTechnique.INIT
    config.techniques.ip_protocol = True
    assert args_of(config) == ["-sS", "-sU", "-sY", "-sO"]


def test_modes_suppress_port_options():
    config = base()
    config.techniques.mode = ScanMode.PING_ONLY
    config.ports.mode = PortSelectionMode.ALL
    assert args_of(config) == ["-sn"]
    config.techniques.mode = ScanMode.LIST_ONLY
    assert args_of(config) == ["-sL"]


@pytest.mark.parametrize(
    "mode, expected",
    [
        (PortSelectionMode.ALL, ["-p-"]),
        (PortSelectionMode.FAST, ["-F"]),
        (PortSelectionMode.TOP, ["--top-ports", "250"]),
        (PortSelectionMode.SPECIFIC, ["-p", "T:22,U:53"]),
    ],
)
def test_port_modes(mode, expected):
    config = base()
    config.ports.mode = mode
    config.ports.top_ports = 250
    config.ports.specification = "T:22,U:53"
    assert args_of(config) == expected


def test_port_refinements():
    config = base()
    config.ports.exclude_ports = "9100"
    config.ports.sequential = True
    assert args_of(config) == ["--exclude-ports", "9100", "-r"]


def test_discovery_probes_are_attached_to_flags():
    config = base()
    d = config.discovery
    d.icmp_echo = True
    d.icmp_timestamp = True
    d.tcp_syn_ports = "22,443"
    d.tcp_ack_ports = "80"
    d.udp_ports = "53"
    d.sctp_ports = "80"
    d.ip_protocols = "1,2"
    d.arp_ping = ArpPingMode.DISABLED
    d.traceroute = True
    assert args_of(config) == ["-PE", "-PP", "-PS22,443", "-PA80", "-PU53", "-PY80", "-PO1,2", "--disable-arp-ping", "--traceroute"]


def test_skip_discovery_wins_over_probes():
    config = base()
    config.discovery.skip_discovery = True
    config.discovery.icmp_echo = True
    assert args_of(config) == ["-Pn"]


def test_dns():
    config = base()
    config.dns.resolution = DnsResolutionMode.NEVER
    config.dns.servers = ["1.1.1.1", "9.9.9.9"]
    config.dns.use_system_resolver = True
    assert args_of(config) == ["-n", "--dns-servers", "1.1.1.1,9.9.9.9", "--system-dns"]


def test_aggressive_does_not_duplicate_detection_flags():
    config = base()
    config.aggressive = True
    config.service_detection.enabled = True
    config.service_detection.intensity = 5
    config.os_detection.enabled = True
    assert args_of(config) == ["-A", "--version-intensity", "5"]


def test_detection_flags():
    config = base()
    config.service_detection.enabled = True
    config.service_detection.intensity = 2
    config.os_detection.enabled = True
    config.os_detection.limit_to_promising = True
    config.os_detection.max_tries = 3
    assert args_of(config) == ["-sV", "--version-intensity", "2", "-O", "--osscan-limit", "--max-os-tries", "3"]


def test_intensity_ignored_without_detection():
    config = base()
    config.service_detection.intensity = 9
    assert args_of(config) == []


def test_script_arguments_are_quoted_when_needed():
    config = base()
    config.scripts.scripts = ["default", "http-* and not http-brute"]
    config.scripts.arguments = [
        ScriptArgument(name="http.useragent", value="Mozilla/5.0 (Genmap, test)"),
        ScriptArgument(name="vulns.showall"),
        ScriptArgument(name="path", value='C:\\tmp\\"x"'),
    ]
    config.scripts.timeout = "2m"
    args = args_of(config)
    assert args[0] == "--script=default,http-* and not http-brute"
    assert args[1] == '--script-args=http.useragent="Mozilla/5.0 (Genmap, test)",vulns.showall,path="C:\\\\tmp\\\\\\"x\\""'
    assert args[2:] == ["--script-timeout", "2m"]


def test_timing():
    config = base()
    t = config.timing
    t.template = 4
    t.host_timeout = "30m"
    t.max_retries = 0
    t.min_rate = 100
    t.max_rate = 500
    t.defeat_rst_ratelimit = True
    assert args_of(config) == ["-T4", "--host-timeout", "30m", "--max-retries", "0", "--min-rate", "100", "--max-rate", "500", "--defeat-rst-ratelimit"]


def test_evasion():
    config = base()
    e = config.evasion
    e.fragment_packets = 2
    e.decoys = ["RND:3", "ME"]
    e.source_port = 53
    e.data_length = 24
    e.ttl = 64
    e.spoof_mac = "0"
    e.bad_checksum = True
    assert args_of(config) == ["-f", "-f", "-D", "RND:3,ME", "-g", "53", "--data-length", "24", "--ttl", "64", "--spoof-mac", "0", "--badsum"]


def test_network_and_output():
    config = base()
    config.network.ipv6 = True
    config.network.interface = "eth0"
    config.network.privileged = False
    config.output.verbosity = 2
    config.output.debugging = 1
    config.output.show_reason = True
    config.output.open_only = True
    assert args_of(config) == ["-6", "-e", "eth0", "--unprivileged", "-vv", "-d", "--reason", "--open"]


def test_advanced_arguments_are_appended_not_discarded():
    config = base()
    config.advanced_arguments = '--max-os-tries 2 --data-string "a b"'
    assert args_of(config) == ["--max-os-tries", "2", "--data-string", "a b"]


def test_advanced_arguments_block_output_files():
    config = base()
    config.advanced_arguments = "-oX mine.xml"
    with pytest.raises(ArgumentError):
        build_user_arguments(config)


def test_targets_come_last_with_exclusions():
    config = base()
    config.targets.exclusions = ["192.168.1.1"]
    config.targets.target_file = "C:\\lists\\hosts.txt"
    assert build_targets(config) == ["--exclude", "192.168.1.1", "-iL", "C:\\lists\\hosts.txt", "192.168.1.0/24"]


def test_plan_separates_managed_arguments():
    config = base()
    config.techniques.tcp = TcpScanTechnique.SYN
    xml = Path("/tmp/run/result.xml")
    plan = build_command_plan(NMAP, config, xml_output=xml, stats_interval="2s", noninteractive=True)
    assert plan.arguments == ["-sS", "-oX", str(xml), "--stats-every", "2s", "--noninteractive", "192.168.1.0/24"]
    assert plan.user_arguments == ["-sS"]
    assert plan.display_user_command() == "nmap -sS 192.168.1.0/24"


def test_user_stats_interval_takes_precedence():
    config = base()
    config.output.stats_interval = "10s"
    plan = build_command_plan(NMAP, config, stats_interval="2s")
    assert plan.arguments.count("--stats-every") == 1
    assert "10s" in plan.arguments


def test_hostile_values_stay_single_arguments():
    config = base()
    config.evasion.data_string = "; rm -rf / &"
    plan = build_command_plan(NMAP, config)
    assert "; rm -rf / &" in plan.arguments
    assert "'; rm -rf / &'" in plan.display() or '"; rm -rf / &"' in plan.display()


def test_format_command_quotes_spaces():
    rendered = format_command(["nmap", "--script", "default and safe", "10.0.0.1"])
    assert "default and safe" in rendered
    assert rendered.count("default and safe") == 1
    assert rendered != "nmap --script default and safe 10.0.0.1"
