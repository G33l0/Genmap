import pytest

from genmap.nmap.output_monitor import OutputMonitor


def feed(lines):
    monitor = OutputMonitor()
    events = [monitor.feed(line) for line in lines]
    return monitor, events


def test_progress_and_stats_lines():
    monitor, events = feed([
        "Stats: 0:00:12 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan",
        "SYN Stealth Scan Timing: About 36.20% done; ETC: 14:02 (0:00:21 remaining)",
    ])
    assert events == ["stats", "progress"]
    assert monitor.state.stats.hosts_up == 1
    assert monitor.state.progress.percent == 36.2
    assert monitor.state.progress.remaining == "0:00:21"


def test_progress_without_etc():
    monitor, _ = feed(["Service scan Timing: About 50.00% done"])
    assert monitor.state.progress.task == "Service scan"
    assert monitor.state.progress.etc is None


def test_real_stdout_fixture(fixtures):
    monitor = OutputMonitor()
    for line in (fixtures / "localhost_stdout.txt").read_text().splitlines():
        monitor.feed(line)
    state = monitor.state
    assert [(p.host, p.port, p.protocol) for p in state.ports] == [("127.0.0.1", 8765, "tcp")]
    assert state.hosts_reported == ["127.0.0.1"]
    assert state.services == {"http"}
    assert state.done_line.startswith("Nmap done: 1 IP address (1 host up)")
    assert state.hosts_up == 1


def test_discovered_ports_are_deduplicated():
    line = "Discovered open port 22/tcp on 10.0.0.5"
    monitor, _ = feed([line, line, "Discovered open port 53/udp on 10.0.0.5"])
    assert monitor.state.open_port_count == 2


def test_known_problems_become_hints():
    monitor, events = feed([
        "You requested a scan type which requires root privileges.",
        "QUITTING!",
        "Failed to resolve \"no-such-host.invalid\".",
        "WARNING: RST from 10.0.0.1 port 22 -- is this port really open?",
    ])
    assert events[0] == "problem"
    messages = [p.message for p in monitor.state.problems]
    assert "This scan type needs elevated privileges." in messages
    assert "One or more target names could not be resolved." in messages
    assert len(monitor.state.warnings) == 4


def test_report_line_with_hostname():
    monitor, _ = feed(["Nmap scan report for files.lab.internal (192.168.56.5)"])
    assert monitor.state.hosts_reported == ["192.168.56.5"]


def test_port_table_services_only_count_open():
    monitor, _ = feed(["22/tcp open  ssh", "80/tcp closed http", "443/tcp open  https?", "9/tcp open unknown"])
    # "https?" is Nmap marking an uncertain guess, so it is not an identification.
    assert monitor.state.services == {"ssh"}


@pytest.mark.parametrize(
    "line",
    [
        "/usr/bin/nmap: unrecognized option '--bogus'",
        "C:\\Program Files (x86)\\Nmap\\nmap.exe: unrecognized option '--bogus'",
        "Ports specified must be between 0 and 65535 inclusive",
        "/usr/share/nmap/nse_main.lua:829: 'nosuch' did not match a category, filename, or directory",
        "NSE: failed to initialize the script engine:",
        "dnet: Failed to open device eth9",
        "WARNING: Could not import all necessary Npcap functions. You may need to upgrade to the latest version.",
        'Failed to resolve "nosuch.invalid".',
    ],
)
def test_real_nmap_errors_are_recognised(line):
    monitor, events = feed([line])
    assert events == ["problem"]


@pytest.mark.parametrize(
    "line",
    [
        "|_http-title: Download Npcap for Windows",
        "| ssl-cert: Subject: commonName=Failed to open device",
        "NSE: Script Engine scan of 1 host",
        "|   Error: server returned 500",
        "80/tcp open  http    nginx 1.24 (Illegal port redirect test page)",
        "Nmap scan report for pcap_open_live.example (10.0.0.1)",
    ],
)
def test_script_output_and_banners_are_not_errors(line):
    monitor, events = feed([line])
    assert "problem" not in events
    assert monitor.state.problems == []
