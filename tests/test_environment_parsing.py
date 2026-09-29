
from genmap.nmap.capabilities import detect_capabilities
from genmap.nmap.interfaces import parse_iflist_output
from genmap.nmap.locator import EXECUTABLE_NAME, locate_nmap, validate_executable_path
from genmap.nmap.npcap import CaptureDriverInfo, CaptureDriverStatus
from genmap.nmap.privileges import PrivilegeLevel
from genmap.nmap.version import parse_version_output


def test_linux_version(fixtures):
    version = parse_version_output((fixtures / "nmap_version_linux.txt").read_text())
    assert (version.major, version.minor) == (7, 94)
    assert version.is_development
    assert version.has_library("liblua")
    assert "epoll" in version.nsock_engines


def test_windows_version(fixtures):
    version = parse_version_output((fixtures / "nmap_version_windows.txt").read_text())
    assert version.tuple == (7, 95, 0)
    assert not version.is_development
    assert version.platform == "i686-pc-windows-windows"
    assert version.has_library("Npcap")
    assert version.compiled_without == ()
    assert version.at_least(7, 70)
    assert not version.at_least(8, 0)


def test_non_nmap_version_output():
    assert parse_version_output("Python 3.13.0") is None
    assert parse_version_output("") is None


def test_iflist_linux(fixtures):
    listing = parse_iflist_output((fixtures / "iflist_linux.txt").read_text())
    devices = {i.device for i in listing.interfaces}
    assert "lo" in devices
    loopback = next(i for i in listing.interfaces if i.device == "lo")
    assert loopback.interface_type == "loopback"
    assert loopback not in listing.usable_interfaces
    assert any(r.destination == "0.0.0.0/0" and r.gateway for r in listing.routes)


def test_iflist_windows_names_with_spaces(fixtures):
    listing = parse_iflist_output((fixtures / "iflist_windows.txt").read_text())
    names = [(i.device, i.short_name) for i in listing.interfaces]
    assert ("lo0", "Loopback Pseudo-Interface 1") in names
    wifi = next(i for i in listing.interfaces if i.short_name == "Wi-Fi 2")
    assert wifi.address is None and not wifi.is_up and wifi.mac == "AC:12:03:44:55:66"
    loop = next(i for i in listing.interfaces if i.device == "lo0")
    assert loop.mtu is None
    assert listing.routes[-1].gateway == "192.168.56.1"


def _windows_version(fixtures):
    return parse_version_output((fixtures / "nmap_version_windows.txt").read_text())


def test_capabilities_when_capture_driver_missing(fixtures, monkeypatch):
    monkeypatch.setattr("sys.platform", "win32")
    driver = CaptureDriverInfo(CaptureDriverStatus.MISSING, "Npcap")
    caps = detect_capabilities(_windows_version(fixtures), driver, PrivilegeLevel.ELEVATED)
    assert caps.is_available("raw_packets") is False
    assert caps.is_available("syn_scan") is False
    assert caps.is_available("connect_scan") is True
    assert caps.is_available("nse") is True
    assert caps.is_available("noninteractive") is True


def test_capabilities_admin_only_npcap(fixtures, monkeypatch):
    monkeypatch.setattr("sys.platform", "win32")
    driver = CaptureDriverInfo(CaptureDriverStatus.DETECTED, "Npcap", admin_only=True)
    assert detect_capabilities(_windows_version(fixtures), driver, PrivilegeLevel.STANDARD).is_available("raw_packets") is False
    assert detect_capabilities(_windows_version(fixtures), driver, PrivilegeLevel.ELEVATED).is_available("raw_packets") is True


def test_capabilities_unprivileged_posix_is_unknown(fixtures, monkeypatch):
    monkeypatch.setattr("sys.platform", "linux")
    version = parse_version_output((fixtures / "nmap_version_linux.txt").read_text())
    driver = CaptureDriverInfo(CaptureDriverStatus.NOT_APPLICABLE, "libpcap")
    caps = detect_capabilities(version, driver, PrivilegeLevel.STANDARD)
    assert caps.is_available("raw_packets") is None


def test_old_version_capabilities():
    version = parse_version_output("Nmap version 7.60 ( https://nmap.org )\nCompiled without: liblua openssl\n")
    driver = CaptureDriverInfo(CaptureDriverStatus.NOT_APPLICABLE, "libpcap")
    caps = detect_capabilities(version, driver, PrivilegeLevel.ELEVATED)
    assert caps.is_available("noninteractive") is False
    assert caps.is_available("nse") is False
    assert caps.is_available("ssl") is False


def test_locator_configured_path(tmp_path):
    fake = tmp_path / EXECUTABLE_NAME
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    located = locate_nmap(str(tmp_path))
    assert located is not None and located.source == "configured" and located.path.name == EXECUTABLE_NAME


def test_locator_bad_configured_path_does_not_fall_back(tmp_path):
    assert locate_nmap(str(tmp_path / "nope" / "nmap.exe")) is None


def test_validate_executable_path_messages(tmp_path):
    assert "does not exist" in validate_executable_path(tmp_path / "missing")
    assert "folder" in validate_executable_path(tmp_path)
