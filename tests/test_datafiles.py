"""Data file lookup, requirement warnings, and the new advanced options."""

from pathlib import Path

import pytest

from genmap.core.scan_config import ScanConfiguration, validate_configuration
from genmap.errors import ArgumentError
from genmap.nmap.arguments import review_arguments
from genmap.nmap.command_builder import build_command_plan
from genmap.nmap.datafiles import SearchDirectory, check_data_files, search_directories, status_for
from genmap.nmap.version import parse_version_output

V794 = parse_version_output("Nmap version 7.94 ( https://nmap.org )\n")
V780 = parse_version_output("Nmap version 7.80 ( https://nmap.org )\n")


def _write(folder: Path, name: str, text: str) -> Path:
    path = folder / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_search_order_matches_nmap(tmp_path):
    exe = tmp_path / "bin" / "nmap"
    dirs = search_directories(exe, tmp_path / "custom", environ={"NMAPDIR": str(tmp_path / "env")}, windows=False)
    origins = [d.origin for d in dirs]
    assert origins[:3] == ["the data directory setting (--datadir)", "NMAPDIR environment variable", "your ~/.nmap folder"]
    assert dirs[3].path == exe.parent and dirs[4].path == exe.parent / ".." / "share" / "nmap"
    assert all(d.assumed for d in dirs[5:])
    windows = search_directories(exe, None, environ={"APPDATA": str(tmp_path / "roaming")}, windows=True)
    assert [d.path for d in windows] == [tmp_path / "roaming" / "nmap", exe.parent]


def test_each_file_resolves_independently(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    _write(first, "nmap-services", "http\t80/tcp\t0.48\n")
    _write(second, "nmap-services", "ssh\t22/tcp\t0.2\nhttp\t80/tcp\t0.48\n")
    _write(second, "nmap-os-db", "# comment\nFingerprint Linux 5\nFingerprint Windows 11\n")
    dirs = [SearchDirectory(first, "--datadir"), SearchDirectory(second, "the Nmap program folder")]
    statuses = check_data_files(None, version=V794, directories=dirs)
    services, os_db = status_for(statuses, "nmap-services"), status_for(statuses, "nmap-os-db")
    assert services.path == first / "nmap-services" and services.summary == "1 entry" and services.origin == "--datadir"
    assert os_db.path == second / "nmap-os-db" and os_db.summary == "2 fingerprints"
    assert not status_for(statuses, "nmap-service-probes").found


def test_payloads_file_only_checked_before_7_94(tmp_path):
    dirs = [SearchDirectory(tmp_path, "x")]
    assert status_for(check_data_files(None, version=V794, directories=dirs), "nmap-payloads") is None
    assert status_for(check_data_files(None, version=V780, directories=dirs), "nmap-payloads") is not None


def test_empty_file_is_reported(tmp_path):
    _write(tmp_path, "nmap-service-probes", "\n")
    status = status_for(check_data_files(None, version=V794, directories=[SearchDirectory(tmp_path, "x")]), "nmap-service-probes")
    assert status.path is not None and not status.found and "empty" in status.problem


def test_new_options_reach_the_command(tmp_path):
    services = _write(tmp_path, "svc", "http 80/tcp 0.1\n")
    config = ScanConfiguration()
    config.targets.targets = ["scanme.nmap.org"]
    config.dns.resolve_all = True
    config.dns.unique_addresses = True
    config.data_files.data_directory = str(tmp_path)
    config.data_files.services_file = str(services)
    assert validate_configuration(config) == []  # --resolve-all and --unique combine without conflict
    plan = build_command_plan(Path("nmap"), config, data_directory=tmp_path / "settings")
    args = plan.arguments
    assert "--resolve-all" in args and "--unique" in args
    assert args[args.index("--servicedb") + 1] == str(services)
    # The scan's own data directory wins over the one from Settings.
    assert args.count("--datadir") == 1 and args[args.index("--datadir") + 1] == str(tmp_path)


def test_settings_data_directory_is_a_managed_argument(tmp_path):
    config = ScanConfiguration()
    config.targets.targets = ["10.0.0.1"]
    plan = build_command_plan(Path("nmap"), config, data_directory=tmp_path)
    managed = [m for m in plan.managed_arguments if m.arguments[0] == "--datadir"]
    assert managed and managed[0].arguments[1] == str(tmp_path) and "Settings" in managed[0].reason
    assert "--datadir" not in plan.user_arguments


@pytest.mark.parametrize("option", ["--datadir /tmp", "--servicedb=x", "--versiondb x"])
def test_data_file_options_rejected_in_advanced_arguments(option):
    with pytest.raises(ArgumentError):
        review_arguments(option)


def test_missing_data_paths_are_errors(tmp_path):
    config = ScanConfiguration()
    config.targets.targets = ["10.0.0.1"]
    config.data_files.data_directory = str(tmp_path / "nope")
    config.data_files.version_probes_file = str(tmp_path / "missing-probes")
    errors = [i.message for i in validate_configuration(config) if i.severity == "error"]
    assert any("data directory" in m for m in errors) and any("version probes file" in m for m in errors)
    with pytest.raises(ValueError):
        ScanConfiguration.model_validate({"data_files": {"services_file": "a\nb"}})


def test_requirement_warnings(tmp_path):
    from genmap.nmap.capabilities import Capability
    from genmap.nmap.environment import NmapEnvironment, _apply_data_file_capabilities
    from genmap.nmap.requirements import environment_warnings

    env = NmapEnvironment(executable=Path("nmap"), version=V780)
    env.data_files = check_data_files(None, version=V780, directories=[SearchDirectory(tmp_path, "x")])
    _apply_data_file_capabilities(env)
    env.capabilities.add(Capability("raw_packets", "Raw packet scans", True))
    config = ScanConfiguration()
    config.targets.targets = ["10.0.0.1"]
    assert environment_warnings(config, env) == []
    config.service_detection.enabled = True
    config.os_detection.enabled = True
    config.dns.unique_addresses = True
    config.scripts.scripts = ["default"]
    warnings = " ".join(environment_warnings(config, env))
    assert "nmap-service-probes" in warnings and "nmap-os-db" in warnings
    assert "7.92" in warnings and "NSE" in warnings
    assert environment_warnings(config, None) == []


def test_diagnostic_report_omits_addresses(tmp_path):
    from genmap.nmap.diagnostic_report import render_diagnostic_report
    from genmap.nmap.environment import NmapEnvironment
    from genmap.nmap.interfaces import parse_iflist_output

    _write(tmp_path, "nmap-services", "http 80/tcp 0.1\n")
    env = NmapEnvironment(executable=Path("/usr/bin/nmap"), version=V794)
    env.data_files = check_data_files(None, version=V794, directories=[SearchDirectory(tmp_path, "the Nmap program folder")])
    env.interfaces = parse_iflist_output(
        "************************INTERFACES************************\n"
        "DEV  (SHORT) IP/MASK                     TYPE     UP MTU   MAC\n"
        "eth0 (eth0)  192.168.7.20/24             ethernet up 1500  02:42:AC:11:00:02\n"
    )
    text = render_diagnostic_report(env, [("Genmap", "test")])
    assert "nmap-services: " in text and "1 entry" in text
    assert "nmap-os-db: Not found" in text
    assert "eth0: ethernet, up" in text
    assert "192.168.7.20" not in text and "02:42:AC" not in text


def test_services_file_conflicts_with_port_choices(tmp_path):
    from genmap.core.scan_config import PortSelectionMode, ScanMode

    services = _write(tmp_path, "svc", "http 80/tcp 0.1\n")
    config = ScanConfiguration()
    config.targets.targets = ["10.0.0.1"]
    config.data_files.services_file = str(services)
    for mode, spec in ((PortSelectionMode.SPECIFIC, "80"), (PortSelectionMode.TOP, ""), (PortSelectionMode.ALL, "")):
        config.ports.mode, config.ports.specification = mode, spec
        assert any("services file" in i.message for i in validate_configuration(config) if i.severity == "error")
    config.ports.mode, config.ports.specification = PortSelectionMode.FAST, ""
    assert not [i for i in validate_configuration(config) if i.severity == "error"]
    config.ports.mode = PortSelectionMode.DEFAULT
    config.techniques.mode = ScanMode.PING_ONLY
    assert any("only applies to port scans" in i.message for i in validate_configuration(config))
