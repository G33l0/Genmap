import pytest
from pydantic import ValidationError

from genmap.core.scan_config import (
    PortSelectionMode,
    ScanConfiguration,
    ScanMode,
    ScriptArgument,
    TcpScanTechnique,
    has_errors,
    issues_from_validation_error,
    validate_configuration,
)


def configured(**targets):
    config = ScanConfiguration()
    config.targets.targets = targets.get("targets", ["10.0.0.1"])
    return config


def messages(config):
    return [issue.message for issue in validate_configuration(config)]


def test_defaults_are_valid_with_a_target():
    assert validate_configuration(configured()) == []


def test_default_tcp_technique_lets_nmap_choose():
    assert ScanConfiguration().techniques.tcp == TcpScanTechnique.AUTO
    assert not ScanConfiguration().techniques.uses_raw_packets


def test_missing_targets_is_an_error():
    issues = validate_configuration(ScanConfiguration())
    assert has_errors(issues)
    assert "No targets" in issues[0].message


def test_invalid_field_values_are_rejected_on_assignment():
    config = ScanConfiguration()
    with pytest.raises(ValidationError):
        config.targets.targets = ["not a target"]
    with pytest.raises(ValidationError):
        config.ports.specification = "80,,443"
    with pytest.raises(ValidationError):
        config.timing.template = 6
    with pytest.raises(ValidationError):
        config.evasion.mtu = 12
    with pytest.raises(ValidationError):
        config.timing.host_timeout = "soon"


def test_unknown_fields_are_rejected():
    with pytest.raises(ValidationError):
        ScanConfiguration.model_validate({"unknown": 1})


def test_json_round_trip():
    config = configured()
    config.scripts.scripts = ["default", "http-* and not http-brute"]
    config.scripts.arguments = [ScriptArgument(name="http.useragent", value="Genmap")]
    config.timing.host_timeout = "30m"
    assert ScanConfiguration.from_json(config.to_json()) == config


def test_idle_scan_requires_zombie():
    config = configured()
    config.techniques.tcp = TcpScanTechnique.IDLE
    assert "Idle scan requires a zombie host." in messages(config)


def test_custom_flags_validation():
    config = configured()
    config.techniques.custom_tcp_flags = "synfin"
    assert config.techniques.custom_tcp_flags == "SYNFIN"
    with pytest.raises(ValidationError):
        config.techniques.custom_tcp_flags = "SYNBOGUS"
    with pytest.raises(ValidationError):
        config.techniques.custom_tcp_flags = "300"


def test_no_technique_selected():
    config = configured()
    config.techniques.tcp = None
    assert any("No scan technique" in m for m in messages(config))


def test_auto_tcp_with_udp_warns_that_tcp_is_skipped():
    config = configured()
    config.techniques.udp = True
    issues = validate_configuration(config)
    assert not has_errors(issues)
    assert any("skips TCP" in i.message for i in issues)


def test_specific_ports_need_a_list():
    config = configured()
    config.ports.mode = PortSelectionMode.SPECIFIC
    assert any("port list" in m for m in messages(config))


def test_contradictions_are_errors():
    config = configured()
    config.timing.min_rate = 100
    config.timing.max_rate = 10
    config.evasion.fragment_packets = 1
    config.evasion.mtu = 16
    config.network.send_ethernet = True
    config.network.send_ip = True
    found = messages(config)
    assert "Minimum packet rate is above the maximum packet rate." in found
    assert "Choose either packet fragmentation or a custom MTU, not both." in found
    assert "Choose either raw Ethernet or raw IP sending, not both." in found


def test_ping_only_with_skip_discovery_is_an_error():
    config = configured()
    config.techniques.mode = ScanMode.PING_ONLY
    config.discovery.skip_discovery = True
    assert has_errors(validate_configuration(config))


def test_ipv6_restrictions():
    config = configured(targets=["2001:db8::1"])
    config.network.ipv6 = True
    config.techniques.tcp = TcpScanTechnique.IDLE
    config.techniques.idle_zombie = "2001:db8::2"
    assert "Idle scan is not supported over IPv6." in messages(config)


def test_raw_packet_detection():
    config = configured()
    config.techniques.tcp = TcpScanTechnique.CONNECT
    assert not config.techniques.uses_raw_packets
    config.techniques.udp = True
    assert config.techniques.uses_raw_packets


def test_script_argument_names_are_checked():
    with pytest.raises(ValidationError):
        ScriptArgument(name="bad name", value="x")
    with pytest.raises(ValidationError):
        ScriptArgument(name="a=b")


def test_validation_error_translation():
    with pytest.raises(ValidationError) as info:
        ScanConfiguration.model_validate({"ports": {"specification": "99999"}})
    issues = issues_from_validation_error(info.value)
    assert issues and issues[0].severity == "error"
    assert "ports.specification" in issues[0].message
    assert "above the maximum" in issues[0].message
