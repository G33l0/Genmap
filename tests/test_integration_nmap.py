"""Integration tests against the installed Nmap. Skipped when Nmap is absent.

They only touch the loopback interface and use list or connect scans so
they work without elevated privileges and without network access.
"""

from pathlib import Path

import pytest

from genmap.core.scan_config import PortSelectionMode, ScanConfiguration, ScanMode, TcpScanTechnique
from genmap.engine.run_store import RunStatus, RunStore
from genmap.errors import NmapNotFoundError
from genmap.nmap.environment import probe_environment
from tests.conftest import nmap_path, requires_nmap

pytestmark = [pytest.mark.integration, requires_nmap]


def engine_for(tmp_path, executable=None):
    from genmap.engine.scan_engine import ScanEngine
    from genmap.modules import ModuleRegistry
    from genmap.modules.nmap import NmapModule

    store = RunStore(tmp_path / "scans")
    registry = ModuleRegistry()
    registry.register(NmapModule(executable=Path(executable) if executable else Path(nmap_path())))
    return ScanEngine(store, registry), store


def test_probe_environment_finds_nmap():
    env = probe_environment()
    assert env.usable
    assert env.version.major >= 7
    assert env.capabilities.get("connect_scan").available is True
    assert env.interfaces is not None and env.interfaces.interfaces


def test_list_scan_end_to_end(qtbot, tmp_path):
    engine, store = engine_for(tmp_path)
    config = ScanConfiguration()
    config.targets.targets = ["127.0.0.1"]
    config.techniques.mode = ScanMode.LIST_ONLY
    job = engine.start(config)
    with qtbot.waitSignal(job.finished, timeout=60000) as blocker:
        pass
    record = blocker.args[0]
    assert record.status == RunStatus.COMPLETED
    assert record.exit_code == 0
    assert record.summary.hosts_total == 1
    assert record.command.arguments[0] == "-sL"
    assert "-oX" in record.command.arguments
    assert store.stdout_path(record.run_id).read_text().startswith("Starting Nmap")
    result = store.load_result(record.run_id)
    assert result.hosts[0].primary_address == "127.0.0.1"


def test_connect_scan_of_loopback(qtbot, tmp_path):
    engine, store = engine_for(tmp_path)
    config = ScanConfiguration()
    config.targets.targets = ["127.0.0.1"]
    config.techniques.tcp = TcpScanTechnique.CONNECT
    config.ports.mode = PortSelectionMode.SPECIFIC
    config.ports.specification = "1-100"
    job = engine.start(config)
    with qtbot.waitSignal(job.finished, timeout=120000) as blocker:
        pass
    record = blocker.args[0]
    assert record.status == RunStatus.COMPLETED
    assert job.live_state.done_line is not None


def test_bad_argument_is_explained(qtbot, tmp_path):
    engine, _ = engine_for(tmp_path)
    config = ScanConfiguration()
    config.targets.targets = ["127.0.0.1"]
    config.advanced_arguments = "--definitely-not-an-option"
    job = engine.start(config)
    with qtbot.waitSignal(job.finished, timeout=60000) as blocker:
        pass
    record = blocker.args[0]
    assert record.status == RunStatus.FAILED
    assert record.exit_code not in (None, 0)
    assert record.error_message


def test_cancel_running_scan(qtbot, tmp_path):
    engine, _ = engine_for(tmp_path)
    config = ScanConfiguration()
    config.targets.targets = ["127.0.0.1"]
    config.techniques.tcp = TcpScanTechnique.CONNECT
    config.ports.mode = PortSelectionMode.ALL
    config.timing.max_rate = 20
    job = engine.start(config)
    with qtbot.waitSignal(job.started, timeout=30000):
        pass
    assert engine.is_busy
    job.cancel()
    with qtbot.waitSignal(job.finished, timeout=30000) as blocker:
        pass
    assert blocker.args[0].status == RunStatus.CANCELLED
    assert not engine.is_busy


def test_missing_executable_is_reported(tmp_path):
    from genmap.engine.scan_engine import ScanEngine

    from genmap.modules import ModuleRegistry
    from genmap.modules.nmap import NmapModule

    store = RunStore(tmp_path / "scans")
    registry = ModuleRegistry()
    registry.register(NmapModule())  # never probed, so no executable is known
    engine = ScanEngine(store, registry)
    config = ScanConfiguration()
    config.targets.targets = ["127.0.0.1"]
    with pytest.raises(NmapNotFoundError):
        engine.start(config)
    assert store.list_runs() == []


def test_executable_that_cannot_start(qtbot, tmp_path):
    engine, _ = engine_for(tmp_path, executable=str(tmp_path / "missing-nmap"))
    config = ScanConfiguration()
    config.targets.targets = ["127.0.0.1"]
    job = engine.start(config)
    with qtbot.waitSignal(job.finished, timeout=30000) as blocker:
        pass
    assert blocker.args[0].status == RunStatus.FAILED
    assert "could not be started" in blocker.args[0].error_message


def test_finished_scan_is_indexed_in_the_database(qtbot, qapp, app_paths):
    from genmap.settings import SettingsStore
    from genmap.ui.app_context import AppContext

    store = SettingsStore(app_paths.settings_file)
    store.load()
    context = AppContext(qapp, app_paths, store)
    try:
        context.nmap_module.refresh_environment(include_interfaces=False)
        config = ScanConfiguration()
        config.targets.targets = ["127.0.0.1"]
        config.techniques.tcp = TcpScanTechnique.CONNECT
        config.ports.mode = PortSelectionMode.SPECIFIC
        config.ports.specification = "1-50"
        job = context.engine.start(config, profile_name="Integration")
        assert context.scan_index.get(job.run_id).status == RunStatus.RUNNING.value
        with qtbot.waitSignal(job.finished, timeout=120000):
            pass
        qtbot.waitUntil(lambda: context.scan_index.get(job.run_id).results_indexed, timeout=30000)
        scan = context.scan_index.get(job.run_id)
        assert scan.status == RunStatus.COMPLETED.value
        assert scan.hosts_up == 1
        assert [t.expression for t in scan.targets] == ["127.0.0.1"]
        assert context.scan_index.list_scans(search="Integration")[0].run_id == job.run_id
    finally:
        context.shutdown()
        context.database.dispose()
