import shutil

import pytest

from genmap.core.scan_config import ScanConfiguration
from genmap.engine.run_store import RunStatus, RunStore, describe_targets
from genmap.errors import StorageError


def config(*targets):
    c = ScanConfiguration()
    c.targets.targets = list(targets) or ["10.0.0.1"]
    return c


def test_create_list_load_delete(tmp_path):
    store = RunStore(tmp_path / "scans")
    first = store.create(config("10.0.0.1"), profile_name="Quick scan")
    second = store.create(config("10.0.0.2"))
    runs = store.list_runs()
    assert {r.run_id for r in runs} == {first.run_id, second.run_id}
    loaded = store.load(first.run_id)
    assert loaded.profile_name == "Quick scan"
    assert loaded.scan_configuration().targets.targets == ["10.0.0.1"]
    store.delete(first.run_id)
    assert [r.run_id for r in store.list_runs()] == [second.run_id]


def test_invalid_run_ids_are_rejected(tmp_path):
    store = RunStore(tmp_path)
    for bad in ("", "..", "../etc", "a/b", "a\\b"):
        with pytest.raises(StorageError):
            store.run_directory(bad)


def test_corrupt_records_are_skipped(tmp_path):
    store = RunStore(tmp_path)
    good = store.create(config())
    broken = tmp_path / "20200101-000000-bad"
    broken.mkdir()
    (broken / "run.json").write_text("{nope")
    assert [r.run_id for r in store.list_runs()] == [good.run_id]


def test_recover_interrupted_runs(tmp_path, fixtures):
    store = RunStore(tmp_path)
    record = store.create(config())
    record.status = RunStatus.RUNNING
    store.save(record)
    shutil.copy(fixtures / "truncated_scan.xml", store.xml_path(record.run_id))
    active = store.create(config())
    active.status = RunStatus.RUNNING
    store.save(active)

    recovered = store.recover_interrupted({active.run_id})
    assert recovered == [record.run_id]
    reloaded = store.load(record.run_id)
    assert reloaded.status == RunStatus.INTERRUPTED
    assert reloaded.summary.hosts_up == 2
    assert store.load(active.run_id).status == RunStatus.RUNNING


def test_load_result_and_read_text(tmp_path, fixtures):
    store = RunStore(tmp_path)
    record = store.create(config())
    assert store.load_result(record.run_id) is None
    shutil.copy(fixtures / "lan_inventory.xml", store.xml_path(record.run_id))
    assert len(store.load_result(record.run_id).hosts) == 4
    store.stdout_path(record.run_id).write_text("hello")
    assert store.read_text(record.run_id, "stdout.log") == "hello"
    assert store.read_text(record.run_id, "missing.log") == ""


def test_describe_targets():
    c = config("a.example", "b.example", "c.example", "d.example")
    assert describe_targets(c) == "a.example, b.example, c.example and 1 more"
    c = ScanConfiguration()
    c.targets.target_file = "/tmp/hosts.txt"
    assert describe_targets(c) == "file:hosts.txt"
    assert describe_targets(ScanConfiguration()) == "(no targets)"
