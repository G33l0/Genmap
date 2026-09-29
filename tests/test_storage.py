import json
import shutil

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import func, select

from genmap.core.scan_config import PortSelectionMode, ScanConfiguration
from genmap.engine.run_store import RunStatus, RunStore
from genmap.storage import Database, open_database
from genmap.storage.models import Base, Cpe, Host, OsMatch, Port, ScriptResult, TracerouteHop
from genmap.storage.profiles import ProfileError, ProfileRepository
from genmap.storage.scans import ScanIndex
from genmap.storage.target_groups import TargetGroupError, TargetGroupRepository, parse_target_file_text


@pytest.fixture
def db():
    database = Database(None)
    database.migrate()
    yield database
    database.dispose()


def test_migrations_match_models(tmp_path):
    database = open_database(tmp_path / "genmap.sqlite3")
    assert database.current_revision() == "0001"
    with database.engine.connect() as connection:
        assert compare_metadata(MigrationContext.configure(connection), Base.metadata) == []
    assert database.migrate() == []
    database.dispose()


def test_foreign_keys_are_enforced(db):
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError):
        with db.session() as session:
            session.add(Host(scan_id=999, state="up"))


def test_damaged_database_is_set_aside(tmp_path):
    path = tmp_path / "genmap.sqlite3"
    path.write_bytes(b"this is not a sqlite database at all" * 100)
    database = open_database(path)
    assert database.recovered_from is not None and database.recovered_from.exists()
    assert database.current_revision() == "0001"
    database.dispose()


def make_run(store, fixtures, *targets, xml="lan_inventory.xml", status=RunStatus.COMPLETED):
    config = ScanConfiguration()
    config.targets.targets = list(targets) or ["192.168.56.0/29"]
    record = store.create(config, profile_name="Network inventory")
    if xml:
        shutil.copy(fixtures / xml, store.xml_path(record.run_id))
    record.status = status
    store.save(record)
    return record


def test_reconcile_indexes_normalised_results(db, tmp_path, fixtures):
    store = RunStore(tmp_path / "scans")
    record = make_run(store, fixtures)
    index = ScanIndex(db)
    report = index.reconcile(store)
    assert (report.added, report.indexed, report.failed) == (1, 1, 0)
    assert index.reconcile(store).indexed == 0  # nothing to do the second time

    scan = index.get(record.run_id)
    assert (scan.hosts_total, scan.hosts_up, scan.open_ports) == (4, 3, 6)
    with db.session() as session:
        assert session.scalar(select(func.count(Port.id))) == 11
        assert session.scalar(select(func.count(Cpe.id)).where(Cpe.source == "os")) == 5
        assert session.scalar(select(func.count(OsMatch.id))) == 3
        assert session.scalar(select(func.count(TracerouteHop.id))) == 2
        phases = dict(session.execute(select(ScriptResult.phase, func.count()).group_by(ScriptResult.phase)).all())
        assert phases == {"pre": 1, "post": 1, "host": 3, "port": 3}
        files = session.scalar(select(Host).where(Host.primary_address == "192.168.56.5"))
        assert files.primary_hostname == "files.lab.internal"
        assert files.os_name == "Linux 4.15 - 5.19"
        assert files.extra == {"futurefield": [{"flavour": "unknown-to-genmap"}]}
        ssh = next(p for p in files.ports if p.number == 22)
        assert ssh.service.product == "OpenSSH" and ssh.service.method == "probed"
        assert [s.script_id for s in ssh.scripts] == ["ssh-hostkey"]
        assert isinstance(ssh.scripts[0].structured, list)


def test_reindexing_replaces_rows(db, tmp_path, fixtures):
    store = RunStore(tmp_path / "scans")
    record = make_run(store, fixtures)
    index = ScanIndex(db)
    index.reconcile(store)
    result = store.load_result(record.run_id)
    index.index_results(record.run_id, result)
    with db.session() as session:
        assert session.scalar(select(func.count(Host.id))) == 4


def test_missing_folders_and_deletes(db, tmp_path, fixtures):
    store = RunStore(tmp_path / "scans")
    record = make_run(store, fixtures)
    index = ScanIndex(db)
    index.reconcile(store)
    shutil.rmtree(store.run_directory(record.run_id))
    assert index.reconcile(store).missing == 1
    assert index.get(record.run_id).folder_missing
    index.delete(record.run_id)
    with db.session() as session:
        assert session.scalar(select(func.count(Host.id))) == 0
        assert session.scalar(select(func.count(ScriptResult.id))) == 0


def test_unfinished_and_unparseable_runs(db, tmp_path, fixtures):
    store = RunStore(tmp_path / "scans")
    running = make_run(store, fixtures, status=RunStatus.RUNNING)
    broken = make_run(store, fixtures, xml="not_nmap.xml")
    index = ScanIndex(db)
    report = index.reconcile(store, active_run_ids=[running.run_id])
    assert report.indexed == 0 and report.failed == 1
    assert not index.get(running.run_id).results_indexed
    assert index.get(broken.run_id) is not None


def test_search_tags_and_recent_targets(db, tmp_path, fixtures):
    store = RunStore(tmp_path / "scans")
    first = make_run(store, fixtures, "192.168.56.0/29")
    make_run(store, fixtures, "10.0.0.1", xml="localhost_syn_version_os.xml")
    index = ScanIndex(db)
    index.reconcile(store)
    assert [s.run_id for s in index.list_scans(search="files.lab")] == [first.run_id]
    assert len(index.list_scans(search="Network inventory")) == 2
    assert index.list_scans(search="no-such-thing") == []
    assert index.set_tags(first.run_id, ["Baseline", " baseline ", "lab"]) == ["Baseline", "lab"]
    assert [s.run_id for s in index.list_scans(tag="lab")] == [first.run_id]
    index.set_tags(first.run_id, ["lab"])
    assert index.all_tags() == ["lab"]  # unused tags are removed
    recent = [expression for expression, _when, _count in index.recent_targets()]
    assert set(recent) == {"192.168.56.0/29", "10.0.0.1"}
    stats = index.stats()
    assert stats.scans == 2 and stats.distinct_hosts == 4


def test_profiles_crud_and_builtins(db):
    repo = ProfileRepository(db)
    added = repo.seed_builtins([])
    assert "full_tcp" in added
    assert repo.seed_builtins(added) == []
    full = next(p for p in repo.list() if p.builtin_key == "full_tcp")
    assert full.configuration.ports.mode == PortSelectionMode.ALL
    repo.delete(full.id)
    assert repo.seed_builtins(added) == []  # deleted built ins stay deleted

    config = ScanConfiguration()
    config.targets.targets = ["10.0.0.1"]
    config.service_detection.enabled = True
    mine = repo.create("  My   web scan ", config, "Web servers")
    assert mine.name == "My web scan"
    assert mine.configuration.targets.targets == []  # profiles never carry targets
    with pytest.raises(ProfileError):
        repo.create("my WEB scan", config)
    copy = repo.duplicate(mine.id)
    assert copy.name == "My web scan copy"
    assert repo.duplicate(mine.id).name == "My web scan copy (2)"
    renamed = repo.update(copy.id, name="Renamed")
    assert renamed.name == "Renamed"
    with pytest.raises(ProfileError):
        repo.update(copy.id, name="My web scan")
    quick = next(p for p in repo.list() if p.builtin_key == "quick_scan")
    changed = quick.configuration.model_copy(deep=True)
    changed.timing.template = 2
    repo.update(quick.id, config=changed)
    assert repo.reset_builtin(quick.id).configuration.timing.template == 4
    with pytest.raises(ProfileError):
        repo.reset_builtin(mine.id)


def test_profile_files(db, tmp_path):
    repo = ProfileRepository(db)
    config = ScanConfiguration()
    config.timing.template = 3
    original = repo.create("Export me", config, "desc")
    path = tmp_path / "profile.json"
    repo.export_file(original.id, path)
    imported = repo.import_file(path)
    assert imported.name == "Export me (2)"
    assert imported.configuration == original.configuration

    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"format": "genmap.profile", "version": 1, "configuration": {"ports": {"specification": "99999"}}}))
    with pytest.raises(ProfileError) as info:
        repo.import_file(bad)
    assert "cannot accept" in info.value.message
    future = tmp_path / "future.json"
    future.write_text(json.dumps({"format": "genmap.profile", "version": 99, "configuration": {}}))
    with pytest.raises(ProfileError):
        repo.import_file(future)
    other = tmp_path / "other.json"
    other.write_text("{}")
    with pytest.raises(ProfileError):
        repo.import_file(other)
    garbage = tmp_path / "garbage.json"
    garbage.write_text("{nope")
    with pytest.raises(ProfileError):
        repo.import_file(garbage)


def test_target_groups(db, tmp_path):
    repo = TargetGroupRepository(db)
    group = repo.create("Lab", ["10.0.0.0/24", "files.lab.internal", "10.0.0.0/24"], ["10.0.0.1"], "Test lab")
    assert group.targets == ["10.0.0.0/24", "files.lab.internal"]
    assert group.exclusions == ["10.0.0.1"]
    with pytest.raises(TargetGroupError):
        repo.create("lab", ["10.0.0.2"])
    with pytest.raises(TargetGroupError):
        repo.create("Bad", ["10.0.0.300"])
    with pytest.raises(TargetGroupError):
        repo.create("Empty", [])
    updated = repo.update(group.id, targets=["192.168.1.0/24"], name="Lab network")
    assert updated.targets == ["192.168.1.0/24"] and updated.exclusions == ["10.0.0.1"]

    text_file = tmp_path / "hosts.txt"
    text_file.write_text(repo.export_text(group.id))
    imported = repo.import_file(text_file)
    assert imported.name == "hosts"
    assert imported.targets == ["192.168.1.0/24"] and imported.exclusions == ["10.0.0.1"]
    json_file = tmp_path / "group.json"
    json_file.write_text(json.dumps(repo.export_data(group.id)))
    assert repo.import_file(json_file).name == "Lab network (2)"
    repo.delete(group.id)
    assert "Lab network" not in [g.name for g in repo.list()]


def test_target_file_parsing():
    targets, exclusions = parse_target_file_text("# comment\n10.0.0.1 10.0.0.2\n\nscanme.nmap.org # trailing\n!10.0.0.2\n")
    assert targets == ["10.0.0.1", "10.0.0.2", "scanme.nmap.org"]
    assert exclusions == ["10.0.0.2"]
    with pytest.raises(TargetGroupError):
        parse_target_file_text("10.0.0.1;rm -rf /\n")
