import shutil
from pathlib import Path

from PyQt6.QtCore import QProcess

from genmap.core.scan_config import ScanConfiguration
from genmap.engine.run_store import RunStatus, RunStore
from genmap.engine.scan_engine import ScanJob
from genmap.modules.nmap import NmapModule
from genmap.nmap.command_builder import build_command_plan


def make_job(tmp_path, fixtures, with_xml=True):
    store = RunStore(tmp_path)
    config = ScanConfiguration()
    config.targets.targets = ["files.lab.internal"]
    record = store.create(config)
    if with_xml:
        shutil.copy(fixtures / "lan_inventory.xml", store.xml_path(record.run_id))
    return ScanJob(record, build_command_plan(Path("nmap"), config), store, module=NmapModule())


def finish(job, lines, exit_code, stderr=()):
    for line in lines:
        job.monitor.feed(line)
    job.stderr_lines.extend(stderr)
    job._on_finished(exit_code, QProcess.ExitStatus.NormalExit)
    return job.record


def test_clean_exit_is_completed(qapp, tmp_path, fixtures):
    record = finish(make_job(tmp_path, fixtures), ["Nmap done: 8 IP addresses (3 hosts up) scanned in 121.30 seconds"], 0)
    assert record.status == RunStatus.COMPLETED
    assert record.error_message is None
    assert record.summary.hosts_up == 3


def test_exit_zero_with_recognised_problem_is_not_a_clean_success(qapp, tmp_path, fixtures):
    record = finish(make_job(tmp_path, fixtures), ['Failed to resolve "files.lab.internal".'], 0)
    assert record.status == RunStatus.COMPLETED_WITH_WARNINGS
    assert record.error_message == "One or more target names could not be resolved."
    assert 'Nmap reported: Failed to resolve "files.lab.internal".' in record.error_remedy


def test_failure_quotes_the_line_that_explains_it(qapp, tmp_path, fixtures):
    record = finish(
        make_job(tmp_path, fixtures, with_xml=False),
        ["/usr/bin/nmap: unrecognized option '--bogus'"],
        255,
    )
    assert record.status == RunStatus.FAILED
    assert record.error_message == "Nmap did not understand one of the arguments."
    assert record.error_remedy.endswith("Nmap reported: /usr/bin/nmap: unrecognized option '--bogus'")


def test_unknown_failure_uses_nmaps_last_real_message(qapp, tmp_path, fixtures):
    stderr = ["Something unexpected happened in the engine", "stack traceback:", "\t[C]: in ?", "", "QUITTING!"]
    record = finish(make_job(tmp_path, fixtures, with_xml=False), [], 1, stderr)
    assert record.status == RunStatus.FAILED
    assert record.error_message == "Nmap exited with code 1."
    assert record.error_remedy == "Nmap reported: Something unexpected happened in the engine"


def test_last_meaningful_line_skips_noise():
    assert NmapModule().failure_line(["real problem", "See the output of nmap -h for a summary of options.", "QUITTING!"]) == "real problem"
    assert NmapModule().failure_line(["", "   "]) is None
