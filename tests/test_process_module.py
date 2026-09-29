"""The scan engine runs any ProcessModule, not just Nmap.

A small Python script stands in for an external tool so the whole path is
exercised for real: QProcess, console capture, progress from the module's
monitor, the module's failure line, and its result handling.
"""

import json
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import pytest
from pydantic import BaseModel, Field

from genmap.core.diagnostics import Diagnostic, DiagnosticLevel
from genmap.core.process_plan import CommandPlan, ManagedArgument
from genmap.core.scan_config import ValidationIssue
from genmap.engine.run_store import RunRecord, RunStatus, RunStore, RunSummary
from genmap.engine.scan_engine import ScanEngine
from genmap.errors import ConfigurationError, ModuleError
from genmap.modules import Module, ModuleContext, ModuleManifest, ModuleRegistry, ModuleState, ProcessModule

SCRIPT = """
import json, sys
steps, exit_code, out = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
for i in range(1, steps + 1):
    print(f"step {i}/{steps}", flush=True)
if exit_code:
    print("boom: the fake tool failed", file=sys.stderr, flush=True)
else:
    json.dump({"items": steps}, open(out, "w"))
sys.exit(exit_code)
"""


class FakeConfig(BaseModel):
    steps: int = Field(default=3, ge=0)
    exit_code: int = 0
    label: str = "fake target"


@dataclass
class FakeState:
    problems: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    progress: Optional[float] = None


class FakeMonitor:
    def __init__(self) -> None:
        self.state = FakeState()

    def feed(self, line: str) -> Optional[str]:
        if line.startswith("step "):
            done, total = line[5:].split("/")
            self.state.progress = int(done) / int(total)
            return "progress"
        return None


class FakeModule(ProcessModule):
    tool_name = "Fake tool"

    def __init__(self, *, explode_on_finalize: bool = False) -> None:
        super().__init__()
        self.explode_on_finalize = explode_on_finalize
        self.finalized: list[str] = []

    @property
    def manifest(self) -> ModuleManifest:
        return ModuleManifest(id="fake", name="Fake", version="1.0")

    def check_environment(self) -> list[Diagnostic]:
        return [Diagnostic(DiagnosticLevel.OK, "Python found", sys.executable)]

    def default_configuration(self) -> BaseModel:
        return FakeConfig()

    def validate(self, configuration: BaseModel) -> list[ValidationIssue]:
        if isinstance(configuration, FakeConfig) and configuration.label == "":
            return [ValidationIssue(severity="error", message="A label is required.")]
        return []

    def describe_targets(self, configuration: BaseModel) -> str:
        return configuration.label

    def build_plan(self, configuration: BaseModel, *, run_directory: Path) -> CommandPlan:
        out = run_directory / "fake.json"
        return CommandPlan(
            program=Path(sys.executable),
            user_arguments=["-c", SCRIPT, str(configuration.steps), str(configuration.exit_code)],
            managed_arguments=[ManagedArgument([str(out)], "Where the fake tool writes its result.")],
            targets=[],
        )

    def create_monitor(self) -> FakeMonitor:
        return FakeMonitor()

    def finalize_run(self, record: RunRecord, store: RunStore) -> None:
        if self.explode_on_finalize:
            raise RuntimeError("module bug")
        self.finalized.append(record.run_id)
        path = store.run_directory(record.run_id) / "fake.json"
        if path.is_file():
            record.summary = RunSummary(hosts_total=json.loads(path.read_text())["items"])


class NotAProcess(Module):
    @property
    def manifest(self) -> ModuleManifest:
        return ModuleManifest(id="lookup", name="Lookup", version="1.0")

    def check_environment(self) -> list[Diagnostic]:
        return []

    def default_configuration(self) -> BaseModel:
        return FakeConfig()

    def validate(self, configuration: BaseModel) -> list[ValidationIssue]:
        return []


def _engine(tmp_path, module: Any = None):
    registry = ModuleRegistry()
    module = module or FakeModule()
    registry.register(module)
    registry.register(NotAProcess())
    registry.initialize_all(ModuleContext(paths=None, settings_provider=lambda: None, logger=logging.getLogger("t")))
    store = RunStore(tmp_path / "scans")
    return ScanEngine(store, registry), store, registry, module


def test_engine_runs_a_non_nmap_module(qtbot, tmp_path):
    engine, store, _, module = _engine(tmp_path)
    progress = []
    job = engine.start(FakeConfig(steps=4), module_id="fake")
    job.progress_changed.connect(progress.append)
    with qtbot.waitSignal(job.finished, timeout=30000) as blocker:
        pass
    record = blocker.args[0]
    assert record.status == RunStatus.COMPLETED and record.exit_code == 0
    assert record.module_id == "fake" and record.target_summary == "fake target"
    assert record.summary.hosts_total == 4
    assert module.finalized == [record.run_id]
    assert progress and progress[-1] == 1.0
    assert job.stdout_lines == ["step 1/4", "step 2/4", "step 3/4", "step 4/4"]
    assert store.load(record.run_id).command.managed_arguments[-1].endswith("fake.json")


def test_failure_uses_the_modules_wording(qtbot, tmp_path):
    engine, _, _, _ = _engine(tmp_path)
    job = engine.start(FakeConfig(steps=1, exit_code=3), module_id="fake")
    with qtbot.waitSignal(job.finished, timeout=30000) as blocker:
        pass
    record = blocker.args[0]
    assert record.status == RunStatus.FAILED
    assert record.error_message == "Fake tool exited with code 3."
    assert record.error_remedy == "Fake tool reported: boom: the fake tool failed"


def test_module_bug_during_finalize_is_contained(qtbot, tmp_path):
    engine, _, _, _ = _engine(tmp_path, FakeModule(explode_on_finalize=True))
    job = engine.start(FakeConfig(steps=1), module_id="fake")
    with qtbot.waitSignal(job.finished, timeout=30000) as blocker:
        pass
    record = blocker.args[0]
    assert record.status == RunStatus.COMPLETED_WITH_WARNINGS
    assert any("could not be read" in w for w in record.warnings)


def test_disabled_unknown_and_non_process_modules_are_refused(tmp_path):
    engine, store, registry, _ = _engine(tmp_path)
    registry.set_enabled("fake", False)
    with pytest.raises(ModuleError, match="turned off"):
        engine.start(FakeConfig(), module_id="fake")
    with pytest.raises(ModuleError, match="does not run scans"):
        engine.start(FakeConfig(), module_id="lookup")
    with pytest.raises(ModuleError, match="No module"):
        engine.start(FakeConfig(), module_id="missing")
    registry.set_enabled("fake", True)
    assert registry.get("fake").state == ModuleState.READY
    with pytest.raises(ConfigurationError):
        engine.start(FakeConfig(label=""), module_id="fake")
    assert store.list_runs() == []


def test_registry_check_records_diagnostics(tmp_path):
    _, _, registry, module = _engine(tmp_path)
    diagnostics = registry.check("fake")
    assert module.last_diagnostics == diagnostics and module.state == ModuleState.READY
