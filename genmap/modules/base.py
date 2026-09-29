"""The contract every Genmap module implements.

Nmap is the first module. Future tools (DNS, WHOIS, screenshots, Domain
Atlas) plug in through the same interface, so the core only ever talks to
``Module`` and the data types declared here. Modules may wrap external
processes; nothing here assumes the work happens in Python.
"""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Optional, Protocol

from pydantic import BaseModel, ConfigDict, Field

from genmap import MODULE_API_VERSION
from genmap.core.diagnostics import Diagnostic
from genmap.core.scan_config import ValidationIssue
from genmap.paths import AppPaths

if TYPE_CHECKING:
    from genmap.core.process_plan import CommandPlan
    from genmap.engine.run_store import RunRecord, RunStore


class ExternalToolRequirement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    minimum_version: Optional[str] = None
    optional: bool = False
    purpose: str = ""


class ModuleManifest(BaseModel):
    """Static description of a module, used for compatibility checks and display."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$")
    name: str
    version: str
    description: str = ""
    author: str = ""
    homepage: Optional[str] = None
    api_version: str = MODULE_API_VERSION
    capabilities: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=lambda: ["windows", "linux", "darwin"])
    external_tools: list[ExternalToolRequirement] = Field(default_factory=list)
    configuration_schema: Optional[dict[str, Any]] = None
    result_schema: Optional[dict[str, Any]] = None
    tags: list[str] = Field(default_factory=list)

    def is_api_compatible(self, host_api_version: str = MODULE_API_VERSION) -> bool:
        return self.api_version.split(".")[0] == host_api_version.split(".")[0]


class ModuleState(str, Enum):
    REGISTERED = "registered"
    READY = "ready"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    DISABLED = "disabled"
    INCOMPATIBLE = "incompatible"
    ERROR = "error"


@dataclass
class ModuleContext:
    """Services the host makes available to modules during initialisation.

    Settings are read through a provider because the host replaces the
    settings object whenever the person saves changes; holding on to the
    object from startup would keep stale values.
    """

    paths: AppPaths
    settings_provider: Callable[[], Any]
    logger: logging.Logger

    @property
    def settings(self) -> Any:
        return self.settings_provider()

    def module_data_dir(self, module_id: str) -> Path:
        directory = self.paths.data_dir / "modules" / module_id
        directory.mkdir(parents=True, exist_ok=True)
        return directory


class Module(abc.ABC):
    """Base class for modules.

    Lifecycle: ``initialize`` once at startup, ``check_environment`` whenever
    diagnostics are refreshed, ``shutdown`` at exit. Configuration objects
    are pydantic models created by ``default_configuration`` and checked by
    ``validate``. Modules that run an external program also implement
    ``ProcessModule`` so the scan engine can run them.
    """

    def __init__(self) -> None:
        self.context: Optional[ModuleContext] = None
        self.state: ModuleState = ModuleState.REGISTERED
        self.last_error: Optional[str] = None
        self.last_diagnostics: list[Diagnostic] = []

    def record_diagnostics(self, diagnostics: list[Diagnostic]) -> None:
        """Store the latest environment check and derive the module state from it."""
        from genmap.core.diagnostics import DiagnosticLevel, worst_level

        self.last_diagnostics = list(diagnostics)
        if self.state in (ModuleState.DISABLED, ModuleState.INCOMPATIBLE, ModuleState.ERROR):
            return
        level = worst_level(diagnostics)
        self.state = (
            ModuleState.UNAVAILABLE if level == DiagnosticLevel.ERROR
            else ModuleState.DEGRADED if level == DiagnosticLevel.WARNING
            else ModuleState.READY
        )

    @property
    @abc.abstractmethod
    def manifest(self) -> ModuleManifest: ...

    def initialize(self, context: ModuleContext) -> None:
        self.context = context

    @abc.abstractmethod
    def check_environment(self) -> list[Diagnostic]: ...

    @abc.abstractmethod
    def default_configuration(self) -> BaseModel: ...

    @abc.abstractmethod
    def validate(self, configuration: BaseModel) -> list[ValidationIssue]: ...

    def shutdown(self) -> None:
        return None

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.manifest.id} {self.manifest.version} {self.state.value}>"


class ProblemLike(Protocol):
    message: str
    remedy: str
    source_line: str


class MonitorState(Protocol):
    problems: list[ProblemLike]
    warnings: list[str]
    progress: Any


class RunMonitor(Protocol):
    """Reads a tool's console output line by line while it runs.

    ``feed`` returns None when the line changed nothing, "progress" when
    ``state.progress`` was updated, and any other string for other changes.
    """

    state: MonitorState

    def feed(self, line: str) -> Optional[str]: ...


class ProcessModule(Module):
    """A module that runs an external program through the scan engine.

    The engine owns the process, console capture, cancellation, and time
    limits. The module decides what to run, how to read the output while it
    runs, and what the finished run produced.
    """

    tool_name: str = "The tool"

    @abc.abstractmethod
    def build_plan(self, configuration: BaseModel, *, run_directory: Path) -> "CommandPlan":
        """The process to start. Raise a GenmapError when it cannot run."""

    @abc.abstractmethod
    def create_monitor(self) -> RunMonitor: ...

    @abc.abstractmethod
    def finalize_run(self, record: "RunRecord", store: "RunStore") -> None:
        """Read what the run left in its folder and complete the record.

        ``record.status`` already reflects how the process ended; a module may
        downgrade a completed run to completed with warnings, and fills in
        ``record.summary`` when it can.
        """

    def describe_targets(self, configuration: BaseModel) -> str:
        return ""

    def failure_line(self, lines: list[str]) -> Optional[str]:
        """The line that best explains a failed run, for the error message."""
        for line in reversed(lines):
            if line.strip():
                return line.strip()
        return None
