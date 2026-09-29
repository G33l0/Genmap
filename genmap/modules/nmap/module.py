"""The Nmap module: wires the Nmap adapter into the module contract."""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, ValidationError

from genmap import __version__
from genmap.core.diagnostics import Diagnostic
from genmap.core.scan_config import ScanConfiguration, ValidationIssue, issues_from_validation_error, validate_configuration
from genmap.core.process_plan import CommandPlan
from genmap.engine.run_store import RunRecord, RunStatus, RunStore, describe_targets, summarize_result
from genmap.errors import NmapNotFoundError, XmlParseError
from genmap.modules.base import ExternalToolRequirement, ModuleManifest, ProcessModule
from genmap.nmap.command_builder import build_command_plan
from genmap.nmap.environment import NmapEnvironment, probe_environment
from genmap.nmap.output_monitor import OutputMonitor
from genmap.settings import AppSettings

log = logging.getLogger(__name__)


class NmapModule(ProcessModule):
    MANIFEST = ModuleManifest(
        id="nmap",
        name="Nmap",
        version=__version__,
        description="Port scanning, host discovery, service and OS detection, and NSE scripting through the installed Nmap engine.",
        author="Genmap",
        homepage="https://nmap.org",
        capabilities=[
            "host-discovery",
            "port-scan",
            "service-detection",
            "os-detection",
            "scripting",
            "traceroute",
        ],
        external_tools=[
            ExternalToolRequirement(name="nmap", minimum_version="7.0", purpose="Scanning engine"),
            ExternalToolRequirement(name="npcap", optional=True, purpose="Raw packet access on Windows"),
        ],
        configuration_schema=ScanConfiguration.model_json_schema(),
        tags=["network", "scanner"],
    )

    tool_name = "Nmap"

    def __init__(self, *, executable: Optional[Path] = None) -> None:
        """``executable`` pins the program to run and skips locating it, for tests and embedding."""
        super().__init__()
        self._environment: Optional[NmapEnvironment] = None
        self._pinned_executable = executable
        self._lock = threading.Lock()

    @property
    def manifest(self) -> ModuleManifest:
        return self.MANIFEST

    @property
    def environment(self) -> Optional[NmapEnvironment]:
        return self._environment

    def _settings(self) -> AppSettings:
        settings = self.context.settings if self.context is not None else None
        return settings if isinstance(settings, AppSettings) else AppSettings()

    def configured_path(self) -> Optional[str]:
        return self._settings().nmap.executable_path

    def probe_timeout(self) -> float:
        return float(self._settings().nmap.probe_timeout_seconds)

    def configured_data_directory(self) -> Optional[str]:
        return self._settings().nmap.data_directory

    def data_directory_argument(self) -> Optional[Path]:
        """The folder passed to Nmap as --datadir, when the setting names an existing folder."""
        configured = self.configured_data_directory()
        if not configured:
            return None
        path = Path(configured).expanduser()
        return path if path.is_dir() else None

    def stats_interval(self) -> Optional[str]:
        scanning = self._settings().scanning
        return scanning.stats_interval if scanning.inject_stats_interval else None

    def refresh_environment(self, *, include_interfaces: bool = True) -> NmapEnvironment:
        env = probe_environment(
            self.configured_path(),
            timeout=self.probe_timeout(),
            include_interfaces=include_interfaces,
            data_directory=self.configured_data_directory(),
        )
        with self._lock:
            self._environment = env
        self.record_diagnostics(env.diagnostics)
        return env

    def executable(self) -> Optional[Path]:
        if self._pinned_executable is not None:
            return self._pinned_executable
        env = self._environment
        return env.executable if env and env.usable else None

    def check_environment(self) -> list[Diagnostic]:
        return self.refresh_environment().diagnostics

    def default_configuration(self) -> BaseModel:
        return ScanConfiguration()

    def validate(self, configuration: BaseModel) -> list[ValidationIssue]:
        if not isinstance(configuration, ScanConfiguration):
            try:
                configuration = ScanConfiguration.model_validate(configuration.model_dump())
            except ValidationError as exc:
                return issues_from_validation_error(exc)
        return validate_configuration(configuration)

    # Execution ------------------------------------------------------------

    def plan_for(self, program: Path, configuration: ScanConfiguration, *, xml_output: Optional[Path]) -> CommandPlan:
        """The command for ``configuration``; also used for previews before Nmap is found."""
        return build_command_plan(
            program,
            configuration,
            xml_output=xml_output,
            stats_interval=self.stats_interval(),
            data_directory=self.data_directory_argument(),
        )

    def build_plan(self, configuration: BaseModel, *, run_directory: Path) -> CommandPlan:
        executable = self.executable()
        if executable is None:
            raise NmapNotFoundError(remedy="Install Nmap or set its location under Settings, Nmap.")
        config = configuration if isinstance(configuration, ScanConfiguration) else ScanConfiguration.model_validate(configuration.model_dump())
        return self.plan_for(executable, config, xml_output=run_directory / RunStore.XML_FILE)

    def create_monitor(self) -> OutputMonitor:
        return OutputMonitor()

    def describe_targets(self, configuration: BaseModel) -> str:
        return describe_targets(configuration) if isinstance(configuration, ScanConfiguration) else ""

    def failure_line(self, lines: list[str]) -> Optional[str]:
        # Skip Lua traceback noise, QUITTING!, and the pointer to nmap -h.
        for line in reversed(lines):
            text = line.strip()
            if not text or text == "QUITTING!" or line.startswith(("\t", " ")) or text.startswith(("stack traceback", "[C]")):
                continue
            if text.startswith("See the output of nmap -h"):
                continue
            return text
        return None

    def finalize_run(self, record: RunRecord, store: RunStore) -> None:
        completed = record.status == RunStatus.COMPLETED
        xml_path = store.xml_path(record.run_id)
        if not xml_path.is_file():
            if completed:
                record.status = RunStatus.COMPLETED_WITH_WARNINGS
                record.warnings.append("Nmap finished without writing an XML result file.")
            return
        try:
            result = store.load_result(record.run_id)
        except XmlParseError as exc:
            log.warning("Result XML for %s unusable: %s", record.run_id, exc.details)
            if completed:
                record.status = RunStatus.COMPLETED_WITH_WARNINGS
                record.warnings.append("Nmap finished but its XML output could not be parsed.")
            return
        if result is None:
            return
        record.summary = summarize_result(result)
        record.nmap_version = record.nmap_version or result.nmap_version
        if completed and (result.truncated or result.statistics.exit_status == "error"):
            record.status = RunStatus.COMPLETED_WITH_WARNINGS
            if result.statistics.error_message:
                record.warnings.append(result.statistics.error_message)
