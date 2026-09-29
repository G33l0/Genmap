"""On disk storage for scan runs.

Each run gets its own folder containing the run record, the raw Nmap XML,
and the captured console output. The database added in a later phase will
index these folders; the folder layout is the durable source of truth so
raw Nmap output is never lost.
"""

from __future__ import annotations

import json
import logging
import secrets
import shutil
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from genmap.core.results import ScanResult
from genmap.core.scan_config import ScanConfiguration
from genmap.errors import StorageError
from genmap.nmap.xml_parser import parse_nmap_xml_file

log = logging.getLogger(__name__)


class RunStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_WARNINGS = "completed_with_warnings"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    CRASHED = "crashed"
    INTERRUPTED = "interrupted"

    @property
    def is_terminal(self) -> bool:
        return self not in (RunStatus.PENDING, RunStatus.RUNNING)

    @property
    def label(self) -> str:
        return self.value.replace("_", " ").capitalize()


class CommandRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")

    program: str
    arguments: list[str]
    display: str
    working_directory: Optional[str] = None
    managed_arguments: list[str] = Field(default_factory=list)


class RunSummary(BaseModel):
    model_config = ConfigDict(extra="ignore")

    hosts_total: int = 0
    hosts_up: int = 0
    open_ports: int = 0
    services: int = 0  # confirmed by version detection; port table guesses are not counted
    truncated: bool = False
    nmap_summary: Optional[str] = None


class RunRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")

    schema_version: int = 1
    run_id: str
    module_id: str = "nmap"
    profile_name: Optional[str] = None
    target_summary: str = ""
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    status: RunStatus = RunStatus.PENDING
    exit_code: Optional[int] = None
    nmap_version: Optional[str] = None
    command: Optional[CommandRecord] = None
    configuration: dict[str, Any] = Field(default_factory=dict)
    summary: Optional[RunSummary] = None
    error_message: Optional[str] = None
    error_remedy: Optional[str] = None
    warnings: list[str] = Field(default_factory=list)

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    def scan_configuration(self) -> ScanConfiguration:
        return ScanConfiguration.model_validate(self.configuration)


def _new_run_id(now: datetime) -> str:
    return f"{now.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(3)}"


def summarize_result(result: ScanResult) -> RunSummary:
    return RunSummary(
        hosts_total=len(result.hosts) or result.statistics.hosts_total,
        hosts_up=len(result.hosts_up) or result.statistics.hosts_up,
        open_ports=result.total_open_ports,
        services=len(result.identified_services),
        truncated=result.truncated,
        nmap_summary=result.statistics.summary,
    )


class RunStore:
    RECORD_FILE = "run.json"
    XML_FILE = "result.xml"
    STDOUT_FILE = "stdout.log"
    STDERR_FILE = "stderr.log"

    def __init__(self, root: Path) -> None:
        self.root = root

    def run_directory(self, run_id: str) -> Path:
        if not run_id or "/" in run_id or "\\" in run_id or run_id in (".", ".."):
            raise StorageError("Invalid run identifier.", details=repr(run_id))
        return self.root / run_id

    def xml_path(self, run_id: str) -> Path:
        return self.run_directory(run_id) / self.XML_FILE

    def stdout_path(self, run_id: str) -> Path:
        return self.run_directory(run_id) / self.STDOUT_FILE

    def stderr_path(self, run_id: str) -> Path:
        return self.run_directory(run_id) / self.STDERR_FILE

    def create(self, config: ScanConfiguration, *, profile_name: Optional[str] = None, module_id: str = "nmap") -> RunRecord:
        now = datetime.now().astimezone()
        run_id = _new_run_id(now)
        directory = self.run_directory(run_id)
        try:
            directory.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            run_id = _new_run_id(now)
            directory = self.run_directory(run_id)
            directory.mkdir(parents=True, exist_ok=False)
        except OSError as exc:
            raise StorageError(
                "Could not create a folder for the scan results.",
                remedy=f"Check that {self.root} is writable.",
                details=str(exc),
            ) from exc
        record = RunRecord(
            run_id=run_id,
            module_id=module_id,
            profile_name=profile_name,
            target_summary=describe_targets(config),
            created_at=now,
            configuration=config.model_dump(mode="json"),
        )
        self.save(record)
        return record

    def save(self, record: RunRecord) -> None:
        path = self.run_directory(record.run_id) / self.RECORD_FILE
        try:
            temp = path.with_suffix(".tmp")
            temp.write_text(record.model_dump_json(indent=2), encoding="utf-8")
            temp.replace(path)
        except OSError as exc:
            raise StorageError("Could not save the scan record.", details=str(exc)) from exc

    def load(self, run_id: str) -> RunRecord:
        path = self.run_directory(run_id) / self.RECORD_FILE
        try:
            return RunRecord.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise StorageError(f"Scan record {run_id} could not be read.", details=str(exc)) from exc

    def list_runs(self, limit: Optional[int] = None) -> list[RunRecord]:
        if not self.root.exists():
            return []
        records: list[RunRecord] = []
        for directory in self.root.iterdir():
            if not directory.is_dir() or not (directory / self.RECORD_FILE).is_file():
                continue
            try:
                records.append(self.load(directory.name))
            except StorageError as exc:
                log.warning("Skipping unreadable run %s: %s", directory.name, exc.details)
        records.sort(key=lambda r: r.created_at, reverse=True)
        return records[:limit] if limit else records

    def recover_interrupted(self, active_run_ids: set[str] = frozenset()) -> list[str]:
        """Mark runs left in a running state by a previous session as interrupted.

        Returns the identifiers of the runs that were updated.
        """
        recovered: list[str] = []
        for record in self.list_runs():
            if record.status not in (RunStatus.RUNNING, RunStatus.PENDING) or record.run_id in active_run_ids:
                continue
            record.status = RunStatus.INTERRUPTED
            record.error_message = "Genmap stopped before this scan finished."
            record.error_remedy = "Hosts Nmap completed before that point are kept as partial results."
            xml = self.xml_path(record.run_id)
            if xml.is_file():
                try:
                    record.summary = summarize_result(parse_nmap_xml_file(xml))
                except Exception:
                    log.debug("Partial XML for %s not readable", record.run_id, exc_info=True)
            try:
                self.save(record)
                recovered.append(record.run_id)
            except StorageError:
                log.warning("Could not update interrupted run %s", record.run_id)
        return recovered

    def load_result(self, run_id: str) -> Optional[ScanResult]:
        path = self.xml_path(run_id)
        if not path.is_file():
            return None
        return parse_nmap_xml_file(path)

    def read_text(self, run_id: str, name: str, max_bytes: int = 5_000_000) -> str:
        path = self.run_directory(run_id) / name
        if not path.is_file():
            return ""
        try:
            with path.open("rb") as handle:
                data = handle.read(max_bytes)
            return data.decode("utf-8", errors="replace")
        except OSError:
            return ""

    def delete(self, run_id: str) -> None:
        directory = self.run_directory(run_id)
        if directory.exists():
            try:
                shutil.rmtree(directory)
            except OSError as exc:
                raise StorageError("Could not delete the scan folder.", details=str(exc)) from exc

    def total_size_bytes(self) -> int:
        total = 0
        if self.root.exists():
            for path in self.root.rglob("*"):
                if path.is_file():
                    try:
                        total += path.stat().st_size
                    except OSError:
                        pass
        return total


def describe_targets(config: ScanConfiguration) -> str:
    spec = config.targets
    parts = list(spec.targets)
    if spec.target_file:
        parts.append(f"file:{Path(spec.target_file).name}")
    if spec.random_targets:
        parts.append(f"{spec.random_targets} random")
    if not parts:
        return "(no targets)"
    if len(parts) > 3:
        return ", ".join(parts[:3]) + f" and {len(parts) - 3} more"
    return ", ".join(parts)


def dump_json(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)
