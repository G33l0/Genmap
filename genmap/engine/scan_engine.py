"""Process execution on top of QProcess.

A ScanJob owns one external process and everything captured from it. What
to run, how to read its output, and what the finished run produced all
come from the module (for example the Nmap module); the job only handles
the process itself: console capture, cancellation, and time limits.
"""

from __future__ import annotations

import codecs
import logging
import sys
from datetime import datetime
from typing import IO, Optional

from PyQt6.QtCore import QObject, QProcess, QTimer, pyqtSignal
from pydantic import BaseModel

from genmap.core.process_plan import CommandPlan
from genmap.core.scan_config import has_errors
from genmap.engine.run_store import CommandRecord, RunRecord, RunStatus, RunStore
from genmap.errors import ConfigurationError, ModuleError, NmapExecutionError, ScanEngineBusyError
from genmap.modules.base import ModuleState, ProcessModule, RunMonitor
from genmap.modules.registry import ModuleRegistry

log = logging.getLogger(__name__)


class ScanJob(QObject):
    """One running (or finished) tool process."""

    started = pyqtSignal()
    output = pyqtSignal(str, bool)  # text, is_stderr
    live_state_changed = pyqtSignal(object)  # the module monitor's state
    progress_changed = pyqtSignal(object)  # the monitor's progress value
    finished = pyqtSignal(object)  # RunRecord

    def __init__(
        self,
        record: RunRecord,
        plan: CommandPlan,
        store: RunStore,
        *,
        module: ProcessModule,
        timeout_seconds: int = 0,
        keep_console_logs: bool = True,
        parent: Optional[QObject] = None,
    ) -> None:
        super().__init__(parent)
        self.record = record
        self.plan = plan
        self.store = store
        self.module = module
        self.monitor: RunMonitor = module.create_monitor()
        self.timeout_seconds = timeout_seconds
        self._keep_logs = keep_console_logs
        self._process = QProcess(self)
        self._process.setProgram(str(plan.program))
        self._process.setArguments(plan.arguments)
        if plan.working_directory:
            self._process.setWorkingDirectory(str(plan.working_directory))
        self._process.setProcessChannelMode(QProcess.ProcessChannelMode.SeparateChannels)
        self._process.readyReadStandardOutput.connect(self._read_stdout)
        self._process.readyReadStandardError.connect(self._read_stderr)
        self._process.started.connect(self._on_started)
        self._process.errorOccurred.connect(self._on_error)
        self._process.finished.connect(self._on_finished)
        self._stdout_decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._stderr_decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._stdout_partial = ""
        self._stderr_partial = ""
        self._stdout_file: Optional[IO[str]] = None
        self._stderr_file: Optional[IO[str]] = None
        self._cancel_requested = False
        self._timed_out = False
        self._finished_emitted = False
        self._kill_timer = QTimer(self)
        self._kill_timer.setSingleShot(True)
        self._kill_timer.timeout.connect(self._force_kill)
        self._timeout_timer = QTimer(self)
        self._timeout_timer.setSingleShot(True)
        self._timeout_timer.timeout.connect(self._on_timeout)
        self.profile_id: Optional[int] = None
        self.stdout_lines: list[str] = []
        self.stderr_lines: list[str] = []

    @property
    def run_id(self) -> str:
        return self.record.run_id

    @property
    def live_state(self):
        return self.monitor.state

    @property
    def is_running(self) -> bool:
        return self._process.state() != QProcess.ProcessState.NotRunning

    @property
    def elapsed_seconds(self) -> float:
        if self.record.started_at is None:
            return 0.0
        end = self.record.finished_at or datetime.now().astimezone()
        return (end - self.record.started_at).total_seconds()

    def start(self) -> None:
        if self._keep_logs:
            try:
                # Line buffered so the log survives if Genmap itself is killed mid scan.
                self._stdout_file = self.store.stdout_path(self.run_id).open("w", encoding="utf-8", buffering=1)
                self._stderr_file = self.store.stderr_path(self.run_id).open("w", encoding="utf-8", buffering=1)
            except OSError as exc:
                log.warning("Console logs disabled for %s: %s", self.run_id, exc)
        self.record.status = RunStatus.RUNNING
        self.record.started_at = datetime.now().astimezone()
        self.store.save(self.record)
        log.info("Starting scan %s: %s", self.run_id, self.plan.display())
        self._process.start()

    def cancel(self) -> None:
        if not self.is_running:
            return
        self._cancel_requested = True
        log.info("Cancelling scan %s", self.run_id)
        if sys.platform.startswith("win"):
            # Console programs ignore the WM_CLOSE that terminate() sends on Windows.
            self._process.kill()
        else:
            self._process.terminate()
            self._kill_timer.start(3000)

    def _force_kill(self) -> None:
        if self.is_running:
            log.warning("Scan %s did not exit after terminate; killing", self.run_id)
            self._process.kill()

    def _on_timeout(self) -> None:
        if self.is_running:
            self._timed_out = True
            log.warning("Scan %s exceeded the configured time limit", self.run_id)
            self.cancel()

    def _on_started(self) -> None:
        if self.timeout_seconds > 0:
            self._timeout_timer.start(self.timeout_seconds * 1000)
        self.started.emit()

    def _read_stdout(self) -> None:
        data = bytes(self._process.readAllStandardOutput())
        text = self._stdout_decoder.decode(data)
        if self._stdout_file:
            self._stdout_file.write(text)
        self._stdout_partial = self._dispatch_lines(self._stdout_partial + text, False)

    def _read_stderr(self) -> None:
        data = bytes(self._process.readAllStandardError())
        text = self._stderr_decoder.decode(data)
        if self._stderr_file:
            self._stderr_file.write(text)
        self._stderr_partial = self._dispatch_lines(self._stderr_partial + text, True)

    def _dispatch_lines(self, buffer: str, is_stderr: bool) -> str:
        *complete, remainder = buffer.split("\n")
        state_changed = False
        for line in complete:
            line = line.rstrip("\r")
            (self.stderr_lines if is_stderr else self.stdout_lines).append(line)
            self.output.emit(line, is_stderr)
            event = self.monitor.feed(line)
            if event == "progress" and self.monitor.state.progress is not None:
                self.progress_changed.emit(self.monitor.state.progress)
                state_changed = True
            elif event is not None:
                state_changed = True
        if state_changed:
            self.live_state_changed.emit(self.monitor.state)
        return remainder

    def _flush_partial_lines(self) -> None:
        if self._stdout_partial:
            self._dispatch_lines(self._stdout_partial + "\n", False)
            self._stdout_partial = ""
        if self._stderr_partial:
            self._dispatch_lines(self._stderr_partial + "\n", True)
            self._stderr_partial = ""

    def _on_error(self, error: QProcess.ProcessError) -> None:
        if error == QProcess.ProcessError.FailedToStart:
            self._finish(
                RunStatus.FAILED,
                exit_code=None,
                error_message=f"{self.module.tool_name} could not be started from {self.plan.program}.",
                error_remedy=f"Check the {self.module.tool_name} path under Settings and that the file is executable.",
            )
        elif error == QProcess.ProcessError.Crashed and not self._cancel_requested:
            # finished() follows with CrashExit; nothing to do here.
            pass

    def _on_finished(self, exit_code: int, exit_status: QProcess.ExitStatus) -> None:
        self._read_stdout()
        self._read_stderr()
        self._flush_partial_lines()
        if self._timed_out:
            self._finish(
                RunStatus.TIMED_OUT,
                exit_code=exit_code,
                error_message="The scan was stopped because it exceeded the configured time limit.",
                error_remedy="Raise or disable the scan time limit under Settings, Scanning.",
            )
        elif self._cancel_requested:
            self._finish(RunStatus.CANCELLED, exit_code=exit_code, error_message="The scan was cancelled.")
        elif exit_status == QProcess.ExitStatus.CrashExit:
            self._finish(
                RunStatus.CRASHED,
                exit_code=exit_code,
                error_message=f"{self.module.tool_name} terminated unexpectedly.",
                error_remedy="Review the console output for the last messages before it stopped.",
            )
        elif exit_code != 0:
            tool = self.module.tool_name
            hint = self.monitor.state.problems[0] if self.monitor.state.problems else None
            message = hint.message if hint else f"{tool} exited with code {exit_code}."
            if hint:
                remedy = f"{hint.remedy} {tool} reported: {hint.source_line}"
            else:
                error_line = self.module.failure_line(self.stderr_lines) or self.module.failure_line(self.stdout_lines)
                remedy = f"{tool} reported: {error_line}" if error_line else None
            self._finish(RunStatus.FAILED, exit_code=exit_code, error_message=message, error_remedy=remedy)
        elif self.monitor.state.problems:
            # Tools can exit 0 after skipping work, as Nmap does when a name does not resolve.
            first = self.monitor.state.problems[0]
            self._finish(
                RunStatus.COMPLETED_WITH_WARNINGS,
                exit_code=exit_code,
                error_message=first.message,
                error_remedy=f"{first.remedy} {self.module.tool_name} reported: {first.source_line}",
            )
        else:
            self._finish(RunStatus.COMPLETED, exit_code=exit_code)

    def _finish(
        self,
        status: RunStatus,
        *,
        exit_code: Optional[int],
        error_message: Optional[str] = None,
        error_remedy: Optional[str] = None,
    ) -> None:
        if self._finished_emitted:
            return
        self._finished_emitted = True
        self._timeout_timer.stop()
        self._kill_timer.stop()
        for handle in (self._stdout_file, self._stderr_file):
            if handle:
                try:
                    handle.close()
                except OSError:
                    pass
        record = self.record
        record.finished_at = datetime.now().astimezone()
        record.exit_code = exit_code
        record.status = status
        record.error_message = error_message
        record.error_remedy = error_remedy
        record.warnings = list(self.monitor.state.warnings)[:50]

        try:
            self.module.finalize_run(record, self.store)
        except Exception:
            # A module bug must not leave the run looking as if it were still going.
            log.exception("Module %s could not finalise run %s", self.module.manifest.id, self.run_id)
            if record.status == RunStatus.COMPLETED:
                record.status = RunStatus.COMPLETED_WITH_WARNINGS
            record.warnings.append("The results of this run could not be read completely.")

        self.store.save(record)
        log.info("Scan %s finished: %s (exit code %s)", self.run_id, record.status.value, exit_code)
        self.finished.emit(record)


class ScanEngine(QObject):
    """Creates and tracks ScanJobs while enforcing the concurrency policy."""

    job_started = pyqtSignal(object)  # ScanJob
    job_finished = pyqtSignal(object)  # ScanJob

    def __init__(self, store: RunStore, registry: ModuleRegistry, *, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self.store = store
        self.registry = registry
        self._jobs: dict[str, ScanJob] = {}
        self.max_concurrent = 1
        self.timeout_seconds = 0
        self.keep_console_logs = True

    @property
    def active_jobs(self) -> list[ScanJob]:
        return [job for job in self._jobs.values() if job.is_running]

    @property
    def is_busy(self) -> bool:
        return len(self.active_jobs) >= self.max_concurrent

    def job(self, run_id: str) -> Optional[ScanJob]:
        return self._jobs.get(run_id)

    def module_for(self, module_id: str) -> ProcessModule:
        module = self.registry.get(module_id)
        if module is None:
            raise ModuleError(f"No module with id '{module_id}' is registered.")
        name = module.manifest.name
        if not isinstance(module, ProcessModule):
            raise ModuleError(f"The {name} module does not run scans.")
        if not self.registry.is_enabled(module_id):
            raise ModuleError(f"The {name} module is turned off.", remedy="Turn it on again on the Modules page.")
        if module.state in (ModuleState.INCOMPATIBLE, ModuleState.ERROR):
            raise ModuleError(f"The {name} module cannot run: {module.last_error or module.state.value}.")
        return module

    def start(
        self,
        config: BaseModel,
        *,
        module_id: str = "nmap",
        profile_name: Optional[str] = None,
        profile_id: Optional[int] = None,
    ) -> ScanJob:
        if self.is_busy:
            raise ScanEngineBusyError(
                remedy="Wait for the running scan to finish or cancel it before starting another.",
            )
        module = self.module_for(module_id)
        issues = module.validate(config)
        if has_errors(issues):
            first = next(i for i in issues if i.severity == "error")
            raise ConfigurationError(first.message, remedy=first.remedy)

        record = self.store.create(config, profile_name=profile_name, module_id=module_id, target_summary=module.describe_targets(config))
        try:
            plan = module.build_plan(config, run_directory=self.store.run_directory(record.run_id))
        except Exception:
            self.store.delete(record.run_id)
            raise
        plan.working_directory = self.store.run_directory(record.run_id)
        record.command = CommandRecord(
            program=str(plan.program),
            arguments=plan.arguments,
            display=plan.display(),
            working_directory=str(plan.working_directory),
            managed_arguments=[a for m in plan.managed_arguments for a in m.arguments],
        )
        self.store.save(record)

        job = ScanJob(
            record,
            plan,
            self.store,
            module=module,
            timeout_seconds=self.timeout_seconds,
            keep_console_logs=self.keep_console_logs,
            parent=self,
        )
        job.profile_id = profile_id
        self._jobs[record.run_id] = job
        job.finished.connect(lambda _record, job=job: self._on_job_finished(job))
        try:
            job.start()
        except Exception as exc:
            self._jobs.pop(record.run_id, None)
            raise NmapExecutionError(f"{module.tool_name} could not be started.", cause=exc)
        self.job_started.emit(job)
        return job

    def cancel_all(self) -> None:
        for job in self.active_jobs:
            job.cancel()

    def _on_job_finished(self, job: ScanJob) -> None:
        self.job_finished.emit(job)
